#!/usr/bin/env python3

###############################################################################
#                                                                             #
# OpenStack Resource Cleanup Tool                                             #
#                                                                             #
# This is a comprehensive cleanup script for OpenStack resources. It can      #
# delete compute instances, networks, volumes, load balancers, Heat stacks,   #
# and other resources matching a specified filter pattern.                    #                                         #
#                                                                             #
# Usage examples:                                                             #
#     $ python3 openstack_cleanup.py --filter ".*test-cluster.*" --dryrun     #
#     $ python3 openstack_cleanup.py --cloud production --dryrun              #
#     $ python3 openstack_cleanup.py --file resource_list.log                 #
#     $ python3 openstack_cleanup.py -r openrc.sh --yes                       #
#                                                                             #
# When no resource list is provided, the script will discover resources       #
# matching the filter pattern (default: ".*test-cluster.*" pattern). You can  #
# specify any regex pattern to match your resource naming convention.         #
#                                                                             #
# Always test with --dryrun first to see what would be deleted!               #
#                                                                             #
###############################################################################

# ====================================================== #
#                        WARNING                         #
# ====================================================== #
# IMPORTANT FOR PRODUCTION ENVIRONMENTS                  #
#                                                        #
# ALWAYS USE --dryrun FIRST TO VERIFY WHICH RESOURCES    #
# WILL BE DELETED. DOUBLE CHECK RESOURCE NAMES MATCH     #
# YOUR INTENDED PATTERN ONLY.                            #
# ====================================================== #

from abc import ABCMeta, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import os
import re
import sys
import threading
import time

from tabulate import tabulate

# OpenStack SDK - the modern way to talk to OpenStack
try:
    import openstack
    from openstack import exceptions as os_exceptions
except ImportError:
    print("❌ ERROR: OpenStack SDK is required but not available.")
    print("   Please install it with: pip install openstacksdk")
    print("   OpenStack SDK has been the standard client since 2018.")
    exit(1)

# Constants to avoid magic numbers scattered throughout the code
DEFAULT_RETRY_COUNT = 3
DEFAULT_VOLUME_DETACH_EXTRA_RETRIES = 5
DEFAULT_LB_RETRY_DELAY = 10
DEFAULT_ROUTER_FIP_WAIT = 5
DEFAULT_PARALLEL = 10
# Verification of asynchronous deletes: each cleaner polls get_*() until the
# resource raises ResourceNotFound or the timeout elapses. Tune via CLI flags
# --wait-timeout / --wait-interval. Set --wait-timeout 0 to disable verification.
DEFAULT_WAIT_TIMEOUT = 300
DEFAULT_WAIT_INTERVAL = 2


# Single lock for all stdout writes so parallel workers don't interleave log lines.
_PRINT_LOCK = threading.Lock()


def log(msg):
    """Thread-safe print; use this from any code that may run under the thread pool."""
    with _PRINT_LOCK:
        print(msg)


def run_in_parallel(items, worker_fn, max_workers):
    """Run ``worker_fn(item)`` for each entry in ``items``.

    - ``max_workers <= 1`` (or a single item) falls back to a plain loop, so callers
      can always use this helper without special-casing the serial path.
    - Exceptions raised by workers are logged but do not abort the batch; individual
      resources already report their own errors via ``report_error``.
    """
    items = list(items)
    if not items:
        return
    if max_workers <= 1 or len(items) == 1:
        for item in items:
            try:
                worker_fn(item)
            except Exception as e:
                log(f'    . Worker error: {e}')
        return
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(worker_fn, item) for item in items]
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                log(f'    . Worker error: {e}')


class ClaimedFloatingIPSet:
    """Thread-safe set of already-handled floating-IP ids.

    ``claim(fid)`` atomically checks membership and, if absent, inserts and returns
    True. This replaces the earlier ``if fid in s: ... s.add(fid)`` pattern which was
    racy when called from multiple workers.
    """

    def __init__(self):
        self._ids = set()
        self._lock = threading.Lock()

    def __contains__(self, fid):
        with self._lock:
            return fid in self._ids

    def claim(self, fid):
        with self._lock:
            if fid in self._ids:
                return False
            self._ids.add(fid)
            return True

    def add(self, fid):
        with self._lock:
            self._ids.add(fid)


class FloatingIPIndex:
    """Lazy, shared port_id -> [FloatingIP] index.

    A single list() call is reused across cleaners to avoid an O(ports * fips)
    listing cost. Listing failures are not cached so transient errors don't
    permanently disable FIP release; retries are capped by _MAX_FAILED_ATTEMPTS.
    """

    _MAX_FAILED_ATTEMPTS = 3

    def __init__(self, conn):
        self._conn = conn
        self._by_port = None
        self._failed_attempts = 0
        self._lock = threading.Lock()

    def _ensure_loaded(self):
        if self._by_port is not None:
            return self._by_port
        with self._lock:
            if self._by_port is not None:
                return self._by_port
            if self._failed_attempts >= self._MAX_FAILED_ATTEMPTS:
                return {}
            by_port = {}
            try:
                for fip in self._conn.network.ips():
                    pid = getattr(fip, 'port_id', None)
                    if pid:
                        by_port.setdefault(pid, []).append(fip)
            except Exception as e:
                self._failed_attempts += 1
                log(f'    . Could not list floating IPs '
                    f'(attempt {self._failed_attempts}/{self._MAX_FAILED_ATTEMPTS}): {e}')
                return {}
            self._by_port = by_port
            return by_port

    def for_port(self, port_id):
        if not port_id:
            return []
        return list(self._ensure_loaded().get(port_id, []))

    def all_by_port(self):
        return dict(self._ensure_loaded())


def release_floating_ips_on_port(conn, port_id, dryrun, claimed_fip_ids,
                                   report_deletion, report_not_found, report_error,
                                   fip_index=None):
    """Delete Neutron floating IPs associated with ``port_id`` (``floatingip.port_id``).

    When ``fip_index`` (a :class:`FloatingIPIndex`) is supplied, lookups avoid issuing
    a fresh ``network.ips()`` listing for every call, which is the single biggest
    win on large deployments. When ``claimed_fip_ids`` is a :class:`ClaimedFloatingIPSet`,
    the claim is atomic so duplicate delete attempts don't race across threads.
    """
    if not port_id:
        return
    if fip_index is not None:
        attached = fip_index.for_port(port_id)
    else:
        try:
            attached = [
                fip for fip in conn.network.ips()
                if getattr(fip, 'port_id', None) == port_id
            ]
        except Exception as e:
            log(f'    . Could not list floating IPs for port {port_id}: {e}')
            return

    for fip in attached:
        fid = fip.id
        if claimed_fip_ids is not None:
            # Atomic check-and-claim: prevents two workers from both attempting the
            # same delete_ip when the same FIP is reachable from, e.g., both an
            # instance port and a router port.
            if isinstance(claimed_fip_ids, ClaimedFloatingIPSet):
                if not claimed_fip_ids.claim(fid):
                    continue
            else:
                if fid in claimed_fip_ids:
                    continue
                claimed_fip_ids.add(fid)
        addr = fip.floating_ip_address
        if dryrun:
            report_deletion('FLOATING IP', addr)
        else:
            try:
                conn.network.delete_ip(fid)
                report_deletion('FLOATING IP', addr)
            except os_exceptions.ResourceNotFound:
                report_not_found('FLOATING IP', addr)
            except Exception as e:
                report_error('FLOATING IP', addr, str(e))


# ============================================================================ #
# Credentials - handling OpenStack authentication the easy way                 #
# ============================================================================ #

class Credentials:
    """Dead simple credentials class that just uses OpenStack SDK's built-in auth."""
    
    def __init__(self, openrc_file=None, cloud_name=None):
        """Set up credentials from openrc file, clouds.yaml, or environment.
        
        Args:
            openrc_file: Path to OpenRC file (optional)
            cloud_name: Name of cloud in clouds.yaml (optional)
        """
        self.openrc_file = openrc_file
        self.cloud_name = cloud_name
        self.rc_auth_url = None
        
        # Load openrc file if we have one
        if openrc_file and os.path.exists(openrc_file):
            self._load_openrc_file(openrc_file)
        elif openrc_file:
            print(f'Error: rc file does not exist {openrc_file}')
            return
        
        # Quick sanity check (skip if using clouds.yaml)
        if not cloud_name:
            self._validate_auth()
    
    def _load_openrc_file(self, openrc_file):
        """Parse openrc file and load environment variables."""
        try:
            with open(openrc_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('export '):
                        # Handle export statements: export VAR=value
                        line = line[7:]  # Strip 'export '
                        if '=' in line:
                            key, value = line.split('=', 1)
                            # Clean up quotes
                            value = value.strip('"\'')
                            os.environ[key] = value
        except Exception as e:
            print(f'Failed to load openrc file {openrc_file}: {e}')
    
    def _validate_auth(self):
        """Make sure we have the basics for authentication."""
        # If using clouds.yaml, let SDK validate
        if self.cloud_name:
            return True
            
        # Need auth URL no matter what
        self.rc_auth_url = os.environ.get('OS_AUTH_URL')
        
        if not self.rc_auth_url:
            return False
            
        # App credentials are preferred
        if (os.environ.get('OS_APPLICATION_CREDENTIAL_ID') and 
            os.environ.get('OS_APPLICATION_CREDENTIAL_SECRET')):
            return True
            
        # Old school username/password still works
        if (os.environ.get('OS_USERNAME') and 
            os.environ.get('OS_PROJECT_NAME')):
            return True
            
        return False
    
    def get_session(self):
        """Get an authenticated session to talk to OpenStack.
        
        Returns:
            keystoneauth1.session.Session: Ready to use session
        """
        try:
            # If we have a specific cloud name, use it
            if self.cloud_name:
                conn = openstack.connect(cloud=self.cloud_name)
            else:
                # Let the SDK figure out the auth details
                # It handles everything: app creds, passwords, tokens, clouds.yaml, etc.
                conn = openstack.connect()
            return conn.session
        except Exception as e:
            print(f'Failed to create OpenStack session: {e}')
            if self.cloud_name:
                print(f"Make sure cloud '{self.cloud_name}' exists in your clouds.yaml")
                print("Expected locations: ~/.config/openstack/clouds.yaml or ./clouds.yaml")
            raise

# Global regex pattern for matching resource names
resource_name_re = None

def prompt_to_run(auto_approve=False):
    print("Warning: You didn't specify a resource list file as the input. "
          "The script will delete all resources shown above.")
    if auto_approve:
        print("Auto-approved with --yes flag.")
        return
    answer = input("Are you sure? (y/n) ")
    if answer.lower() != 'y':
        sys.exit(0)

def fetch_resources(fetcher, options=None):
    """Get OpenStack resources with some basic error handling."""
    try:
        return fetcher(search_opts=options) if options else fetcher()
    except os_exceptions.ForbiddenException:
        print('⚠️  Warning: Insufficient permissions to list some resources')
        return []
    except os_exceptions.EndpointNotFound:
        print('⚠️  Warning: Service endpoint not found in catalog (service may be disabled or unavailable)')
        return []
    except Exception as e:
        print(f'⚠️  Warning: Exception while listing resources: {e}')
        return []

def build_resource_dict(res_list):
    """Turn a list of resources into a nice ID->name dictionary."""
    resources = {}
    for res in res_list:
        try:
            resid = res.id
            resname = getattr(res, 'name', resid)
            resdesc = getattr(res, 'description', '')
        except AttributeError:
            resid = res.get('id', res)
            resname = res.get('name', resid)
            resdesc = res.get('description', '')

        if resname and (resource_name_re.search(str(resname)) or
                       (resdesc and resource_name_re.search(str(resdesc)))):
            resources[resid] = resname
    return resources

class AbstractCleaner(metaclass=ABCMeta):

    def __init__(self, res_category, res_desc, resources, dryrun, parallelism=1,
                 wait_timeout=DEFAULT_WAIT_TIMEOUT, wait_interval=DEFAULT_WAIT_INTERVAL):
        self.dryrun = dryrun
        self.category = res_category
        self.parallelism = max(1, int(parallelism))
        self.wait_timeout = max(0, int(wait_timeout))
        self.wait_interval = max(1, int(wait_interval))
        self._wait_lock = threading.Lock()
        self.resources = {}
        self.fip_index = None  # Set via set_fip_index() before clean().
        if not resources:
            print(f'Discovering {res_category} resources...')
        for rtype, fetch_args in res_desc.items():
            if resources and rtype in resources:
                self.resources[rtype] = resources[rtype]
            else:
                res_list = fetch_resources(*fetch_args)
                self.resources[rtype] = build_resource_dict(res_list)

    def set_fip_index(self, fip_index):
        """Inject the shared FloatingIPIndex so per-port FIP lookups are O(1)."""
        self.fip_index = fip_index

    def report_deletion(self, rtype, name):
        status = "(but is not deleted: dry run)" if self.dryrun else "is successfully deleted"
        log(f'    + {rtype} {name} {status}')

    def report_not_found(self, rtype, name):
        log(f'    ? {rtype} {name} not found (already deleted?)')

    def report_error(self, rtype, name, reason):
        log(f'    - {rtype} {name} ERROR: {reason}')

    def report_verified(self, rtype, name):
        log(f'    ✓ {rtype} {name} confirmed deleted')

    def _wait_until_gone(self, label, items, getter, on_gone=None):
        """Poll ``getter(id)`` for each ``(id, name)`` in ``items`` until each one
        either raises ``ResourceNotFound`` (confirmed deleted) or the configured
        ``wait_timeout`` elapses.

        Returns the list of ``(id, name)`` tuples that did NOT confirm deletion
        (the "stragglers"). ``on_gone(label, name)`` is called once per
        confirmed deletion; defaults to :meth:`report_verified`.
        """
        if self.dryrun or self.wait_timeout <= 0 or not items:
            return []
        if on_gone is None:
            on_gone = self.report_verified
        pending = dict(items)
        deadline = time.time() + self.wait_timeout

        def _check(rid):
            try:
                getter(rid)
            except os_exceptions.ResourceNotFound:
                with self._wait_lock:
                    name = pending.pop(rid, None)
                if name is not None:
                    on_gone(label, name)
            except Exception:
                # Transient errors: leave it for the next round.
                pass

        while pending and time.time() < deadline:
            run_in_parallel(list(pending.keys()), _check, self.parallelism)
            if pending and time.time() < deadline:
                time.sleep(self.wait_interval)
        return list(pending.items())

    def verify(self):
        """Confirm targeted resources are actually gone.

        Subclasses override this to poll ``get_*`` for each resource type they
        manage. Returns a list of ``(rtype, id, name)`` for any resource that
        did not disappear within ``wait_timeout`` seconds. Default: no-op.
        """
        return []

    def get_resource_list(self):
        result = []
        for rtype, rdict in self.resources.items():
            for resid, resname in rdict.items():
                result.append([rtype, resname, resid])
        return result

    @abstractmethod
    def clean(self):
        pass

class StorageCleaner(AbstractCleaner):
    def __init__(self, sess, resources, dryrun, parallelism=1,
                 wait_timeout=DEFAULT_WAIT_TIMEOUT, wait_interval=DEFAULT_WAIT_INTERVAL):
        self.conn = openstack.connection.Connection(session=sess)
        
        def volumes_fetcher():
            return list(self.conn.block_storage.volumes())
            
        def snapshots_fetcher():
            return list(self.conn.block_storage.snapshots())

        res_desc = {
            'volumes': [volumes_fetcher],
            'volume_snapshots': [snapshots_fetcher]
        }
            
        super(StorageCleaner, self).__init__(
            'Storage', res_desc, resources, dryrun, parallelism,
            wait_timeout=wait_timeout, wait_interval=wait_interval,
        )

    def _delete_volume(self, item):
        vid, name = item
        try:
            if self.dryrun:
                self.conn.block_storage.get_volume(vid)
            else:
                self.conn.block_storage.delete_volume(vid)
            self.report_deletion('VOLUME', name)
        except os_exceptions.ResourceNotFound:
            self.report_not_found('VOLUME', name)
        except Exception as e:
            self.report_error('VOLUME', name, str(e))

    def _delete_snapshot(self, item):
        sid, name = item
        try:
            if self.dryrun:
                self.conn.block_storage.get_snapshot(sid)
            else:
                self.conn.block_storage.delete_snapshot(sid)
            self.report_deletion('VOLUME SNAPSHOT', name)
        except os_exceptions.ResourceNotFound:
            self.report_not_found('VOLUME SNAPSHOT', name)
        except Exception as e:
            self.report_error('VOLUME SNAPSHOT', name, str(e))

    def clean(self):
        print('*** STORAGE cleanup')

        # Volumes and snapshots are all independent; parallelize each group.
        run_in_parallel(
            list(self.resources.get('volumes', {}).items()),
            self._delete_volume, self.parallelism,
        )
        run_in_parallel(
            list(self.resources.get('volume_snapshots', {}).items()),
            self._delete_snapshot, self.parallelism,
        )

    def verify(self):
        stragglers = []
        remaining = self._wait_until_gone(
            'VOLUME',
            list(self.resources.get('volumes', {}).items()),
            self.conn.block_storage.get_volume,
        )
        stragglers.extend(('volumes', rid, name) for rid, name in remaining)
        remaining = self._wait_until_gone(
            'VOLUME SNAPSHOT',
            list(self.resources.get('volume_snapshots', {}).items()),
            self.conn.block_storage.get_snapshot,
        )
        stragglers.extend(('volume_snapshots', rid, name) for rid, name in remaining)
        return stragglers


class ComputeCleaner(AbstractCleaner):
    def __init__(self, sess, resources, dryrun, parallelism=1,
                 wait_timeout=DEFAULT_WAIT_TIMEOUT, wait_interval=DEFAULT_WAIT_INTERVAL):
        self.conn = openstack.connection.Connection(session=sess)
        
        def instances_fetcher():
            return list(self.conn.compute.servers())

        def keypairs_fetcher():
            return list(self.conn.compute.keypairs())

        res_desc = {
            'instances': [instances_fetcher],
            'keypairs': [keypairs_fetcher]
        }
        
        super(ComputeCleaner, self).__init__(
            'Compute', res_desc, resources, dryrun, parallelism,
            wait_timeout=wait_timeout, wait_interval=wait_interval,
        )
        self.claimed_fip_ids = None
        # Guards the shared ``deleting_instances`` dict mutated from delete/poll workers.
        self._deleting_lock = threading.Lock()
        # Instances we asked Nova to delete but couldn't confirm gone within the
        # wait timeout. Surfaced via ``verify()`` so the parent run can report
        # / fail strictly.
        self._instance_stragglers = {}

    def set_claimed_floating_ips(self, id_set):
        self.claimed_fip_ids = id_set

    def _release_floating_ips_for_instance(self, instance_id):
        try:
            for port in self.conn.network.ports(device_id=instance_id):
                release_floating_ips_on_port(
                    self.conn, port.id, self.dryrun, self.claimed_fip_ids,
                    self.report_deletion, self.report_not_found, self.report_error,
                    fip_index=self.fip_index)
        except Exception as e:
            log(f'    . Could not list Neutron ports for instance {instance_id}: {e}')

    def _delete_instance(self, item, deleting_instances):
        ins_id, ins_name = item
        try:
            self.conn.compute.get_server(ins_id)
            self._release_floating_ips_for_instance(ins_id)
            if self.dryrun:
                self.report_deletion('INSTANCE', ins_name)
            else:
                self.conn.compute.delete_server(ins_id)
        except os_exceptions.ResourceNotFound:
            with self._deleting_lock:
                deleting_instances.pop(ins_id, None)
            self.report_not_found('INSTANCE', ins_name)
        except Exception as e:
            self.report_error('INSTANCE', ins_name, str(e))

    def clean(self):
        print('*** COMPUTE cleanup')

        deleting_instances = dict(self.resources.get('instances', {}))
        run_in_parallel(
            list(self.resources.get('instances', {}).items()),
            lambda item: self._delete_instance(item, deleting_instances),
            self.parallelism,
        )

        if not self.dryrun and deleting_instances:
            self._wait_for_instance_deletion(deleting_instances)

        # Snapshot stragglers so verify() can re-check / report them.
        self._instance_stragglers = dict(deleting_instances)

        self._clean_keypairs()

    def _wait_for_instance_deletion(self, deleting_instances):
        """Wait for instances to finish deleting - sometimes they take a while.

        Each polling round issues one ``get_server`` per still-deleting instance.
        We fan those reads out across the thread pool so a 500-node cluster doesn't
        serialize 500 GETs per iteration. Bounded by ``--wait-timeout`` /
        ``--wait-interval`` (see :data:`DEFAULT_WAIT_TIMEOUT`).
        """
        if self.wait_timeout <= 0:
            print(f'    . Skipping instance deletion wait (--wait-timeout 0); '
                  f'{len(deleting_instances)} delete requests issued.')
            return
        print(f'    . Waiting up to {self.wait_timeout}s for {len(deleting_instances)} '
              f'instances to be fully deleted...')

        items = list(deleting_instances.items())
        remaining = self._wait_until_gone(
            'INSTANCE', items, self.conn.compute.get_server,
            on_gone=self.report_deletion,
        )
        # Sync ``deleting_instances`` so the caller observes the post-wait state.
        with self._deleting_lock:
            deleting_instances.clear()
            for rid, name in remaining:
                deleting_instances[rid] = name

        if remaining:
            print(f'    . Warning: {len(remaining)} instances may still be deleting '
                  f'(timeout {self.wait_timeout}s; tune via --wait-timeout)')

    def _delete_keypair(self, item):
        _keypair_id, keypair_name = item
        try:
            if not self.dryrun:
                self.conn.compute.delete_keypair(keypair_name)
            self.report_deletion('KEYPAIR', keypair_name)
        except os_exceptions.ResourceNotFound:
            self.report_not_found('KEYPAIR', keypair_name)
        except Exception as e:
            self.report_error('KEYPAIR', keypair_name, str(e))

    def _clean_keypairs(self):
        """Clean up keypairs."""
        run_in_parallel(
            list(self.resources.get('keypairs', {}).items()),
            self._delete_keypair, self.parallelism,
        )

    def verify(self):
        # Instances were already polled inside ``clean()``; re-check stragglers
        # in case they finished after we gave up. Keypairs are synchronous, so
        # we trust the delete response.
        if not self._instance_stragglers:
            return []
        remaining = self._wait_until_gone(
            'INSTANCE',
            list(self._instance_stragglers.items()),
            self.conn.compute.get_server,
        )
        return [('instances', rid, name) for rid, name in remaining]


class NetworkCleaner(AbstractCleaner):

    _PORT_SKIP_OWNERS = frozenset([
        'network:router_interface', 'network:dhcp', 'network:router_gateway',
    ])
    _NETWORK_PORT_SKIP_OWNERS = frozenset([
        'network:dhcp', 'network:router_interface',
        'network:router_gateway', 'network:floatingip',
        'network:ha_router_replicated_interface',
    ])

    def __init__(self, sess, resources, dryrun, parallelism=1,
                 wait_timeout=DEFAULT_WAIT_TIMEOUT, wait_interval=DEFAULT_WAIT_INTERVAL):
        self.conn = openstack.connection.Connection(session=sess)
        
        def networks_fetcher():
            return list(self.conn.network.networks())

        def routers_fetcher():
            return list(self.conn.network.routers())

        def secgroup_fetcher():
            return list(self.conn.network.security_groups())

        res_desc = {
            'sec_groups': [secgroup_fetcher],
            'networks': [networks_fetcher],
            'routers': [routers_fetcher]
        }
        super(NetworkCleaner, self).__init__(
            'Network', res_desc, resources, dryrun, parallelism,
            wait_timeout=wait_timeout, wait_interval=wait_interval,
        )
        self.claimed_fip_ids = None

    def set_claimed_floating_ips(self, id_set):
        self.claimed_fip_ids = id_set

    def _release_fips_on_port(self, port_id):
        release_floating_ips_on_port(
            self.conn, port_id, self.dryrun, self.claimed_fip_ids,
            self.report_deletion, self.report_not_found, self.report_error,
            fip_index=self.fip_index)

    def remove_router_interface(self, router_id, port):
        """Clean up router interface the hard way."""
        try:
            subnet_id = port['fixed_ips'][0]['subnet_id'] if 'fixed_ips' in port else port.fixed_ips[0]['subnet_id']
            self.conn.network.remove_interface_from_router(router_id, subnet_id=subnet_id)
            ip_address = port['fixed_ips'][0]['ip_address'] if 'fixed_ips' in port else port.fixed_ips[0]['ip_address']
            self.report_deletion('Router Interface', ip_address)
        except Exception:
            pass

    def _delete_matching_port(self, port):
        port_id = port.id
        port_name = port.name
        try:
            device_owner = port.device_owner
            # System ports are owned by their parent (router/DHCP/gateway) and are
            # cleaned up when the parent is deleted; trying to delete them via the
            # port API fails.
            if device_owner in self._PORT_SKIP_OWNERS:
                log(f'    . Skipping {device_owner} port {port_name}')
                return
            self._release_fips_on_port(port_id)
            if not self.dryrun:
                self.conn.network.delete_port(port_id)
            self.report_deletion('PORT', port_name)
        except os_exceptions.ResourceNotFound:
            self.report_not_found('PORT', port_name)
        except Exception as e:
            self.report_error('PORT', port_name, str(e))

    def _delete_router(self, item):
        rid, name = item
        try:
            if self.dryrun:
                self.conn.network.get_router(rid)
                port_list = list(self.conn.network.ports(device_id=rid))
                for port in port_list:
                    self._release_fips_on_port(port.id)
                self.report_deletion('Router Gateway', name)
                for port in port_list:
                    if port.fixed_ips:
                        self.report_deletion('Router Interface', port.fixed_ips[0]['ip_address'])
            else:
                router = self.conn.network.get_router(rid)
                log(f'    . Releasing floating IPs on ports for router {name}...')
                port_list = list(self.conn.network.ports(device_id=rid))
                # Release FIPs on this router's ports in parallel; they're independent.
                run_in_parallel(
                    [p.id for p in port_list],
                    self._release_fips_on_port, self.parallelism,
                )

                if port_list or router.external_gateway_info:
                    log('    . Waiting for floating IPs to be fully released...')
                    time.sleep(DEFAULT_ROUTER_FIP_WAIT)

                if router.external_gateway_info:
                    try:
                        self.conn.network.update_router(rid, external_gateway_info=None)
                        self.report_deletion('Router Gateway', name)
                    except Exception as e:
                        log(f'    . Could not remove router gateway: {str(e)}')

                # Re-list after gateway removal to catch any residual interfaces.
                port_list = list(self.conn.network.ports(device_id=rid))

                def _remove_iface(port):
                    if not port.fixed_ips:
                        return
                    try:
                        self.conn.network.remove_interface_from_router(
                            rid, subnet_id=port.fixed_ips[0]['subnet_id']
                        )
                    except Exception:
                        pass  # Interface may already be removed.

                run_in_parallel(port_list, _remove_iface, self.parallelism)

                self.conn.network.delete_router(rid)
            self.report_deletion('ROUTER', name)
        except os_exceptions.ResourceNotFound:
            self.report_not_found('ROUTER', name)
        except os_exceptions.ConflictException as e:
            self.report_error('ROUTER', name, f'Conflict (may have dependencies): {str(e)}')
        except Exception as e:
            self.report_error('ROUTER', name, str(e))

    def _delete_network(self, item):
        nid, name = item
        retry_count = 3
        while retry_count > 0:
            try:
                if self.dryrun:
                    self.conn.network.get_network(nid)
                    self.report_deletion('NETWORK', name)
                    return
                # Clean up any residual ports we can (skip system-owned ones).
                try:
                    remaining_ports = list(self.conn.network.ports(network_id=nid))
                    if remaining_ports:
                        log(f'    . Network {name} has {len(remaining_ports)} remaining ports, checking...')

                        def _delete_residual(port):
                            owner = port.device_owner or ''
                            if (owner in self._NETWORK_PORT_SKIP_OWNERS
                                    or owner.startswith('network:router')
                                    or owner.startswith('network:ha_router')):
                                return
                            try:
                                self._release_fips_on_port(port.id)
                                log(f'    . Deleting remaining port {port.name or port.id}...')
                                self.conn.network.delete_port(port.id)
                            except Exception as e:
                                log(f'    . Could not delete port {port.id}: {str(e)}')

                        run_in_parallel(remaining_ports, _delete_residual, self.parallelism)
                except Exception as e:
                    log(f'    . Could not check network ports: {str(e)}')

                self.conn.network.delete_network(nid)
                self.report_deletion('NETWORK', name)
                return
            except os_exceptions.ResourceNotFound:
                self.report_not_found('NETWORK', name)
                return
            except os_exceptions.ConflictException as e:
                retry_count -= 1
                if retry_count > 0:
                    log(f'    . Network {name} still has dependencies, retrying in 5 seconds... ({retry_count} retries left)')
                    time.sleep(5)
                else:
                    self.report_error('NETWORK', name, f'Still has dependencies after retries: {str(e)}')
                    return
            except Exception as e:
                self.report_error('NETWORK', name, str(e))
                return

    def _delete_security_group(self, item):
        sgid, name = item
        retry_count = 3
        while retry_count > 0:
            try:
                if self.dryrun:
                    self.conn.network.get_security_group(sgid)
                else:
                    self.conn.network.delete_security_group(sgid)
                self.report_deletion('SECURITY GROUP', name)
                return
            except os_exceptions.ResourceNotFound:
                self.report_not_found('SECURITY GROUP', name)
                return
            except os_exceptions.ConflictException as e:
                retry_count -= 1
                if retry_count > 0:
                    log(f'    . Security group {name} still in use, retrying in 5 seconds... ({retry_count} retries left)')
                    time.sleep(5)
                else:
                    self.report_error('SECURITY GROUP', name, f'Still in use after retries: {str(e)}')
                    return
            except Exception as e:
                self.report_error('SECURITY GROUP', name, str(e))
                return

    def clean(self):
        print('*** NETWORK cleanup')
        global resource_name_re

        # The between-step order (ports -> routers -> networks -> security groups)
        # is preserved; only the work within each step is parallelized.
        security_groups_to_delete = list(self.resources.get('sec_groups', {}).items())

        # Ports matching the filter.
        try:
            all_ports = list(self.conn.network.ports())
            matching_ports = [
                p for p in all_ports
                if resource_name_re.search(str(p.name)) or resource_name_re.search(str(p.id))
            ]
            run_in_parallel(matching_ports, self._delete_matching_port, self.parallelism)
        except Exception as e:
            print(f'    . Could not list ports: {str(e)}')

        run_in_parallel(
            list(self.resources.get('routers', {}).items()),
            self._delete_router, self.parallelism,
        )
        run_in_parallel(
            list(self.resources.get('networks', {}).items()),
            self._delete_network, self.parallelism,
        )

        if security_groups_to_delete:
            if not self.dryrun:
                print('    . Waiting a moment for instances to be fully deleted...')
                time.sleep(5)
            run_in_parallel(
                security_groups_to_delete,
                self._delete_security_group, self.parallelism,
            )

    def verify(self):
        stragglers = []
        remaining = self._wait_until_gone(
            'NETWORK',
            list(self.resources.get('networks', {}).items()),
            self.conn.network.get_network,
        )
        stragglers.extend(('networks', rid, name) for rid, name in remaining)
        remaining = self._wait_until_gone(
            'ROUTER',
            list(self.resources.get('routers', {}).items()),
            self.conn.network.get_router,
        )
        stragglers.extend(('routers', rid, name) for rid, name in remaining)
        remaining = self._wait_until_gone(
            'SECURITY GROUP',
            list(self.resources.get('sec_groups', {}).items()),
            self.conn.network.get_security_group,
        )
        stragglers.extend(('sec_groups', rid, name) for rid, name in remaining)
        return stragglers


class LoadBalancerCleaner(AbstractCleaner):

    def __init__(self, sess, resources, dryrun, parallelism=1,
                 wait_timeout=DEFAULT_WAIT_TIMEOUT, wait_interval=DEFAULT_WAIT_INTERVAL):
        self.session = sess

        # Initialize OpenStack SDK connection
        self.conn = openstack.connection.Connection(session=sess)
        
        def loadbalancers_fetcher():
            return list(self.conn.load_balancer.load_balancers())

        res_desc = {
            'loadbalancers': [loadbalancers_fetcher]
        }
        super(LoadBalancerCleaner, self).__init__(
            'LoadBalancer', res_desc, resources, dryrun, parallelism,
            wait_timeout=wait_timeout, wait_interval=wait_interval,
        )
        self.claimed_fip_ids = None

    def set_claimed_floating_ips(self, id_set):
        self.claimed_fip_ids = id_set

    def _delete_loadbalancer(self, item):
        lb_id, name = item
        retry_count = DEFAULT_RETRY_COUNT
        while retry_count > 0:
            try:
                if self.dryrun:
                    try:
                        lb = self.conn.load_balancer.get_load_balancer(lb_id)
                        release_floating_ips_on_port(
                            self.conn, lb.vip_port_id, True, self.claimed_fip_ids,
                            self.report_deletion, self.report_not_found, self.report_error,
                            fip_index=self.fip_index)
                    except os_exceptions.ResourceNotFound:
                        pass
                    except Exception as e:
                        log(f'    . Could not inspect load balancer {name} for VIP floating IPs (dryrun): {e}')
                    self.report_deletion('LOAD BALANCER', name)
                    return

                try:
                    lb = self.conn.load_balancer.get_load_balancer(lb_id)
                    if lb.provisioning_status in ['PENDING_UPDATE', 'PENDING_CREATE', 'PENDING_DELETE']:
                        log(f'    . Load balancer {name} is in {lb.provisioning_status} state, waiting...')
                        retry_count -= 1
                        if retry_count > 0:
                            time.sleep(DEFAULT_LB_RETRY_DELAY)
                            continue
                        self.report_error('LOAD BALANCER', name, f'Still in {lb.provisioning_status} state after retries')
                        return
                    release_floating_ips_on_port(
                        self.conn, lb.vip_port_id, False, self.claimed_fip_ids,
                        self.report_deletion, self.report_not_found, self.report_error,
                        fip_index=self.fip_index)
                except os_exceptions.ResourceNotFound:
                    self.report_not_found('LOAD BALANCER', name)
                    return

                self.conn.load_balancer.delete_load_balancer(lb_id, cascade=True)
                self.report_deletion('LOAD BALANCER', name)
                return
            except os_exceptions.ResourceNotFound:
                self.report_not_found('LOAD BALANCER', name)
                return
            except os_exceptions.ConflictException as e:
                retry_count -= 1
                if retry_count > 0:
                    log(f'    . Load balancer {name} conflict, retrying in {DEFAULT_LB_RETRY_DELAY} seconds... ({retry_count} retries left)')
                    time.sleep(DEFAULT_LB_RETRY_DELAY)
                else:
                    self.report_error('LOAD BALANCER', name, f'Conflict after retries: {str(e)}')
                    return
            except Exception as e:
                self.report_error('LOAD BALANCER', name, str(e))
                return

    def clean(self):
        print('*** LOAD BALANCER cleanup')
        # Cascade-delete each LB independently; listeners/pools go with them.
        run_in_parallel(
            list(self.resources.get('loadbalancers', {}).items()),
            self._delete_loadbalancer, self.parallelism,
        )

    def verify(self):
        remaining = self._wait_until_gone(
            'LOAD BALANCER',
            list(self.resources.get('loadbalancers', {}).items()),
            self.conn.load_balancer.get_load_balancer,
        )
        return [('loadbalancers', rid, name) for rid, name in remaining]


class DnsCleaner(AbstractCleaner):
    """Cleaner for DNS (Designate) zones."""

    def __init__(self, sess, resources, dryrun, parallelism=1,
                 wait_timeout=DEFAULT_WAIT_TIMEOUT, wait_interval=DEFAULT_WAIT_INTERVAL):
        self.conn = openstack.connection.Connection(session=sess)
        res_desc = {}
        try:
            list(self.conn.dns.zones(limit=1))
            res_desc['dns_zones'] = [lambda c=self.conn: list(c.dns.zones())]
        except Exception:
            pass
        super(DnsCleaner, self).__init__(
            'DNS', res_desc, resources, dryrun, parallelism,
            wait_timeout=wait_timeout, wait_interval=wait_interval,
        )

    def _delete_zone(self, item):
        zone_id, zone_name = item
        try:
            if not self.dryrun:
                self.conn.dns.delete_zone(zone_id)
            self.report_deletion('DNS ZONE', zone_name)
        except os_exceptions.ResourceNotFound:
            self.report_not_found('DNS ZONE', zone_name)
        except Exception as e:
            self.report_error('DNS ZONE', zone_name, str(e))

    def clean(self):
        if 'dns_zones' not in self.resources:
            return
        print('*** DNS (Designate) cleanup')
        run_in_parallel(
            list(self.resources['dns_zones'].items()),
            self._delete_zone, self.parallelism,
        )


class HeatCleaner(AbstractCleaner):
    """Cleaner for Heat (orchestration) stacks."""

    def __init__(self, sess, resources, dryrun, parallelism=1,
                 wait_timeout=DEFAULT_WAIT_TIMEOUT, wait_interval=DEFAULT_WAIT_INTERVAL):
        self.conn = openstack.connection.Connection(session=sess)
        res_desc = {}
        try:
            list(self.conn.orchestration.stacks(limit=1))

            def stacks_fetcher():
                all_stacks = list(self.conn.orchestration.stacks())
                unique_stacks = {s.id: s for s in all_stacks}
                return list(unique_stacks.values())

            res_desc['heat_stacks'] = [stacks_fetcher]
        except Exception:
            pass
        super(HeatCleaner, self).__init__(
            'Heat', res_desc, resources, dryrun, parallelism,
            wait_timeout=wait_timeout, wait_interval=wait_interval,
        )

    def _delete_and_wait_stack(self, item):
        # Each stack's ``get -> delete -> wait_for_delete`` sequence is independent
        # of other stacks, so running the whole sequence per-worker gives maximum
        # parallelism. ``wait_for_delete`` is what used to dominate runtime.
        stack_id, stack_name = item
        try:
            if self.dryrun:
                self.report_deletion('HEAT STACK', stack_name)
                return
            log(f'    . Deleting Heat stack {stack_name} and waiting for completion...')
            stack = self.conn.orchestration.get_stack(stack_id)
            self.conn.orchestration.delete_stack(stack)
            self.conn.orchestration.wait_for_delete(stack)
            self.report_deletion('HEAT STACK', stack_name)
        except os_exceptions.ResourceNotFound:
            self.report_not_found('HEAT STACK', stack_name)
        except Exception as e:
            self.report_error('HEAT STACK', stack_name, str(e))

    def clean(self):
        if 'heat_stacks' not in self.resources:
            return
        print('*** HEAT (orchestration) cleanup')
        run_in_parallel(
            list(self.resources['heat_stacks'].items()),
            self._delete_and_wait_stack, self.parallelism,
        )


def collect_preview_floating_ip_rows(conn, cleaners, fip_index=None):
    """FIPs that cleanup will remove (same attachment rules as release), for the summary table."""
    if fip_index is not None:
        fips_by_port = fip_index.all_by_port()
    else:
        try:
            fips_by_port = {}
            for fip in conn.network.ips():
                pid = getattr(fip, 'port_id', None)
                if pid:
                    fips_by_port.setdefault(pid, []).append(fip)
        except Exception:
            return []

    seen = set()
    rows = []

    def add_port_fips(port_id):
        if not port_id:
            return
        for fip in fips_by_port.get(port_id, ()):
            if fip.id in seen:
                continue
            seen.add(fip.id)
            rows.append(['floating_ips', fip.floating_ip_address, fip.id])

    skip_port_owners = frozenset([
        'network:router_interface', 'network:dhcp', 'network:router_gateway'])

    for c in cleaners:
        if isinstance(c, ComputeCleaner):
            for ins_id in c.resources.get('instances', {}):
                try:
                    for port in conn.network.ports(device_id=ins_id):
                        add_port_fips(port.id)
                except Exception:
                    pass
        elif isinstance(c, LoadBalancerCleaner):
            for lb_id in c.resources.get('loadbalancers', {}):
                try:
                    lb = conn.load_balancer.get_load_balancer(lb_id)
                    add_port_fips(lb.vip_port_id)
                except Exception:
                    pass
        elif isinstance(c, NetworkCleaner):
            try:
                for port in conn.network.ports():
                    port_name = port.name
                    if not (resource_name_re.search(str(port_name)) or
                            resource_name_re.search(str(port.id))):
                        continue
                    if (port.device_owner or '') in skip_port_owners:
                        continue
                    add_port_fips(port.id)
            except Exception:
                pass
            for rid in c.resources.get('routers', {}):
                try:
                    for port in conn.network.ports(device_id=rid):
                        add_port_fips(port.id)
                except Exception:
                    pass
    rows.sort(key=lambda r: (r[1] or ''))
    return rows


# Type names (for --types) and their cleaner classes, in cleanup order
CLEANER_TYPES = [
    ('heat', HeatCleaner),                  # orchestration stacks
    ('dns', DnsCleaner),                    # Designate DNS zones
    ('compute', ComputeCleaner),            # instances, keypairs
    ('storage', StorageCleaner),            # volumes, volume_snapshots
    ('loadbalancer', LoadBalancerCleaner),
    ('network', NetworkCleaner),            # ports, sec_groups, networks, routers
]


class OpenStackCleaners():

    def __init__(self, creds_obj, resources, dryrun, resource_types=None,
                 parallelism=DEFAULT_PARALLEL,
                 wait_timeout=DEFAULT_WAIT_TIMEOUT,
                 wait_interval=DEFAULT_WAIT_INTERVAL):
        """
        resource_types: if set, only run these cleaners (e.g. ['compute', 'network']).
        If None or empty, run all cleaners.
        parallelism: max concurrent delete workers per resource type (1 == serial).
        wait_timeout: max seconds to poll each resource group for confirmed
            deletion (0 disables verification).
        wait_interval: seconds between poll rounds.
        """
        self.cleaners = []
        self.dryrun = dryrun
        self.parallelism = max(1, int(parallelism))
        self.wait_timeout = max(0, int(wait_timeout))
        self.wait_interval = max(1, int(wait_interval))
        sess = creds_obj.get_session()
        self._session = sess
        # Thread-safe set shared across cleaners so they don't double-delete FIPs
        # that happen to be reachable from multiple resources.
        claimed_floating_ip_ids = ClaimedFloatingIPSet()
        # Single FIP index built lazily on first use, shared across all cleaners
        # and the preview step. Avoids listing all FIPs once per port.
        self._preview_conn = openstack.connection.Connection(session=sess)
        self.fip_index = FloatingIPIndex(self._preview_conn)

        types_set = set(resource_types) if resource_types else None
        for type_name, cleaner_class in CLEANER_TYPES:
            if types_set is not None and type_name not in types_set:
                continue
            cleaner = cleaner_class(
                sess, resources, dryrun,
                parallelism=self.parallelism,
                wait_timeout=self.wait_timeout,
                wait_interval=self.wait_interval,
            )
            if hasattr(cleaner, 'set_claimed_floating_ips'):
                cleaner.set_claimed_floating_ips(claimed_floating_ip_ids)
            cleaner.set_fip_index(self.fip_index)
            self.cleaners.append(cleaner)

    def show_resources(self):
        fip_rows = collect_preview_floating_ip_rows(
            self._preview_conn, self.cleaners, fip_index=self.fip_index)
        table = [["Resource type", "Name", "UUID"]]
        for cleaner in self.cleaners:
            table.extend(cleaner.get_resource_list())
        if fip_rows:
            table.extend(fip_rows)
        count = len(table) - 1
        print()
        if count:
            print('SELECTED RESOURCES:')
            print(tabulate(table, headers="firstrow", tablefmt="psql"))
        else:
            print('There are no resources to delete.')
        print()
        return count

    def clean(self):
        for cleaner in self.cleaners:
            cleaner.clean()

    def verify_all(self):
        """Confirm every targeted resource is actually gone.

        Returns a list of ``(rtype, id, name)`` tuples for resources that did
        not disappear within ``wait_timeout`` seconds. Each cleaner is
        responsible for polling its own resource types.
        """
        if self.dryrun or self.wait_timeout <= 0:
            return []
        stragglers = []
        print()
        print('*** VERIFY deletions')
        for cleaner in self.cleaners:
            try:
                stragglers.extend(cleaner.verify())
            except Exception as e:
                log(f'    . Verification error in {cleaner.category}: {e}')
        return stragglers

# Here's how we store what needs to be cleaned up:
# First level keys are service types: keypairs, users, routers, instances,
# volumes, floating_ips (preview), etc.
# Second level keys are the actual resource IDs  
# Values are the human-readable names (e.g. 'TEST-instance-1', 'DEV-network-2')
def get_resources_from_cleanup_log(logfile):
    """Load cleanup targets from a log file - expects lines with 'type|name|id' format"""
    resources = {}
    with open(logfile) as ff:
        content = ff.readlines()
        for line in content:
            tokens = line.strip().split('|')
            restype = tokens[0]
            resname = tokens[1]
            resid = tokens[2]
            if not resid:
                # normally only the keypairs have no ID
                if restype != "keypairs":
                    print(f'Error: resource type {restype} has no ID - ignored!!!')
                else:
                    resid = '0'
            if restype not in resources:
                resources[restype] = {}
            tres = resources[restype]
            tres[resid] = resname
    return resources


def _is_wildcard_filter(pattern):
    """Return True if the pattern is too broad for safe discovery (likely to match all resources).

    Catches regexes that match the empty string (e.g. ``.*``, ``^$``) and those that full-match
    every member of a small set of diverse sample names (e.g. ``.+``, ``^.+$``), which would
    also select essentially everything in the project.
    """
    try:
        r = re.compile(pattern)
    except re.error:
        return False
    if r.fullmatch('') is not None:
        return True
    samples = (
        'a',
        '0',
        'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx',
        'very-long-openstack-resource-name-segment-0123456789',
    )
    return all(r.fullmatch(s) is not None for s in samples)


def main():
    parser = argparse.ArgumentParser(description='OpenStack Resource Cleanup Tool')

    parser.add_argument('-r', '--rc', dest='rc',
                        action='store', required=False,
                        help='openrc file',
                        metavar='<file>')
    parser.add_argument('-c', '--cloud', dest='cloud',
                        action='store', required=False,
                        help='cloud name from clouds.yaml',
                        metavar='<cloud-name>')
    parser.add_argument('-f', '--file', dest='file',
                        action='store', required=False,
                        help='get resources to delete from cleanup log file '
                             '(default:discover from OpenStack)',
                        metavar='<file>')
    parser.add_argument('-d', '--dryrun', dest='dryrun',
                        action='store_true',
                        default=False,
                        help='check resources only - do not delete anything')
    parser.add_argument('--filter', dest='filter',
                        action='store', required=False,
                        help='resource name regular expression filter (default:".*test-cluster.*") '
                             'for OpenStack resource discovery. Change to match your naming pattern.',
                        metavar='<regex-pattern>')
    parser.add_argument('-y', '--yes', dest='auto_approve',
                        action='store_true',
                        default=False,
                        help='automatic yes to prompts; assume "yes" as answer to all prompts')
    parser.add_argument('-t', '--types', dest='types',
                        action='store', default=None, metavar='types',
                        help='limit cleanup to these types only (default: all). '
                             'Types: heat, dns, compute, storage, loadbalancer, network. '
                             'E.g. -t compute,network')
    parser.add_argument('-p', '--parallel', dest='parallel',
                        action='store', type=int, default=DEFAULT_PARALLEL,
                        metavar='N',
                        help=f'max concurrent delete workers per resource type '
                             f'(default: {DEFAULT_PARALLEL}). Use 1 for serial '
                             f'deletion. Increase for faster cleanup on large '
                             f'deployments; decrease if the OpenStack API rate-limits.')
    parser.add_argument('--wait-timeout', dest='wait_timeout',
                        action='store', type=int, default=DEFAULT_WAIT_TIMEOUT,
                        metavar='SECONDS',
                        help=f'max seconds to poll each resource group for '
                             f'confirmed deletion (default: {DEFAULT_WAIT_TIMEOUT}). '
                             f'Set to 0 to disable verification entirely.')
    parser.add_argument('--wait-interval', dest='wait_interval',
                        action='store', type=int, default=DEFAULT_WAIT_INTERVAL,
                        metavar='SECONDS',
                        help=f'seconds between deletion-verification poll rounds '
                             f'(default: {DEFAULT_WAIT_INTERVAL}).')
    parser.add_argument('--wait-strict', dest='wait_strict',
                        action='store_true', default=False,
                        help='exit with code 2 if any resource is not confirmed '
                             'gone within --wait-timeout, otherwise stragglers '
                             'are only warned about (default: false).')
    opts = parser.parse_args()

    if opts.parallel < 1:
        print('❌ ERROR: --parallel must be >= 1')
        return 1
    if opts.wait_timeout < 0:
        print('❌ ERROR: --wait-timeout must be >= 0')
        return 1
    if opts.wait_interval < 1:
        print('❌ ERROR: --wait-interval must be >= 1')
        return 1

    # Validate mutual exclusivity
    if opts.rc and opts.cloud:
        print("❌ ERROR: Cannot use both --rc and --cloud options together")
        print("   Use either --rc for openrc file OR --cloud for clouds.yaml")
        return 1

    # Normalize --types: split comma-separated string
    resource_types = None
    if opts.types:
        resource_types = [s.strip().lower() for s in opts.types.split(',') if s.strip()]
        allowed = {'heat', 'dns', 'compute', 'storage', 'loadbalancer', 'network'}
        invalid = [t for t in resource_types if t not in allowed]
        if invalid:
            print(f"❌ ERROR: Invalid type(s): {invalid}")
            print(f"   Allowed: {', '.join(sorted(allowed))}")
            return 1

    print("🧹 OpenStack Resource Cleanup Tool")
    print("=" * 50)
    if opts.dryrun:
        print("Mode: DRY RUN (simulation only)")
    else:
        print("Mode: LIVE CLEANUP (will delete resources)")
    
    if opts.auto_approve:
        print("Auto-approve: ENABLED (--yes)")
    
    if opts.filter:
        print(f"Filter: '{opts.filter}'")
    else:
        print("Filter: '.*test-cluster.*' (default, use --filter to change)")
        
    if opts.cloud:
        print(f"Authentication: clouds.yaml cloud '{opts.cloud}'")
    elif opts.rc:
        print(f"Authentication: openrc file '{opts.rc}'")
    else:
        print("Authentication: environment variables or default cloud")

    if resource_types:
        print(f"Types: {', '.join(resource_types)} (only these will be cleaned)")
    else:
        print("Types: all")
    print(f"Parallel (--parallel): {opts.parallel} workers per resource type"
          + (" (serial)" if opts.parallel == 1 else ""))
    if opts.wait_timeout > 0:
        print(f"Verification: poll up to {opts.wait_timeout}s "
              f"(every {opts.wait_interval}s) per resource group"
              + (" [STRICT: exit 2 on stragglers]" if opts.wait_strict else ""))
    else:
        print("Verification: DISABLED (--wait-timeout 0)")
    print()

    cred = Credentials(opts.rc, opts.cloud)
    
    # Check if credentials are properly configured
    if not opts.cloud and not cred.rc_auth_url:
        print("❌ ERROR: Missing OpenStack authentication configuration!")
        print()
        print("You need to provide authentication credentials in one of these ways:")
        print()
        print("1. Use clouds.yaml (recommended):")
        print("   python3 openstack_cleanup.py --cloud my-cloud --dryrun")
        print()
        print("2. Use an openrc file:")
        print("   python3 openstack_cleanup.py -r openrc.sh --dryrun")
        print()
        print("3. Set environment variables:")
        print("   export OS_AUTH_URL=https://your-openstack.com:5000/v3")
        print("   export OS_IDENTITY_API_VERSION=3")
        print("   # Then either:")
        print("   export OS_APPLICATION_CREDENTIAL_ID=your-app-cred-id")
        print("   export OS_APPLICATION_CREDENTIAL_SECRET=your-app-cred-secret")
        print("   # OR:")
        print("   export OS_USERNAME=your-username")
        print("   export OS_PROJECT_NAME=your-project")
        print("   export OS_PROJECT_DOMAIN_NAME=default")
        print("   export OS_USER_DOMAIN_NAME=default")
        print()
        print("For clouds.yaml setup, create one of:")
        print("   ./clouds.yaml (current directory)")
        print("   ~/.config/openstack/clouds.yaml (user config)")
        print("   /etc/openstack/clouds.yaml (system-wide)")
        print()
        print("For detailed authentication setup instructions, see OpenStack documentation.")
        return 1

    if opts.file:
        resources = get_resources_from_cleanup_log(opts.file)
    else:
        # No file means we'll discover resources by scanning OpenStack and matching names
        resources = None
    global resource_name_re
    filter_pattern = opts.filter if opts.filter else '.*test-cluster.*'

    if _is_wildcard_filter(filter_pattern):
        print(f"❌ ERROR: Filter '{filter_pattern}' is too broad (would match almost any resource).")
        print("   Use a more specific pattern, e.g. '.*my-cluster.*'")
        return 1

    try:
        resource_name_re = re.compile(filter_pattern)
    except re.error as exc:
        print(f"❌ ERROR: Filter '{filter_pattern}' is not a valid regular expression.")
        print(f"   {exc}")
        print("   Use Python regex syntax, e.g. '.*my-cluster.*' (not shell globs: * alone is invalid).")
        return 1


    cleaners = OpenStackCleaners(
        cred, resources, opts.dryrun,
        resource_types=resource_types,
        parallelism=opts.parallel,
        wait_timeout=opts.wait_timeout,
        wait_interval=opts.wait_interval,
    )

    if opts.dryrun:
        print()
        print('!!! DRY RUN - RESOURCES WILL BE CHECKED BUT WILL NOT BE DELETED !!!')
        print()

    # Display resources to be deleted
    count = cleaners.show_resources()
    if not count:
        print("✅ No resources found matching the specified filter.")
        if opts.filter:
            print(f"   Filter used: '{opts.filter}'")
        return 0

    if not opts.file and not opts.dryrun:
        prompt_to_run(opts.auto_approve)

    cleaners.clean()

    stragglers = []
    if not opts.dryrun and opts.wait_timeout > 0:
        stragglers = cleaners.verify_all()

    print()
    if opts.dryrun:
        print("✅ Dry run completed successfully!")
        print(f"   Found {count} resources that would be deleted.")
        print("   To actually delete these resources, run the same command without --dryrun")
        return 0

    if stragglers:
        print(f"⚠️  Cleanup finished with {len(stragglers)} unverified resource(s) "
              f"(still present after --wait-timeout {opts.wait_timeout}s):")
        table = [["Resource type", "Name", "UUID"]]
        for rtype, rid, name in stragglers:
            table.append([rtype, name, rid])
        print(tabulate(table, headers="firstrow", tablefmt="psql"))
        print("   Re-run the script to retry, raise --wait-timeout, or "
              "investigate dependencies blocking deletion.")
        if opts.wait_strict:
            return 2
        return 0

    print("✅ Cleanup completed!")
    print(f"   Processed {count} resources.")
    if opts.wait_timeout > 0:
        print("   All targeted resources confirmed deleted.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
