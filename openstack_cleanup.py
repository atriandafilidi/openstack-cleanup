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
import argparse
import os
import re
import sys
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
DEFAULT_DESCRIPTION_TRUNCATE_LENGTH = 30
DEFAULT_RETRY_COUNT = 3
DEFAULT_VOLUME_DETACH_EXTRA_RETRIES = 5
DEFAULT_LB_RETRY_DELAY = 10
DEFAULT_ROUTER_FIP_WAIT = 5
DEFAULT_INSTANCE_DELETE_RETRIES = 30

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

class ResourceMonitor:
    """Watch resources being deleted and verify they're actually gone."""
    
    def __init__(self, session, dryrun=False):
        self.session = session
        self.dryrun = dryrun
        
        # Get our OpenStack connection
        self.conn = openstack.connection.Connection(session=session)
    
    def verify_resource_deleted(self, resource_type, resource_id, max_attempts=10, delay=2):
        """Double-check that a resource is actually gone."""
        if self.dryrun:
            return True
            
        print(f"    🔍 Verifying {resource_type} {resource_id[:8]}... deletion", end='', flush=True)
        
        for attempt in range(max_attempts):
            try:
                time.sleep(delay)
                
                # Try to get the resource - if it exists, it's not deleted yet
                if resource_type.upper() in ['INSTANCE', 'SERVER']:
                    self.conn.compute.get_server(resource_id)
                elif resource_type.upper() == 'FLAVOR':
                    self.conn.compute.get_flavor(resource_id)
                elif resource_type.upper() == 'VOLUME':
                    self.conn.block_storage.get_volume(resource_id)
                elif resource_type.upper() == 'SNAPSHOT':
                    self.conn.block_storage.get_snapshot(resource_id)
                elif resource_type.upper() == 'NETWORK':
                    self.conn.network.get_network(resource_id)
                elif resource_type.upper() == 'ROUTER':
                    self.conn.network.get_router(resource_id)
                elif resource_type.upper() == 'PORT':
                    self.conn.network.get_port(resource_id)
                elif resource_type.upper() == 'SECURITY_GROUP':
                    self.conn.network.get_security_group(resource_id)
                elif resource_type.upper() == 'LOAD BALANCER':
                    self.conn.load_balancer.get_load_balancer(resource_id)
                # Still here? Resource exists, keep waiting
                print('.', end='', flush=True)
                
            except os_exceptions.ResourceNotFound:
                # Perfect! Resource is gone
                print(' ✅ DELETED')
                return True
            except Exception as e:
                # Something else happened, probably means it's gone
                print(f' ⚠️  UNKNOWN ({str(e)[:30]}...)')
                return True
                
        # Ran out of attempts
        print(' ⏰ TIMEOUT (may still be deleting)')
        return False
    
    def watch_bulk_deletion(self, resource_list, resource_type):
        """Keep an eye on multiple resources being deleted at once."""
        if self.dryrun or not resource_list:
            return
            
        print(f"    🔍 Monitoring {len(resource_list)} {resource_type.lower()} deletion(s)...")
        
        remaining = list(resource_list)
        start_time = time.time()
        max_wait = 300  # Don't wait forever
        
        while remaining and (time.time() - start_time) < max_wait:
            still_remaining = []
            
            for resource_id, resource_name in remaining:
                try:
                    # Check if each resource still exists
                    if resource_type.upper() == 'LOAD BALANCER':
                        self.conn.load_balancer.get_load_balancer(resource_id)
                        still_remaining.append((resource_id, resource_name))
                    elif resource_type.upper() in ['INSTANCE', 'SERVER']:
                        self.conn.compute.get_server(resource_id)
                        still_remaining.append((resource_id, resource_name))
                    elif resource_type.upper() == 'NETWORK':
                        self.conn.network.get_network(resource_id)
                        still_remaining.append((resource_id, resource_name))
                    elif resource_type.upper() == 'ROUTER':
                        self.conn.network.get_router(resource_id)
                        still_remaining.append((resource_id, resource_name))
                    elif resource_type.upper() == 'PORT':
                        self.conn.network.get_port(resource_id)
                        still_remaining.append((resource_id, resource_name))
                    elif resource_type.upper() == 'VOLUME':
                        self.conn.block_storage.get_volume(resource_id)
                        still_remaining.append((resource_id, resource_name))
                        
                except os_exceptions.ResourceNotFound:
                    # Gone! Good news
                    print(f"      ✅ {resource_name[:50]} - DELETED")
                except Exception:
                    # Can't access it, probably gone
                    pass
            
            if len(still_remaining) != len(remaining):
                print(f"      📊 {len(remaining) - len(still_remaining)} deleted, {len(still_remaining)} remaining")
            
            remaining = still_remaining
            
            if remaining:
                time.sleep(3)
        
        if remaining:
            print(f"      ⏰ Timeout: {len(remaining)} {resource_type.lower()}(s) may still be deleting")
        else:
            print(f"      🎉 All {resource_type.lower()}(s) successfully deleted!")

# Global regex pattern gets set by main()
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
            
            # Special handling for floating IPs since they're a bit different
            if hasattr(res, 'floating_ip_address'):
                resname = res.floating_ip_address
                if resdesc:
                    truncated_desc = resdesc[:50] + "..." if len(resdesc) > 50 else resdesc
                    resname += f" (desc: {truncated_desc})"
                    
        except AttributeError:
            # Handle dict-style resources
            resid = res.get('id', res)
            resname = res.get('name', resid)
            resdesc = res.get('description', '')
            
            # Floating IPs in dict format
            if 'floating_ip_address' in res:
                resname = res['floating_ip_address']
                if resdesc:
                    truncated_desc = resdesc[:50] + "..." if len(resdesc) > 50 else resdesc
                    resname += f" (desc: {truncated_desc})"
        
        # Include resource if name or description matches our pattern
        if resname and (resource_name_re.search(resname) or 
                       (resdesc and resource_name_re.search(resdesc))):
            resources[resid] = resname
    return resources

class AbstractCleaner(metaclass=ABCMeta):

    def __init__(self, res_category, res_desc, resources, dryrun):
        self.dryrun = dryrun
        self.category = res_category
        self.resources = {}
        if not resources:
            print(f'Discovering {res_category} resources...')
        for rtype, fetch_args in res_desc.items():
            if resources and rtype in resources:
                self.resources[rtype] = resources[rtype]
            else:
                res_list = fetch_resources(*fetch_args)
                self.resources[rtype] = build_resource_dict(res_list)

    def report_deletion(self, rtype, name):
        status = "(but is not deleted: dry run)" if self.dryrun else "is successfully deleted"
        print(f'    + {rtype} {name} {status}')

    def report_not_found(self, rtype, name):
        print(f'    ? {rtype} {name} not found (already deleted?)')

    def report_error(self, rtype, name, reason):
        print(f'    - {rtype} {name} ERROR: {reason}')

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
    def __init__(self, sess, resources, dryrun):
        self.conn = openstack.connection.Connection(session=sess)
        
        def volumes_fetcher():
            return list(self.conn.block_storage.volumes())
            
        def snapshots_fetcher():
            return list(self.conn.block_storage.snapshots())

        res_desc = {
            'volumes': [volumes_fetcher],
            'volume_snapshots': [snapshots_fetcher]
        }
            
        super(StorageCleaner, self).__init__('Storage', res_desc, resources, dryrun)

    def clean(self):
        print('*** STORAGE cleanup')
        
        # Delete volumes (instances should be deleted first, so all volumes can be safely deleted)
        try:
            for id, name in self.resources['volumes'].items():
                try:
                    if self.dryrun:
                        self.conn.block_storage.get_volume(id)
                        self.report_deletion('VOLUME', name)
                    else:
                        self.conn.block_storage.delete_volume(id)
                        self.report_deletion('VOLUME', name)
                except os_exceptions.ResourceNotFound:
                    self.report_not_found('VOLUME', name)
                except Exception as e:
                    self.report_error('VOLUME', name, str(e))
        except KeyError:
            pass

        # Clean up volume snapshots
        try:
            for id, name in self.resources['volume_snapshots'].items():
                try:
                    if self.dryrun:
                        self.conn.block_storage.get_snapshot(id)
                        self.report_deletion('VOLUME SNAPSHOT', name)
                    else:
                        self.conn.block_storage.delete_snapshot(id)
                        self.report_deletion('VOLUME SNAPSHOT', name)
                except os_exceptions.ResourceNotFound:
                    self.report_not_found('VOLUME SNAPSHOT', name)
                except Exception as e:
                    self.report_error('VOLUME SNAPSHOT', name, str(e))
        except KeyError:
            pass

class ComputeCleaner(AbstractCleaner):
    def __init__(self, sess, resources, dryrun):
        self.conn = openstack.connection.Connection(session=sess)
        
        def instances_fetcher():
            return list(self.conn.compute.servers())
            
        def flavors_fetcher():
            return list(self.conn.compute.flavors())
            
        def keypairs_fetcher():
            return list(self.conn.compute.keypairs())
            
        res_desc = {
            'instances': [instances_fetcher],
            'flavors': [flavors_fetcher],
            'keypairs': [keypairs_fetcher]
        }
        
        super(ComputeCleaner, self).__init__('Compute', res_desc, resources, dryrun)

    def clean(self):
        print('*** COMPUTE cleanup')
        
        # Clean instances with their floating IPs
        deleting_instances = dict(self.resources['instances'])
        for ins_id, ins_name in self.resources['instances'].items():
            try:
                # Get instance and its floating IPs
                instance = self.conn.compute.get_server(ins_id)
                fips = self._get_instance_floating_ips(instance) if instance else []
                
                if self.dryrun:
                    for fip in fips:
                        self.report_deletion('FLOATING IP', fip)
                    self.report_deletion('INSTANCE', ins_name)
                else:
                    # Delete floating IPs first
                    self._delete_floating_ips(fips)
                    # Delete instance
                    self.conn.compute.delete_server(ins_id)
                    
            except os_exceptions.ResourceNotFound:
                deleting_instances.pop(ins_id, None)
                self.report_not_found('INSTANCE', ins_name)
            except Exception as e:
                self.report_error('INSTANCE', ins_name, str(e))

        # Wait for instance deletion to complete
        if not self.dryrun and deleting_instances:
            self._wait_for_instance_deletion(deleting_instances)

        # Clean other compute resources
        self._clean_flavors()
        self._clean_keypairs()

    def _get_instance_floating_ips(self, instance):
        """Extract floating IP addresses from instance."""
        if not instance.addresses:
            return []
        
        fips = []
        for addresses in instance.addresses.values():
            fips.extend([addr['addr'] for addr in addresses 
                        if addr.get('OS-EXT-IPS:type') == 'floating'])
        return fips

    def _delete_floating_ips(self, fip_addresses):
        """Delete floating IPs by their addresses."""
        if not fip_addresses:
            return
            
        fip_lst = list(self.conn.network.ips())
        for fip_addr in fip_addresses:
            for fip_obj in fip_lst:
                if fip_obj.floating_ip_address == fip_addr:
                    try:
                        self.conn.network.delete_ip(fip_obj.id)
                        self.report_deletion('FLOATING IP', fip_addr)
                    except Exception as e:
                        self.report_error('FLOATING IP', fip_addr, str(e))
                    break

    def _wait_for_instance_deletion(self, deleting_instances):
        """Wait for instances to finish deleting - sometimes they take a while."""
        print(f'    . Waiting for {len(deleting_instances)} instances to be fully deleted...')
        retry_count = DEFAULT_INSTANCE_DELETE_RETRIES  # Don't wait forever
        
        while deleting_instances and retry_count > 0:
            retry_count -= 1
            instances_to_check = list(deleting_instances.keys())
            
            for ins_id in instances_to_check:
                try:
                    self.conn.compute.get_server(ins_id)
                except os_exceptions.ResourceNotFound:
                    ins_name = deleting_instances.pop(ins_id)
                    self.report_deletion('INSTANCE', ins_name)
            
            if deleting_instances and retry_count > 0:
                time.sleep(2)
        
        if deleting_instances:
            print(f'    . Warning: {len(deleting_instances)} instances may still be deleting')

    def _clean_flavors(self):
        """Clean up flavors."""
        for flavor_id, flavor_name in self.resources['flavors'].items():
            try:
                if self.dryrun:
                    self.report_deletion('FLAVOR', flavor_name)
                else:
                    self.conn.compute.delete_flavor(flavor_id)
                    self.report_deletion('FLAVOR', flavor_name)
            except os_exceptions.ResourceNotFound:
                self.report_not_found('FLAVOR', flavor_name)
            except Exception as e:
                self.report_error('FLAVOR', flavor_name, str(e))

    def _clean_keypairs(self):
        """Clean up keypairs."""
        for keypair_id, keypair_name in self.resources['keypairs'].items():
            try:
                if self.dryrun:
                    self.report_deletion('KEYPAIR', keypair_name)
                else:
                    self.conn.compute.delete_keypair(keypair_name)
                    self.report_deletion('KEYPAIR', keypair_name)
            except os_exceptions.ResourceNotFound:
                self.report_not_found('KEYPAIR', keypair_name)
            except Exception as e:
                self.report_error('KEYPAIR', keypair_name, str(e))

class NetworkCleaner(AbstractCleaner):

    def __init__(self, sess, resources, dryrun):
        self.conn = openstack.connection.Connection(session=sess)
        
        def networks_fetcher():
            return list(self.conn.network.networks())

        def routers_fetcher():
            return list(self.conn.network.routers())

        def secgroup_fetcher():
            return list(self.conn.network.security_groups())
            
        def floating_ips_fetcher():
            return list(self.conn.network.ips())

        res_desc = {
            'floating_ips': [floating_ips_fetcher],
            'sec_groups': [secgroup_fetcher],
            'networks': [networks_fetcher],
            'routers': [routers_fetcher]
        }
        super(NetworkCleaner, self).__init__('Network', res_desc, resources, dryrun)

    def remove_router_interface(self, router_id, port):
        """Clean up router interface the hard way."""
        try:
            subnet_id = port['fixed_ips'][0]['subnet_id'] if 'fixed_ips' in port else port.fixed_ips[0]['subnet_id']
            self.conn.network.remove_interface_from_router(router_id, subnet_id=subnet_id)
            ip_address = port['fixed_ips'][0]['ip_address'] if 'fixed_ips' in port else port.fixed_ips[0]['ip_address']
            self.report_deletion('Router Interface', ip_address)
        except Exception:
            pass

    def _delete_floating_ip(self, fip, reason=""):
        """Delete a floating IP and report what happened."""
        fip_id = fip.id
        fip_ip = fip.floating_ip_address
        fip_description = getattr(fip, 'description', '') or ''
        
        try:
            if self.dryrun:
                description_info = f" (desc: {fip_description[:DEFAULT_DESCRIPTION_TRUNCATE_LENGTH]}...)" if fip_description else ""
                self.report_deletion('FLOATING IP', f"{fip_ip}{description_info}")
            else:
                self.conn.network.delete_ip(fip_id)
                description_info = f" (desc: {fip_description[:DEFAULT_DESCRIPTION_TRUNCATE_LENGTH]}...)" if fip_description else ""
                self.report_deletion('FLOATING IP', f"{fip_ip}{description_info}")
        except os_exceptions.ResourceNotFound:
            self.report_not_found('FLOATING IP', fip_ip)
        except Exception as e:
            self.report_error('FLOATING IP', fip_ip, str(e))

    def clean(self):
        print('*** NETWORK cleanup')
        global resource_name_re

        # Store security groups for later (delete them last)
        security_groups_to_delete = []

        try:
            for id, name in self.resources['sec_groups'].items():
                security_groups_to_delete.append((id, name))
        except KeyError:
            pass

        # 1. First clean up discovered floating IPs (the ones we found during discovery)
        try:
            for id, name in self.resources.get('floating_ips', {}).items():
                try:
                    fip = self.conn.network.get_ip(id)
                    self._delete_floating_ip(fip)
                except os_exceptions.ResourceNotFound:
                    self.report_not_found('FLOATING IP', name)
                except Exception as e:
                    self.report_error('FLOATING IP', name, str(e))
        except KeyError:
            pass

        # 2. Extra sweep for any floating IPs we might have missed
        try:
            all_floating_ips = list(self.conn.network.ips())
                
            for fip in all_floating_ips:
                fip_id = fip.id
                fip_ip = fip.floating_ip_address
                fip_description = getattr(fip, 'description', '') or ''
                
                # Skip ones we already processed
                if fip_id in self.resources.get('floating_ips', {}):
                    continue
                
                # See if this one matches our pattern
                if (resource_name_re.search(str(fip_ip)) or 
                    resource_name_re.search(str(fip_id)) or
                    resource_name_re.search(str(fip_description))):
                    self._delete_floating_ip(fip)
        except Exception as e:
            print(f'    . Could not list additional floating IPs: {str(e)}')

        # 3. Look for ports that match our pattern and clean them up too
        try:
            all_ports = list(self.conn.network.ports())
                
            for port in all_ports:
                port_id = port.id
                port_name = port.name
                
                # Does this port match what we're looking for?
                if resource_name_re.search(str(port_name)) or resource_name_re.search(str(port_id)):
                    try:
                        device_owner = port.device_owner
                        
                        # Skip system ports (they get handled by their parent resources)
                        if device_owner not in ['network:router_interface', 'network:dhcp', 'network:router_gateway']:
                            if self.dryrun:
                                self.report_deletion('PORT', port_name)
                            else:
                                self.conn.network.delete_port(port_id)
                                self.report_deletion('PORT', port_name)
                        else:
                            print(f'    . Skipping {device_owner} port {port_name}')
                    except os_exceptions.ResourceNotFound:
                        self.report_not_found('PORT', port_name)
                    except Exception as e:
                        self.report_error('PORT', port_name, str(e))
        except Exception as e:
            print(f'    . Could not list ports: {str(e)}')

        try:
            for id, name in self.resources['routers'].items():
                try:
                    if self.dryrun:
                        self.conn.network.get_router(id)
                        self.report_deletion('Router Gateway', name)
                        
                        port_list = list(self.conn.network.ports(device_id=id))
                            
                        for port in port_list:
                            if port.fixed_ips:
                                self.report_deletion('Router Interface', port.fixed_ips[0]['ip_address'])
                    else:
                        router = self.conn.network.get_router(id)
                        
                        # First thing - find any floating IPs hanging around this router
                        print(f'    . Checking for floating IPs on router {name}...')
                        try:
                            all_floating_ips = list(self.conn.network.ips())
                            router_fips = []
                            for fip in all_floating_ips:
                                if (hasattr(fip, 'router_id') and fip.router_id == id) or \
                                   (hasattr(fip, 'port_id') and fip.port_id):
                                    # Is this floating IP on a port that belongs to our router?
                                    try:
                                        port = self.conn.network.get_port(fip.port_id)
                                        if port.device_id == id:
                                            router_fips.append(fip)
                                    except:
                                        pass
                            
                            # Get rid of those floating IPs first
                            for fip in router_fips:
                                try:
                                    print(f'    . Deleting floating IP {fip.floating_ip_address} attached to router...')
                                    self.conn.network.delete_ip(fip.id)
                                    self.report_deletion('FLOATING IP', fip.floating_ip_address)
                                except Exception as e:
                                    print(f'    . Could not delete floating IP {fip.floating_ip_address}: {str(e)}')
                                    
                        except Exception as e:
                            print(f'    . Could not list floating IPs: {str(e)}')
                        
                        # Give floating IPs a moment to fully disappear (ours or any we deleted earlier)
                        if router_fips:
                            print('    . Waiting for floating IPs to be fully released...')
                            time.sleep(DEFAULT_ROUTER_FIP_WAIT)
                        elif router.external_gateway_info:
                            # FIPs may have been deleted in the floating_ips step; wait for Neutron to see it
                            time.sleep(DEFAULT_ROUTER_FIP_WAIT)
                        
                        # Now remove the gateway (should work better without floating IPs)
                        if router.external_gateway_info:
                            try:
                                self.conn.network.update_router(id, external_gateway_info=None)
                                self.report_deletion('Router Gateway', name)
                            except Exception as e:
                                print(f'    . Could not remove router gateway: {str(e)}')
                                # Keep going anyway
                        
                        # Remove interfaces
                        port_list = list(self.conn.network.ports(device_id=id))
                            
                        for port in port_list:
                            # For SDK, remove interfaces by subnet
                            if port.fixed_ips:
                                try:
                                    self.conn.network.remove_interface_from_router(
                                        id, subnet_id=port.fixed_ips[0]['subnet_id']
                                    )
                                except Exception:
                                    pass  # Interface might already be removed
                        
                        # Delete the router
                        self.conn.network.delete_router(id)
                    self.report_deletion('ROUTER', name)
                except os_exceptions.ResourceNotFound:
                    self.report_not_found('ROUTER', name)
                except os_exceptions.ConflictException as e:
                    self.report_error('ROUTER', name, f'Conflict (may have dependencies): {str(e)}')
                except Exception as e:
                    self.report_error('ROUTER', name, str(e))
        except KeyError:
            pass
        try:
            for id, name in self.resources['networks'].items():
                retry_count = 3
                while retry_count > 0:
                    try:
                        if self.dryrun:
                            self.conn.network.get_network(id)
                            self.report_deletion('NETWORK', name)
                            break
                        else:
                            # Let's see what ports are still hanging around and clean up what we can
                            try:
                                remaining_ports = list(self.conn.network.ports(network_id=id))
                                if remaining_ports:
                                    print(f'    . Network {name} has {len(remaining_ports)} remaining ports, checking...')
                                    for port in remaining_ports:
                                        # Skip ports owned by router/DHCP/FIP (cannot be deleted via port API)
                                        skip_owners = [
                                            'network:dhcp', 'network:router_interface',
                                            'network:router_gateway', 'network:floatingip',
                                            'network:ha_router_replicated_interface',
                                        ]
                                        if port.device_owner in skip_owners:
                                            continue
                                        if (port.device_owner or '').startswith('network:router') or \
                                           (port.device_owner or '').startswith('network:ha_router'):
                                            continue
                                        # Try to clean up the stragglers
                                        try:
                                            print(f'    . Deleting remaining port {port.name or port.id}...')
                                            self.conn.network.delete_port(port.id)
                                        except Exception as e:
                                            print(f'    . Could not delete port {port.id}: {str(e)}')
                            except Exception as e:
                                print(f'    . Could not check network ports: {str(e)}')
                            
                            self.conn.network.delete_network(id)
                            self.report_deletion('NETWORK', name)
                            break
                    except os_exceptions.ResourceNotFound:
                        self.report_not_found('NETWORK', name)
                        break
                    except os_exceptions.ConflictException as e:
                        retry_count -= 1
                        if retry_count > 0:
                            print(f'    . Network {name} still has dependencies, retrying in 5 seconds... ({retry_count} retries left)')
                            time.sleep(5)
                        else:
                            self.report_error('NETWORK', name, f'Still has dependencies after retries: {str(e)}')
                            break
                    except Exception as e:
                        self.report_error('NETWORK', name, str(e))
                        break
        except KeyError:
            pass

        # Delete security groups last (after instances are gone)
        if security_groups_to_delete:
            if not self.dryrun:
                print('    . Waiting a moment for instances to be fully deleted...')
                time.sleep(5)  # Give instances time to be fully deleted
            
            for id, name in security_groups_to_delete:
                retry_count = 3
                while retry_count > 0:
                    try:
                        if self.dryrun:
                            self.conn.network.get_security_group(id)
                            self.report_deletion('SECURITY GROUP', name)
                            break
                        else:
                            self.conn.network.delete_security_group(id)
                            self.report_deletion('SECURITY GROUP', name)
                            break
                    except os_exceptions.ResourceNotFound:
                        self.report_not_found('SECURITY GROUP', name)
                        break
                    except os_exceptions.ConflictException as e:
                        retry_count -= 1
                        if retry_count > 0:
                            print(f'    . Security group {name} still in use, retrying in 5 seconds... ({retry_count} retries left)')
                            time.sleep(5)
                        else:
                            self.report_error('SECURITY GROUP', name, f'Still in use after retries: {str(e)}')
                            break
                    except Exception as e:
                        self.report_error('SECURITY GROUP', name, str(e))
                        break

class LoadBalancerCleaner(AbstractCleaner):

    def __init__(self, sess, resources, dryrun):
        self.session = sess
        self.monitor = None  # Will be set by OpenStackCleaners
        
        # Initialize OpenStack SDK connection
        self.conn = openstack.connection.Connection(session=sess)
        
        def loadbalancers_fetcher():
            return list(self.conn.load_balancer.load_balancers())

        res_desc = {
            'loadbalancers': [loadbalancers_fetcher]
        }
        super(LoadBalancerCleaner, self).__init__('LoadBalancer', res_desc, resources, dryrun)
    
    def set_monitor(self, monitor):
        """Hook up the progress monitor so we can track what's happening"""
        self.monitor = monitor

    def clean(self):
        print('*** LOAD BALANCER cleanup')
        
        # For Load Balancers, it's often better to delete the entire LB with cascade
        # This avoids issues with individual component deletion when LB is in PENDING_UPDATE state
        
        # Delete load balancers first with cascade - this should take care of listeners and pools too
        try:
            for id, name in self.resources.get('loadbalancers', {}).items():
                retry_count = DEFAULT_RETRY_COUNT
                while retry_count > 0:
                    try:
                        if self.dryrun:
                            self.report_deletion('LOAD BALANCER', name)
                            break
                        else:
                            # Check what state this load balancer is in
                            try:
                                lb = self.conn.load_balancer.get_load_balancer(id)
                                if lb.provisioning_status in ['PENDING_UPDATE', 'PENDING_CREATE', 'PENDING_DELETE']:
                                    print(f'    . Load balancer {name} is in {lb.provisioning_status} state, waiting...')
                                    retry_count -= 1
                                    if retry_count > 0:
                                        time.sleep(DEFAULT_LB_RETRY_DELAY)
                                        continue
                                    else:
                                        self.report_error('LOAD BALANCER', name, f'Still in {lb.provisioning_status} state after retries')
                                        break
                            except os_exceptions.ResourceNotFound:
                                self.report_not_found('LOAD BALANCER', name)
                                break
                            
                            # Try cascade delete (should handle dependencies automatically)
                            self.conn.load_balancer.delete_load_balancer(id, cascade=True)
                            self.report_deletion('LOAD BALANCER', name)
                            
                            # Double check it's really gone if we have a monitor
                            if self.monitor:
                                self.monitor.verify_resource_deleted('LOAD BALANCER', id)
                            break
                            
                    except os_exceptions.ResourceNotFound:
                        self.report_not_found('LOAD BALANCER', name)
                        break
                    except os_exceptions.ConflictException as e:
                        retry_count -= 1
                        if retry_count > 0:
                            print(f'    . Load balancer {name} conflict, retrying in {DEFAULT_LB_RETRY_DELAY} seconds... ({retry_count} retries left)')
                            time.sleep(DEFAULT_LB_RETRY_DELAY)
                        else:
                            self.report_error('LOAD BALANCER', name, f'Conflict after retries: {str(e)}')
                            break
                    except Exception as e:
                        self.report_error('LOAD BALANCER', name, str(e))
                        break
        except KeyError:
            pass

class DnsCleaner(AbstractCleaner):
    """Cleaner for DNS (Designate) zones."""

    def __init__(self, sess, resources, dryrun):
        self.conn = openstack.connection.Connection(session=sess)
        res_desc = {}
        try:
            list(self.conn.dns.zones(limit=1))
            res_desc['dns_zones'] = [lambda c=self.conn: list(c.dns.zones())]
        except Exception:
            pass
        super(DnsCleaner, self).__init__('DNS', res_desc, resources, dryrun)

    def clean(self):
        if 'dns_zones' not in self.resources:
            return
        print('*** DNS (Designate) cleanup')
        try:
            for zone_id, zone_name in self.resources['dns_zones'].items():
                try:
                    if self.dryrun:
                        self.report_deletion('DNS ZONE', zone_name)
                    else:
                        self.conn.dns.delete_zone(zone_id)
                        self.report_deletion('DNS ZONE', zone_name)
                except os_exceptions.ResourceNotFound:
                    self.report_not_found('DNS ZONE', zone_name)
                except Exception as e:
                    self.report_error('DNS ZONE', zone_name, str(e))
        except Exception as e:
            print(f'    . Could not clean DNS zones: {str(e)}')


class HeatCleaner(AbstractCleaner):
    """Cleaner for Heat (orchestration) stacks."""

    def __init__(self, sess, resources, dryrun):
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
        super(HeatCleaner, self).__init__('Heat', res_desc, resources, dryrun)

    def clean(self):
        if 'heat_stacks' not in self.resources:
            return
        print('*** HEAT (orchestration) cleanup')
        try:
            for stack_id, stack_name in self.resources['heat_stacks'].items():
                try:
                    if self.dryrun:
                        self.report_deletion('HEAT STACK', stack_name)
                    else:
                        print(f'    . Deleting Heat stack {stack_name} and waiting for completion...')
                        stack = self.conn.orchestration.get_stack(stack_id)
                        self.conn.orchestration.delete_stack(stack)
                        self.conn.orchestration.wait_for_delete(stack)
                        self.report_deletion('HEAT STACK', stack_name)
                except os_exceptions.ResourceNotFound:
                    self.report_not_found('HEAT STACK', stack_name)
                except Exception as e:
                    self.report_error('HEAT STACK', stack_name, str(e))
        except Exception as e:
            print(f'    . Could not clean Heat stacks: {str(e)}')


# Type names (for --types) and their cleaner classes, in cleanup order
CLEANER_TYPES = [
    ('heat', HeatCleaner),                  # orchestration stacks
    ('dns', DnsCleaner),                    # Designate DNS zones
    ('compute', ComputeCleaner),            # instances, flavors, keypairs
    ('storage', StorageCleaner),            # volumes, volume_snapshots
    ('loadbalancer', LoadBalancerCleaner),
    ('network', NetworkCleaner),            # floating_ips, sec_groups, networks, routers
]


class OpenStackCleaners():

    def __init__(self, creds_obj, resources, dryrun, resource_types=None):
        """
        resource_types: if set, only run these cleaners (e.g. ['compute', 'network']).
        If None or empty, run all cleaners.
        """
        self.cleaners = []
        self.dryrun = dryrun
        sess = creds_obj.get_session()
        self.monitor = ResourceMonitor(sess, dryrun)

        types_set = set(resource_types) if resource_types else None
        for type_name, cleaner_class in CLEANER_TYPES:
            if types_set is not None and type_name not in types_set:
                continue
            cleaner = cleaner_class(sess, resources, dryrun)
            if hasattr(cleaner, 'set_monitor'):
                cleaner.set_monitor(self.monitor)
            self.cleaners.append(cleaner)

    def show_resources(self):
        table = [["Resource type", "Name", "UUID"]]
        for cleaner in self.cleaners:
            table.extend(cleaner.get_resource_list())
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

# Here's how we store what needs to be cleaned up:
# First level keys are service types: flavors, keypairs,
# users, routers, floating_ips, instances, volumes, etc.
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
    opts = parser.parse_args()

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
    if opts.filter:
        try:
            resource_name_re = re.compile(opts.filter)
        except Exception as exc:
            print('Provided filter is not a valid python regular expression: ' + opts.filter)
            print(str(exc))
            return 1
    else:
        resource_name_re = re.compile('.*test-cluster.*')


    cleaners = OpenStackCleaners(cred, resources, opts.dryrun, resource_types=resource_types)

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
    
    # Let them know how it went
    print()
    if opts.dryrun:
        print("✅ Dry run completed successfully!")
        print(f"   Found {count} resources that would be deleted.")
        print("   To actually delete these resources, run the same command without --dryrun")
    else:
        print("✅ Cleanup completed!")
        print(f"   Processed {count} resources.")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
