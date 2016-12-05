# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 Big Switch Networks, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from neutron.db import common_db_mixin as base_db
# from neutron.openstack.common import log
from neutron.plugins.proxydriver.common.rest import servermanager
from oslo_log import log

from neutron.extensions import portsecurity as psec

LOG = log.getLogger(__name__)

# The following are used to invoke the API on the external controller
TENANT = 'tenant'
NETWORK = 'network'
SUBNET = 'subnet'
PORT = 'port'
ROUTER = 'router'
FLOATING_IP = 'floating-ip'
VXLAN_TUNNEL = 'vxlan-tunnel'
SECURITY_GROUP = 'sg'
SECURITY_GROUP_RULE = 'sg-rule'
CLASSIFIER = 'classifier'

BASE_URI = '/restconf/operations/zenic-vdcapp-model:'
SUCCESS_CODES = range(200, 207)
FAILURE_CODES = [0, 9, 301, 302, 303, 400, 401, 403, 404, 500, 501, 502, 503,
                 504, 505]


class ZnicServerPool(servermanager.ServerPool, base_db.CommonDbMixin):
    """Znic Server Pool for Znic Mechanism Driver.

    This server pool has the network,subnet,port and security group operations
    of create, update and delete, to the Znic Controller.
    """
    def __init__(self, servers, auth, zenic_version, ssl, no_ssl_validation,
                 ssl_sticky, ssl_cert_directory, consistency_interval,
                 timeout=False, cache_connections=True, base_uri=BASE_URI,
                 success_codes=SUCCESS_CODES,
                 failure_codes=FAILURE_CODES, name='ZnicRestProxy'):
        super(ZnicServerPool, self).__init__(
            servers, auth, ssl, no_ssl_validation, ssl_sticky,
            ssl_cert_directory, consistency_interval, timeout,
            cache_connections, base_uri, success_codes, failure_codes, name)
        version = zenic_version.split('.')
        version = version[0] + version[1]
        if (not version.isdigit()) or (int(version) < 403):
            LOG.error(_("zenic_version error!zenic_version = %s"), version)
        self.zenic_version = int(version)

    def validate_dict(self, instance, key, default_val):
        return instance[key] if (key in instance and
                                 instance[key] is not None) else default_val

    def validate_ipv4(self, ip_in, default_val):
        return ip_in if (ip_in != 0 and (ip_in is not None)) else default_val

    def construct_network_info(self, mech_context, action):
        network = mech_context.current
        context = mech_context._plugin_context
        # validate tenant
        tenant_id = self._get_tenant_id_for_create(context, network)

        if action == 'DELETE' or action == 'GET':
            network_info = {
                "input": {
                    "id": network['id']
                }
            }
        else:
            network_info = {
                "input": {
                    "id": network['id'],
                    "name": network['name'],
                    "admin_state_up": network['admin_state_up'],
                    "tenant_id": tenant_id,
                    "shared": network['shared'],
                    "band_width": self.validate_dict(network, 'bandwidth', 0),
                    "burst_size": self.validate_dict(network, 'cbs', 0),
                    "dscp": self.validate_dict(network, 'dscp', 0),
                    "external":
                        self.validate_dict(network, 'router:external', False),
                }
            }

            input = network_info['input']
            if network.get('provider:network_type') != "flat":
                input['segmentation_id'] = \
                    mech_context.network_segments[0]['segmentation_id']

            if self.zenic_version > 403:
                if 'mtu' in network:
                    input['mtu'] = self.validate_dict(network, "mtu", 0)

        if action == 'POST':
            input = network_info['input']
            if self.zenic_version > 403:
                if 'port_security_enabled' in network and \
                        self.en_security_group:
                    input['port_security_enabled'] = \
                        self.validate_dict(network, psec.PORTSECURITY, True)
        return network_info

    def construct_subnet_info(self, mech_context, action):
        subnet = mech_context.current
        context = mech_context._plugin_context
        # validate tenant
        tenant_id = self._get_tenant_id_for_create(context, subnet)

        if action == 'DELETE' or action == 'GET':
            subnet_info = {
                "input": {
                    "id": subnet['id']
                }
            }
        else:
            if subnet['ip_version'] == 6:
                gateway_default = "::"
            else:
                gateway_default = "0.0.0.0"

            subnet_info = {
                "input": {
                    "id": subnet['id'],
                    "subnet_name": subnet['name'],
                    # "network_id": subnet['network_id'],
                    # "tenant_id": tenant_id,
                    "dns_nameservers": ','.join(subnet['dns_nameservers']),
                    "allocation_pools": subnet['allocation_pools'],
                    "host_routes":
                        '\r\n'.join(','.join([route.get("destination", ""),
                                              route.get("nexthop", "")])
                                    for route in self.validate_dict(
                            subnet, 'host_routes', [])),
                    # "ip_version": subnet['ip_version'],
                    "gateway_ip": self.validate_ipv4(
                        subnet['gateway_ip'], gateway_default),
                    # "cidr": subnet['cidr']
                }
            }

        if action == 'POST':
            input = subnet_info['input']
            input['network_id'] = subnet['network_id']
            input['tenant_id'] = tenant_id
            input['cidr'] = subnet['cidr']
            input['ip_version'] = subnet['ip_version']

        return subnet_info

    def construct_port_info(self, mech_context, action):
        port = mech_context.current
        context = mech_context._plugin_context
        # validate tenant
        tenant_id = self._get_tenant_id_for_create(context, port)

        if action == 'DELETE' or action == 'GET':
            port_info = {
                "input": {
                    "id": port["id"]
                }
            }
        else:
            if not self.en_security_group:
                port["security_groups"] = []
            port_info = {
                "input": {
                    "id": port['id'],
                    "name": port['name'],
                    "allowed_address_pairs":
                        [{'ip_address': pairs['ip_address'],
                          'mac_address': pairs['mac_address']}
                         for pairs in port['allowed_address_pairs']],
                    "admin_state_up": port["admin_state_up"],
                    # "network_id": port["network_id"],
                    # "tenant_id": tenant_id,
                    # "mac_address": port["mac_address"],
                    "binding_profile": str(port['binding:profile']),
                    "device_owner": port["device_owner"],
                    "fixed_ips": [{'subnet_id': ip["subnet_id"],
                                   'ip_address': ip["ip_address"]}
                                  for ip in port["fixed_ips"]],
                    "security_groups": port["security_groups"],
                    "band_width": self.validate_dict(port, 'bandwidth', 0),
                    "burst_size": self.validate_dict(port, 'cbs', 0),
                    "dscp": self.validate_dict(port, 'dscp', 0),
                }
            }

        if action == 'POST' or action == 'PUT':
            input = port_info['input']
            if self.zenic_version > 403:
                if 'extra_dhcp_opts' in port:
                    input['extra_dhcp_opts'] = [{'opt_value':
                                                dhcp["opt_value"],
                                                 'ip_version':
                                                dhcp["ip_version"],
                                                 'opt_name':
                                                dhcp["opt_name"]}
                                                for dhcp in
                                                port["extra_dhcp_opts"]]

        if action == 'POST':
            input = port_info['input']
            input['network_id'] = port['network_id']
            input['tenant_id'] = tenant_id
            input['mac_address'] = port['mac_address']
            if self.zenic_version > 403:
                if 'port_security_enabled' in port and self.en_security_group:
                    input['port_security_enabled'] = \
                        self.validate_dict(port, psec.PORTSECURITY, True)
        return port_info

    def construct_securitygroup_info(self, mech_context, action):
        sg = mech_context.current
        context = mech_context._plugin_context
        # validate tenant
        tenant_id = self._get_tenant_id_for_create(context, sg)

        if action == 'DELETE' or action == 'GET':
            securitygroup_info = {"input": {"id": sg["id"]}}
        elif action == 'PUT':
            securitygroup_info = {
                "input": {
                    "id": sg['id'],
                    "name": sg['name'],
                    "description": sg["description"],
                }
            }
        else:
            securitygroup_info = {
                "input": {
                    "id": sg['id'],
                    "name": sg['name'],
                    "description": sg["description"],
                    "tenant_id": tenant_id
                }
            }

        if action == "POST":
            securitygroup_rules = self.validate_dict(
                sg, 'security_group_rules', None)
            if securitygroup_rules is not None:
                security_group_rules = []
                for rule in securitygroup_rules:
                    ethertype = self.validate_dict(rule, 'ethertype', None)
                    ipv4 = None
                    ipv6 = None
                    if ethertype and ethertype.find('4') != -1:
                        ipv4 = self.validate_dict(
                            rule, 'remote_ip_prefix', None)
                    elif ethertype and ethertype.find('6') != -1:
                        ipv6 = self.validate_dict(
                            rule, 'remote_ip_prefix', None)
                    else:
                        LOG.error("ethertype:%s is error!" % ethertype)

                    sg_rule = {
                        "id": rule['id'],
                        "port_range_max":
                            self.validate_dict(rule, 'port_range_max', 0),
                        "port_range_min":
                            self.validate_dict(rule, 'port_range_min', 0),
                        "protocol":
                            self.validate_dict(rule, 'protocol', None),
                        "remote_group_id":
                            self.validate_dict(rule, 'remote_group_id', None),
                        "remote_ipv4_prefix": ipv4,
                        "remote_ipv6_prefix": ipv6,
                        "direction":
                            self.validate_dict(rule, 'direction', None),
                        "ethertype": ethertype,
                        "tenant_id": tenant_id,
                        "security_group_id":
                            self.validate_dict(rule, 'security_group_id', None)
                    }
                    security_group_rules.append(sg_rule)
                securitygroup_info['input']['security_group_rules'] = \
                    security_group_rules
        return securitygroup_info

    def construct_securitygroup_rule_info(self, mech_context, action):
        rule = mech_context.current
        context = mech_context._plugin_context
        # validate tenant
        tenant_id = self._get_tenant_id_for_create(context, rule)
        ethertype = self.validate_dict(rule, 'ethertype', None)
        ipv4 = None
        ipv6 = None
        if ethertype and ethertype.find('4') != -1:
            ipv4 = self.validate_dict(rule, 'remote_ip_prefix', None)
        elif ethertype and ethertype.find('6') != -1:
            ipv6 = self.validate_dict(rule, 'remote_ip_prefix', None)
        else:
            LOG.error("ethertype:%s is error!" % ethertype)

        if action == 'DELETE' or action == 'GET':
            securitygroup_rule_info = {"input": {"id": rule["id"]}}
        else:
            securitygroup_rule_info = {
                "input": {
                    "id": rule['id'],
                    "port_range_max":
                        self.validate_dict(rule, 'port_range_max', 0),
                    "port_range_min":
                        self.validate_dict(rule, 'port_range_min', 0),
                    "protocol":
                        self.validate_dict(rule, 'protocol', None),
                    "remote_group_id":
                        self.validate_dict(rule, 'remote_group_id', None),
                    "remote_ipv4_prefix": ipv4,
                    "remote_ipv6_prefix": ipv6,
                    "security_group_id":
                        self.validate_dict(rule, 'security_group_id', None)
                }
            }

        if action == 'POST':
            input = securitygroup_rule_info['input']
            input['direction'] = self.validate_dict(rule, 'direction', None)
            input['ethertype'] = ethertype
            input['tenant_id'] = tenant_id

        return securitygroup_rule_info

    def set_enable_security_group(self, en_security_group):
        self.en_security_group = en_security_group

    def rest_create_tenant(self, tenant_id, tenant_name, description):
        tenant_data = {"id": tenant_id,
                       "name": tenant_name,
                       "description": description}
        data = {"input": tenant_data}
        resource = 'add-' + TENANT
        errstr = _("Unable to create tenant: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_update_tenant(self, tenant_id, tenant_name, description):
        tenant_data = {"id": tenant_id,
                       "name": tenant_name,
                       "description": description}
        data = {"input": tenant_data}
        resource = 'update-' + TENANT
        errstr = _("Unable to update tenant: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_delete_tenant(self, tenant_id):
        tenant_data = {"id": tenant_id}
        data = {"input": tenant_data}
        resource = 'del-' + TENANT
        errstr = _("Unable to delete tenant: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_get_tenant(self, tenant_id):
        tenant_data = {"id": tenant_id}
        data = {"input": tenant_data}
        resource = 'get-' + TENANT
        errstr = _("Unable to get tenant: %s")
        return self.rest_action('POST', resource, data, errstr)

    def rest_create_network(self, mech_context):
        data = self.construct_network_info(mech_context, 'POST')
        resource = 'add-' + NETWORK
        errstr = _("Unable to create remote network: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_update_network(self, mech_context):
        data = self.construct_network_info(mech_context, 'PUT')
        resource = 'update-' + NETWORK
        errstr = _("Unable to update remote network: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_delete_network(self, mech_context):
        data = self.construct_network_info(mech_context, 'DELETE')
        resource = 'del-' + NETWORK
        errstr = _("Unable to delete remote network: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_get_network(self, mech_context):
        data = self.construct_network_info(mech_context, 'GET')
        resource = 'get-' + NETWORK
        errstr = _("Unable to get remote network: %s")
        return self.rest_action('POST', resource, data, errstr)

    def rest_create_subnet(self, mech_context):
        data = self.construct_subnet_info(mech_context, 'POST')
        resource = 'add-' + SUBNET
        errstr = _("Unable to create remote subnet: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_update_subnet(self, mech_context):
        data = self.construct_subnet_info(mech_context, 'PUT')
        resource = 'update-' + SUBNET
        errstr = _("Unable to update remote subnet: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_delete_subnet(self, mech_context):
        data = self.construct_subnet_info(mech_context, 'DELETE')
        resource = 'del-' + SUBNET
        errstr = _("Unable to delete remote subnet: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_get_subnet(self, mech_context):
        data = self.construct_subnet_info(mech_context, 'GET')
        resource = 'get-' + SUBNET
        errstr = _("Unable to get remote subnet: %s")
        return self.rest_action('POST', resource, data, errstr)

    def rest_create_port(self, mech_context):
        data = self.construct_port_info(mech_context, 'POST')
        resource = 'add-' + PORT
        errstr = _("Unable to create remote port: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_update_port(self, mech_context):
        data = self.construct_port_info(mech_context, 'PUT')
        resource = 'update-' + PORT
        errstr = _("Unable to update remote port: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_delete_port(self, mech_context):
        data = self.construct_port_info(mech_context, 'DELETE')
        resource = 'del-' + PORT
        errstr = _("Unable to delete remote port: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_get_port(self, mech_context):
        data = self.construct_port_info(mech_context, 'GET')
        resource = 'get-' + PORT
        errstr = _("Unable to get remote port: %s")
        return self.rest_action('POST', resource, data, errstr)

    def rest_create_securitygroup(self, mech_context):
        data = self.construct_securitygroup_info(mech_context, 'POST')
        resource = 'add-' + SECURITY_GROUP
        errstr = _("Unable to create remote securitygroup: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_update_securitygroup(self, mech_context):
        data = self.construct_securitygroup_info(mech_context, 'PUT')
        resource = 'update-' + SECURITY_GROUP
        errstr = _("Unable to update remote securitygroup: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_delete_securitygroup(self, mech_context):
        data = self.construct_securitygroup_info(mech_context, 'DELETE')
        resource = 'del-' + SECURITY_GROUP
        errstr = _("Unable to delete remote securitygroup: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_get_securitygroup(self, mech_context):
        data = self.construct_securitygroup_info(mech_context, 'GET')
        resource = 'get-' + SECURITY_GROUP
        errstr = _("Unable to get remote securitygroup: %s")
        return self.rest_action('POST', resource, data, errstr)

    def rest_create_securitygroup_rule(self, mech_context):
        data = self.construct_securitygroup_rule_info(mech_context, 'POST')
        resource = 'add-' + SECURITY_GROUP_RULE
        errstr = _("Unable to create remote securitygroup_rule: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_update_securitygroup_rule(self, mech_context):
        data = self.construct_securitygroup_rule_info(mech_context, 'PUT')
        resource = 'update-' + SECURITY_GROUP_RULE
        errstr = _("Unable to update remote securitygroup_rule: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_delete_securitygroup_rule(self, mech_context):
        data = self.construct_securitygroup_rule_info(mech_context, 'DELETE')
        resource = 'del-' + SECURITY_GROUP_RULE
        errstr = _("Unable to delete remote securitygroup_rule: %s")
        self.rest_action('POST', resource, data, errstr)

    def rest_get_securitygroup_rule(self, mech_context):
        data = self.construct_securitygroup_rule_info(mech_context, 'GET')
        resource = 'get-' + SECURITY_GROUP_RULE
        errstr = _("Unable to get remote securitygroup_rule: %s")
        return self.rest_action('POST', resource, data, errstr)
