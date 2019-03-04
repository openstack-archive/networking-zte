# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2017 ZTE, Inc.
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

import httplib
from networking_zte.common import servermanager
from networking_zte.ml2.common.rest.ml2_zenic import config as pl_config
from neutron.db import common_db_mixin as base_db
try:
    from neutron_lib.api.definitions import port_security as psec
except Exception:
    from neutron.extensions import portsecurity as psec
from neutron.plugins.ml2 import driver_api as api
from oslo_log import log
from oslo_serialization import jsonutils


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

QOS_POLICY = 'qos-policy'
QOS_BANDWIDTH_RULE = 'qos-bandwidth-limit-rule'

BASE_URI = '/restconf/operations/zenic-vdcapp-model:'
SUCCESS_CODES = range(200, 207)
FAILURE_CODES = [
    0,
    9,
    301,
    302,
    303,
    400,
    401,
    403,
    404,
    409,
    500,
    501,
    502,
    503,
    504,
    505]


class ZenicServerPool(servermanager.ServerPool, base_db.CommonDbMixin):
    """Zenic Server Pool for Zenic Mechanism Driver.
    This server pool has the network,subnet,port and security group operations
    of create, update and delete, to the Zenic Controller.
    """

    def __init__(
            self,
            servers,
            auth,
            zenic_version,
            enable_qos,
            ssl,
            no_ssl_validation,
            ssl_sticky,
            ssl_cert_directory,
            consistency_interval,
            timeout=False,
            cache_connections=True,
            base_uri=BASE_URI,
            success_codes=SUCCESS_CODES,
            failure_codes=FAILURE_CODES,
            name='ZenicRestProxy'):
        super(ZenicServerPool, self).__init__(
            servers, auth, ssl, no_ssl_validation, ssl_sticky,
            ssl_cert_directory, consistency_interval, timeout,
            cache_connections, base_uri, success_codes, failure_codes, name)
        version = zenic_version.split('.')
        version = version[0] + version[1]
        if (version.isdigit() is False) or (int(version) < 403):
            LOG.error(_("zenic_version error! zenic_version = %s"), version)
        self.zenic_version = int(version)
        self.enable_qos = enable_qos
        pl_config.register_config()
        self.enable_mitaka_qos = pl_config.cfg.CONF.RESTPROXY.enable_M_qos
        self.enable_bandwidth = pl_config.cfg.CONF.RESTPROXY.enable_bandwidth
        self.flat_segment_id = pl_config.cfg.CONF.RESTPROXY.flat_segment_id
        self.vlan_transparent = pl_config.cfg.CONF.RESTPROXY.vlan_transparent
        self.hierarchical = pl_config.cfg.CONF. \
            RESTPROXY.enable_hierarchical_port
        self.en_security_group = False
        LOG.info(_("proxyMechanismDriver enable_mitaka_qos = %s"),
                 self.enable_mitaka_qos)
        LOG.info(_("proxyMechanismDriver enable_qos = %s"), self.enable_qos)

    @staticmethod
    def validate_dict(instance, key, default_val):
        return instance[key] if (key in instance and
                                 instance[key] is not None) else default_val

    @staticmethod
    def validate_ipv4(ip_in, default_val):
        return ip_in if (ip_in != 0 and (ip_in is not None)) else default_val

    def construct_network_info(self, mech_context, action):
        network = mech_context.current
        LOG.debug("construct_network_info network = %s" % network)

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
                    "tenant_id": network['tenant_id'],
                    "shared": network['shared'],
                    "band_width": self.validate_dict(network, 'bandwidth', 0),
                    "burst_size": self.validate_dict(network, 'cbs', 0),
                    "dscp": self.validate_dict(network, 'dscp', 0),
                    "external":
                        self.validate_dict(network, 'router:external', False),
                }
            }

            input = network_info['input']
            if self.vlan_transparent == 'True':
                if network['vlan_transparent'] is not None:
                    input['vlan_transparent'] = \
                        self.validate_dict(network, 'vlan_transparent', False)
            if network.get('provider:segmentation_id', None) is not None:
                if network.get('provider:network_type') != "flat":
                    input['segmentation_id'] =\
                        mech_context.network_segments[0]['segmentation_id']
                else:
                    input['segmentation_id'] = self.flat_segment_id
            else:
                return None

            if self.zenic_version > 403:
                if 'mtu' in network:
                    input['mtu'] = self.validate_dict(network, "mtu", 0)
                if self.enable_mitaka_qos == "True":
                    if 'qos_policy_id' in network.keys():
                        input['qos_policy_id'] = network['qos_policy_id']

        if action == 'POST':
            input = network_info['input']
            if self.zenic_version > 403:
                if 'port_security_enabled' in network:
                    if self.en_security_group:
                        input['port_security_enabled'] = \
                            self.validate_dict(network, psec.PORTSECURITY,
                                               True)

        return network_info

    def construct_subnet_info(self, mech_context, action):
        subnet = mech_context.current
        LOG.debug("construct_subnet_info subnet = %s" % subnet)

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
            input['tenant_id'] = subnet['tenant_id']
            input['cidr'] = subnet['cidr']
            input['ip_version'] = subnet['ip_version']

        return subnet_info

    def get_next_segment_id(self, action, mech_context, host_id):
        next_segment = mech_context.bottom_bound_segment
        top_segment = mech_context.top_bound_segment
        LOG.info(_("port next_segment=%s"), next_segment)
        LOG.info(_("port top_segment=%s"), top_segment)
        if action == 'PUT':
            if next_segment is not None and top_segment is not None\
                    and host_id != 'unknow':
                return next_segment['segmentation_id']
        else:
            return 999999
        return None

    def update_port_filter(self, current_port, original_port):
        if current_port is None or original_port is None:
            return True
        if current_port.keys() != original_port.keys():
            return True
        for key in original_port.keys():
            if key != 'updated_at' and key != 'revision_number' \
                    and key != 'status' and original_port[key] != \
                    current_port[key]:
                return True
        return False

    def construct_port_info(self, mech_context, action):
        current_port = mech_context.current
        LOG.debug("construct_port_info current_port = %s" % current_port)
        original_port = mech_context.original
        LOG.debug("construct_port_info original_port = %s" % original_port)
        flag = self.update_port_filter(current_port, original_port)
        if not flag:
            LOG.debug("update port filter")
            return None
        else:
            port = current_port

        if action == 'DELETE' or action == 'GET':
            port_info = {
                "input": {
                    "id": port["id"]
                }
            }
        else:
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
                    # "binding_profile": str(port['binding:profile']),
                    "device_owner": port["device_owner"],
                    "fixed_ips": [{'subnet_id': ip["subnet_id"],
                                   'ip_address': ip["ip_address"]}
                                  for ip in port["fixed_ips"]],
                    "burst_size": self.validate_dict(port, 'cbs', 0),
                    "vnic_type": self.validate_dict(port,
                                                    'binding:vnic_type',
                                                    'normal'),
                    "vif_type": self.validate_dict(port,
                                                   'binding:vif_type',
                                                   'unbound'),
                    "host_id": self.validate_dict(port,
                                                  'binding:host_id', ''),
                }
            }

        if action == 'POST' or action == 'PUT':
            input = port_info['input']
            if self.zenic_version > 403:
                if 'extra_dhcp_opts' in port:
                    input['extra_dhcp_opts'] = [
                        {'opt_value': dhcp["opt_value"],
                         'ip_version': dhcp["ip_version"],
                         'opt_name': dhcp["opt_name"]}
                        for dhcp in port["extra_dhcp_opts"]]
                if self.enable_qos == "True":
                    if port.get('qos', None):
                        input['qos_policy_id'] = port['qos']
                    else:
                        input['qos_policy_id'] = ''
                if self.enable_mitaka_qos == "True":
                    if 'qos_policy_id' in port.keys():
                        input['qos_policy_id'] = port['qos_policy_id']

                pl_config.register_config()
                if pl_config.cfg.CONF.RESTPROXY.enable_hierarchical_port == \
                        "True":
                    next_segment = self.get_next_segment_id(
                        action, mech_context, port['binding:host_id'])
                    if next_segment:
                        input['next_segment_to_bind'] = next_segment
                if original_port:
                    if port['binding:profile'] != {} \
                            or original_port['binding:profile'] != {}:
                        input["binding_profile"] = jsonutils.dumps(
                            port['binding:profile'])
                else:
                    if port['binding:profile'] != {}:
                        input["binding_profile"] = jsonutils.dumps(
                            port['binding:profile'])
                if self.enable_bandwidth == "True":
                    input["band_width"] = self.validate_dict(port, 'bandwidth',
                                                             0)
                    input["dscp"] = self.validate_dict(port, 'dscp', 0)
                if self.en_security_group:
                    if 'port_security_enabled' in port.keys():
                        if port['port_security_enabled'] is True:
                            input["security_groups"] = port["security_groups"]
                        else:
                            input["security_groups"] = []
                    else:
                        input["security_groups"] = port["security_groups"]
                else:
                    input["security_groups"] = []

        if action == 'POST':
            input = port_info['input']
            input['network_id'] = port['network_id']
            input['tenant_id'] = port['tenant_id']
            input['mac_address'] = port['mac_address']
            if self.zenic_version > 403:
                if 'port_security_enabled' in port and self.en_security_group:
                    input['port_security_enabled'] = \
                        self.validate_dict(port, psec.PORTSECURITY, True)
        return port_info

    def construct_security_group_info(self, mech_context, action):
        sg = mech_context.current
        LOG.debug("construct_security_group_info sg = %s" % sg)

        if action == 'DELETE' or action == 'GET':
            security_group_info = {"input": {"id": sg["id"]}}
        elif action == 'PUT':
            security_group_info = {
                "input": {
                    "id": sg['id'],
                    "name": sg['name'],
                    "description": sg["description"],
                }
            }
        else:
            security_group_info = {
                "input": {
                    "id": sg['id'],
                    "name": sg['name'],
                    "description": sg["description"],
                    "tenant_id": sg['tenant_id']
                }
            }

        if action == "POST":
            security_group_rules = self.validate_dict(
                sg, 'security_group_rules', None)
            if security_group_rules is not None:
                sg_rules = []
                for rule in security_group_rules:
                    ether_type = self.validate_dict(rule, 'ethertype', None)
                    ipv4 = None
                    ipv6 = None
                    if ether_type and ether_type.find('4') != -1:
                        ipv4 = self.validate_dict(
                            rule, 'remote_ip_prefix', None)
                    elif ether_type and ether_type.find('6') != -1:
                        ipv6 = self.validate_dict(
                            rule, 'remote_ip_prefix', None)
                    else:
                        LOG.error("ether_type:%s is error!" % ether_type)

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
                        "ethertype": ether_type,
                        "tenant_id": sg['tenant_id'],
                        "security_group_id":
                            self.validate_dict(rule, 'security_group_id', None)
                    }
                    sg_rules.append(sg_rule)
                security_group_info['input']['security_group_rules'] =\
                    sg_rules
        return security_group_info

    def construct_security_group_rule_info(self, mech_context, action):
        rule = mech_context.current
        LOG.debug("construct_security_group_rule_info rule = %s" % rule)

        ether_type = self.validate_dict(rule, 'ethertype', None)
        ipv4 = None
        ipv6 = None
        if ether_type and ether_type.find('4') != -1:
            ipv4 = self.validate_dict(rule, 'remote_ip_prefix', None)
        elif ether_type and ether_type.find('6') != -1:
            ipv6 = self.validate_dict(rule, 'remote_ip_prefix', None)
        else:
            LOG.error("ether_type:%s is error!" % ether_type)

        if action == 'DELETE' or action == 'GET':
            security_group_rule_info = {"input": {"id": rule["id"]}}
        else:
            security_group_rule_info = {
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
            input = security_group_rule_info['input']
            input['direction'] = self.validate_dict(rule, 'direction', None)
            input['ethertype'] = ether_type
            input['tenant_id'] = rule['tenant_id']

        return security_group_rule_info

    def set_enable_security_group(self, en_security_group):
        self.en_security_group = en_security_group
        LOG.info(_(
            "zenic_l2restconf en_security_group = %s"),
            self.en_security_group)

    def rest_create_tenant(self, tenant_id, tenant_name, description):
        tenant_data = {"id": tenant_id,
                       "name": tenant_name,
                       "description": description}
        data = {"input": tenant_data}
        resource = 'add-' + TENANT
        err_str = _("Unable to create tenant: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_update_tenant(self, tenant_id, tenant_name, description):
        tenant_data = {"id": tenant_id,
                       "name": tenant_name,
                       "description": description}
        data = {"input": tenant_data}
        resource = 'update-' + TENANT
        err_str = _("Unable to update tenant: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_delete_tenant(self, tenant_id):
        tenant_data = {"id": tenant_id}
        data = {"input": tenant_data}
        resource = 'del-' + TENANT
        err_str = _("Unable to delete tenant: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_get_tenant(self, tenant_id):
        tenant_data = {"id": tenant_id}
        data = {"input": tenant_data}
        resource = 'get-' + TENANT
        err_str = _("Unable to get tenant: %s")
        return self.rest_action('POST', resource, data, err_str)

    def rest_create_network(self, mech_context):
        data = self.construct_network_info(mech_context, 'POST')
        if not data:
            return None
        resource = 'add-' + NETWORK
        err_str = _("Unable to create remote network: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_update_network(self, mech_context):
        data = self.construct_network_info(mech_context, 'PUT')
        if not data:
            return None
        resource = 'update-' + NETWORK
        err_str = _("Unable to update remote network: %s")

        ret = self.rest_action('POST', resource, data, err_str)
        if ret[0] == httplib.NOT_FOUND:
            self.rest_create_network(mech_context)

    def rest_delete_network(self, mech_context):
        try:
            from neutron.db import segments_db as db
        except Exception:
            from neutron.plugins.ml2 import db
        session = mech_context._plugin_context.session
        network_id = mech_context.current['id']
        if self.hierarchical == "True":
            dynamic_segment = db.get_dynamic_segment(session, network_id)
            LOG.info(_("delete_network dynamic_segment = %s"), dynamic_segment)
            if dynamic_segment:
                db.delete_network_segment(session,
                                          dynamic_segment[api.SEGMENTATION_ID])
        data = self.construct_network_info(mech_context, 'DELETE')
        resource = 'del-' + NETWORK
        err_str = _("Unable to delete remote network: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_get_network(self, mech_context):
        data = self.construct_network_info(mech_context, 'GET')
        resource = 'get-' + NETWORK
        err_str = _("Unable to get remote network: %s")
        return self.rest_action('POST', resource, data, err_str)

    def rest_create_subnet(self, mech_context):
        data = self.construct_subnet_info(mech_context, 'POST')
        resource = 'add-' + SUBNET
        err_str = _("Unable to create remote subnet: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_update_subnet(self, mech_context):
        data = self.construct_subnet_info(mech_context, 'PUT')
        resource = 'update-' + SUBNET
        err_str = _("Unable to update remote subnet: %s")
        ret = self.rest_action('POST', resource, data, err_str)
        if ret[0] == httplib.NOT_FOUND:
            self.rest_create_subnet(mech_context)

    def rest_delete_subnet(self, mech_context):
        data = self.construct_subnet_info(mech_context, 'DELETE')
        resource = 'del-' + SUBNET
        err_str = _("Unable to delete remote subnet: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_get_subnet(self, mech_context):
        data = self.construct_subnet_info(mech_context, 'GET')
        resource = 'get-' + SUBNET
        err_str = _("Unable to get remote subnet: %s")
        return self.rest_action('POST', resource, data, err_str)

    def rest_create_port(self, mech_context):
        data = self.construct_port_info(mech_context, 'POST')
        resource = 'add-' + PORT
        err_str = _("Unable to create remote port: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_update_port(self, mech_context):
        data = self.construct_port_info(mech_context, 'PUT')
        if not data:
            return None
        resource = 'update-' + PORT
        err_str = _("Unable to update remote port: %s")
        ret = self.rest_action('POST', resource, data, err_str)
        if ret[0] == httplib.NOT_FOUND:
            self.rest_create_port(mech_context)

    def rest_delete_port(self, mech_context):
        data = self.construct_port_info(mech_context, 'DELETE')
        resource = 'del-' + PORT
        err_str = _("Unable to delete remote port: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_get_port(self, mech_context):
        data = self.construct_port_info(mech_context, 'GET')
        resource = 'get-' + PORT
        err_str = _("Unable to get remote port: %s")
        return self.rest_action('POST', resource, data, err_str)

    def rest_create_security_group(self, mech_context):
        data = self.construct_security_group_info(mech_context, 'POST')
        resource = 'add-' + SECURITY_GROUP
        err_str = _("Unable to create remote security_group: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_update_security_group(self, mech_context):
        data = self.construct_security_group_info(mech_context, 'PUT')
        resource = 'update-' + SECURITY_GROUP
        err_str = _("Unable to update remote security_group: %s")
        ret = self.rest_action('POST', resource, data, err_str)
        if ret[0] == httplib.NOT_FOUND:
            self.rest_create_security_group(mech_context)

    def rest_delete_security_group(self, mech_context):
        data = self.construct_security_group_info(mech_context, 'DELETE')
        resource = 'del-' + SECURITY_GROUP
        err_str = _("Unable to delete remote security_group: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_get_security_group(self, mech_context):
        data = self.construct_security_group_info(mech_context, 'GET')
        resource = 'get-' + SECURITY_GROUP
        err_str = _("Unable to get remote security_group: %s")
        return self.rest_action('POST', resource, data, err_str)

    def rest_create_security_group_rule(self, mech_context):
        data = self.construct_security_group_rule_info(mech_context, 'POST')
        resource = 'add-' + SECURITY_GROUP_RULE
        err_str = _("Unable to create remote security_group_rule: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_update_security_group_rule(self, mech_context):
        data = self.construct_security_group_rule_info(mech_context, 'PUT')
        resource = 'update-' + SECURITY_GROUP_RULE
        err_str = _("Unable to update remote security_group_rule: %s")
        ret = self.rest_action('POST', resource, data, err_str)
        if ret[0] == httplib.NOT_FOUND:
            self.rest_create_security_group_rule(mech_context)

    def rest_delete_security_group_rule(self, mech_context):
        data = self.construct_security_group_rule_info(mech_context, 'DELETE')
        resource = 'del-' + SECURITY_GROUP_RULE
        err_str = _("Unable to delete remote security_group_rule: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_get_security_group_rule(self, mech_context):
        data = self.construct_security_group_rule_info(mech_context, 'GET')
        resource = 'get-' + SECURITY_GROUP_RULE
        err_str = _("Unable to get remote security_group_rule: %s")
        return self.rest_action('POST', resource, data, err_str)

    @staticmethod
    def construct_qos_policy_info(mech_context, action):
        qos_policy = mech_context.current
        qos_policy_info = {
            "input": {
                "id": qos_policy['id'],
            }
        }
        input = qos_policy_info['input']
        if 'type' in qos_policy:
            input['type'] = qos_policy['type']
        if 'description' in qos_policy:
            input['description'] = qos_policy['description']
        if 'tenant_id' in qos_policy:
            input['tenant_id'] = qos_policy['tenant_id']
        if 'shared' in qos_policy:
            input['shared'] = qos_policy['shared']
        if 'name' in qos_policy:
            input['name'] = qos_policy['name']

        return qos_policy_info

    @staticmethod
    def construct_bandwidth_limit_rule_info(mech_context, action):
        """
        {u'bandwidth_limit_rule':
             {u'max_kbps': u'300',
              u'max_burst_kbps': u'30',
              'tenant_id': u'c414cf57e9fc49efb8e3e0c8d4e41b33',
              'id' :'aa1e84d8-9ea3-45ec-8197-83b7d9abc647'}
        }
        """
        bandwidth_limit_rule = mech_context.current

        bandwidth_rule_info = {
            "input": {
                "id": bandwidth_limit_rule['id'],
                "qos_policy_id": bandwidth_limit_rule['id'],
            }
        }
        input = bandwidth_rule_info['input']
        if 'max_kbps' in bandwidth_limit_rule:
            input['max_kbps'] = bandwidth_limit_rule['max_kbps']
        if 'max_burst_kbps' in bandwidth_limit_rule:
            input['max_burst_kbps'] = bandwidth_limit_rule['max_burst_kbps']

        if 'tenant_id' in bandwidth_limit_rule:
            input['tenant_id'] = bandwidth_limit_rule['tenant_id']
        return bandwidth_rule_info

    @staticmethod
    def construct_delete_qos_info(mech_context):
        qos = mech_context.current
        qos_info = {
            "input": {
                "id": qos['id']
            }
        }
        return qos_info

    def rest_create_qos_policy(self, mech_context):
        data = self.construct_qos_policy_info(mech_context, 'CREATE')
        resource = 'add-' + QOS_POLICY
        err_str = _("Unable to add qos policy: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_update_qos_policy(self, mech_context):
        data = self.construct_qos_policy_info(mech_context, 'UPDATE')
        resource = 'update-' + QOS_POLICY
        err_str = _("Unable to update qos policy: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_delete_qos_policy(self, mech_context):
        data = self.construct_delete_qos_info(mech_context)
        resource = 'del-' + QOS_POLICY
        err_str = _("Unable to add qos policy: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_create_qos_bandwidth_limit_rule(self, mech_context):
        data = self.construct_bandwidth_limit_rule_info(mech_context, 'CREATE')
        resource = 'add-' + QOS_BANDWIDTH_RULE
        err_str = _("Unable to add bandwidth limit rule: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_update_qos_bandwidth_limit_rule(self, mech_context):
        data = self.construct_bandwidth_limit_rule_info(mech_context, 'UPDATE')
        resource = 'update-' + QOS_BANDWIDTH_RULE
        err_str = _("Unable to update bandwidth limit rule: %s")
        self.rest_action('POST', resource, data, err_str)

    def rest_delete_qos_bandwidth_limit_rule(self, mech_context):
        data = self.construct_delete_qos_info(mech_context)
        resource = 'del-' + QOS_BANDWIDTH_RULE
        err_str = _("Unable to del bandwidth limit rule: %s")
        self.rest_action('POST', resource, data, err_str)
