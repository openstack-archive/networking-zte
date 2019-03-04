# vim: tabstop=4 shiftwidth=4 softtabstop=4
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

import abc
from networking_zte.ml2 import driver_context
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import portbindings
from neutron.plugins.ml2 import driver_context as ml2_context
from oslo_log import log
import six

LOG = log.getLogger(__name__)


def try_del(d, keys):
    """Ignore key errors when deleting from a dictionary."""
    for key in keys:
        try:
            del d[key]
        except KeyError:
            pass


@six.add_metaclass(abc.ABCMeta)
class ResourceFilterBase(object):
    @staticmethod
    @abc.abstractmethod
    def filter_create_attributes(resource, context):
        pass

    @staticmethod
    @abc.abstractmethod
    def filter_create_attributes_with_plugin(resource, plugin, dbcontext):
        pass

    @abc.abstractmethod
    def filter_create_attributes_without_plugin(
            resource, dbcontext, resourceplus):
        pass

    @staticmethod
    def _filter_unmapped_null(resource_dict, unmapped_keys):
        keys_to_del = [key for key in unmapped_keys
                       if resource_dict.get(key) is None]
        if keys_to_del:
            try_del(resource_dict, keys_to_del)


class NetworkFilter(ResourceFilterBase):
    _UNMAPPED_KEYS = ['qos_policy_id']

    @classmethod
    def filter_create_attributes(cls, network, context):
        """Filter out network attributes not required for a create."""
        try_del(network, ['status', 'subnets'])
        cls._filter_unmapped_null(network, cls._UNMAPPED_KEYS)

    @classmethod
    def filter_create_attributes_with_plugin(cls, network, plugin, dbcontext):
        context = ml2_context.NetworkContext(plugin, dbcontext, network)
        cls.filter_create_attributes(network, context)
        return context

    @classmethod
    def filter_create_attributes_without_plugin(
            cls, network, dbcontext, networkplus):
        context = ml2_context.NetworkContext(None, dbcontext, network)
        cls.filter_create_attributes(network, context)
        return context


class SubnetFilter(ResourceFilterBase):
    @classmethod
    def filter_create_attributes_with_plugin(cls, subnet, plugin, dbcontext):
        network = plugin.get_network(dbcontext, subnet['network_id'])
        context = ml2_context.SubnetContext(plugin, dbcontext, subnet,
                                            network)
        cls.filter_create_attributes(subnet, context)
        return context

    @classmethod
    def filter_create_attributes_without_plugin(
            cls, subnet, dbcontext, network):
        context = ml2_context.SubnetContext(None, dbcontext, subnet,
                                            network)
        cls.filter_create_attributes(subnet, context)
        return context


class PortFilter(ResourceFilterBase):
    _UNMAPPED_KEYS = ['binding:profile', 'dns_name',
                      'port_security_enabled', 'qos_policy_id']

    @classmethod
    def filter_create_attributes(cls, port, context, network):
        """Filter out port attributes not required for a create."""

        if portbindings.PROFILE not in port:
            port[portbindings.PROFILE] = ''

        cls._filter_unmapped_null(port, cls._UNMAPPED_KEYS)
        try_del(port, ['status'])

        if port['tenant_id'] == '' and 'tenant_id' in network:
            LOG.debug('empty string was passed for tenant_id: %s(port)', port)
            port['tenant_id'] = network['tenant_id']

    @classmethod
    def filter_create_attributes_with_plugin(cls, port, plugin, dbcontext):
        network = plugin.get_network(dbcontext, port['network_id'])
        port[addr_pair.ADDRESS_PAIRS] = (
            plugin.get_allowed_address_pairs(dbcontext, port['id']))
        plugin.extend_port_extra_dhcp_opts_dict(dbcontext, port)
        cls.filter_create_attributes(port, dbcontext, network)
        return plugin.get_bound_port_context(dbcontext, port['id'])

    @classmethod
    def filter_create_attributes_without_plugin(cls, port, dbcontext, network):
        binding = {}
        port[addr_pair.ADDRESS_PAIRS] = []
        context = ml2_context.PortContext(
            None, dbcontext, port, network, binding, None)
        cls.filter_create_attributes(port, context, network)
        return context


class SecurityGroupFilter(ResourceFilterBase):
    @classmethod
    def filter_create_attributes_with_plugin(cls, sg, plugin, dbcontext):
        context = driver_context.SecurityGroupContext(plugin, dbcontext, sg)
        return context

    @classmethod
    def filter_create_attributes_without_plugin(cls, sg, dbcontext, network):
        return cls.filter_create_attributes_with_plugin(sg, None, dbcontext)


class SecurityGroupRuleFilter(ResourceFilterBase):
    @classmethod
    def filter_create_attributes_with_plugin(cls, sg_rule, plugin, dbcontext):
        context = driver_context.SecurityGroupRuleContext(
            plugin, dbcontext, sg_rule)
        return context

    @classmethod
    def filter_create_attributes_without_plugin(
            cls, sg_rule, dbcontext, network):
        return cls.filter_create_attributes_with_plugin(
            sg_rule, None, dbcontext)
