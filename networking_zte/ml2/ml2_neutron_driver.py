# Copyright 2011 ZTE, Inc.
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

from networking_zte.common import servermanager
from networking_zte.ml2.common.rest.ml2_zenic import config as pl_config
from networking_zte.ml2 import driver_context
from networking_zte.ml2 import sync_filter
try:
    from neutron import context as neutron_context
except Exception:
    from neutron_lib import context as neutron_context
from neutron.db import db_base_plugin_v2
from neutron.db import securitygroups_rpc_base as sg_db_rpc
try:
    from neutron_lib.api.definitions import portbindings
except Exception:
    from neutron.extensions import portbindings
from neutron.extensions import securitygroup as ext_sg
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import managers as manager
from neutron.plugins.ml2 import plugin
from oslo_config import cfg
from oslo_log import log
from oslo_utils import excutils
from oslo_utils import importutils
import six

LOG = log.getLogger(__name__)

ML2_NETWORK = 'network'
ML2_NETWORKS = 'networks'
ML2_SUBNET = 'subnet'
ML2_SUBNETS = 'subnets'
ML2_PORT = 'port'
ML2_PORTS = 'ports'
ML2_SG = 'security_group'
ML2_SGS = 'security_groups'
ML2_SG_RULE = 'security_group_rule'
ML2_SG_RULES = 'security_group_rules'


proxy_opts = [
    cfg.StrOpt(
        'driver_list',
        default='sdn:networking_zte.ml2.'
                'common.rest.ml2_zenic.mech_zenic_l2.ZenicL2Driver',
        help="Define the drivers of proxy agent"),
]
security_group_opts = [
    cfg.BoolOpt(
        'enable_security_group',
        default=True,
        help=_(
            'Controls whether the neutron security group API is enabled '
            'in the server. It should be false when using no security '
            'groups or using the nova security group API.')),
]
CONF = cfg.CONF
CONF.register_opts(proxy_opts, 'ml2')
CONF.register_opts(security_group_opts, 'securitygroup')


def method_patch(cls, bases, dct):
    base = bases[0]
    for name, value in dct.iteritems():
        if name not in("__module__", "__metaclass__", "__doc__"):
            setattr(base, name, value)
    return base


@six.add_metaclass(method_patch)
class MechanismDriverExt(api.MechanismDriver):
    """Define stable abstract interface extension for ML2 mechanism
    drivers.
    """

    def bind_port(self, context):
        binding_levels = context.binding_levels
        if hasattr(context, "vif_type"):
            vif_type = context.vif_type
        else:
            LOG.info(_("zte_ml2 bind_port vif_type is None"))
            return
        LOG.info(_("zte_ml2 bind_port binding_level =%s"), binding_levels)

        LOG.info(_("zte_ml2 bind_port binding_level =%s"), binding_levels)
        if (binding_levels is not None and
                binding_levels['driver'] == 'ml2_ztedriver') or \
                (vif_type != portbindings.VIF_TYPE_UNBOUND and
                    vif_type != portbindings.VIF_TYPE_BINDING_FAILED):
            return
        pl_config.register_config()
        if pl_config.cfg.CONF.RESTPROXY.enable_hierarchical_port == "True":
            LOG.info(_("zte_ml2 bind_port segments_to_bind= %s"),
                     context.segments_to_bind)
            next_segments_to_bind = list()
            segment_to_bind = context.segments_to_bind[-1]
            physical_network = \
                segment_to_bind.get(api.PHYSICAL_NETWORK, None)
            if physical_network is None:
                LOG.info("physical_network is not configed!")
            segment = {api.NETWORK_TYPE: 'vlan',
                       api.PHYSICAL_NETWORK: physical_network,
                       }
            LOG.info(_("zte_ml2 bind_port segment= %s"), segment)
            next_segment_to_bind = \
                context.allocate_dynamic_segment(segment)
            LOG.info(_("zte_ml2 bind_port next_segment_to_bind= %s"),
                     next_segment_to_bind)
            next_segments_to_bind.append(next_segment_to_bind)
            next_segments_to_bind.append(segment_to_bind)

            context.continue_binding(segment_to_bind[api.ID],
                                     next_segments_to_bind)

    def create_security_group_precommit(self, context):
        """Create resources of a security group.

        :param context: SecurityGroupContext instance describing the current
        state of the security group, prior to the call to create it.

        Called inside transaction context on session. Runtime errors
        are not expected, but raising an exception will result in
        rollback of the transaction.
        """
        pass

    def create_security_group_postcommit(self, context):
        """Create a security group.

        :param context: SecurityGroupContext instance describing the current
        state of the security group, prior to the call to create it.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Runtime errors are not
        expected, and will not prevent the resource from being
        created.
        """
        pass

    def update_security_group_precommit(self, context):
        """Create resources of a security group.

        :param context: SecurityGroupContext instance describing the current
        state of the security group, prior to the call to create it.

        Called inside transaction context on session. Runtime errors
        are not expected, but raising an exception will result in
        rollback of the transaction.
        """
        LOG.debug("MechanismDriverExt precommit")
        pass

    def update_security_group_postcommit(self, context):
        """Create resources of a security group.

        :param context: SecurityGroupContext instance describing the current
        state of the security group, prior to the call to create it.

        Called inside transaction context on session. Runtime errors
        are not expected, but raising an exception will result in
        rollback of the transaction.
        """
        LOG.debug("MechanismDriverExt postcommit")
        pass

    def delete_security_group_precommit(self, context):
        """Delete resources of a security group.

        :param context: SecurityGroupContext instance describing the current
        state of the security group, prior to the call to delete it.

        Called inside transaction context on session. Runtime errors
        are not expected, but raising an exception will result in
        rollback of the transaction.
        """
        pass

    def delete_security_group_postcommit(self, context):
        """Delete a security group.

        :param context: SecurityGroupContext instance describing the current
        state of the security group, prior to the call to delete it.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        pass

    def create_security_group_rule_precommit(self, context):
        """Create resources of a security group rule.

        :param context: SecurityGroupContext instance describing the current
        state of the security group, prior to the call to create it.

        Called inside transaction context on session. Runtime errors
        are not expected, but raising an exception will result in
        rollback of the transaction.
        """
        pass

    def create_security_group_rule_postcommit(self, context):
        """Create a security group rule.

        :param context: SecurityGroupContext instance describing the current
        state of the security group, prior to the call to create it.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Runtime errors are not
        expected, and will not prevent the resource from being
        created.
        """
        pass

    def delete_security_group_rule_precommit(self, context):
        """Delete resources of a security group rule.

        :param context: SecurityGroupContext instance describing the current
        state of the security group, prior to the call to delete it.

        Called inside transaction context on session. Runtime errors
        are not expected, but raising an exception will result in
        rollback of the transaction.
        """
        pass

    def delete_security_group_rule_postcommit(self, context):
        """Delete a security group rule.

        :param context: SecurityGroupContext instance describing the current
        state of the security group, prior to the call to delete it.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        pass

    def create_qos_policy_precommit(self, context):
        pass

    def update_qos_policy_precommit(self, context):
        pass

    def delete_qos_policy_precommit(self, context):
        pass

    def create_qos_bandwidth_limit_rule_precommit(self, context):
        pass

    def update_qos_bandwidth_limit_rule_precommit(self, context):
        pass

    def delete_qos_bandwidth_limit_rule_precommit(self, context):
        pass


@six.add_metaclass(method_patch)
class MechanismManagerExt(manager.MechanismManager):
    """Manage networking mechanisms using drivers."""

    def create_security_group_precommit(self, context):
        """Notify all mechanism drivers during security group creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_security_group_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("create_security_group_precommit", context)

    def create_security_group_postcommit(self, context):
        """Notify all mechanism drivers after security group creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_security_group_postcommit call fails.

        Called after the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, where the subnet will be deleted, triggering
        any required cleanup. There is no guarantee that all mechanism
        drivers are called in this case.
        """
        self._call_on_drivers("create_security_group_postcommit", context)

    def delete_security_group_precommit(self, context):
        """Notify all mechanism drivers during security group deletion.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_security_group_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("delete_security_group_precommit", context)

    def delete_security_group_postcommit(self, context):
        """Notify all mechanism drivers after security group deletion.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_security_group_postcommit call fails.

        Called after the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, where the subnet will be deleted, triggering
        any required cleanup. There is no guarantee that all mechanism
        drivers are called in this case.
        """
        self._call_on_drivers("delete_security_group_postcommit", context)

    def update_security_group_precommit(self, context):
        """Notify all mechanism drivers during security group creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_security_group_precommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        LOG.debug("MechanismManagerExt precommit")
        self._call_on_drivers("update_security_group_precommit", context)

    def update_security_group_postcommit(self, context):
        """Notify all mechanism drivers during security group creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver update_security_group_postcommit call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        LOG.debug("MechanismManagerExt postcommit")
        self._call_on_drivers("update_security_group_postcommit", context)

    def create_security_group_rule_precommit(self, context):
        """Notify all mechanism drivers during security group rule creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_security_group_rule_precommit
        call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("create_security_group_rule_precommit", context)

    def create_security_group_rule_postcommit(self, context):
        """Notify all mechanism drivers after security group rule creation.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_security_group_rule_postcommit
        call fails.

        Called after the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, where the subnet will be deleted, triggering
        any required cleanup. There is no guarantee that all mechanism
        drivers are called in this case.
        """
        self._call_on_drivers("create_security_group_rule_postcommit", context)

    def delete_security_group_rule_precommit(self, context):
        """Notify all mechanism drivers during security group rule deletion.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_security_group_rule_precommit
        call fails.

        Called within the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propogated
        to the caller, triggering a rollback. There is no guarantee
        that all mechanism drivers are called in this case.
        """
        self._call_on_drivers("delete_security_group_rule_precommit", context)

    def delete_security_group_rule_postcommit(self, context):
        """Notify all mechanism drivers after security group rule deletion.

        :raises: neutron.plugins.ml2.common.MechanismDriverError
        if any mechanism driver create_security_group_rule_postcommit
        call fails.

        Called after the database transaction. If a mechanism driver
        raises an exception, then a MechanismDriverError is propagated
        to the caller, where the subnet will be deleted, triggering
        any required cleanup. There is no guarantee that all mechanism
        drivers are called in this case.
        """
        self._call_on_drivers("delete_security_group_rule_postcommit", context)

    def create_qos_policy_precommit(self, context):
        self._call_on_drivers("create_qos_policy_precommit", context)

    def update_qos_policy_precommit(self, context):
        self._call_on_drivers("update_qos_policy_precommit", context)

    def delete_qos_policy_precommit(self, context):
        self._call_on_drivers("delete_qos_policy_precommit", context)

    def create_qos_bandwidth_limit_rule_precommit(self, context):
        self._call_on_drivers(
            "create_qos_bandwidth_limit_rule_precommit", context)

    def update_qos_bandwidth_limit_rule_precommit(self, context):
        self._call_on_drivers(
            "update_qos_bandwidth_limit_rule_precommit", context)

    def delete_qos_bandwidth_limit_rule_precommit(self, context):
        self._call_on_drivers(
            "delete_qos_bandwidth_limit_rule_precommit", context)


@six.add_metaclass(method_patch)
class Ml2PluginExt(plugin.Ml2Plugin):
    """Extend the Neutron L2 abstractions using modules.

    Implement security_group,security_group_rule methods to notify
    SDN controller.
    """

    def create_qos(self, context, qos):
        LOG.info(_("Ml2PluginExt create_qos qos = %s"), qos)
        result = super(Ml2PluginExt, self).create_qos(context, qos)

        rate_limit = result['policies']['ratelimit']
        bandwidth_limit_rule = {
            "tenant_id": result['tenant_id'],
            "id": result['id'],
            "max_kbps": rate_limit,
        }
        mech_bandwidth_context = driver_context.QosBandWidthRuleContext(
            self, context, bandwidth_limit_rule)
        mech_policy_context = driver_context.QosPolicyContext(
            self, context, result)
        try:
            self.mechanism_manager.create_qos_policy_precommit(
                mech_policy_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager."
                            "create_qos_precommit failed, "
                            "create qos '%s'"), result)
                super(Ml2PluginExt, self).delete_qos(context, result['id'])

        try:
            self.mechanism_manager.create_qos_bandwidth_limit_rule_precommit(
                mech_bandwidth_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager."
                            "create_qos_precommit failed, "
                            "create qos '%s'"), result)
                self.mechanism_manager.delete_qos_policy_precommit(
                    mech_policy_context)
                super(Ml2PluginExt, self).delete_qos(context, result['id'])

        return result

    def update_qos(self, context, id, qos):
        qos_info = qos['qos']
        LOG.info(_("Ml2PluginExt update_qos qos = %s"), qos_info)
        if 'policies' in qos_info:
            rate_limit = qos_info['policies']['ratelimit']
            bandwidth_limit_rule = {
                "id": id,
                "max_kbps": rate_limit,
            }
            mech_bandwidth_context = driver_context.QosBandWidthRuleContext(
                self, context, bandwidth_limit_rule)
            try:
                self.mechanism_manager.update_qos_bandwidth_limit_rule_precommit(        # noqa
                    mech_bandwidth_context)
            except ml2_exc.MechanismDriverError:
                with excutils.save_and_reraise_exception():
                    LOG.error(_("mechanism_manager."
                                "update_qos_bandwidth_limit_rule_precommit "
                                "failed, udpate_qos_bandwidth rule '%s'"),
                              bandwidth_limit_rule)

        if 'description' in qos_info:
            policy = {
                "id": id,
                "description": qos_info['description'],
            }
            mech_policy_context = driver_context.QosPolicyContext(
                self, context, policy)
            try:
                self.mechanism_manager.update_qos_policy_precommit(
                    mech_policy_context)
            except ml2_exc.MechanismDriverError:
                with excutils.save_and_reraise_exception():
                    LOG.error(_("mechanism_manager."
                                "update_qos_policy_precommit failed, "
                                "update_qos_policy '%s'"), policy)

        result = super(Ml2PluginExt, self).update_qos(context,
                                                      id,
                                                      qos)
        return result

    def delete_qos(self, context, id):
        bandwidth_limit_rule = {
            "id": id,
        }
        mech_bandwidth_context = driver_context.QosBandWidthRuleContext(
            self, context, bandwidth_limit_rule)

        policy = {
            "id": id,
        }
        mech_policy_context = driver_context.QosPolicyContext(
            self, context, policy)

        try:
            self.mechanism_manager.delete_qos_policy_precommit(
                mech_policy_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager."
                            "delete_qos_policy_precommit failed, "
                            "deleting qos '%s'"), policy)
        try:
            self.mechanism_manager.delete_qos_bandwidth_limit_rule_precommit(
                mech_bandwidth_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager."
                            "delete_qos_bandwidth_limit_rule_precommit "
                            "failed, deleting qos '%s'"), policy)
        super(Ml2PluginExt, self).delete_qos(context, id)

    def extend_port_extra_dhcp_opts_dict(self, context, port):
        self._extend_port_extra_dhcp_opts_dict(context, port)

    def create_security_group(
            self, context, security_group, default_sg=False):
        """Create security group.

        Create a new security group, including the default security group.
        """
        LOG.debug(_("Ml2Plugin.create_security_group called: "
                    "security_group=%(security_group)s "
                    "default_sg=%(default_sg)s "),
                  {'security_group': security_group,
                   'default_sg': default_sg})

        with context.session.begin(subtransactions=True):
            sg = security_group.get('security_group')
            tenant_id = sg['tenant_id']
            if not default_sg:
                self._ensure_default_security_group(context, tenant_id)

            # Create the Neutron sg first
            sg = super(plugin.Ml2Plugin, self).create_security_group(
                context, security_group, default_sg)

            LOG.debug(_("sg: %s"), sg)

            mech_context = driver_context.SecurityGroupContext(
                self, context, sg)
            self.mechanism_manager.create_security_group_precommit(
                mech_context)

        try:
            self.mechanism_manager.create_security_group_postcommit(
                mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager."
                            "create_security_group_postcommit failed, "
                            "deleting security group '%s'"), sg)
                self.delete_security_group(context, sg['id'])

        return sg

    def update_security_group(
            self, context, id, security_group):
        """Update security group.

        update security group, not including the default security group.
        """

        LOG.debug(_("update_sg,context= %s"), (', '.join(
            ['%s:%s' % item for item in context.__dict__.items()])))
        LOG.debug(_("Ml2Plugin.update_security_group called: "
                    "security_group=%(security_group)s "),
                  {'security_group': security_group})

        sg = super(plugin.Ml2Plugin, self).update_security_group(
            context, id, security_group)

        LOG.debug(_("sg: %s"), sg)

        mech_context = driver_context.SecurityGroupContext(
            self, context, sg)
        self.mechanism_manager.update_security_group_precommit(
            mech_context)

        try:
            self.mechanism_manager.update_security_group_postcommit(
                mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager."
                            "update_security_group_postcommit failed, "
                            "deleting security group '%s'"), sg)

        return sg

    def delete_security_group(self, context, id):
        """Delete chains for Neutron security group."""
        LOG.debug(_("Ml2Plugin.delete_security_group called: id=%s"), id)

        with context.session.begin(subtransactions=True):
            sg = super(plugin.Ml2Plugin, self).get_security_group(context, id)

            if not sg:
                raise ext_sg.SecurityGroupNotFound(id=id)

            if sg["name"] == 'default' and not context.is_admin:
                raise ext_sg.SecurityGroupCannotRemoveDefault()

            sg_id = sg['id']
            filters = {'security_group_id': [sg_id]}
            if super(
                plugin.Ml2Plugin, self)._get_port_security_group_bindings(
                    context, filters):
                raise ext_sg.SecurityGroupInUse(id=sg_id)

            super(plugin.Ml2Plugin, self).delete_security_group(context, id)
            mech_context = driver_context.SecurityGroupContext(
                self, context, sg)

            self.mechanism_manager.delete_security_group_precommit(
                mech_context)

        try:
            self.mechanism_manager.delete_security_group_postcommit(
                mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager."
                            "delete_security_group_postcommit "
                            "failed, deleting security group '%s'"), sg)

    def create_security_group_rule(self, context, security_group_rule):
        """Create a security group rule

        Create a security group rule in the Neutron DB and corresponding
        SDN resources in its data store.
        """
        LOG.debug(_("Ml2Plugin.create_security_group_rule called: "
                    "security_group_rule=%(security_group_rule)r"),
                  {'security_group_rule': security_group_rule})

        with context.session.begin(subtransactions=True):
            rule = super(plugin.Ml2Plugin, self).create_security_group_rule(
                context, security_group_rule)

            LOG.debug(_("Ml2Plugin.create_security_group_rule exiting: "
                        "rule=%r"), rule)

            mech_context = driver_context.SecurityGroupRuleContext(
                self, context, rule)
            self.mechanism_manager.create_security_group_rule_precommit(
                mech_context)

        try:
            self.mechanism_manager.create_security_group_rule_postcommit(
                mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager."
                            "create_security_group_rule_postcommit "
                            "failed, security group rule'%s'"), rule)
                self.delete_security_group_rule(context, rule["id"])
        return rule

    def create_security_group_rule_bulk(self, context, security_group_rules):
        created_rules = list()
        for security_group_rule in security_group_rules[
            'security_group_rules']:
            created_rules.append(
                self.create_security_group_rule(
                    context, security_group_rule))
        return created_rules

    def delete_security_group_rule(self, context, sg_rule_id):
        """Delete a security group rule

        Delete a security group rule from the Neutron DB and corresponding
        SDN resources from its data store.
        """
        LOG.debug(_("Ml2Plugin.delete_security_group_rule called: "
                    "sg_rule_id=%s"), sg_rule_id)
        with context.session.begin(subtransactions=True):
            rule = super(plugin.Ml2Plugin, self).get_security_group_rule(
                context, sg_rule_id)

            if not rule:
                raise ext_sg.SecurityGroupRuleNotFound(id=sg_rule_id)

            super(plugin.Ml2Plugin, self).delete_security_group_rule(
                context, sg_rule_id)

            mech_context = driver_context.SecurityGroupRuleContext(
                self, context, rule)
            self.mechanism_manager.delete_security_group_rule_precommit(
                mech_context)

        try:
            self.mechanism_manager.delete_security_group_rule_postcommit(
                mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager."
                            "delete_security_group_rule_postcommit "
                            "failed, security group rule'%s'"), rule)


class Ml2MechanismDriver(api.MechanismDriver,
                         db_base_plugin_v2.NeutronDbPluginV2,
                         sg_db_rpc.SecurityGroupServerRpcMixin):

    """Mechanism Driver for Ml2Plugin.
    """
    FILTER_MAP = {
        ML2_NETWORK: sync_filter.NetworkFilter,
        ML2_SUBNET: sync_filter.SubnetFilter,
        ML2_PORT: sync_filter.PortFilter,
        ML2_SG: sync_filter.SecurityGroupFilter,
        ML2_SG_RULE: sync_filter.SecurityGroupRuleFilter,
    }

    def initialize(self):
        self.driver_provider = {}
        self._load_driver_provider()
        self.set_enable_security_group()
        pl_config.register_config()
        self.enable_pre_commit = pl_config.cfg.CONF.RESTPROXY.enable_pre_commit
        LOG.info(_(
            "ZTE Ml2MechanismDriver enable_pre_commit = %s"),
            self.enable_pre_commit)

    def sync_full(self, context=None):
        dbcontext = neutron_context.get_admin_context()
        for collection_name in [ML2_NETWORK,
                                ML2_SUBNET,
                                ML2_PORT,
                                ML2_SG,
                                ML2_SG_RULE]:
            filter_cls = self.FILTER_MAP[collection_name]
            obj_getter = getattr(self, 'get_%ss' % collection_name)
            resources = obj_getter(dbcontext)
            for resource in resources:
                LOG.debug(
                    "sync_full sync %s = %s" %
                    (collection_name, resource))
                operation = 'create' + '_' + collection_name
                if context is not None:
                    mech_context = \
                        filter_cls.filter_create_attributes_with_plugin(
                            resource, context._plugin, dbcontext)
                else:
                    if 'network_id' in resource:
                        network = self.get_network(
                            dbcontext, resource['network_id'])
                        LOG.info(_("sync_full,network= %s"), network)
                    else:
                        network = None
                    mech_context = \
                        filter_cls.filter_create_attributes_without_plugin(
                            resource, dbcontext, network)

                try:
                    self._call_on_drivers_to_rest(operation, mech_context)
                    LOG.debug(_("sync_full success!,resource= %s"),
                              (', '.join(['%s:%s' %
                         item for item in mech_context.__dict__.items()])))
                except BaseException as e:
                    LOG.error(_("sync_full error!,resource= %s"), (', '.join(
                        ['%s:%s' %
                         item for item in mech_context.__dict__.items()])))
                    LOG.error(_("sync_full, except:%s"), str(e))

    def _load_driver_provider(self):
        """Loads service drivers.
        """
        driver_providers = [driver_set.split(':')
                            for driver_set in CONF.ml2.driver_list.split(',')]

        while [''] in driver_providers:
            driver_providers.remove([''])

        if not driver_providers:
            LOG.info(_("Can't find service drivers"))
            return

        LOG.debug(_("Loading service drivers: %s"), driver_providers)
        for driver_name, driver_class in driver_providers:
            if driver_name is None or driver_class is None:
                continue

            LOG.debug(_("Loading service driver: %(dn)s, class path: %(cla)s"),
                      {"dn": driver_name, "cla": driver_class})
            driver_cls = importutils.import_class(driver_class)
            driver_inst = driver_cls()

            self.driver_provider[driver_name] = driver_inst

            LOG.info(_("Successfully loaded %(name)s driver. "
                       "Description: %(desc)s"),
                     {"name": driver_name, "desc": driver_class})

    def _call_on_drivers(self, method, context, continue_on_failure=False):
        """Call method of service drivers.
        """
        self._call_on_drivers_to_rest(method, context, continue_on_failure)
#         try:
#             self._call_on_drivers_to_rest(method,context,continue_on_failure)
#         except:
#             self.sync_full(context)
#             self._call_on_drivers_to_rest(method,context,
#             continue_on_failure)

    def _call_on_drivers_to_rest(
            self,
            method,
            context,
            continue_on_failure=False):
        """Call method of service drivers.
        """
        if not self.driver_provider:
            return

        error = False
        for name, inst in self.driver_provider.items():
            try:
                if hasattr(inst, method):
                    getattr(inst, method)(context)
            except servermanager.RemoteRestError:
                LOG.error(
                    _("ZTE Ml2MechanismDriver '%(name)s' failed in "
                      "%(method)s"), {'name': name, 'method': method}
                )
                error = True
                if not continue_on_failure:
                    break

        if error:
            raise ml2_exc.MechanismDriverError(
                method=method
            )

    def set_enable_security_group(self):
        en_security_group = CONF.securitygroup.enable_security_group
        self._call_on_drivers_to_rest(
            'set_enable_security_group', en_security_group)
    # Postcommit hooks are used to trigger synchronization.

    def create_network_postcommit(self, context):
        if CONF.securitygroup.enable_security_group:
            tenant_id = context.current.get("tenant_id", None)
            if tenant_id:
                default_sg_id = self._ensure_default_security_group(
                    context._plugin_context, tenant_id)
                default_sg = self.get_security_group(
                    context._plugin_context, default_sg_id)

                LOG.debug(_("ZTE Ml2MechanismDriver."
                            "create_network_postcommit called: "
                            "security_group=%(security_group)s "
                            "default_sg_id=%(default_sg)s "),
                          {'security_group': default_sg,
                           'default_sg': default_sg_id})
                mech_context = driver_context.SecurityGroupContext(
                    self, context._plugin_context, default_sg)

                try:
                    self.create_security_group_postcommit(mech_context)
                except ml2_exc.MechanismDriverError:
                    with excutils.save_and_reraise_exception():
                        LOG.error(_("ZTE Ml2MechanismDriver."
                                    "create_security_group_postcommit "
                                    "failed '%s'"), default_sg)
        self._call_on_drivers('create_network', context)

    def delete_network_precommit(self, context):
        self._call_on_drivers_to_rest('delete_network', context)

    def update_network_precommit(self, context):
        if self.enable_pre_commit == "True":
            LOG.debug("ZTE Ml2MechanismDriver enter update_subnet_precommit")
            self._call_on_drivers('update_network', context)

    def update_network_postcommit(self, context):
        if self.enable_pre_commit == "False":
            LOG.debug("ZTE Ml2MechanismDriver enter update_network_postcommit")
            self._call_on_drivers('update_network', context)

    def create_subnet_postcommit(self, context):
        self._call_on_drivers('create_subnet', context)

    def delete_subnet_precommit(self, context):
        self._call_on_drivers_to_rest('delete_subnet', context)

    def update_subnet_postcommit(self, context):
        if self.enable_pre_commit == "False":
            LOG.debug("ZTE Ml2MechanismDriver enter update_subnet_postcommit")
            self._call_on_drivers('update_subnet', context)

    def update_subnet_precommit(self, context):
        if self.enable_pre_commit == "True":
            LOG.debug("ZTE Ml2MechanismDriverenter update_subnet_precommit")
            self._call_on_drivers('update_subnet', context)

    def create_port_postcommit(self, context):
        if CONF.securitygroup.enable_security_group:
            tenant_id = context.current.get("tenant_id", None)
            if tenant_id:
                default_sg_id = self._ensure_default_security_group(
                    context._plugin_context, tenant_id)
                default_sg = self.get_security_group(
                    context._plugin_context, default_sg_id)

                LOG.debug(_("ZTE Ml2MechanismDriver."
                            "create_network_postcommit called: "
                            "security_group=%(security_group)s "
                            "default_sg_id=%(default_sg)s "),
                          {'security_group': default_sg,
                           'default_sg': default_sg_id})
                mech_context = driver_context.SecurityGroupContext(
                    self, context._plugin_context, default_sg)

                try:
                    self.create_security_group_postcommit(mech_context)
                except ml2_exc.MechanismDriverError:
                    with excutils.save_and_reraise_exception():
                        LOG.error(_("ZTE Ml2MechanismDriver."
                                    "create_security_group_postcommit "
                                    "failed '%s'"), default_sg)
        self._call_on_drivers('create_port', context)

    def delete_port_precommit(self, context):
        self._call_on_drivers_to_rest('delete_port', context)

    def update_port_postcommit(self, context):
        if self.enable_pre_commit == "False":
            LOG.debug("ZTE Ml2MechanismDriver enter update_port_postcommit")
            self._call_on_drivers('update_port', context)

    def update_port_precommit(self, context):
        if self.enable_pre_commit == "True":
            LOG.debug("ZTE Ml2MechanismDriver enter update_port_precommit")
            self._call_on_drivers('update_port', context)

    def create_security_group_postcommit(self, context):
        self._call_on_drivers('create_security_group', context)

    def update_security_group_precommit(self, context):
        if self.enable_pre_commit == "True":
            LOG.debug("ZTE Ml2MechanismDriver enter update_security_group_"
                      "precommit")
            self._call_on_drivers('update_security_group', context)

    def update_security_group_postcommit(self, context):
        if self.enable_pre_commit == "False":
            LOG.debug("ZTE Ml2MechanismDriver enter update_security_group_"
                      "postcommit")
            self._call_on_drivers('update_security_group', context)

    def delete_security_group_precommit(self, context):
        self._call_on_drivers_to_rest('delete_security_group', context)

    def create_security_group_rule_postcommit(self, context):
        self._call_on_drivers('create_security_group_rule', context)

    def delete_security_group_rule_precommit(self, context):
        self._call_on_drivers_to_rest('delete_security_group_rule', context)

    def create_qos_policy_precommit(self, context):
        self._call_on_drivers("create_qos_policy", context)

    def update_qos_policy_precommit(self, context):
        self._call_on_drivers("update_qos_policy", context)

    def delete_qos_policy_precommit(self, context):
        self._call_on_drivers_to_rest("delete_qos_policy", context)

    def create_qos_bandwidth_limit_rule_precommit(self, context):
        self._call_on_drivers("create_qos_bandwidth_limit_rule", context)

    def update_qos_bandwidth_limit_rule_precommit(self, context):
        self._call_on_drivers("update_qos_bandwidth_limit_rule", context)

    def delete_qos_bandwidth_limit_rule_precommit(self, context):
        self._call_on_drivers_to_rest(
            "delete_qos_bandwidth_limit_rule", context)

    def check_vlan_transparency(self, context):
        return True

    def notify_sg_on_port_change(self, **kwargs):
        pass
