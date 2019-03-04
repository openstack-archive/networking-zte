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

from networking_zte.qos.zenic_qos_pool import ZenicRestServerPool
try:
    from neutron_lib import exceptions
except Exception:
    from neutron.common import exceptions
try:
    from neutron.services.qos.qos_plugin import QoSPlugin
except Exception:
    pass
try:
    from neutron.objects.qos import rule as rule_object
except Exception:
    pass
from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

rest_proxy_opts = [
    cfg.ListOpt('servers', default=['localhost:8800'],
                help=_("A comma separated list of Big Switch or Floodlight "
                       "servers and port numbers. The plugin proxies the "
                       "requests to the Big Switch/Floodlight server, "
                       "which performs the networking configuration. Only one"
                       "server is needed per deployment, but you may wish to"
                       "deploy multiple servers to support failover.")),
    cfg.StrOpt('server_auth', default=None, secret=True,
               help=_("The username and password for authenticating against "
                      " the Big Switch or Floodlight controller.")),
    cfg.StrOpt('base_url', default='/restconf/operations/zenic-vdcapp-model:',
               help=_("Base URL for restconf server ")),
    cfg.BoolOpt('server_ssl', default=False,
                help=_("If True, Use SSL when connecting to the Big Switch or "
                       "Floodlight controller.")),
    cfg.BoolOpt('ssl_sticky', default=True,
                help=_("Trust and store the first certificate received for "
                       "each controller address and use it to validate future "
                       "connections to that address.")),
    cfg.BoolOpt('no_ssl_validation', default=False,
                help=_("Disables SSL certificate validation for controllers")),
    cfg.BoolOpt('cache_connections', default=True,
                help=_("Re-use HTTP/HTTPS connections to the controller.")),
    cfg.StrOpt('ssl_cert_directory',
               default='/etc/neutron/plugins/proxyagent/znic/ssl',
               help=_("Directory containing ca_certs and host_certs "
                      "certificate directories.")),
    cfg.BoolOpt('sync_data', default=False,
                help=_("Sync data on connect")),
    cfg.BoolOpt('auto_sync_on_failure', default=True,
                help=_("If neutron fails to create a resource because "
                       "the backend controller doesn't know of a dependency, "
                       "the plugin automatically triggers a full data "
                       "synchronization to the controller.")),
    cfg.IntOpt('consistency_interval', default=60,
               help=_("Time between verifications that the backend controller "
                      "database is consistent with Neutron")),
    cfg.IntOpt('server_timeout', default=10,
               help=_("Maximum number of seconds to wait for proxy request "
                      "to connect and complete.")),
    cfg.IntOpt('thread_pool_size', default=4,
               help=_("Maximum number of threads to spawn to handle large "
                      "volumes of port creations.")),
]


def get_rest_proxy_conf():
    conf_proxy = cfg.ConfigOpts()
    conf_proxy.register_opts(rest_proxy_opts, 'RESTPROXY')
    conf_proxy(args=[], default_config_files=['/etc/neutron/plugin.ini'])
    return conf_proxy


class PostZenicRestError(exceptions.NeutronException):
    message = _("The error occurred when posting to zenic: %(reason)s")

    def __init__(self, **kwargs):
        self.msg = self.message % kwargs


class ZenicQoSPlugin(QoSPlugin):
    def __init__(self):
        conf_proxy = get_rest_proxy_conf()
        if conf_proxy.RESTPROXY.servers is not '':
            self.servers = ZenicRestServerPool(
                conf_proxy.RESTPROXY.servers,
                conf_proxy.RESTPROXY.server_auth,
                conf_proxy.RESTPROXY.server_ssl,
                conf_proxy.RESTPROXY.no_ssl_validation,
                conf_proxy.RESTPROXY.ssl_sticky,
                conf_proxy.RESTPROXY.ssl_cert_directory,
                conf_proxy.RESTPROXY.consistency_interval,
                conf_proxy.RESTPROXY.server_timeout,
                conf_proxy.RESTPROXY.cache_connections,
                conf_proxy.RESTPROXY.base_url)
        super(ZenicQoSPlugin, self).__init__()

    def create_policy(self, context, policy):
        LOG.info(_("create_qos_policy1 policy= %s"), policy)
        policy = super(ZenicQoSPlugin, self).create_policy(context, policy)
        LOG.info(_("create_qos_policy2 policy= %s"), policy)
        try:
            self.servers.create_policy(context, policy)
        except BaseException:
            super(ZenicQoSPlugin, self).delete_policy(context, policy['id'])
            raise PostZenicRestError(reason="create qos policy!")
        return policy

    def update_policy(self, context, policy_id, policy):
        LOG.info(_("update_qos_policy policy=%s"), policy)
        try:
            self.servers.update_policy(context, policy_id, policy)
        except BaseException:
            raise PostZenicRestError(reason="update qos policy!")
        policy = super(ZenicQoSPlugin, self).update_policy(context, policy_id,
                                                           policy)
        return policy

    def delete_policy(self, context, policy_id):
        LOG.info(_("delete_qos_policy id = %s"), policy_id)
        try:
            self.servers.delete_policy(context, policy_id)
        except BaseException:
            raise PostZenicRestError(reason="delete qos policy!")
        super(ZenicQoSPlugin, self).delete_policy(context, policy_id)

    def create_policy_bandwidth_limit_rule(self, context, policy_id,
                                           bandwidth_limit_rule):
        LOG.info(_("create_policy_bandwidth_limit_rule1 rule= %s"),
                 bandwidth_limit_rule)
        rule_cls = rule_object.QosBandwidthLimitRule
        rule = super(ZenicQoSPlugin, self).create_policy_rule(
            context, rule_cls, policy_id, bandwidth_limit_rule)
        LOG.info(_("create_policy_bandwidth_limit_rule2 rule= %s"), rule)
        try:
            self.servers.create_policy_bandwidth_limit_rule(context,
                                                            policy_id, rule)
        except BaseException:
            super(ZenicQoSPlugin, self).delete_policy_rule(
                context, rule_cls, rule['id'], policy_id)
            raise PostZenicRestError(
                reason="create bandwidth limit rule of qos policy!")
        return rule

    def update_policy_bandwidth_limit_rule(self, context, rule_id, policy_id,
                                           bandwidth_limit_rule):
        LOG.info(_("update_policy_bandwidth_limit_rule rule=%s"),
                 bandwidth_limit_rule)
        try:
            self.servers.update_policy_bandwidth_limit_rule(
                context, rule_id, policy_id, bandwidth_limit_rule)
        except BaseException:
            raise PostZenicRestError(
                reason="update bandwidth limit rule of qos policy!")
        rule_cls = rule_object.QosBandwidthLimitRule
        rule = super(ZenicQoSPlugin, self).update_policy_rule(
            context, rule_cls, rule_id, policy_id, bandwidth_limit_rule)
        return rule

    def delete_policy_bandwidth_limit_rule(self, context, rule_id, policy_id):
        LOG.info(_("delete_policy_bandwidth_limit_rule rule_id = %(rule_id)s "
                 "policy_id = %(policy_id)s"), {'rule_id': rule_id,
                                                'policy_id': policy_id})
        try:
            self.servers.delete_policy_bandwidth_limit_rule(context, rule_id,
                                                            policy_id)
        except BaseException:
            raise PostZenicRestError(
                reason="delete bandwidth limit rule of qos policy!")
        rule_cls = rule_object.QosBandwidthLimitRule
        super(ZenicQoSPlugin, self).delete_policy_rule(
            context, rule_cls, rule_id, policy_id)

    def create_policy_dscp_marking_rule(self, context, policy_id,
                                        dscp_marking_rule):
        LOG.info(_("create_policy_dscp_marking_rule1 rule= %s"),
                dscp_marking_rule)
        rule_cls = rule_object.QosDscpMarkingRule
        rule = super(ZenicQoSPlugin, self).create_policy_rule(
            context, rule_cls, policy_id, dscp_marking_rule)
        LOG.info(_("create_policy_dscp_marking_rule2 rule= %s"), rule)
        try:
            self.servers.create_policy_dscp_marking_rule(context,
                                                     policy_id, rule)
        except BaseException:
            super(ZenicQoSPlugin, self).delete_policy_rule(
                context, rule_cls, rule['id'], policy_id)
            raise PostZenicRestError(
                reason="create dscp marking rule of qos policy!")
        return rule

    def update_policy_dscp_marking_rule(self, context, rule_id, policy_id,
                                    dscp_marking_rule):
        LOG.info(_("update_policy_dscp_marking_rule rule=%s"),
                dscp_marking_rule)
        try:
            self.servers.update_policy_dscp_marking_rule(
                context, rule_id, policy_id, dscp_marking_rule)
        except BaseException:
            raise PostZenicRestError(
                reason="update dscp marking rule of qos policy!")
        rule_cls = rule_object.QosDscpMarkingRule
        rule = super(ZenicQoSPlugin, self).update_policy_rule(
            context, rule_cls, rule_id, policy_id, dscp_marking_rule)
        return rule

    def delete_policy_dscp_marking_rule(self, context, rule_id, policy_id):
        LOG.info(_("delete_policy_dscp_marking_rule rule_id = %(rule_id)s "
                   "policy_id = %(policy_id)s"), {'rule_id': rule_id,
                                                  'policy_id': policy_id})
        try:
            self.servers.delete_policy_dscp_marking_rule(context, rule_id,
                                                        policy_id)
        except BaseException:
            raise PostZenicRestError(
                reason="delete dscp marking rule of qos policy!")
        rule_cls = rule_object.QosDscpMarkingRule
        super(ZenicQoSPlugin, self).delete_policy_rule(
            context, rule_cls, rule_id, policy_id)
