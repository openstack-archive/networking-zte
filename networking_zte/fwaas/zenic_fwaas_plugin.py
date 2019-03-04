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

from networking_zte.fwaas.zenic_firewall_pool import ZenicRestServerPool
try:
    from neutron_lib import exceptions
except Exception:
    from neutron.common import exceptions
from neutron.plugins.common import constants as const
from neutron_fwaas.services.firewall.fwaas_plugin import FirewallPlugin
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
    cfg.StrOpt('base_url', default='/restconf/operations/zenic-fwapp-model:',
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


class ZenicFirewallPlugin(FirewallPlugin):

    """Implementation of the Zenic Firewall Service Plugin.

    This class manages the workflow of FWaaS request/response.
    Most DB related works are implemented in class
    firewall_db.Firewall_db_mixin.
    """

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
        super(ZenicFirewallPlugin, self).__init__()

    def create_firewall(self, context, firewall):
        LOG.info(_("create_firewall firewall=%s"), firewall)
        fw = super(ZenicFirewallPlugin, self).create_firewall(
            context, firewall)
        LOG.info(_("create_firewall firewall=%s"), fw)
        try:
            self.servers.create_firewall(context, fw)
            self.set_firewall_status(context, fw['id'], const.ACTIVE)
        except BaseException:
            super(ZenicFirewallPlugin, self).delete_firewall(context,
                                                             fw['id'])
            raise PostZenicRestError(reason="create firewall!")
        return fw

    def update_firewall(self, context, id, firewall):
        LOG.info(_("update_firewall firewall=%s"), firewall)
        try:
            self.servers.update_firewall(context, id, firewall)
        except BaseException:
            raise PostZenicRestError(reason="update firewall!")
        fw = super(ZenicFirewallPlugin, self).update_firewall(
            context, id, firewall)
        self.set_firewall_status(context, id, const.ACTIVE)
        return fw

    def delete_firewall(self, context, id):
        LOG.info(_("delete_firewall id = %s"), id)
        try:
            self.servers.delete_firewall(context, id)
        except BaseException:
            raise PostZenicRestError(reason="delete firewall!")
        super(ZenicFirewallPlugin, self).delete_firewall(context, id)
        self.firewall_deleted(context, id)

    def create_firewall_policy(self, context, firewall_policy):
        LOG.info(_("create_firewall_policy firewall_policy=%s"),
                 firewall_policy)
        fwp = super(ZenicFirewallPlugin,
                    self).create_firewall_policy(context, firewall_policy)
        LOG.info(_("create_firewall_policy firewall_policy=%s"), fwp)
        try:
            self.servers.create_firewall_policy(context, fwp)
        except BaseException:
            super(ZenicFirewallPlugin,
                  self).delete_firewall_policy(context, fwp['id'])
            raise PostZenicRestError(reason="create firewall policy!")
        return fwp

    def update_firewall_policy(self, context, id, firewall_policy):
        LOG.info(_("update_firewall_policy firewall_policy=%s"),
                 firewall_policy)
        try:
            self.servers.update_firewall_policy(context, id, firewall_policy)
        except BaseException:
            raise PostZenicRestError(reason="update firewall policy!")
        fwp = super(ZenicFirewallPlugin,
                    self).update_firewall_policy(context, id, firewall_policy)
        self.update_policy_related_firewall_status(context, id, const.ACTIVE)
        return fwp

    def delete_firewall_policy(self, context, id):
        LOG.info(_("delete_firewall_policy id = %s"), id)
        try:
            self.servers.delete_firewall_policy(context, id)
        except BaseException:
            raise PostZenicRestError(reason="delete firewall policy!")
        super(ZenicFirewallPlugin, self).delete_firewall_policy(context, id)

    def create_firewall_rule(self, context, firewall_rule):
        LOG.info(_("create_firewall_policy firewall_rule=%s"), firewall_rule)
        fwr = super(ZenicFirewallPlugin,
                    self).create_firewall_rule(context, firewall_rule)
        LOG.info(_("create_firewall_policy firewall_rule=%s"), fwr)
        try:
            self.servers.create_firewall_rule(context, fwr)
        except BaseException:
            super(ZenicFirewallPlugin,
                  self).delete_firewall_rule(context, fwr['id'])
            raise PostZenicRestError(reason="create firewall rule!")
        return fwr

    def update_firewall_rule(self, context, id, firewall_rule):
        LOG.info(_("upate_firewall_rule firewall_rule=%s"), firewall_rule)
        try:
            self.servers.update_firewall_rule(context, id, firewall_rule)
        except BaseException:
            raise PostZenicRestError(reason="update firewall rule!")
        fwr = super(ZenicFirewallPlugin,
                    self).update_firewall_rule(context, id, firewall_rule)
        firewall_policy_id = fwr['firewall_policy_id']
        if firewall_policy_id:
            self.update_policy_related_firewall_status(
                context, firewall_policy_id, const.ACTIVE)
        return fwr

    def delete_firewall_rule(self, context, id):
        LOG.info(_("delete_firewall_rule id = %s"), id)
        try:
            self.servers.delete_firewall_rule(context, id)
        except BaseException:
            raise PostZenicRestError(reason="delete firewall policy!")
        super(ZenicFirewallPlugin, self).delete_firewall_rule(context, id)

    def insert_rule(self, context, id, rule_info):
        LOG.info(_("insert_rule rule_info=%s"), rule_info)
        try:
            self.servers.insert_rule(context, id, rule_info)
        except BaseException:
            raise PostZenicRestError(reason="insert rule!")
        fwp = super(ZenicFirewallPlugin,
                    self).insert_rule(context, id, rule_info)
        self.update_policy_related_firewall_status(context, id, const.ACTIVE)
        return fwp

    def remove_rule(self, context, id, rule_info):
        LOG.info(_("remove_rule rule_info=%s"), rule_info)
        try:
            self.servers.remove_rule(context, id, rule_info)
        except BaseException:
            raise PostZenicRestError(reason="remove rule!")
        fwp = super(ZenicFirewallPlugin,
                    self).remove_rule(context, id, rule_info)
        self.update_policy_related_firewall_status(context, id, const.ACTIVE)
        return fwp

    def set_firewall_status(self, context, firewall_id, status):
        """uses this to set a firewall's status."""
        LOG.debug("set_firewall_status() called")
        with context.session.begin(subtransactions=True):
            fw_db = self._get_firewall(context, firewall_id)
            # ignore changing status if firewall expects to be deleted
            # That case means that while some pending operation has been
            # performed on the backend, neutron server received delete request
            # and changed firewall status to const.PENDING_DELETE
            if fw_db.status == const.PENDING_DELETE:
                LOG.debug("Firewall %(fw_id)s in PENDING_DELETE state, "
                          "not changing to %(status)s",
                          {'fw_id': firewall_id, 'status': status})
                return False
            if status in (const.ACTIVE, const.DOWN, const.INACTIVE):
                fw_db.status = status
                return True
            else:
                fw_db.status = const.ERROR
                return False

    def firewall_deleted(self, context, firewall_id):
        """Agent uses this to indicate firewall is deleted."""
        LOG.debug("firewall_deleted() called")
        with context.session.begin(subtransactions=True):
            fw_db = self._get_firewall(context, firewall_id)
            # allow to delete firewalls in ERROR state
            if fw_db.status in (const.PENDING_DELETE, const.ERROR):
                self.delete_db_firewall_object(context, firewall_id)
                return True
            else:
                LOG.warn(_('Firewall %(fw)s unexpectedly deleted by agent, '
                           'status was %(status)s'),
                         {'fw': firewall_id, 'status': fw_db.status})
                fw_db.status = const.ERROR
                return False

    def update_policy_related_firewall_status(
            self, context, firewall_policy_id, status):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                self.set_firewall_status(context, firewall_id, status)
