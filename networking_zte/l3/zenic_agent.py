# Copyright 2017 ZTE, Inc.
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
#


from networking_zte.common import servermanager
from networking_zte.utils import cmcc_util
try:
    from neutron.agent.common import config as config
except Exception:
    from neutron.conf.agent import common as config
try:
    from neutron.agent.l3 import config as l3_config
    from neutron.agent.l3 import ha
except Exception:
    from neutron.conf.agent.l3 import config as l3_config
    from neutron.conf.agent.l3 import ha as ha_conf
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import iptables_manager
try:
    from neutron.agent.metadata import config as metadata_config
except Exception:
    from neutron.conf.agent.metadata import config as metadata_config
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
try:
    from neutron_lib import constants as l3_constants
except Exception:
    from neutron.common import constants as l3_constants
from neutron.common import eventlet_utils
from neutron.common import rpc as n_rpc
from neutron.common import topics
try:
    from neutron_lib.utils import net as utils
except Exception:
    from neutron.common import utils

try:
    from neutron import context as context
except Exception:
    from neutron_lib import context as context
from neutron import manager
try:
    from neutron.openstack.common import loopingcall
    from neutron.openstack.common import service
except Exception:
    from neutron.agent.linux import pd
    from neutron.agent.linux import ra
    from oslo_service import loopingcall
    from oslo_service import service
try:
    from neutron import context as qcontext
except Exception:
    from neutron_lib import context as qcontext
try:
    from neutron.db.models import l3 as l3_db
except Exception:
    from neutron.db import l3_db
from neutron import service as neutron_service
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
import sys
import time


eventlet_utils.monkey_patch()


# NS_PREFIX = namespaces.NS_PREFIX
# INTERNAL_DEV_PREFIX = namespaces.INTERNAL_DEV_PREFIX
# EXTERNAL_DEV_PREFIX = namespaces.EXTERNAL_DEV_PREFIX
# LOG = LOG.getLogger(__name__)
# NS_PREFIX = 'qrouter-'
# INTERNAL_DEV_PREFIX = 'qr-'
# EXTERNAL_DEV_PREFIX = 'qg-'
# RPC_LOOP_INTERVAL = 1
# FLOATING_IP_CIDR_SUFFIX = '/32'
#
# SUBNET  = 'subnet'
# PORT    = 'port'
# ROUTER  = 'router'
# FLOATING_IP = 'floating-ip'
# VXLAN_TUNNEL = 'vxlan-tunnel'
# SECURITY_GROUP = 'sg'
# SECURITY_GROUP_RULE = 'sg-rule'
# CLASSIFIER = 'classifier'

SUCCESS_CODES = range(200, 207)
FAILURE_CODES = [400, 401, 404, 409]

# Number of routers to fetch from server at a time on resync.
# Needed to reduce load on server side and to speed up resync on agent side.
SYNC_ROUTERS_MAX_CHUNK_SIZE = 16

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
    cfg.StrOpt('neutron_id', default='neutron-' + utils.get_hostname(),
               deprecated_name='quantum_id',
               help=_("User defined identifier for this Neutron deployment")),
    cfg.BoolOpt('add_meta_server_route', default=True,
               help=_("Flag to decide if a route to the metadata server "
                      "should be injected into the VM")),
    cfg.StrOpt('zenic_version', default="50.1",
               help=_("Version number of the zenic controller corresponding "
                      "to the zenic agent")),
    cfg.StrOpt('up_gw_status', default="True",
               help=_("up gwport status bind to router")),
    cfg.StrOpt('op_version', default="",
               help=_("Version number of the zenic plugins")),
    cfg.StrOpt('sync_router', default="False",
               help=_("Flag to decide if plugin use sync router function")),
]

LOG = logging.getLogger(__name__)


class ZenicPluginApi(agent_rpc.PluginApi):
    pass


class ZenicL3RestServerPool(servermanager.ServerPool):
    """Zenic L3 Rest Server Pool for Zenic L3 Agent.

    This server pool has the router and floatingip operations
    of create, update and delete, to the Zenic Controller.
    """

    def __init__(
            self,
            servers,
            auth,
            zenic_version,
            ssl,
            no_ssl_validation,
            ssl_sticky,
            ssl_cert_directory,
            consistency_interval,
            timeout=False,
            cache_connections=True,
            base_uri='/restconf/operations/zenic-vdcapp-model:',
            op_version="",
            success_codes=SUCCESS_CODES,
            failure_codes=FAILURE_CODES,
            name='ZenicL3RestProxy'):
        super(
            ZenicL3RestServerPool,
            self).__init__(
            servers,
            auth,
            ssl,
            no_ssl_validation,
            ssl_sticky,
            ssl_cert_directory,
            consistency_interval,
            timeout,
            cache_connections,
            base_uri,
            success_codes,
            failure_codes,
            name)
        version = zenic_version.split('.')
        version = version[0] + version[1]
        LOG.debug(_("zenic_version = %s"), version)
        if (version.isdigit() is False) or (int(version) < 403):
            LOG.error(_("zenic_version error!zenic_version = %s"), version)
        self.zenic_version = int(version)
        self.floating_status = {}
        self.op_version = op_version
        self.cmcc = cmcc_util.CmccUtil()

    @staticmethod
    def validate_dict(instance, key, default_val):
        return instance[key] if (key in instance and
                                 instance[key]) else default_val

    def construct_router_rest_msg(self, router_info, action):
        # LOG.info(_('construct_router_info r_info:{0}'.format(router_info)))
        if action == 'DELETE' or action == 'GET':
            router_rest_data = {"input": {"id": router_info}}
            return router_rest_data
        else:
            internal_interfaces = router_info.get('_interfaces', set())
            internal_interfaces_subnets = list()
            if internal_interfaces:
                internal_interfaces_subnets =\
                    [intf['subnets'] for intf in internal_interfaces]
                LOG.debug("subnets:%s", internal_interfaces_subnets)
                for subnet in internal_interfaces_subnets:
                    LOG.debug('subnet:%s', subnet)
            routes_injects = router_info.get('routes', set())
            LOG.debug('internal_interfaces:{0}'.format(internal_interfaces))
            real_gw_port = router_info.get('gw_port_id', '')
            if not real_gw_port:
                real_gw_port = ''
            real_gw_port = self.cmcc.filter_gw_port(
                self.op_version, router=router_info, gw_port=real_gw_port)
            d = []
            for c in internal_interfaces_subnets:
                a = [subnet['id'] for subnet in c]
                for i in a:
                    d.append(i)
            b = [router_inject for router_inject in routes_injects]
            router_rest_data =\
                {"input": {"id": router_info['id'],
                           "name": router_info['name'],
                           "admin_state_up": router_info['admin_state_up'],
                           "tenant_id": router_info['tenant_id'],
                           "ext-gw-port": real_gw_port,
                           "enable_snat": router_info.get('enable_snat', True),
                           "router-interfaces": d,
                           "routes": b}
                 }

            if self.zenic_version > 403:
                if '_floatingips' in router_info:
                    routes_floatingips = router_info.get('_floatingips', set())
                    floating_ip = []
                    for routes_floatingip in routes_floatingips:
                        if 'host' in routes_floatingip:
                            del routes_floatingip['host']
                        if 'description' in routes_floatingip:
                            del routes_floatingip['description']
                        if 'dns_name' in routes_floatingip:
                            del routes_floatingip['dns_name']
                        if 'created_at' in routes_floatingip:
                            del routes_floatingip['created_at']
                        if 'updated_at' in routes_floatingip:
                            del routes_floatingip['updated_at']
                        if 'dns_domain' in routes_floatingip:
                            del routes_floatingip['dns_domain']
                        if 'revision_number' in routes_floatingip:
                            del routes_floatingip['revision_number']
                        if 'fixed_ip_address_scope' in routes_floatingip:
                            del routes_floatingip['fixed_ip_address_scope']
                        if 'project_id' in routes_floatingip:
                            del routes_floatingip['project_id']
                        if 'floating_port_id' in routes_floatingip:
                            del routes_floatingip['floating_port_id']
                        routes_floatingip['status'] = \
                            l3_constants.FLOATINGIP_STATUS_ACTIVE
                        floating_ip.append(routes_floatingip)
                        if router_info['id'] not in self.floating_status:
                            self.floating_status[router_info['id']] = {
                                routes_floatingip['id']:
                                l3_constants.FLOATINGIP_STATUS_ACTIVE}
                        else:
                            status = self.floating_status[router_info['id']]
                            status[routes_floatingip['id']] = \
                                l3_constants.FLOATINGIP_STATUS_ACTIVE
                    input = router_rest_data['input']
                    input["floating-ips"] = floating_ip
                else:
                    input = router_rest_data['input']
                    input["floating-ips"] = []
        rest_info = '\n'
        for k, v in router_rest_data['input'].items():
            rest_info += '{0} is {1}\n'.format(k, v)
            rest_info += '{0} is {1}\n'.format(k, v)
        LOG.debug('rest_router_data:{0}'.format(rest_info))
        return router_rest_data

    def rest_update_router(self, router_info):
        data = self.construct_router_rest_msg(router_info, 'ADD')
        resource = 'update-router'
        err_str = "Unable to create remote router: %s"
        resp = self.rest_action('POST', resource, data, err_str)
        if resp[0] == 0:
            return False
        return True

    def rest_delete_router(self, router_id):
        LOG.debug('While deleting,'
                  'construct_router_info router_id:{0}'.format(router_id))
        data = self.construct_router_rest_msg(router_id, 'DELETE')
        resource = 'del-router'
        err_str = "Unable to delete remote router: %s"
        resp = self.rest_action('POST', resource, data, err_str)
        if resp[0] == 0:
            return False
        return True

    @staticmethod
    def construct_all_routers_rest_msg(router_info):
        router_rest_data = {
            "input": {
                "router-list": list(router_info)}
        }
        return router_rest_data

    def rest_all_router_ids(self, all_router_ids):
        LOG.info(_('While rest_all_router_ids, '
                   'construct_router_info %s'), all_router_ids)
        data = self.construct_all_routers_rest_msg(all_router_ids)
        resource = 'sync-router-info'
        err_str = "Unable to rest_all_router_ids: %s"
        self.rest_action('POST', resource, data, err_str)
        return True


class L3PluginApi(object):
    """Agent side of the l3 agent RPC API.

    API version history:
        1.0 - Initial version.
        1.1 - Floating IP operational status updates

    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_routers(self, context, router_ids=None):
        """Make a remote process call to retrieve the sync data for routers."""
        cctxt = self.client.prepare()
        return cctxt.call(context, 'sync_routers', host=self.host,
                          router_ids=router_ids)

    def get_service_plugin_list(self, context):
        """Make a call to get the list of activated services."""
        cctxt = self.client.prepare(version='1.3')
        return cctxt.call(context, 'get_service_plugin_list')

    def update_floatingip_statuses(self, context, router_id, fip_statuses):
        """Call the plugin update floating IPs's operational status."""
        cctxt = self.client.prepare(version='1.1')
        return cctxt.call(context, 'update_floatingip_statuses',
                          router_id=router_id, fip_statuses=fip_statuses)


class RouterInfo(object):

    def __init__(self, router_id, root_helper, router):
        self.router_id = router_id
        self.ex_gw_port = None
        self._snat_enabled = None
        self._snat_action = None
        self.internal_ports = []
        self.root_helper = root_helper
        # Invoke the setter for establishing initial SNAT action
        self.router = router
        self.ns_name = None
        self.iptables_manager = iptables_manager.IptablesManager(
            root_helper=root_helper,
            # FIXME(danwent): use_ipv6=True,
            namespace=self.ns_name)
        self.routes = []

    @property
    def router(self):
        return self._router

    @router.setter
    def router(self, value):
        self._router = value
        if not self._router:
            return
        # enable_snat by default if it wasn't specified by plugin
        self._snat_enabled = self._router.get('enable_snat', True)
        # Set a SNAT action for the router
        if self._router.get('gw_port'):
            self._snat_action = ('add_rules' if self._snat_enabled
                                 else 'remove_rules')
        elif self.ex_gw_port:
            # Gateway port was removed, remove rules
            self._snat_action = 'remove_rules'


def get_rest_proxy_conf():
    conf_proxy = cfg.ConfigOpts()
    conf_proxy.register_opts(rest_proxy_opts, 'RESTPROXY')
    conf_proxy(args=[], default_config_files=['/etc/neutron/plugin.ini'])
    return conf_proxy


def register_opts(conf):
    conf.register_opts(l3_config.OPTS)
    conf.register_opts(metadata_config.SHARED_OPTS)
    try:
        conf.register_opts(ha.OPTS)
    except Exception:
        ha_conf.register_l3_agent_ha_opts(conf)
    config.register_interface_driver_opts_helper(conf)
    config.register_agent_state_opts_helper(conf)
    conf.register_opts(interface.OPTS)
    conf.register_opts(external_process.OPTS)
    try:
        config.register_use_namespaces_opts_helper(conf)
    except Exception:
        conf.register_opts(pd.OPTS)
        conf.register_opts(ra.OPTS)
        config.register_availability_zone_opts_helper(conf)


class ZenicAgent(manager.Manager):
    """Manager for L3NatAgent

        API version history:
        1.0 initial Version
        1.1 changed the type of the routers parameter
            to the routers_updated method.
            It was previously a list of routers in dict format.
            It is now a list of router IDs only.
            Per rpc versioning rules,  it is backwards compatible.
    """
    RPC_API_VERSION = '1.1'

    OPTS = [
        cfg.StrOpt('external_network_bridge', default='br-ex',
                   help=_("Name of bridge used for external network "
                          "traffic.")),
        cfg.IntOpt('metadata_port',
                   default=9697,
                   help=_("TCP Port used by Neutron metadata namespace "
                          "proxy.")),
        cfg.IntOpt('send_arp_for_ha',
                   default=0,
                   help=_("Send this many gratuitous ARPs for HA setup, if "
                          "less than or equal to 0, the feature is disabled")),
        cfg.StrOpt('router_id', default='',
                   help=_("If namespaces is disabled, the l3 agent can only"
                          " configure a router that has the matching router "
                          "ID.")),
        cfg.BoolOpt('handle_internal_only_routers',
                    default=True,
                    help=_("Agent should implement routers with no gateway")),
        cfg.StrOpt('gateway_external_network_id', default='',
                   help=_("UUID of external network for routers implemented "
                          "by the agents.")),
        cfg.BoolOpt('enable_metadata_proxy', default=True,
                    help=_("Allow running metadata proxy.")),
        cfg.BoolOpt('router_delete_namespaces', default=False,
                    help=_("Delete namespace after removing a router.")),
        cfg.StrOpt('metadata_proxy_socket',
                   default='$state_path/metadata_proxy',
                   help=_('Location of Metadata Proxy UNIX domain '
                          'socket')),
    ]
    target = oslo_messaging.Target(version='1.2')

    def __init__(self, host, conf=None):
        if conf:
            self.conf = conf
        else:
            self.conf = cfg.CONF
        self.root_helper = config.get_root_helper(self.conf)
        self.router_info = {}
        self.context = context.get_admin_context_without_session()
        self.plugin_rpc = L3PluginApi(topics.L3PLUGIN, host)
        self.fullsync = True
        self.updated_routers = set()
        self.removed_routers = set()
        self.sync_progress = False
        self.servers = None
        self.fail_update_rest_router_id = set()
        self.fail_delete_rest_router_id = set()
        conf_proxy = get_rest_proxy_conf()
        self.whole_syncing_not_succ_yet = False
        self.sync_protect_tick = 0
        self.agent_id = 'zenic-agent-%s' % self.conf.host
        self.zenic_rpc = ZenicPluginApi(topics.PLUGIN)
        self.up_gw_status = conf_proxy.RESTPROXY.up_gw_status
        self.sync_router = conf_proxy.RESTPROXY.sync_router
        if conf_proxy.RESTPROXY.servers is not '':
            self.servers = ZenicL3RestServerPool(
                conf_proxy.RESTPROXY.servers,
                conf_proxy.RESTPROXY.server_auth,
                conf_proxy.RESTPROXY.zenic_version,
                conf_proxy.RESTPROXY.server_ssl,
                conf_proxy.RESTPROXY.no_ssl_validation,
                conf_proxy.RESTPROXY.ssl_sticky,
                conf_proxy.RESTPROXY.ssl_cert_directory,
                conf_proxy.RESTPROXY.consistency_interval,
                conf_proxy.RESTPROXY.server_timeout,
                conf_proxy.RESTPROXY.cache_connections,
                conf_proxy.RESTPROXY.base_url,
                conf_proxy.RESTPROXY.op_version)
        # self.rpc_loop = loopingcall.FixedIntervalLoopingCall(
        #     self._rpc_loop)
        # self.rpc_loop.start(interval=RPC_LOOP_INTERVAL)
        super(ZenicAgent, self).__init__(host=host)
        self.target_ex_net_id = None
        self.sync_routers_chunk_size = SYNC_ROUTERS_MAX_CHUNK_SIZE

    def router_deleted(self, context, router_id):
        """Deal with router deletion RPC message."""
        LOG.info(_('zenic_agent Got router deleted notification for %s'),
                 router_id)
        try:
            with lockutils.lock("zenic_agent_remove_router"):
                LOG.debug('router_deleted Got remove mutex')
                self.removed_routers.add(router_id)
        except Exception as e:
            LOG.debug("lockutils, except:%s", str(e))

    def routers_updated(self, context, routers):
        """Deal with routers modification and creation RPC message."""
        LOG.info(_(' zenic_agent Got routers updated notification :%s'),
                 routers)
        if routers:
            # This is needed for backward compatibility
            if isinstance(routers[0], dict):
                routers = [router['id'] for router in routers]
            try:
                with lockutils.lock("zenic_agent_update_router"):
                    LOG.info(_('routers_updated Got update mutex'))
                    self.updated_routers.update(routers)
            except Exception as e:
                LOG.debug("lockutils, except:%s", str(e))

    def router_added_to_agent(self, context, payload):
        pass

    def _process_update_rest_fail_routers(self, routers):
        for r in routers:
            if self.servers:
                if self.servers.rest_update_router(r):
                    self.fail_update_rest_router_id.discard(r['id'])

    def _sync_all_valid_routers(self, routers):
        # pool = eventlet.GreenPool()
        return self.servers.rest_all_router_ids(routers)

    def _process_routers(self, routers):
        # pool = eventlet.GreenPool()
        for r in routers:
            if self.servers:
                if not self.servers.rest_update_router(r):
                    self.fail_update_rest_router_id.add(r['id'])
                else:
                    internal_interfaces = r.get('_interfaces', set())
                    internal_interfaces_devices = list()
                    if internal_interfaces:
                        internal_interfaces_devices = \
                            [intf['mac_address']
                             for intf in internal_interfaces]
                    for device in internal_interfaces_devices:
                        LOG.info(_('up router internal %s status'), device)
                        self.zenic_rpc.update_device_up(
                            self.context,
                            device,
                            self.agent_id,
                            self.conf.host)
                    if self.up_gw_status == "True":
                        if r.get('gw_port_id'):
                            device = r.get('gw_port')['mac_address']
                            LOG.info(_('up router gw %s status'), device)
                            self.zenic_rpc.update_device_up(
                                self.context,
                                device,
                                self.agent_id,
                                self.conf.host)
                    if r['id'] in self.servers.floating_status:
                        LOG.debug(_('update floatingip_statuses: %s'),
                                  self.servers.floating_status[r['id']])
                        self.plugin_rpc.update_floatingip_statuses(
                            self.context,
                            r['id'],
                            self.servers.floating_status[r['id']])
                        self.servers.floating_status[r['id']] = {}
                        if '_floatingips' not in r:
                            del self.servers.floating_status[r['id']]

    @staticmethod
    def get_all_router_ids(context):
        query = context.session.query(l3_db.Router.id)
        return [item[0] for item in query]

    def _sync_all_router_restconf(self, context):
        admin_context = qcontext.get_admin_context()
        routers = self.get_all_router_ids(admin_context)
        LOG.info(_('zenic_agent, starting, get_all_routers:%s'), routers)
        routers = set(router for router in routers)
        self.updated_routers.update(routers)
        now_valid_routers = routers & self.fail_delete_rest_router_id
        self.fail_delete_rest_router_id =\
            self.fail_delete_rest_router_id - now_valid_routers
        if self._sync_all_valid_routers(routers):
            LOG.debug('zenic_agent,  now_routers:{0}'.format(routers))
            self.whole_syncing_not_succ_yet = True

    def _process_routers_loop(self):
        LOG.debug("Starting _process_routers_loop")
        if not self.whole_syncing_not_succ_yet:
            if self.sync_router == "True":
                self._sync_all_router_restconf(self.context)
        while True:
            self._process_router_update()

    def after_start(self):
        LOG.info(_("zenic agent started"))
        self._process_routers_loop()
        # When L3 agent is ready, we immediately do a full sync
        # self.periodic_sync_routers_task(self.context)

    # @lockutils.synchronized('zenic-agent', 'neutron-')
    def _process_router_update(self):
        # _rpc_loop and _sync_routers_task will not be
        # executed in the same time because of lock.
        # so we can clear the value of updated_routers
        # and removed_routers
        self.sync_protect_tick += 1
        time.sleep(0.01)
        try:
            if self.updated_routers:
                LOG.info(_("zenic Starting RPC loop for %d updated routers"),
                         len(self.updated_routers))
                try:
                    with lockutils.lock("zenic_agent_update_router"):
                        LOG.info(_('_process_router_update Got update mutex'))
                        now_processed = list(self.updated_routers)
                        router_ids = list(self.updated_routers)
                        self.updated_routers.clear()
                except Exception as e:
                    LOG.error(_("lockutils, except:%s"), str(e))

                # fetch routers by chunks to reduce the load on server and to
                # start router processing earlier
                for i in range(
                        0,
                        len(router_ids),
                        self.sync_routers_chunk_size):
                    try:
                        now_processed_feched = now_processed[i:i +
                            self.sync_routers_chunk_size]
                        time_start_get_router = time.time()
                        routers = self.plugin_rpc.get_routers(
                            self.context,
                            router_ids[i:i + self.sync_routers_chunk_size])
                    except oslo_messaging.MessagingTimeout:
                        try:
                            time.sleep(5)
                            routers = self.plugin_rpc.get_routers(
                                self.context,
                                router_ids[i:i + self.sync_routers_chunk_size])
                        except oslo_messaging.MessagingTimeout:
                            LOG.error(_(
                                "Second time out error!!!,router_ids:%s"),
                                router_ids)
                            continue

                    LOG.debug('Processing routers: %r', routers)
                    fetched = set([r['id'] for r in routers])
                    try:
                        with lockutils.lock("zenic_agent_remove_router"):
                            self.removed_routers.update(
                                set(now_processed_feched) - fetched)
                    except Exception as e:
                        LOG.error(_("lockutils, except:%s"), str(e))

                    time_start_proc_router = time.time()
                    self._process_routers(routers)
                    LOG.info(_(
                        "Zenic ended _process_routers %(num)d routers, "
                        "get time: %(time)s, proc time: %(time2)s"),
                        {'num': len(fetched), 'time':
                            time_start_proc_router - time_start_get_router,
                            'time2': time.time() -
                            time_start_proc_router})
            self._process_router_delete()
        except Exception as e:
            LOG.exception(_("Failed synchronizing routers: %s"), str(e))
            self.fullsync = True

    def _process_router_delete(self):
        current_removed_routers = list(self.removed_routers)
        for router_id in current_removed_routers:
            self.removed_routers.remove(router_id)
            if self.servers:
                if not self.servers.rest_delete_router(router_id):
                    self.fail_delete_rest_router_id.add(router_id)

    def _router_ids(self):
        return [self.conf.router_id]


class ZenicAgentWithStateReport(ZenicAgent):

    def __init__(self, host, conf=None):
        super(ZenicAgentWithStateReport, self).__init__(host=host, conf=conf)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        self.agent_state = {
            'binary': 'neutron_zenic_agent',
            'host': host,
            'topic': topics.L3_AGENT,
            'configurations': {'agent_mode': self.conf.agent_mode, },
            'start_flag': True,
            'agent_type': 'L3 agent'}
        self.use_call = True
        self.heartbeat = loopingcall.FixedIntervalLoopingCall(
            self._report_state)
        self.heartbeat.start(30)

    def _report_state(self):
        LOG.debug("Report state task started")
        # configurations = self.agent_state['configurations']
        try:
            self.state_rpc.report_state(self.context, self.agent_state,
                                        self.use_call)
            self.agent_state.pop('start_flag', None)
            self.use_call = False
            LOG.debug("Report state task successfully completed")
        except AttributeError:
            # This means the server does not support report_state
            LOG.warn("Neutron server does not support state report."
                     "State report for this agent will be disabled.")
            self.heartbeat.stop()
            return
        except Exception:
            LOG.exception("Failed reporting state!")

    def agent_updated(self, context, payload):
        """Handle the agent_updated notification event."""
        self.fullsync = True
        LOG.info(_("agent_updated by server side %s!"), payload)


def main(manager='networking_zte.l3.zenic_agent.ZenicAgentWithStateReport'):
    register_opts(cfg.CONF)
    common_config.init(sys.argv[1:])
    config.setup_logging()
    server = neutron_service.Service.create(
        binary='neutron-zenic-agent',
        topic=topics.L3_AGENT,
        report_interval=cfg.CONF.AGENT.report_interval,
        manager=manager)
    try:
        service.launch(server).wait()
    except Exception:
        service.launch(cfg.CONF, server).wait()
