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
#


"""
This module manages configuration options
"""

from oslo_config import cfg
try:
    from neutron.agent.common import config as agconfig
except Exception:
    from neutron.conf.agent import common as agconfig

try:
    from neutron_lib.utils import net as utils
except Exception:
    from neutron.common import utils
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
                      "to the ml2-plugin")),
    cfg.StrOpt('enable_qos', default="False",
               help=_("Flag to decide if plugin use qos function")),
    cfg.StrOpt('enable_M_qos', default="False",
               help=_("Flag to decide if plugin use M version qos function")),
    cfg.StrOpt('enable_bandwidth', default="False",
               help=_("Flag to decide if plugin use bandwidth function")),
    cfg.StrOpt('enable_pre_commit', default="False",
               help=_("Flag to decide if using pre_commit")),
    cfg.IntOpt('flat_segment_id', default=1000001,
               help=_("Set the only flat network segmentation id for "
                      "zenic controller.")),
    cfg.StrOpt('enable_hierarchical_port', default="False",
               help=_("Flag to decide if using hierarchical port")),
    cfg.StrOpt('vlan_transparent', default="True",
               help=_("Flag to decide if plugin use vlan_transparent "
                      "function.")),
]


def register_config():
    cfg.CONF.register_opts(rest_proxy_opts, "RESTPROXY")
    agconfig.register_root_helper(cfg.CONF)
