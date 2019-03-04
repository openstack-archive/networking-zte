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

from networking_zte.ml2.common.rest.ml2_zenic \
    import config as pl_config
from networking_zte.ml2.common.rest.ml2_zenic \
    import ml2_zenic_restconf as restconf
from oslo_log import log


LOG = log.getLogger(__name__)


class ZenicL2Driver(object):
    """Mechanism Driver for Zenic Networks Controller.

    This driver relays the network create, update, delete
    operations to the Zenic Controller.
    """

    def __init__(self):
        LOG.debug(_('Initializing zte zenic ml2 driver...'))
        # register plugin config opts
        pl_config.register_config()
        # backend doesn't support bulk operations yet
        self.native_bulk_support = False
        # init network ctrl connections
        self.servers = restconf.ZenicServerPool(
            pl_config.cfg.CONF.RESTPROXY.servers,
            pl_config.cfg.CONF.RESTPROXY.server_auth,
            pl_config.cfg.CONF.RESTPROXY.zenic_version,
            pl_config.cfg.CONF.RESTPROXY.enable_qos,
            pl_config.cfg.CONF.RESTPROXY.server_ssl,
            pl_config.cfg.CONF.RESTPROXY.no_ssl_validation,
            pl_config.cfg.CONF.RESTPROXY.ssl_sticky,
            pl_config.cfg.CONF.RESTPROXY.ssl_cert_directory,
            pl_config.cfg.CONF.RESTPROXY.consistency_interval,
            pl_config.cfg.CONF.RESTPROXY.server_timeout,
            pl_config.cfg.CONF.RESTPROXY.cache_connections)
        LOG.debug(_("Initialize zte zenic ml2 driver is done!"))

    def set_enable_security_group(self, en_security_group):
        self.servers.set_enable_security_group(en_security_group)

    def create_network(self, mech_context):
        # create network on the network controller
        self.servers.rest_create_network(mech_context)

    def update_network(self, mech_context):
        # update network on the network controller
        self.servers.rest_update_network(mech_context)

    def delete_network(self, mech_context):
        # delete network on the network controller
        self.servers.rest_delete_network(mech_context)

    def create_subnet(self, mech_context):
        # create subnet on the network controller
        self.servers.rest_create_subnet(mech_context)

    def update_subnet(self, mech_context):
        # update subnet on the network controller
        self.servers.rest_update_subnet(mech_context)

    def delete_subnet(self, mech_context):
        # delete subnet on the network controller
        self.servers.rest_delete_subnet(mech_context)

    def create_port(self, mech_context):
        # create port on the network controller
        self.servers.rest_create_port(mech_context)

    def update_port(self, mech_context):
        # update port on the network controller
        self.servers.rest_update_port(mech_context)

    def delete_port(self, mech_context):
        # delete port on the network controller
        self.servers.rest_delete_port(mech_context)

    def create_security_group(self, mech_context):
        # create security group on the network controller
        self.servers.rest_create_security_group(mech_context)

    def update_security_group(self, mech_context):
        # update security group on the network controller
        self.servers.rest_update_security_group(mech_context)

    def delete_security_group(self, mech_context):
        # delete security group on the network controller
        self.servers.rest_delete_security_group(mech_context)

    def create_security_group_rule(self, mech_context):
        # create securitygroup rule on the network controller
        self.servers.rest_create_security_group_rule(mech_context)

    def update_security_group_rule(self, mech_context):
        # update securitygroup rule on the network controller
        self.servers.rest_update_security_group_rule(mech_context)

    def delete_security_group_rule(self, mech_context):
        # delete securitygroup rule on the network controller
        self.servers.rest_delete_security_group_rule(mech_context)

    def create_qos_policy(self, mech_context):
        self.servers.rest_create_qos_policy(mech_context)

    def update_qos_policy(self, mech_context):
        self.servers.rest_update_qos_policy(mech_context)

    def delete_qos_policy(self, mech_context):
        self.servers.rest_delete_qos_policy(mech_context)

    def create_qos_bandwidth_limit_rule(self, mech_context):
        self.servers.rest_create_qos_bandwidth_limit_rule(mech_context)

    def update_qos_bandwidth_limit_rule(self, mech_context):
        self.servers.rest_update_qos_bandwidth_limit_rule(mech_context)

    def delete_qos_bandwidth_limit_rule(self, mech_context):
        self.servers.rest_delete_qos_bandwidth_limit_rule(mech_context)
