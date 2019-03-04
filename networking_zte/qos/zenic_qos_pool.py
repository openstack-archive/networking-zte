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

from networking_zte.common import servermanager
from neutron.db import common_db_mixin as base_db
from oslo_log import log

LOG = log.getLogger(__name__)

# The following are used to invoke the API on the external controller

QOS_POLICY = 'qos-policy'
QOS_BANDWIDTH_RULE = 'qos-bandwidth-limit-rule'
QOS_DSCP_RULE = 'qos-dscp-marking-rule'
BASE_URI = '/restconf/operations/zenic-vdcapp-model:'
SUCCESS_CODES = range(200, 207)
FAILURE_CODES = [0, 9, 301, 302, 303, 400, 401, 403, 404, 409, 500, 501, 502,
                 503, 504, 505]


class ZenicRestServerPool(servermanager.ServerPool,
                          base_db.CommonDbMixin):
    """ZenicRestServerPool for qos plugin.
    This server pool has qos_policy and qos_bandwidth operations
    of create, update and delete, to the Zenic Controller.
    """

    def __init__(self, servers, auth, ssl, no_ssl_validation, ssl_sticky,
                 ssl_cert_directory, consistency_interval, timeout=False,
                 cache_connections=True, base_uri=BASE_URI,
                 success_codes=SUCCESS_CODES,
                 failure_codes=FAILURE_CODES, name='ZenicRestProxy'):
        super(ZenicRestServerPool, self).__init__(
            servers, auth, ssl, no_ssl_validation, ssl_sticky,
            ssl_cert_directory, consistency_interval, timeout,
            cache_connections, base_uri, success_codes, failure_codes, name)

    @staticmethod
    def construct_qos_policy_info(context, id, qos_policy, action):
        """
        #    {u'policy': {
        #               'shared': False,
        #               'tenant_id': u'c414cf57e9fc49efb8e3e0c8d4e41b33',
        #                u'name': u'qos-policy',
        #               'description': '',
        #               'rules':[],
        #               'id' :'5720800f-dece-4c9a-93d4-5dc3ef94ccb7'}}
        """
        if action == 'UPDATE':
            qos_policy = qos_policy['policy']
        qos_policy_info = {
            "input": {
                "id": id if (id != 0) else qos_policy['id'],
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
    def construct_bandwidth_limit_rule_info(context, rule_id, policy_id,
                                            bandwidth_limit_rule, action):
        """
        # {u'bandwidth_limit_rule': {
        #              u'max_kbps': u'300',
        #              u'max_burst_kbps': u'30',
        #              'tenant_id': u'c414cf57e9fc49efb8e3e0c8d4e41b33',
        #              'id' :'aa1e84d8-9ea3-45ec-8197-83b7d9abc647'}}
        """
        LOG.info(_("rule_id = %(rule_id)s,policy_id = %(policy_id)s,"
                   "bandwith= %(bandwidth_limit_rule)s"),
                 {'rule_id': rule_id,
                  'policy_id': policy_id,
                  'bandwidth_limit_rule': bandwidth_limit_rule})
        if action == 'UPDATE':
            bandwidth_limit_rule = bandwidth_limit_rule['bandwidth_limit_rule']
        bandwidth_rule_info = {
            "input": {
                "id": rule_id if (rule_id != 0) else
                bandwidth_limit_rule['id'],
                "qos_policy_id": policy_id if (policy_id != 0)
                else bandwidth_limit_rule['policy_id'],
            }
        }
        input = bandwidth_rule_info['input']
        if 'max_kbps' in bandwidth_limit_rule:
            input['max_kbps'] = bandwidth_limit_rule['max_kbps']
        if 'max_burst_kbps' in bandwidth_limit_rule:
            input['max_burst_kbps'] = bandwidth_limit_rule['max_burst_kbps']
        if 'direction' in bandwidth_limit_rule:
            input['direction'] = bandwidth_limit_rule['direction']
        if 'tenant_id' in bandwidth_limit_rule:
            input['tenant_id'] = bandwidth_limit_rule['tenant_id']
        return bandwidth_rule_info

    @staticmethod
    def construct_dscp_marking_rule_info(context, rule_id, policy_id,
                                         dscp_marking_rule, action):
        LOG.info(_("rule_id = %(rule_id)s,policy_id = %(policy_id)s,"),
                 {'rule_id': rule_id,
                  'policy_id': policy_id,
                  'dscp_marking_rule': dscp_marking_rule})
        if action == 'UPDATE':
            dscp_marking_rule = dscp_marking_rule['dscp_marking_rule']
        dscp_rule_info = {
            "input": {
                "id": rule_id if (rule_id != 0) else
                dscp_marking_rule['id'],
                "qos_policy_id": policy_id if (policy_id != 0)
                else dscp_marking_rule['policy_id'],
            }
        }
        input = dscp_rule_info['input']
        if 'dscp_mark' in dscp_marking_rule:
            input['dscp_mark'] = dscp_marking_rule['dscp_mark']
        if 'tenant_id' in dscp_marking_rule:
            input['tenant_id'] = dscp_marking_rule['tenant_id']
        return dscp_rule_info

    @staticmethod
    def construct_delete_qos_info(id):
        qos_info = {
            "input": {
                "id": id
            }
        }
        return qos_info

    def create_policy(self, context, qos_policy):
        data = self.construct_qos_policy_info(context, 0, qos_policy,
                                              'CREATE')
        resource = 'add-' + QOS_POLICY
        err_str = _("Unable to add qos policy: %s")
        self.rest_action('POST', resource, data, err_str)

    def update_policy(self, context, id, qos_policy):
        data = self.construct_qos_policy_info(context, id, qos_policy,
                                              'UPDATE')
        resource = 'update-' + QOS_POLICY
        err_str = _("Unable to update qos policy: %s")
        self.rest_action('POST', resource, data, err_str)

    def delete_policy(self, context, id):
        data = self.construct_delete_qos_info(id)
        resource = 'del-' + QOS_POLICY
        err_str = _("Unable to add qos policy: %s")
        self.rest_action('POST', resource, data, err_str)

    def create_policy_bandwidth_limit_rule(self, context, policy_id,
                                           policy_rule):
        data = self.construct_bandwidth_limit_rule_info(context, 0, policy_id,
                                                        policy_rule, 'CREATE')
        resource = 'add-' + QOS_BANDWIDTH_RULE
        err_str = _("Unable to add bandwidth limit rule: %s")
        self.rest_action('POST', resource, data, err_str)

    def update_policy_bandwidth_limit_rule(self, context, rule_id, policy_id,
                                           policy_rule):
        data = self.construct_bandwidth_limit_rule_info(context, rule_id,
                                                        policy_id, policy_rule,
                                                        'UPDATE')
        resource = 'update-' + QOS_BANDWIDTH_RULE
        err_str = _("Unable to update bandwidth limit rule: %s")
        self.rest_action('POST', resource, data, err_str)

    def delete_policy_bandwidth_limit_rule(self, context, rule_id, policy_id):
        data = self.construct_delete_qos_info(rule_id)
        resource = 'del-' + QOS_BANDWIDTH_RULE
        err_str = _("Unable to del bandwidth limit rule: %s")
        self.rest_action('POST', resource, data, err_str)

    def create_policy_dscp_marking_rule(self, context, policy_id,
                                        policy_rule):
        data = self.construct_dscp_marking_rule_info(context, 0, policy_id,
                                                 policy_rule, 'CREATE')
        resource = 'add-' + QOS_DSCP_RULE
        err_str = _("Unable to add dscp marking rule: %s")
        self.rest_action('POST', resource, data, err_str)

    def update_policy_dscp_marking_rule(self, context, rule_id, policy_id,
                                    policy_rule):
        data = self.construct_dscp_marking_rule_info(context, rule_id,
                                                 policy_id, policy_rule,
                                                 'UPDATE')
        resource = 'update-' + QOS_DSCP_RULE
        err_str = _("Unable to update dscp marking rule: %s")
        self.rest_action('POST', resource, data, err_str)

    def delete_policy_dscp_marking_rule(self, context, rule_id, policy_id):
        data = self.construct_delete_qos_info(rule_id)
        resource = 'del-' + QOS_DSCP_RULE
        err_str = _("Unable to del dscp marking rule: %s")
        self.rest_action('POST', resource, data, err_str)
