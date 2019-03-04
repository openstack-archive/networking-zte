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

from networking_zte.common import servermanager
from neutron.db import common_db_mixin as base_db
from oslo_log import log

LOG = log.getLogger(__name__)

# The following are used to invoke the API on the external controller

FIREWALL = 'firewall'
FIREWALL_POLICY = 'firewall-policy'
FIREWALL_RULE = 'firewall-rule'
INSERT_RULE = 'insert-rule'
REMOVE_RULE = 'remove-rule'


BASE_URI = '/restconf/operations/zenic-fwapp-model:'
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


class ZenicRestServerPool(
        servermanager.ServerPool,
        base_db.CommonDbMixin):
    """ZenicRestServerPool for firewall plugin.
    This server pool has firewall firewall_policy firewall_rule operations
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
    def construct_firewall_info(context, id, firewall, action):
        """
        :param context:
        :param id:
        :param firewall:
        :param action:
        :return: firewall={'status': 'INACTIVE',
           'router_ids': [],
           'name': u'fw2',
           'shared': None,
           'firewall_policy_id': u'58b61e09-b27a-439b-b428-aec51bf6061a',
           'tenant_id': u'a968288bfc9d4ced9c8c007f654310f9',
           'admin_state_up': True,
           'id': '3f2fb3ec-f7ce-450b-82e9-60983c10ff29',
           'description': u''}
        """
        if action == 'UPDATE':
            firewall = firewall['firewall']
        firewall_info = {
            "input": {
                "id": id if (id != 0) else firewall["id"]
            }
        }
        input = firewall_info['input']
        if 'status' in firewall:
            input['status'] = firewall['status']
        if 'router_ids' in firewall:
            input['router_ids'] = firewall['router_ids']
        if 'name' in firewall:
            input['name'] = firewall['name']
        if 'shared' in firewall:
            input['shared'] = firewall['shared']
        if 'tenant_id' in firewall:
            input['tenant_id'] = firewall['tenant_id']
        if 'firewall_policy_id' in firewall:
            input['firewall_policy_id'] = firewall['firewall_policy_id']
        if 'admin_state_up' in firewall:
            input['admin_state_up'] = firewall['admin_state_up']
        if 'description' in firewall:
            input['description'] = firewall['description']

        return firewall_info

    @staticmethod
    def construct_firewall_policy_info(context, id, firewall_policy, action):
        """
        :param context:
        :param id:
        :param firewall_policy:
        :param action:
        :return: firewall_policy={'name': u'fw5',
             'firewall_rules': [],
             'shared': False,
             'audited': False,
             'tenant_id': u'a968288bfc9d4ced9c8c007f654310f9',
             'id': '3c923e59-afed-4501-8e73-27be355746ab',
             'firewall_list': [],
             'description': u''}
        """
        if action == 'UPDATE':
            firewall_policy = firewall_policy['firewall_policy']
        firewall_policy_info = {
            "input": {
                "id": id if (id != 0) else firewall_policy['id'],
            }
        }
        input = firewall_policy_info['input']
        if 'firewall_rules' in firewall_policy:
            input['firewall_rules'] = firewall_policy['firewall_rules']
        if 'description' in firewall_policy:
            input['description'] = firewall_policy['description']
        if 'tenant_id ' in firewall_policy:
            input['tenant_id'] = firewall_policy['tenant_id']
        if 'shared' in firewall_policy:
            input['shared'] = firewall_policy['shared']
        if 'name' in firewall_policy:
            input['name'] = firewall_policy['name']
        if 'audited' in firewall_policy:
            input['audited'] = firewall_policy['audited']
        if 'firewall_list' in firewall_policy:
            input['firewall_list'] = firewall_policy['firewall_list']

        return firewall_policy_info

    @staticmethod
    def construct_firewall_rule_info(context, id, firewall_rule, action):
        """
        :param context:
        :param id:
        :param firewall_rule:
        :param action:
        :return:firewall_rule={'protocol': u'tcp',
            'description': u'',
            'source_port': None,
            'source_ip_address': None,
            'destination_ip_address': None,
            'firewall_policy_id': None,
            'position': 0,
            'destination_port': None,
            'id': '07410a40-3941-4e62-8f26-f87fc2032263',
            'name': u'fw5',
            'tenant_id': u'a968288bfc9d4ced9c8c007f654310f9',
            'enabled': True,
            'action': u'allow',
            'ip_version': 4,
            'shared': False}
        """
        if action == 'UPDATE':
            firewall_rule = firewall_rule['firewall_rule']
        firewall_rule_info = {
            "input": {
                "id": id if (id != 0) else firewall_rule['id'],
            }
        }
        input = firewall_rule_info['input']
        if 'protocol' in firewall_rule:
            input['protocol'] = firewall_rule['protocol']
        if 'description' in firewall_rule:
            input['description'] = firewall_rule['description']
        if firewall_rule.get('source_port', None):
            input['source_port'] = firewall_rule['source_port']
        if firewall_rule.get('source_ip_address', None):
            input['source_ip_address'] = firewall_rule['source_ip_address']
        if firewall_rule.get('destination_ip_address', None):
            input['destination_ip_address'] = firewall_rule[
                'destination_ip_address']
        if firewall_rule.get('destination_port', None):
            input['destination_port'] = firewall_rule['destination_port']
        if 'name' in firewall_rule:
            input['name'] = firewall_rule['name']
        if 'tenant_id' in firewall_rule:
            input['tenant_id'] = firewall_rule['tenant_id']
        if 'enabled' in firewall_rule:
            input['enabled'] = firewall_rule['enabled']
        if 'action' in firewall_rule:
            input['action'] = firewall_rule['action']
        if firewall_rule.get('firewall_policy_id', None):
            input['firewall_policy_id'] = firewall_rule['firewall_policy_id']
        if firewall_rule.get('position', 0):
            input['position'] = firewall_rule['position']
        if 'ip_version' in firewall_rule:
            input['ip_version'] = firewall_rule['ip_version']
        if 'shared' in firewall_rule:
            input['shared'] = firewall_rule['shared']

        return firewall_rule_info

    @staticmethod
    def construct_insert_rule_info(policy_id, insert_rule_info):
        """
        :param policy_id:
        :param insert_rule_info:
        :return: rule_info={u'insert_after': u'',
            u'firewall_rule_id': u'96541466-d916-43f2-926e-24c48939db5c',
            u'insert_before': u'790f6db4-7f63-4697-b037-32a37a08a69f'}
        """
        rule_info = {
            "input": {
                "policy_id": policy_id,
                "firewall_rule_id": insert_rule_info['firewall_rule_id'],
            }
        }
        input_str = rule_info['input']
        if insert_rule_info['insert_after']:
            input_str['insert_after'] = insert_rule_info['insert_after']
        if insert_rule_info['insert_before']:
            input_str['insert_before'] = insert_rule_info['insert_before']
        return rule_info

    @staticmethod
    def construct_delete_firewall_info(id):
        firewall_info = {
            "input": {
                "id": id
            }
        }
        return firewall_info

    @staticmethod
    def construct_remove_firewall_rule_info(policy_id, rule_id):
        firewall_info = {
            "input": {
                "policy_id": policy_id,
                "firewall_rule_id": rule_id['firewall_rule_id'],
            }
        }
        return firewall_info

    def create_firewall(self, context, firewall):
        data = self.construct_firewall_info(context, 0, firewall, 'CREATE')
        resource = 'add-' + FIREWALL
        err_str = _("Unable to add firewall: %s")
        self.rest_action('POST', resource, data, err_str)

    def update_firewall(self, context, id, firewall):
        data = self.construct_firewall_info(context, id, firewall, 'UPDATE')
        resource = 'update-' + FIREWALL
        err_str = _("Unable to update firewall: %s")
        self.rest_action('POST', resource, data, err_str)

    def delete_firewall(self, context, id):
        data = self.construct_delete_firewall_info(id)
        resource = 'del-' + FIREWALL
        err_str = _("Unable to add firewall: %s")
        self.rest_action('POST', resource, data, err_str)

    def create_firewall_policy(self, context, firewall_policy):
        data = self.construct_firewall_policy_info(
            context, 0, firewall_policy, 'CREATE')
        resource = 'add-' + FIREWALL_POLICY
        err_str = _("Unable to add firewall policy: %s")
        self.rest_action('POST', resource, data, err_str)

    def update_firewall_policy(self, context, id, firewall_policy):
        data = self.construct_firewall_policy_info(
            context, id, firewall_policy, 'UPDATE')
        resource = 'update-' + FIREWALL_POLICY
        err_str = _("Unable to update firewall policy: %s")
        self.rest_action('POST', resource, data, err_str)

    def delete_firewall_policy(self, context, id):
        data = self.construct_delete_firewall_info(id)
        resource = 'del-' + FIREWALL_POLICY
        err_str = _("Unable to del firewall policy: %s")
        self.rest_action('POST', resource, data, err_str)

    def create_firewall_rule(self, context, firewall_rule):
        data = self.construct_firewall_rule_info(
            context, 0, firewall_rule, 'CREATE')
        resource = 'add-' + FIREWALL_RULE
        err_str = _("Unable to add firewall rule: %s")
        self.rest_action('POST', resource, data, err_str)

    def update_firewall_rule(self, context, id, firewall_rule):
        data = self.construct_firewall_rule_info(
            context, id, firewall_rule, 'UPDATE')
        resource = 'update-' + FIREWALL_RULE
        err_str = _("Unable to update firewall rule: %s")
        self.rest_action('POST', resource, data, err_str)

    def delete_firewall_rule(self, context, id):
        data = self.construct_delete_firewall_info(id)
        resource = 'del-' + FIREWALL_RULE
        err_str = _("Unable to del firewall rule: %s")
        self.rest_action('POST', resource, data, err_str)

    def insert_rule(self, context, policy_id, rule_info):
        data = self.construct_insert_rule_info(policy_id, rule_info)
        # resource = FIREWALL_POLICY + '-' + INSERT_RULE
        resource = 'insert-' + FIREWALL_POLICY + '-rule'
        err_str = _("Unable to insert rule: %s")
        self.rest_action('POST', resource, data, err_str)

    def remove_rule(self, context, policy_id, rule_id):
        data = self.construct_remove_firewall_rule_info(policy_id, rule_id)
        # resource = FIREWALL_POLICY + '-' + REMOVE_RULE
        resource = 'remove-' + FIREWALL_POLICY + '-rule'
        err_str = _("Unable to remove rule: %s")
        self.rest_action('POST', resource, data, err_str)
