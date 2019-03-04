# Copyright 2015 ZTE, Inc.
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


from networking_zte.ml2 import driver_api as api
from neutron.plugins.ml2 import driver_context as context


class SecurityGroupContext(
        context.MechanismDriverContext, api.SecurityGroupContext):

    def __init__(
            self, plugin, plugin_context,
            security_group, original_security_group=None):
        super(SecurityGroupContext, self).__init__(plugin, plugin_context)
        self._security_group = security_group
        self._original_security_group = original_security_group

    @property
    def current(self):
        return self._security_group

    @property
    def original(self):
        return self._original_security_group


class SecurityGroupRuleContext(
        context.MechanismDriverContext, api.SecurityGroupRuleContext):

    def __init__(
            self, plugin, plugin_context,
            security_group_rule, original_security_group_rule=None):
        super(SecurityGroupRuleContext, self).__init__(plugin, plugin_context)
        self._security_group_rule = security_group_rule
        self._original_security_group_rule = original_security_group_rule

    @property
    def current(self):
        return self._security_group_rule

    @property
    def original(self):
        return self._original_security_group_rule


class QosPolicyContext(
        context.MechanismDriverContext, api.QosPolicyContext):

    def __init__(
            self, plugin, plugin_context,
            qos_policy, original_qos_policy=None):
        super(QosPolicyContext, self).__init__(plugin, plugin_context)
        self._qos_policy = qos_policy
        self._original_qos_policy = original_qos_policy

    @property
    def current(self):
        return self._qos_policy

    @property
    def original(self):
        return self._original_qos_policy


class QosBandWidthRuleContext(
        context.MechanismDriverContext, api.QosBandWidthRuleContext):

    def __init__(
            self, plugin, plugin_context,
            qos_bandwidth_rule, original_qos_bandwidth_rule=None):
        super(QosBandWidthRuleContext, self).__init__(plugin, plugin_context)
        self._qos_bandwidth_rule = qos_bandwidth_rule
        self._original_qos_bandwidth_rule = original_qos_bandwidth_rule

    @property
    def current(self):
        return self._qos_bandwidth_rule

    @property
    def original(self):
        return self._original_qos_bandwidth_rule
