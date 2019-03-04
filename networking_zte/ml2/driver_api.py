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

from abc import ABCMeta
from abc import abstractproperty
import six


@six.add_metaclass(ABCMeta)
class SecurityGroupContext(object):
    """Context passed to MechanismDrivers for changes to
    security_group resources.

    A SecurityGroupContext instance wraps a security_group resource.
    It provides helper methods for accessing other relevant information.
    Results from expensive operations are cached so that other
    MechanismDrivers can freely access the same information.
    """

    @abstractproperty
    def current(self):
        """Return the current state of the security_group.

        Return the current state of the security_group, as defined by
        NeutronPluginBaseV2.create_security_group and all extensions in the
        ml2 plugin.
        """
        pass

    @abstractproperty
    def original(self):
        """Return the original state of the security_group.

        Return the original state of the security_group, prior to a call to
        update_security_group. Method is only valid within calls to
        update_security_group_precommit and update_security_group_postcommit.
        """
        pass


@six.add_metaclass(ABCMeta)
class SecurityGroupRuleContext(object):
    """Context passed to MechanismDrivers for changes
    to security_group_rule resources.

    A SecurityGroupRuleContext instance wraps a
    security_group_rule resource. It provides
    helper methods for accessing other relevant information. Results
    from expensive operations are cached so that other
    MechanismDrivers can freely access the same information.
    """

    @abstractproperty
    def current(self):
        """Return the current state of the security_group_rule.

        Return the current state of the security_group_rule, as defined by
        NeutronPluginBaseV2.create_security_group_rule and all extensions
        in the  ml2 plugin.
        """
        pass

    @abstractproperty
    def original(self):
        """Return the original state of the subnet.

        Return the original state of the security_group_rule, prior to a call
        to update_security_group_rule. Method is only valid within calls to
        update_security_group_rule_precommit and
        update_security_group_rule_postcommit.
        """
        pass


@six.add_metaclass(ABCMeta)
class QosPolicyContext(object):
    @abstractproperty
    def current(self):
        pass

    @abstractproperty
    def original(self):
        pass


@six.add_metaclass(ABCMeta)
class QosBandWidthRuleContext(object):

    @abstractproperty
    def current(self):
        pass

    @abstractproperty
    def original(self):
        pass
