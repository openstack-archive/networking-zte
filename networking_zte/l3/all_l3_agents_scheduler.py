# Copyright (c) 2013 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import random
import six

import l3_agent_scheduler

from eventlet import greenthread
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_db
from neutron.db import l3_hamode_db
from neutron.db import models_v2
from neutron.extensions import agent as ext_agent
from neutron.extensions import l3_ext_ha_mode as l3_ha
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import timeutils
from sqlalchemy.orm import exc as sa_exc

__author__ = '10069907'

LOG = logging.getLogger(__name__)
cfg.CONF.register_opts(l3_hamode_db.L3_HA_OPTS)


def method_patch(cls, bases, dct):
    base = bases[0]
    for name, value in dct.iteritems():
        if name not in("__module__", "__metaclass__", "__doc__"):
            setattr(base, name, value)
    return base


@six.add_metaclass(method_patch)
class AddAgentToRouterBinding(agents_db.AgentDbMixin):
    def _get_all_routers_with_interface_or_gateway(self, context):
        try:
            port_db = (context.session.query(models_v2.Port).
                       enable_eagerloads(False).
                       filter(models_v2.Port.device_owner.
                              startswith("network:router_interface")).
                       all())
        except sa_exc.NoResultFound:
            LOG.debug("No ports have port_id starting with router_interface")
            return None

        try:
            router_db = (context.session.query(l3_db.Router).
                         enable_eagerloads(False).all())
        except sa_exc.NoResultFound:
            LOG.debug("No router have Found")
            return None
        router_ids = [router.id for router in router_db]
        return [
            port.device_id for port in port_db if port.device_id in router_ids
            ]

    def _binding_router_to_agent(self, context, router_ids, agent_id):
        for r_id in router_ids:
            LOG.debug('_binding_router_to_agent, process:%s-%s' %
                      (r_id, agent_id))
            query = context.session.query(l3_agentschedulers_db.
                                          RouterL3AgentBinding)
            query = query.filter(l3_agentschedulers_db.RouterL3AgentBinding.
                                 router_id == r_id,
                                 l3_agentschedulers_db.RouterL3AgentBinding.
                                 l3_agent_id == agent_id)
            try:
                query.one()
                LOG.debug('find old router_agent_binding %s-%s '
                          % (r_id, agent_id))
            except sa_exc.NoResultFound:
                with context.session.begin(subtransactions=True):
                    binding = l3_agentschedulers_db.RouterL3AgentBinding()
                    binding.l3_agent_id = agent_id
                    binding.router_id = r_id
                    try:
                        context.session.add(binding)
                        LOG.debug('add router_agent_binding %s-%s'
                                  % (r_id, agent_id))
                    except db_exc.DBError:
                        LOG.debug('add router_agent_binding %s-%s fail'
                                  % (r_id, agent_id))

    def _update_l3_agent_router_bindings(self, context, agent_id):
        router_ids_need_binding = \
            self._get_all_routers_with_interface_or_gateway(context)
        LOG.info('get all_router_with_port:%(r_id)s,and agent:%(agt_id)s',
                 {'r_id': router_ids_need_binding, 'agt_id': agent_id})
        if router_ids_need_binding is None:
            return
        self._binding_router_to_agent(context,
                                      router_ids_need_binding, agent_id)

    def _create_or_update_agent(self, context, agent):
        with context.session.begin(subtransactions=True):
            res_keys = ['agent_type', 'binary', 'host', 'topic']
            res = dict((k, agent[k]) for k in res_keys)

            configurations_dict = agent.get('configurations', {})
            res['configurations'] = jsonutils.dumps(configurations_dict)
            res['load'] = self._get_agent_load(agent)
            current_time = timeutils.utcnow()
            try:
                agent_db = self._get_agent_by_type_and_host(
                    context, agent['agent_type'], agent['host'])
                if agent['topic'] == "l3_agent":
                    self._update_l3_agent_router_bindings(context, agent_db.id)
                res['heartbeat_timestamp'] = current_time
                if agent.get('start_flag'):
                    res['started_at'] = current_time
                greenthread.sleep(0)
                agent_db.update(res)
            except ext_agent.AgentNotFoundByTypeHost:
                greenthread.sleep(0)
                res['created_at'] = current_time
                res['started_at'] = current_time
                res['heartbeat_timestamp'] = current_time
                res['admin_state_up'] = True
                agent_db = agents_db.Agent(**res)
                greenthread.sleep(0)
                context.session.add(agent_db)
            greenthread.sleep(0)


class AllL3AgentsScheduler(l3_agent_scheduler.L3Scheduler):
    """allocate all L3 agent for a router."""

    def get_all_l3_agents(self, plugin, context):
        """Return L3 agents where a router could be scheduled."""
        with context.session.begin(subtransactions=True):
            query = context.session.query(agents_db.Agent)
            query = query.filter(
                agents_db.Agent.topic == 'l3_agent')
            query = (query.filter_by(admin_state_up=True))

            return [l3_agent
                    for l3_agent in query
                    if (agentschedulers_db.AgentSchedulerDbMixin.
                        is_eligible_agent(True, l3_agent))]

    def _schedule_router(self, plugin, context, router_id, candidates=None):
        sync_router = plugin.get_router(context, router_id)
        router_distributed = sync_router.get('distributed', False)
        if router_distributed or sync_router.get('ha', False):
            raise l3_ha.DistributedHARouterNotSupported()
        if candidates is None:
            candidates = self.get_all_l3_agents(plugin, context)
            LOG.debug('all_cap:%s' % candidates)
        if not candidates:
            return
        for chosen_agent in candidates:
            query = context.session.query(
                l3_agentschedulers_db.RouterL3AgentBinding)
            query = query.filter(
                l3_agentschedulers_db.RouterL3AgentBinding.router_id ==
                router_id,
                l3_agentschedulers_db.RouterL3AgentBinding.l3_agent_id ==
                chosen_agent['id'])
            try:
                query.one()
                LOG.debug('find old router_agent_binding %s-%s '
                          % (router_id, chosen_agent['id']))
            except sa_exc.NoResultFound:
                self.bind_router(context, router_id, chosen_agent)
        return chosen_agent

    def schedule(self, plugin, context, router_id, candidates=None):
        LOG.debug('AllL3AgentsScheduler.schedule')
        return self._schedule_router(
            plugin, context, router_id, candidates=candidates)

    def _choose_router_agent(self, plugin, context, candidates):
        """Choose an agent from candidates based on a specific policy."""
        pass

    def _choose_router_agents_for_ha(self, plugin, context, candidates):
        num_agents = self.get_num_of_agents_for_ha(len(candidates))
        return random.sample(candidates, num_agents)
