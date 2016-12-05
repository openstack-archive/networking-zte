
import unittest
import mock
import random

from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import db
from neutron.scheduler.l3_agent_scheduler import L3Scheduler
from ceilometer.network.notifications import Router

from neutron.scheduler import all_l3_agents_scheduler
from neutron.scheduler.all_l3_agents_scheduler import AllL3AgentsScheduler
from neutron.scheduler.all_l3_agents_scheduler import AddAgentToRouterBinding

class FakeNetwork(object):
    def __init__(self):
        pass   
    def session(self):
        return None
    
        
    
class A():
    def __init__(self):   
        self.name = 'this is a test'  

    def method(self):   
        print"method print" 
        

class TestMethodPatch(unittest.TestCase):
    def setUp(self):
        pass
    def tearDown(self):
        pass
    def testMethodPatch(self):
        Instance = A()
        self.cls = 'cls'
        self.bases = [Instance]
        self.dct = {"__a__":'1', 
                    "__b__":'2', 
                    "__doc__":'3'}
        all_l3_agents_scheduler.method_patch(self.cls, self.bases, self.dct)   
        #return 
        self.assertTrue(isinstance(all_l3_agents_scheduler.method_patch(self.cls, self.bases, self.dct), A))

class TestAddAgentToRouterBinding(unittest.TestCase):
    def setUp(self):
        self.AddAgentToRouterBinding = AddAgentToRouterBinding()
    def tearDown(self):
        pass
    @mock.patch.object(AddAgentToRouterBinding,"_get_all_routers_with_interface_or_gateway")
    def test_update_l3_agent_router_bindings(self,mock_get_all_routers_with_interface_or_gateway):
        self.context = 1
        self.agent_id = 'agent_id'
        
        self.AddAgentToRouterBinding._update_l3_agent_router_bindings(self.context, self.agent_id)
        
    @mock.patch.object(AddAgentToRouterBinding,"_get_all_routers_with_interface_or_gateway")
    def test_update_l3_agent_router_bindings_None(self,mock_get_all_routers_with_interface_or_gateway):
        self.context = 1
        self.agent_id = 'agent_id'
        mock_get_all_routers_with_interface_or_gateway.return_value = None
        self.AddAgentToRouterBinding._update_l3_agent_router_bindings(self.context, self.agent_id)
        
class TestAllL3AgentsScheduler(unittest.TestCase):
    def setUp(self):
        self.AllL3AgentsScheduler = AllL3AgentsScheduler()  
    def tearDown(self):
        pass
    @mock.patch.object(AllL3AgentsScheduler,'_schedule_router')
    def test_schedule(self,mock_schedule_router):
        self.plugin = 'plugin'
        self.context = 'context'
        self.router_id = 'router_id'
        self.AllL3AgentsScheduler.schedule(self.plugin, self.context, self.router_id)
        
    def test_choose_router_agent(self):
        self.plugin = '1'
        self.context = '1'
        self.candidates = '1'
        self.AllL3AgentsScheduler._choose_router_agent(self.plugin, self.context, self.candidates)
    
    @mock.patch('random.sample')
    @mock.patch.object(L3Scheduler,'get_num_of_agents_for_ha')
    def test_choose_router_agents_for_ha(self,mock_get_num_of_agents_for_ha,mock_sample):
        self.plugin = 'plugin'
        self.context = 'context'
        self.candidates = '1'
        self.AllL3AgentsScheduler._choose_router_agents_for_ha(self.plugin, self.context, self.candidates)

if __name__ == "__main__":
    unittest.main()