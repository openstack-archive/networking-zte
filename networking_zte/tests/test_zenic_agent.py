# coding UTF-8
#!/usr/lib/python
import unittest
import mock
from eventlet.greenpool import GreenPool

import neutron.service
import neutron.openstack.common.service
from neutron.agent.zenic_agent import ZnicL3RestServerPool
from neutron.agent.zenic_agent import L3PluginApi
from neutron.agent.zenic_agent import ZenicAgent
from neutron.agent.zenic_agent import ZenicAgentWithStateReport
from neutron.common import proxy_server_manager
from neutron.agent.rpc import PluginReportStateAPI
from neutron.openstack.common import loopingcall
from neutron.common.config import init
from neutron.common import config
from neutron import context
from neutron.plugins.proxydriver.common.rest.znic_l2 import config
from neutron.common import utils
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.openstack.common.service import ServiceLauncher
from oslo_messaging.rpc import client
from oslo_messaging import Target
from oslo_config import cfg
from oslo_concurrency.lockutils import lock

import neutron.agent.zenic_agent

def router_value(self):
    router_value = {'enable_snat':1,
                    'gw_port':'gw_port'
                   }
    return router_value

class CallContextTest():
    def call(self, context, str, host=1, router_ids=1):
        assert str == 'sync_routers'
        return 'get_routers'
    
class CallContextTestArgs():
    def call(self, context, str, host=1, router_ids=1):
        assert str == 'get_service_plugin_list'
        return 'get_service_plugin_list'
  
class RPCClientTest():
    def __init__(self):
        pass
    def prepare(self, version=None):
        if version == None:
            return CallContextTest()
        else:
            if version == '1.3':
                return CallContextTestArgs()
            else:
                assert version == '1.3' , 'version is error.'
 
class TestZnicL3RestServerPool(unittest.TestCase):
    def setUp(self):
        self.servers = 'servers'
        self.auth = 'auth'
        self.ssl = 'ssl'
        self.no_ssl_validation = 'no_ssl_validation'
        self.ssl_sticky = 'ssl_sticky'
        self.ssl_cert_directory = 'ssl_cert_directory'
        self.consistency_interval = 'consistency_interval'
        self.success_codes = 'success_codes'
        self.failure_codes = 'failure_codes'
        self.ZnicL3RestServerPool = ZnicL3RestServerPool(self.servers, self.auth, self.ssl, self.no_ssl_validation, self.ssl_sticky,
                 self.ssl_cert_directory, self.consistency_interval, self.success_codes, self.failure_codes)
    
    def tearDown(self):
        pass

    def testName(self):
        pass
    
    def test_validate_dict(self):
        instance_dict = {'test':'test'}
        # if else
        self.ZnicL3RestServerPool.validate_dict(instance_dict, 'test', 'default')
        self.ZnicL3RestServerPool.validate_dict(instance_dict, 'default', 'default')
        # return
        self.assertEqual(self.ZnicL3RestServerPool.validate_dict(instance_dict, 'test', 'default'), 'test')
        self.assertEqual(self.ZnicL3RestServerPool.validate_dict(instance_dict, 'default', 'default'), 'default')
        
    def test_construct_router_rest_msg(self):
    
        self.router_info = {'_interfaces':[{'subnets':[{'id':1}]}],
                            'routes':'routes',
                            'gw_port_id':'gw_port_id',
                            'id':'id',
                            'name':'name',
                            'admin_state_up':'admin_state_up',
                            'tenant_id':'tenant_id',
                            'ext-gw-port':'ext-gw-port',
                            'enable_snat':'enable_snat',
                            'router-interfaces':'router-interfaces'
                            }
        self.router_info_None = {'_interfaces':[{'subnets':[{'id':1}]}],
                            'routes':'routes',
                            'gw_port_id':None,
                            'id':'id',
                            'name':'name',
                            'admin_state_up':'admin_state_up',
                            'tenant_id':'tenant_id',
                            'ext-gw-port':'ext-gw-port',
                            'enable_snat':'enable_snat',
                            'router-interfaces':'router-interfaces'
                            }
        action_list = ['DETELE', 'GET', 'OTHER']
        # if else
        for action in action_list:
            # check logic
            self.ZnicL3RestServerPool.construct_router_rest_msg(self.router_info, action)
            # check logic None
            self.ZnicL3RestServerPool.construct_router_rest_msg(self.router_info_None, action)
            
        # return
        self.assertEqual(self.ZnicL3RestServerPool.construct_router_rest_msg(self.router_info, 'DELETE'),
                             {'input': {'id': {'_interfaces': [{'subnets': [{'id': 1}]}],
                                               'router-interfaces': 'router-interfaces',
                                               'enable_snat': 'enable_snat',
                                               'name': 'name',
                                               'gw_port_id': 'gw_port_id',
                                               'admin_state_up': 'admin_state_up',
                                               'routes': 'routes',
                                               'tenant_id': 'tenant_id',
                                               'ext-gw-port': 'ext-gw-port',
                                               'id': 'id'}}})
        self.assertEqual(self.ZnicL3RestServerPool.construct_router_rest_msg(self.router_info, 'GET'),
                             {'input': {'id': {'_interfaces': [{'subnets': [{'id': 1}]}],
                                               'router-interfaces': 'router-interfaces',
                                               'enable_snat': 'enable_snat',
                                               'name': 'name',
                                               'gw_port_id': 'gw_port_id',
                                               'admin_state_up': 'admin_state_up',
                                               'routes': 'routes',
                                               'tenant_id': 'tenant_id',
                                               'ext-gw-port': 'ext-gw-port',
                                               'id': 'id'}}})
        self.assertEqual(self.ZnicL3RestServerPool.construct_router_rest_msg(self.router_info, 'OTHER'),
                             {'input': {'router-interfaces': [1],
                                        'enable_snat': 'enable_snat',
                                        'name': 'name',
                                        'admin_state_up': 'admin_state_up',
                                        'routes': ['r', 'o', 'u', 't', 'e', 's'],
                                        'tenant_id': 'tenant_id',
                                        'ext-gw-port': 'gw_port_id',
                                        'id': 'id'}})
        self.assertEqual(self.ZnicL3RestServerPool.construct_router_rest_msg(self.router_info_None, 'OTHER'),
                             {'input': {'router-interfaces': [1],
                                        'enable_snat': 'enable_snat',
                                        'name': 'name',
                                        'admin_state_up': 'admin_state_up',
                                        'routes': ['r', 'o', 'u', 't', 'e', 's'],
                                        'tenant_id': 'tenant_id',
                                        'ext-gw-port': '',
                                        'id': 'id'}})
        
    @mock.patch.object(ZnicL3RestServerPool, 'construct_router_rest_msg')
    @mock.patch.object(proxy_server_manager.ServerPool, 'rest_action')
    def test_rest_update_router(self, mock_rest_action, mock_construct_router_rest_msg):
        self.router_info = {'_interfaces':[{'subnets':[{'id':1}]}],
                            'routes':'routes',
                            'gw_port_id':'gw_port_id',
                            'id':'id',
                            'name':'name',
                            'admin_state_up':'admin_state_up',
                            'tenant_id':'tenant_id',
                            'ext-gw-port':'ext-gw-port',
                            'enable_snat':'enable_snat',
                            'router-interfaces':'router-interfaces'
                            }
         
        # check logic
        self.ZnicL3RestServerPool.rest_update_router(self.router_info)        
        # check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
         
        # check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args, (('POST', 'update-router',
                                                      self.ZnicL3RestServerPool.construct_router_rest_msg(self.router_info, 'ADD'),
                                                      u'Unable to create remote router: %s'),)) 
        # return True
        self.assertTrue(self.ZnicL3RestServerPool.rest_update_router, self.router_info)
         
        # check return False
        mock_rest_action.return_value = [0]
        self.assertFalse(self.ZnicL3RestServerPool.rest_update_router(self.router_info))
         
    @mock.patch.object(ZnicL3RestServerPool, 'construct_router_rest_msg')
    @mock.patch.object(proxy_server_manager.ServerPool, 'rest_action')
    def test_rest_delete_router(self, mock_rest_action, mock_construct_router_rest_msg):
        self.router_id = {'_interfaces':[{'subnets':[{'id':1}]}],
                            'routes':'routes'
                            }
         
        # check logic
        self.ZnicL3RestServerPool.rest_delete_router(self.router_id)        
        # check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
         
        # check rest_action call_args    
        self.assertEqual(mock_rest_action.call_args, (('POST', 'del-router',
                                                      self.ZnicL3RestServerPool.construct_router_rest_msg(self.router_id, 'DELETE'),
                                                      u'Unable to delete remote router: %s'),)) 
        # return True
        self.assertTrue(self.ZnicL3RestServerPool.rest_delete_router, self.router_id)
         
        # check return False
        mock_rest_action.return_value = [0]
        self.assertFalse(self.ZnicL3RestServerPool.rest_delete_router(self.router_id))
         
         
    def test_construct_all_routers_rest_msg(self):
        self.router_info = (1, 2, 3)
        self.ZnicL3RestServerPool.construct_all_routers_rest_msg(self.router_info)
        self.assertEqual(self.ZnicL3RestServerPool.construct_all_routers_rest_msg(self.router_info),
                          {'input': {'router-list': [1, 2, 3]}})
         
    @mock.patch.object(ZnicL3RestServerPool, 'construct_all_routers_rest_msg')
    @mock.patch.object(proxy_server_manager.ServerPool, 'rest_action')
    def test_rest_all_router_ids(self, mock_rest_action, mock_construct_all_routers_rest_msg):
        self.all_router_ids = 'all_router_ids'
        # check logic
        self.ZnicL3RestServerPool.rest_all_router_ids(self.all_router_ids)
        # check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
         
        # check rest_action call_args    
        self.assertEqual(mock_rest_action.call_args, (('POST', 'sync-router-info',
                                                      self.ZnicL3RestServerPool.construct_all_routers_rest_msg(self.all_router_ids),
                                                      u'Unable to rest_all_router_ids: %s'),))
        self.assertTrue(self.ZnicL3RestServerPool.rest_all_router_ids, self.all_router_ids)
         
         
class TestL3PluginApi(unittest.TestCase):
    @mock.patch('neutron.common.rpc.get_client')
    @mock.patch('oslo_messaging.Target')
    def setUp(self, mock_Target, mock_get_client):
        self.topic = 'topic'
        self.host = 'host'
        self.context = 1
        mock_get_client.return_value = RPCClientTest()
        self.L3PluginApi = L3PluginApi(self.topic, self.host)
        # check Target call_count
        self.assertEqual(mock_Target.call_count, 1)
        # check get_client call_count
        self.assertEqual(mock_get_client.call_count, 1)        
       
    def tearDown(self):
        pass
      
    def test_get_routers(self):
        self.context = 1            
        self.L3PluginApi.get_routers(self.context)
        # check return
        self.assertEqual(self.L3PluginApi.get_routers(self.context), 'get_routers')         
         
    def test_get_service_plugin_list(self):
        self.context = 1            
        self.L3PluginApi.get_service_plugin_list(self.context)
        # check return
        self.assertEqual(self.L3PluginApi.get_service_plugin_list(self.context), 'get_service_plugin_list')
      
# class TestRouterInfo(unittest.TestCase):
#     @mock.patch('neutron.agent.linux.iptables_manager.IptablesManager')
#     def setUp(self, mock_IptablesManager):
#         self.router_id = 'router_id'
#         self.root_helper = 'root_helper'
#         self.value = {'enable_snat':1,
#                       'gw_port':'gw_port'
#                       }
#         self.router_value = router_value(self.value)    
#         self.RouterInfo = RouterInfo(self.router_id, self.root_helper, self.router_value)   
#     def tearDown(self):
#         pass  
#      
#     def test_router(self):
#         pass  

class TestRegister(unittest.TestCase):
    @mock.patch.object(cfg.ConfigOpts, 'register_opts')
    def test_get_restproxy_conf(self, mock_register_opts):
        # check logic
        neutron.agent.zenic_agent.get_restproxy_conf()
        # check register_opts call_count
        self.assertEqual(mock_register_opts.call_count, 1)
        # check file /etc/neutron/plugin.ini        
        lineNum = 0
        with open ('/etc/neutron/plugin.ini') as file_object:
            lines = file_object.readlines()
            for line in lines:
                lineNum = lineNum + 1
                if line[:11] == '[RESTPROXY]':
                    assert lines[lineNum][:7] == 'servers'
                    assert lines[lineNum + 1][:11] == 'server_auth' 
               
                                                        
class TestZenicAgent(unittest.TestCase):
    @mock.patch('neutron.agent.zenic_agent.L3PluginApi')
    @mock.patch('neutron.agent.common.config.get_root_helper')
    @mock.patch('neutron.context.get_admin_context_without_session')
    @mock.patch('neutron.agent.zenic_agent.get_restproxy_conf')
    def setUp(self, mock_get_restproxy_conf, mock_get_admin_context_without_session, mock_get_root_helper, mock_L3PluginApi):
        self.host = 'host'
        self.ZenicAgent = ZenicAgent(self.host)
        self.updated_routers = self.ZenicAgent.updated_routers
        
    def tearDown(self):
        pass
     
    def test_router_deleted(self):
        self.router_id = 'router_id'
        # check logic
        self.ZenicAgent.router_deleted(context, self.router_id)
          
    @mock.patch('oslo_concurrency.lockutils.lock')
    def test_router_deleted_expection(self,mock_lock):
        self.router_id = 'router_id'
        mock_lock.side_effect = Exception
        self.ZenicAgent.router_deleted(context, self.router_id)
        mock_lock.side_effect = Exception
         
        self.ZenicAgent.router_deleted(context, self.router_id)  

    def test_routers_updated(self):
        self.context = 1
        self.routers = [{'id':'router'}]
        self.ZenicAgent.routers_updated(self.context, self.routers)
        
    @mock.patch('oslo_concurrency.lockutils.lock')
    def test_routers_updated_exception(self,mock_lock):
        mock_lock.side_effect = Exception
        self.context = 1
        self.routers = [{'id':'router'}]
        self.ZenicAgent.routers_updated(self.context, self.routers)
        
    @mock.patch.object(ZnicL3RestServerPool, 'rest_update_router')
    def test_process_update_rest_fail_routers(self, mock_rest_update_router):
        self.routers = [{'id':'router'}]
        self.ZenicAgent._process_update_rest_fail_routers(self.routers)
        
    @mock.patch.object(ZnicL3RestServerPool, 'rest_all_router_ids')
    def test_sync_all_valid_routers(self, mock_rest_all_router_ids):
        self.routers = [{'id':'router'}]
        self.ZenicAgent._sync_all_valid_routers(self.routers)
        
    @mock.patch.object(ZnicL3RestServerPool, 'rest_update_router')
    def test_process_routers(self, mock_rest_update_router):
        self.routers = [{'id':'router'}]
        self.ZenicAgent._process_routers(self.routers)
        
    @mock.patch.object(ZnicL3RestServerPool, 'rest_update_router')
    def test_process_routers_fail(self, mock_rest_update_router):
        self.routers = [{'id':'id'}]
        mock_rest_update_router.return_value = False
        self.ZenicAgent._process_routers(self.routers)
        # check fail_update_rest_router_id
        self.assertEqual(self.ZenicAgent.fail_update_rest_router_id, set(['id']))
        
    @mock.patch.object(L3PluginApi, 'get_routers')
    @mock.patch.object(ZenicAgent, '_sync_all_valid_routers')
    def test_sync_all_router_restconf(self, mock_get_routers, mock_sync_all_valid_routers):
        self.context = 1
        self.ZenicAgent._sync_all_router_restconf(self.context)
        
#     @mock.patch.object(ZenicAgent,'_process_router_update')    
#     @mock.patch.object(GreenPool,'spawn_n')
#     @mock.patch.object(ZenicAgent,'_sync_all_router_restconf')
#     def test_process_routers_loop(self,mock_sync_all_router_restconf,mock_spawn_n,mock_process_router_update):
#         self.ZenicAgent._process_routers_loop()

    @mock.patch.object(GreenPool, 'spawn_n')
    def test_after_start(self, mock_spawn_n):
        self.ZenicAgent.after_start()
       
    @mock.patch.object(ZenicAgent, '_process_router_delete')
    @mock.patch.object(ZenicAgent, '_process_routers')
    @mock.patch.object(L3PluginApi, 'get_routers')
    @mock.patch('oslo_concurrency.lockutils.lock')    
    def test_process_router_update(self, mock_lock, mock_get_routers, mock_process_routers, mock_process_router_delete):
        self.ZenicAgent.updated_routers = set()
        self.ZenicAgent.updated_routers.add('id')
        self.ZenicAgent._process_router_update()
        
    @mock.patch.object(ZenicAgent, '_process_router_delete')
    @mock.patch.object(ZenicAgent, '_process_routers')
    @mock.patch.object(L3PluginApi, 'get_routers')
    @mock.patch('oslo_concurrency.lockutils.lock')    
    def test_process_router_update_exception(self, mock_lock, mock_get_routers, mock_process_routers, mock_process_router_delete):
        self.ZenicAgent.updated_routers = ['updated_routers']
        mock_process_router_delete.side_effect = Exception
        # check 3 exception
        self.ZenicAgent._process_router_update()
        # check fullsync true
        self.assertTrue(self.ZenicAgent.fullsync)
        
    @mock.patch.object(ZnicL3RestServerPool, 'rest_delete_router')
    def test_process_router_delete(self, mock_rest_delete_router):
        self.ZenicAgent.removed_routers = set()
        self.remove_routers_add_list = ['id', 'name', 'address']
        for i in self.remove_routers_add_list:
            self.ZenicAgent.removed_routers.add(i)
        self.ZenicAgent._process_router_delete()
        # check removed_routers
        self.assertEqual(self.ZenicAgent.removed_routers, set([]))
        
    @mock.patch.object(ZnicL3RestServerPool, 'rest_delete_router')
    def test_process_router_delete_fail(self, mock_rest_delete_router):
        self.ZenicAgent.removed_routers = set()
        self.ZenicAgent.fail_delete_rest_router_id = set()
        self.ZenicAgent.removed_routers.add('id')
        mock_rest_delete_router.return_value = False
        self.ZenicAgent._process_router_delete()
        # check fail_delete_rest_router_id
        self.assertEqual(self.ZenicAgent.fail_delete_rest_router_id, set(['id']))
        
    def test_router_ids(self):
        self.ZenicAgent._router_ids()

class TestZenicAgentWithStateReport(unittest.TestCase):
    @mock.patch('neutron.common.rpc.get_client')
    @mock.patch('neutron.agent.zenic_agent.L3PluginApi')
    @mock.patch('neutron.agent.common.config.get_root_helper')
    @mock.patch('neutron.context.get_admin_context_without_session')
    @mock.patch('neutron.agent.zenic_agent.get_restproxy_conf')
    def setUp(self, mock_get_restproxy_conf, mock_get_admin_context_without_session, mock_get_root_helper, mock_L3PluginApi, mock_get_client):
        self.host = 'host'
        self.ZenicAgentWithStateReport = ZenicAgentWithStateReport(self.host)
    def tearDown(self):
        pass
    
    @mock.patch.object(PluginReportStateAPI, 'report_state')
    def test_report_state(self, mock_report_state):
        self.ZenicAgentWithStateReport._report_state()
        # check report_state call_count
        self.assertEqual(mock_report_state.call_count, 1)
        
        
    @mock.patch.object(loopingcall.LoopingCallBase, 'stop')
    @mock.patch.object(PluginReportStateAPI, 'report_state')
    def test_report_state_AttributeError(self, mock_report_state, mock_stop):
        mock_report_state.side_effect = AttributeError
        self.ZenicAgentWithStateReport._report_state()     
        # check heartbeat.stop() call_count
        self.assertEqual(mock_stop.call_count, 1)
        
    @mock.patch.object(loopingcall.LoopingCallBase, 'stop')
    @mock.patch.object(PluginReportStateAPI, 'report_state')
    def test_report_state_Exception(self, mock_report_state, mock_stop):
        mock_report_state.side_effect = Exception
        self.ZenicAgentWithStateReport._report_state()

    def test_agent_updated(self):
        self.context = 1
        self.payload = 1
        self.ZenicAgentWithStateReport.agent_updated(self.context, self.payload)
        # check fullsync true
        self.assertTrue(self.ZenicAgentWithStateReport.fullsync)
        
class TestMain(unittest.TestCase):
    def setUp(self):
        pass
    def tearDown(self):
        pass
    
    @mock.patch.object(ServiceLauncher, 'wait')
    @mock.patch('neutron.openstack.common.service.launch')
    @mock.patch.object(neutron.service.Service, 'create')
    @mock.patch('neutron.agent.common.config.setup_logging')
    @mock.patch('neutron.common.config.init')
    def test_main(self, mock_init, mock_setup_logging, mock_create, mock_launch, mock_wait):
        neutron.agent.zenic_agent.main()
        # check init call_count
        self.assertEqual(mock_init.call_count, 1)
        # check setup_logging call_count
        self.assertEqual(mock_setup_logging.call_count, 1)
        # check create call_count
        self.assertEqual(mock_create.call_count, 1)
        # check launch call_count
        self.assertEqual(mock_launch.call_count, 1)
#         # check wait call_count
#         self.assertEqual(mock_wait.call_count, 1)
        
if __name__ == "__main__":
    unittest.main()
