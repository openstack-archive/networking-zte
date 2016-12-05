#coding UTF-8
#!/usr/lib/python
from neutron.plugins.proxydriver.common.rest.znic_l2.znic_l2restconf import ZnicServerPool
from neutron.plugins.proxydriver.common.rest.servermanager import ServerPool
import unittest
import mock
from neutron.plugins.proxydriver.common.rest.znic_l2 import config
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import db
from neutron.db.common_db_mixin import CommonDbMixin

tenant_id = u'12wdd34ff'
tenant_name = 'tenant_name_test'
description = 'this is a description'

network_dict = {'id': u'123445',
               'name': 'networkname',
               'tenant_id': u'6e2112f3ddd84fa7a86df02dab60fc89',
               'admin_state_up':'admin_state_up',
               'mtu': 'mtu',
               'status': 'status',
               'shared': 'shared',
               'subnets': 'subnet'
}

sub_dict = {'id': u'123445',
               'name': 'networkname',
               'dns_nameservers': 'dns_nameservers',
               'allocation_pools':'allocation_pools',
               'host_routes': {'host_routes1':'host_routes2'},
               'gateway_ip': 'gateway_ip',
               'network_id': 'network_id',
               'cidr':'cidr',
               'ip_version':'ip_version'
}

port_dict = {'id': u'123445',
               'name': 'networkname',
               'allowed_address_pairs': [{'ip_address':1001,'mac_address':101}],
               'admin_state_up':'admin_state_up',
               'binding:profile': 'binding_profile',
               'device_owner': 'device_owner',
               'fixed_ips': [{'subnet_id':'subnet_id','ip_address':'ip_address'}],
               'security_groups':'security_groups',
               'band_width':'band_width',
               'burst_size':'burst_size',
               'dscp':'dscp',
               'extra_dhcp_opts':[{'opt_value':'opt_value','ip_version':'ip_version','opt_name':'opt_name'}],
               'network_id':'network_id',
               'mac_address':'mac_address',
               'port_security_enabled':'port_security_enabled'          
}

securitygroup_info = {"id": u'123445',
                       "name": 'name',
                       "description": "description",
                       "tenant_id": tenant_id,
                       'securitygroup_rules':[{'ethertype':'100046'}]
                      }

securitygroup_rule_info = {
                        "id": u'123445',
                        'name':'name',
                        "description": "description",
                        "port_range_max":'port_range_max',
                        "port_range_min":'port_range_min',
                        "protocol":'protocol',
                        "remote_group_id":'remote_group_id',
                        "remote_ipv4_prefix": 'remote_ipv4_prefix',
                        "remote_ipv6_prefix": 'remote_ipv6_prefix',
                        "security_group_id":'security_group_id',
                        'direction':'direction',
                        'ethertype':'100046',
                        'tenant_id':tenant_id
                      }


class FakeNetwork(object):
    def __init__(self):
        pass   
    def session(self):
        return None

class TestZnicl2restconf(unittest.TestCase):
   
    @mock.patch.object(db,"get_network_segments")
    def setUp(self,mock_get_network_segments):  
        self.tenant_id = tenant_id
        self.tenant_name = tenant_name
        self.description = description
        config.register_config()
        self.ZnicServerPool = ZnicServerPool(config.cfg.CONF.RESTPROXY.servers,
                config.cfg.CONF.RESTPROXY.server_auth,
                config.cfg.CONF.RESTPROXY.server_ssl,
                config.cfg.CONF.RESTPROXY.no_ssl_validation,
                config.cfg.CONF.RESTPROXY.ssl_sticky,
                config.cfg.CONF.RESTPROXY.ssl_cert_directory,
                config.cfg.CONF.RESTPROXY.consistency_interval,
                config.cfg.CONF.RESTPROXY.server_timeout,
                config.cfg.CONF.RESTPROXY.cache_connections) 
        
        plugin_context = FakeNetwork()
        self.mech_context = driver_context.NetworkContext(
                    None, plugin_context,network_dict)

        
        
    def tearDown(self):  
        self.tenant_id = None  
        self.tenant_name = None 
        self.description = None 
        
        
    def test_validate_dict(self):
        instance_dict = {'test':'test'}
        #if else
        self.ZnicServerPool.validate_dict(instance_dict, 'test', 'default')
        self.ZnicServerPool.validate_dict(instance_dict, 'default', 'default')
        #return
        self.assertEqual(self.ZnicServerPool.validate_dict(instance_dict, 'test', 'default'),'test')
        self.assertEqual(self.ZnicServerPool.validate_dict(instance_dict, 'default', 'default'),'default')
         
    def test_validate_ipv4(self):
        #if else
        self.ZnicServerPool.validate_ipv4('10.0.0.1', '0.0.0.0')  
        self.ZnicServerPool.validate_ipv4(0, '0.0.0.0')  
        self.ZnicServerPool.validate_ipv4(None, '0.0.0.0')   
         
        #return
        self.assertEqual(self.ZnicServerPool.validate_ipv4('10.0.0.1', '0.0.0.0'),'10.0.0.1')
        self.assertEqual(self.ZnicServerPool.validate_ipv4(0, '0.0.0.0'),'0.0.0.0')
        self.assertEqual(self.ZnicServerPool.validate_ipv4(None, '0.0.0.0'),'0.0.0.0')
         
        
    @mock.patch.object(CommonDbMixin,'_get_tenant_id_for_create')
    @mock.patch.object(db,"get_network_segments")
    def test_construct_network_info(self,mock_get_network_segments,mock_get_tenant_id_for_create):
         
        plugin_context = FakeNetwork()
        self.mech_context = driver_context.NetworkContext(
                    None, plugin_context,network_dict)
                  
        segmentation_id = self.mech_context.network_segments[0]['segmentation_id'] 
        tenant_id = CommonDbMixin._get_tenant_id_for_create(self.mech_context._plugin_context, self.mech_context.current) 
        action_list = ['DELETE','GET','CREATE','POST']
        
        #check _get_tenant_id_for_create call_count
        self.assertEqual(mock_get_tenant_id_for_create.call_count,(1),)
        #check _get_tenant_id_for_create call_args
        self.assertEqual(mock_get_tenant_id_for_create.call_args,((self.mech_context._plugin_context, self.mech_context.current),))       
        
        #if else
        for action in action_list:
            self.ZnicServerPool.construct_network_info(self.mech_context, action)
                
        #return
        self.assertEqual(self.ZnicServerPool.construct_network_info(self.mech_context, "DELETE"), {'input': {'id': u'123445'}})
        self.assertEqual(self.ZnicServerPool.construct_network_info(self.mech_context, "GET"), {'input': {'id': u'123445'}})
         
        self.assertEqual(self.ZnicServerPool.construct_network_info(self.mech_context, "CREATE"),
                         {'input': {'burst_size': 0, 
                                    'segmentation_id': segmentation_id, 
                                    'dscp': 0, 
                                    'external': False, 
                                    'id': u'123445', 
                                    'band_width': 0, 
                                    'name': 'networkname', 
                                    'admin_state_up': 'admin_state_up', 
                                    'tenant_id': tenant_id, 
                                    'mtu': 'mtu', 'shared': 'shared'}})
         
        self.assertEqual(self.ZnicServerPool.construct_network_info(self.mech_context, "POST"),
                         {'input': {'burst_size': 0, 
                                    'segmentation_id': segmentation_id, 
                                    'dscp': 0, 
                                    'external': False, 
                                    'port_security_enabled': True, 
                                    'id': u'123445', 
                                    'band_width': 0, 
                                    'name': 'networkname', 
                                    'admin_state_up': 'admin_state_up', 
                                    'tenant_id': tenant_id, 
                                    'mtu': 'mtu', 
                                    'shared': 'shared'}})
         
         
    @mock.patch.object(CommonDbMixin,'_get_tenant_id_for_create')
    @mock.patch.object(db,"get_network_segments")
    @mock.patch.object(ZnicServerPool,"validate_dict")
    def test_construct_subnet_info(self,mock_validate_dict,mock_get_network_segments,mock_get_tenant_id_for_create):
         
        plugin_context = FakeNetwork()
        self.mech_context = driver_context.NetworkContext(
                    None, plugin_context,sub_dict)
                  
        tenant_id = CommonDbMixin._get_tenant_id_for_create(self.mech_context._plugin_context, self.mech_context.current) 
         
        action_list = ['DELETE','GET','CREATE','POST']
        
        #check call_count
        self.assertEqual(mock_get_tenant_id_for_create.call_count,(1),)
        #check call_args
        self.assertEqual(mock_get_tenant_id_for_create.call_args,((self.mech_context._plugin_context, self.mech_context.current),))
        #if else
        for action in action_list:
            self.ZnicServerPool.construct_subnet_info(self.mech_context, action)      
         
        #return
        self.assertEqual(self.ZnicServerPool.construct_subnet_info(self.mech_context, "DELETE"), {'input': {'id': u'123445'}})
        self.assertEqual(self.ZnicServerPool.construct_subnet_info(self.mech_context, "GET"), {'input': {'id': u'123445'}})
          
        self.assertEqual(self.ZnicServerPool.construct_subnet_info(self.mech_context, "CREATE"),
                         {'input': {'dns_nameservers': 'd,n,s,_,n,a,m,e,s,e,r,v,e,r,s', 
                                    'gateway_ip': 'gateway_ip', 
                                    'allocation_pools': 'allocation_pools', 
                                    'host_routes': '', 
                                    'subnet_name': 'networkname', 
                                    'id': u'123445'}})
          
        self.assertEqual(self.ZnicServerPool.construct_subnet_info(self.mech_context, "POST"),
                         {'input': {'network_id': 'network_id', 
                                    'tenant_id': tenant_id, 
                                    'dns_nameservers': 'd,n,s,_,n,a,m,e,s,e,r,v,e,r,s', 
                                    'gateway_ip': 'gateway_ip', 
                                    'allocation_pools': 'allocation_pools', 
                                    'host_routes': '', 
                                    'ip_version': 'ip_version', 
                                    'subnet_name': 'networkname', 
                                    'cidr': 'cidr', 
                                    'id': u'123445'}})
         
    @mock.patch.object(CommonDbMixin,'_get_tenant_id_for_create')
    @mock.patch.object(db,"get_network_segments")
    @mock.patch.object(ZnicServerPool,"validate_dict")
    def test_construct_port_info(self,mock_validate_dict,mock_get_network_segments,mock_get_tenant_id_for_create):
         
        plugin_context = FakeNetwork()
        self.mech_context = driver_context.NetworkContext(
                    None, plugin_context,port_dict)
                  
        tenant_id = CommonDbMixin._get_tenant_id_for_create(self.mech_context._plugin_context, self.mech_context.current) 
         
        action_list = ['DELETE','GET','CREATE','POST','PUT']
        
        #check call_count
        self.assertEqual(mock_get_tenant_id_for_create.call_count,(1),)
        #check call_args
        self.assertEqual(mock_get_tenant_id_for_create.call_args,((self.mech_context._plugin_context, self.mech_context.current),))
        #if else
        for action in action_list:
            self.ZnicServerPool.construct_port_info(self.mech_context, action) 
                    
        #return
        self.assertEqual(self.ZnicServerPool.construct_port_info(self.mech_context, "DELETE"), {'input': {'id': u'123445'}})
        self.assertEqual(self.ZnicServerPool.construct_port_info(self.mech_context, "GET"), {'input': {'id': u'123445'}})
           
        self.assertEqual(self.ZnicServerPool.construct_port_info(self.mech_context, "CREATE"),
                         {'input': {'binding_profile': 'binding_profile', 
                                    'burst_size': self.ZnicServerPool.validate_dict(port_dict, 'cbs', 0), 
                                    'allowed_address_pairs': [{'ip_address': 1001, 'mac_address': 101}], 
                                    'dscp': self.ZnicServerPool.validate_dict(port_dict, 'dscp', 0), 
                                    'device_owner': 'device_owner', 
                                    'fixed_ips': [{'subnet_id': 'subnet_id', 'ip_address': 'ip_address'}], 
                                    'id': u'123445', 
                                    'band_width': self.ZnicServerPool.validate_dict(port_dict, 'bandwidth', 0), 
                                    'name': 'networkname', 
                                    'admin_state_up': 'admin_state_up',
                                    'security_groups': 'security_groups'}})
             
        self.assertEqual(self.ZnicServerPool.construct_port_info(self.mech_context, "POST"),
                         {'input': {'binding_profile': 'binding_profile', 
                                    'burst_size': self.ZnicServerPool.validate_dict(port_dict, 'cbs', 0), 
                                    'allowed_address_pairs': [{'ip_address': 1001, 'mac_address': 101}], 
                                    'extra_dhcp_opts': [{'opt_value': 'opt_value', 'ip_version': 'ip_version', 'opt_name': 'opt_name'}], 
                                    'dscp': self.ZnicServerPool.validate_dict(port_dict, 'dscp', 0), 
                                    'device_owner': 'device_owner', 
                                    'port_security_enabled': self.ZnicServerPool.validate_dict(port_dict, 'port_security_enabled', 0), 
                                    'fixed_ips': [{'subnet_id': 'subnet_id', 'ip_address': 'ip_address'}], 
                                    'id': u'123445', 
                                    'band_width': self.ZnicServerPool.validate_dict(port_dict, 'bandwidth', 0), 
                                    'name': 'networkname', 
                                    'admin_state_up': 'admin_state_up', 
                                    'network_id': 'network_id', 
                                    'tenant_id': tenant_id, 
                                    'security_groups': 'security_groups', 
                                    'mac_address': 'mac_address'}})
         
         
        self.assertEqual(self.ZnicServerPool.construct_port_info(self.mech_context, "PUT"),
                         {'input': {'binding_profile': 'binding_profile', 
                                    'burst_size': self.ZnicServerPool.validate_dict(port_dict, 'burst_size', 0), 
                                    'allowed_address_pairs': [{'ip_address': 1001, 'mac_address': 101}], 
                                    'extra_dhcp_opts': [{'opt_value': 'opt_value', 'ip_version': 'ip_version', 'opt_name': 'opt_name'}], 
                                    'dscp': self.ZnicServerPool.validate_dict(port_dict, 'dscp', 0), 
                                    'device_owner': 'device_owner', 
                                    'fixed_ips': [{'subnet_id': 'subnet_id', 'ip_address': 'ip_address'}], 
                                    'id': u'123445', 
                                    'band_width': self.ZnicServerPool.validate_dict(port_dict, 'band_width', 0), 
                                    'name': 'networkname', 
                                    'admin_state_up': 'admin_state_up', 
                                    'security_groups': 'security_groups'}})
        
        
    @mock.patch.object(CommonDbMixin,'_get_tenant_id_for_create')
    @mock.patch.object(db,"get_network_segments")
    @mock.patch.object(ZnicServerPool,"validate_dict")
    def test_construct_securitygroup_info(self,mock_validate_dict,mock_get_network_segments,mock_get_tenant_id_for_create):
         
        plugin_context = FakeNetwork()
        self.mech_context = driver_context.NetworkContext(
                    None, plugin_context,securitygroup_info)
                  
        tenant_id = CommonDbMixin._get_tenant_id_for_create(self.mech_context._plugin_context, self.mech_context.current) 
         
        action_list = ['DELETE','GET','POST','PUT']
        
        #check call_count
        self.assertEqual(mock_get_tenant_id_for_create.call_count,(1),)
        #check call_args
        self.assertEqual(mock_get_tenant_id_for_create.call_args,((self.mech_context._plugin_context, self.mech_context.current),))
        #if else
        for action in action_list:
            self.ZnicServerPool.construct_securitygroup_info(self.mech_context, action) 
         
        #return
        self.assertEqual(self.ZnicServerPool.construct_securitygroup_info(self.mech_context, "DELETE"), {'input': {'id': u'123445'}})
        self.assertEqual(self.ZnicServerPool.construct_securitygroup_info(self.mech_context, "GET"), {'input': {'id': u'123445'}})
            
        self.assertEqual(self.ZnicServerPool.construct_securitygroup_info(self.mech_context, "POST"),
                         {'input': {'tenant_id': tenant_id, 
                                    'description': 'description', 
                                    'id': u'123445', 
                                    'security_group_rules': [], 
                                    'name': 'name'}})
            
        self.assertEqual(self.ZnicServerPool.construct_securitygroup_info(self.mech_context, "PUT"),
                         {'input': {'tenant_id': tenant_id, 
                                    'description': 'description', 
                                    'id': u'123445', 
                                    'name': 'name'}})
        
        
    @mock.patch.object(CommonDbMixin,'_get_tenant_id_for_create')
    @mock.patch.object(db,"get_network_segments")
    @mock.patch.object(ZnicServerPool,"validate_dict")
    def test_construct_securitygroup_rule_info(self,mock_validate_dict,mock_get_network_segments,mock_get_tenant_id_for_create):
        
        plugin_context = FakeNetwork()
        self.mech_context = driver_context.NetworkContext(
                    None, plugin_context,securitygroup_rule_info)
        
        sg = self.mech_context.current
                 
        tenant_id = CommonDbMixin._get_tenant_id_for_create(self.mech_context._plugin_context, sg) 
        
        action_list = ['DELETE','GET','POST','PUT']
        
        #check call_count
        self.assertEqual(mock_get_tenant_id_for_create.call_count,(1),)
        #check call_args
        self.assertEqual(mock_get_tenant_id_for_create.call_args,((self.mech_context._plugin_context, self.mech_context.current),))
        #if else
        for action in action_list:
            self.ZnicServerPool.construct_securitygroup_rule_info(self.mech_context, action)
            
         
        
    @mock.patch.object(ServerPool,'rest_action')
    def test_rest_create_tenant(self,mock_rest_action):   
        #check logic
        self.ZnicServerPool.rest_create_tenant(tenant_id,tenant_name,description)
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 
                                                      'add-tenant', 
                                                      {'input': {'description': 'this is a description', 'id': u'12wdd34ff', 'name': 'tenant_name_test'}},
                                                       u'Unable to create tenant: %s'),))
                
    @mock.patch.object(ServerPool,'rest_action')
    def test_rest_update_tenant(self,mock_rest_action):   
        #check logic
        self.ZnicServerPool.rest_update_tenant(tenant_id,tenant_name,description)
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 
                                                      'update-tenant', 
                                                      {'input': {'description': 'this is a description', 'id': u'12wdd34ff', 'name': 'tenant_name_test'}},
                                                       u'Unable to update tenant: %s'),))     
   
    @mock.patch.object(ServerPool,'rest_action')
    def test_rest_delete_tenant(self,mock_rest_action):  
        #check logic
        self.ZnicServerPool.rest_delete_tenant(tenant_id)
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'del-tenant', {'input': {'id': u'12wdd34ff'}}, u'Unable to delete tenant: %s'),))        
           
    @mock.patch.object(ServerPool,'rest_action')
    def test_rest_get_tenant(self,mock_rest_action):     
        #check logic
        self.ZnicServerPool.rest_get_tenant(tenant_id)
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'get-tenant', {'input': {'id': u'12wdd34ff'}}, u'Unable to get tenant: %s'),)) 

    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_network_info')  
    def test_rest_create_network(self,mock_construct_network_info,mock_rest_action):            
        #check logic
        self.ZnicServerPool.rest_create_network(self.mech_context)
        #check construct_network_info call_count
        self.assertEqual(mock_construct_network_info.call_count, (1),)
        #check construct_network_info call_args     
        self.assertEqual(mock_construct_network_info.call_args,((self.mech_context, 'POST'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'add-network', self.ZnicServerPool.construct_network_info(self.mech_context, 'POST'), 
                                                      u'Unable to create remote network: %s'),))    
                  
        
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_network_info')
    def test_rest_update_network(self,mock_construct_network_info,mock_rest_action):  
        #check logic
        self.ZnicServerPool.rest_update_network(self.mech_context)
        #check construct_network_info call_count
        self.assertEqual(mock_construct_network_info.call_count, (1),)
        #check construct_network_info call_args     
        self.assertEqual(mock_construct_network_info.call_args,((self.mech_context, 'PUT'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'update-network', self.ZnicServerPool.construct_network_info(self.mech_context, 'PUT'), 
                                                      u'Unable to update remote network: %s'),))          
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_network_info')
    def test_rest_delete_network(self,mock_construct_network_info,mock_rest_action):       
        #check logic
        self.ZnicServerPool.rest_delete_network(self.mech_context)
        #check construct_network_info call_count
        self.assertEqual(mock_construct_network_info.call_count, (1),)
        #check construct_network_info call_args     
        self.assertEqual(mock_construct_network_info.call_args,((self.mech_context, 'DELETE'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'del-network', self.ZnicServerPool.construct_network_info(self.mech_context, 'DELETE'), 
                                                      u'Unable to delete remote network: %s'),))         
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_network_info')
    def test_rest_get_network(self,mock_construct_network_info,mock_rest_action):    
        #check logic
        self.ZnicServerPool.rest_get_network(self.mech_context)
        #check construct_network_info call_count
        self.assertEqual(mock_construct_network_info.call_count, (1),)
        #check construct_network_info call_args     
        self.assertEqual(mock_construct_network_info.call_args,((self.mech_context, 'GET'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'get-network', self.ZnicServerPool.construct_network_info(self.mech_context, 'GET'), 
                                                      u'Unable to get remote network: %s'),))          
          
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_subnet_info')
    def test_rest_create_subnet(self,mock_construct_subnet_info,mock_rest_action):              
        #check logic
        self.ZnicServerPool.rest_create_subnet(self.mech_context)
        #check construct_subnet_info call_count
        self.assertEqual(mock_construct_subnet_info.call_count, (1),)
        #check construct_subnet_info call_args     
        self.assertEqual(mock_construct_subnet_info.call_args,((self.mech_context, 'POST'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'add-subnet', self.ZnicServerPool.construct_subnet_info(self.mech_context, 'POST'), 
                                                      u'Unable to create remote subnet: %s'),))       
    
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_subnet_info')
    def test_rest_update_subnet(self,mock_construct_subnet_info,mock_rest_action): 
        #check logic
        self.ZnicServerPool.rest_update_subnet(self.mech_context)
        #check construct_subnet_info call_count
        self.assertEqual(mock_construct_subnet_info.call_count, (1),)
        #check construct_subnet_info call_args     
        self.assertEqual(mock_construct_subnet_info.call_args,((self.mech_context, 'PUT'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'update-subnet', self.ZnicServerPool.construct_subnet_info(self.mech_context, 'PUT'), 
                                                      u'Unable to update remote subnet: %s'),))                     
  
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_subnet_info')
    def test_rest_delete_subnet(self,mock_construct_subnet_info,mock_rest_action):      
        #check logic
        self.ZnicServerPool.rest_delete_subnet(self.mech_context)
        #check construct_subnet_info call_count
        self.assertEqual(mock_construct_subnet_info.call_count, (1),)
        #check construct_subnet_info call_args     
        self.assertEqual(mock_construct_subnet_info.call_args,((self.mech_context, 'DELETE'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'del-subnet', self.ZnicServerPool.construct_subnet_info(self.mech_context, 'DELETE'), 
                                                      u'Unable to delete remote subnet: %s'),))       
           
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_subnet_info')
    def test_rest_get_subnet(self,mock_construct_subnet_info,mock_rest_action):   
        #check logic
        self.ZnicServerPool.rest_get_subnet(self.mech_context)
        #check construct_subnet_info call_count
        self.assertEqual(mock_construct_subnet_info.call_count, (1),)
        #check construct_subnet_info call_args     
        self.assertEqual(mock_construct_subnet_info.call_args,((self.mech_context, 'GET'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'get-subnet', self.ZnicServerPool.construct_subnet_info(self.mech_context, 'GET'), 
                                                      u'Unable to get remote subnet: %s'),))                  
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_port_info')
    def test_rest_create_port(self,mock_construct_port_info,mock_rest_action):  
        #check logic
        self.ZnicServerPool.rest_create_port(self.mech_context)
        #check construct_port_info call_count
        self.assertEqual(mock_construct_port_info.call_count, (1),)
        #check construct_port_info call_args     
        self.assertEqual(mock_construct_port_info.call_args,((self.mech_context, 'POST'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'add-port', self.ZnicServerPool.construct_port_info(self.mech_context, 'POST'), 
                                                      u'Unable to create remote port: %s'),))                        
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_port_info')
    def test_rest_update_port(self,mock_construct_port_info,mock_rest_action):  
        #check logic
        self.ZnicServerPool.rest_update_port(self.mech_context)
        #check construct_port_info call_count
        self.assertEqual(mock_construct_port_info.call_count, (1),)
        #check construct_port_info call_args     
        self.assertEqual(mock_construct_port_info.call_args,((self.mech_context, 'PUT'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'update-port', self.ZnicServerPool.construct_port_info(self.mech_context, 'PUT'), 
                                                      u'Unable to update remote port: %s'),))                 
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_port_info')
    def test_rest_delete_port(self,mock_construct_port_info,mock_rest_action):  
        #check logic
        self.ZnicServerPool.rest_delete_port(self.mech_context)
        #check construct_port_info call_count
        self.assertEqual(mock_construct_port_info.call_count, (1),)
        #check construct_port_info call_args     
        self.assertEqual(mock_construct_port_info.call_args,((self.mech_context, 'DELETE'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'del-port', self.ZnicServerPool.construct_port_info(self.mech_context, 'DELETE'), 
                                                      u'Unable to delete remote port: %s'),))                       
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_port_info')
    def test_rest_get_port(self,mock_construct_port_info,mock_rest_action):  
        #check logic
        self.ZnicServerPool.rest_get_port(self.mech_context)
        #check construct_port_info call_count
        self.assertEqual(mock_construct_port_info.call_count, (1),)
        #check construct_port_info call_args     
        self.assertEqual(mock_construct_port_info.call_args,((self.mech_context, 'GET'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'get-port', self.ZnicServerPool.construct_port_info(self.mech_context, 'GET'), 
                                                      u'Unable to get remote port: %s'),))                    

           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_securitygroup_info')
    def test_rest_create_securitygroup(self,mock_construct_securitygroup_info,mock_rest_action):      
        #check logic
        self.ZnicServerPool.rest_create_securitygroup(self.mech_context)
        #check construct_securitygroup_info call_count
        self.assertEqual(mock_construct_securitygroup_info.call_count, (1),)
        #check construct_securitygroup_info call_args     
        self.assertEqual(mock_construct_securitygroup_info.call_args,((self.mech_context, 'POST'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'add-sg', self.ZnicServerPool.construct_securitygroup_info(self.mech_context, 'POST'), 
                                                      u'Unable to create remote securitygroup: %s'),))              

           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_securitygroup_info')
    def test_rest_update_securitygroup(self,mock_construct_securitygroup_info,mock_rest_action):       
        #check logic
        self.ZnicServerPool.rest_update_securitygroup(self.mech_context)
        #check construct_securitygroup_info call_count
        self.assertEqual(mock_construct_securitygroup_info.call_count, (1),)
        #check construct_securitygroup_info call_args     
        self.assertEqual(mock_construct_securitygroup_info.call_args,((self.mech_context, 'PUT'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'update-sg', self.ZnicServerPool.construct_securitygroup_info(self.mech_context, 'PUT'), 
                                                      u'Unable to update remote securitygroup: %s'),))                
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_securitygroup_info')
    def test_rest_delete_securitygroup(self,mock_construct_securitygroup_info,mock_rest_action):   
        #check logic
        self.ZnicServerPool.rest_delete_securitygroup(self.mech_context)
        #check construct_securitygroup_info call_count
        self.assertEqual(mock_construct_securitygroup_info.call_count, (1),)
        #check construct_securitygroup_info call_args     
        self.assertEqual(mock_construct_securitygroup_info.call_args,((self.mech_context, 'DELETE'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'del-sg', self.ZnicServerPool.construct_securitygroup_info(self.mech_context, 'DELETE'), 
                                                      u'Unable to delete remote securitygroup: %s'),))                    
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_securitygroup_info')
    def test_rest_get_securitygroup(self,mock_construct_securitygroup_info,mock_rest_action):     
        #check logic
        self.ZnicServerPool.rest_get_securitygroup(self.mech_context)
        #check construct_securitygroup_info call_count
        self.assertEqual(mock_construct_securitygroup_info.call_count, (1),)
        #check construct_securitygroup_info call_args     
        self.assertEqual(mock_construct_securitygroup_info.call_args,((self.mech_context, 'GET'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'get-sg', self.ZnicServerPool.construct_securitygroup_info(self.mech_context, 'GET'), 
                                                      u'Unable to get remote securitygroup: %s'),))               
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_securitygroup_rule_info')
    def test_rest_create_securitygroup_rule(self,mock_construct_securitygroup_rule_info,mock_rest_action):    
        #check logic
        self.ZnicServerPool.rest_create_securitygroup_rule(self.mech_context)
        #check construct_securitygroup_rule_info call_count
        self.assertEqual(mock_construct_securitygroup_rule_info.call_count, (1),)
        #check construct_securitygroup_rule_info call_args     
        self.assertEqual(mock_construct_securitygroup_rule_info.call_args,((self.mech_context, 'POST'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'add-sg-rule', self.ZnicServerPool.construct_securitygroup_rule_info(self.mech_context, 'POST'), 
                                                      u'Unable to create remote securitygroup_rule: %s'),))              
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_securitygroup_rule_info')
    def test_rest_update_securitygroup_rule(self,mock_construct_securitygroup_rule_info,mock_rest_action):    
        #check logic
        self.ZnicServerPool.rest_update_securitygroup_rule(self.mech_context)
        #check construct_securitygroup_rule_info call_count
        self.assertEqual(mock_construct_securitygroup_rule_info.call_count, (1),)
        #check construct_securitygroup_rule_info call_args     
        self.assertEqual(mock_construct_securitygroup_rule_info.call_args,((self.mech_context, 'PUT'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'update-sg-rule', 
                                                      self.ZnicServerPool.construct_securitygroup_rule_info(self.mech_context, 'PUT'), 
                                                      u'Unable to update remote securitygroup_rule: %s'),))             
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_securitygroup_rule_info')
    def test_rest_delete_securitygroup_rule(self,mock_construct_securitygroup_rule_info,mock_rest_action):     
        #check logic
        self.ZnicServerPool.rest_delete_securitygroup_rule(self.mech_context)
        #check construct_securitygroup_rule_info call_count
        self.assertEqual(mock_construct_securitygroup_rule_info.call_count, (1),)
        #check construct_securitygroup_rule_info call_args     
        self.assertEqual(mock_construct_securitygroup_rule_info.call_args,((self.mech_context, 'DELETE'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'del-sg-rule', 
                                                      self.ZnicServerPool.construct_securitygroup_rule_info(self.mech_context, 'DELETE'), 
                                                      u'Unable to delete remote securitygroup_rule: %s'),))              
           
    @mock.patch.object(ServerPool,'rest_action')
    @mock.patch.object(ZnicServerPool,'construct_securitygroup_rule_info')
    def test_rest_get_securitygroup_rule(self,mock_construct_securitygroup_rule_info,mock_rest_action):  
        #check logic
        self.ZnicServerPool.rest_get_securitygroup_rule(self.mech_context)
        #check construct_securitygroup_rule_info call_count
        self.assertEqual(mock_construct_securitygroup_rule_info.call_count, (1),)
        #check construct_securitygroup_rule_info call_args     
        self.assertEqual(mock_construct_securitygroup_rule_info.call_args,((self.mech_context, 'GET'),)) 
        #check rest_action call_count
        self.assertEqual(mock_rest_action.call_count, (1),)
        #check rest_action call_args     
        self.assertEqual(mock_rest_action.call_args,(('POST', 'get-sg-rule', 
                                                      self.ZnicServerPool.construct_securitygroup_rule_info(self.mech_context, 'GET'), 
                                                      u'Unable to get remote securitygroup_rule: %s'),))                    
          
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()