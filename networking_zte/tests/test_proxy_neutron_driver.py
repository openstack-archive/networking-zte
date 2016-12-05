
import unittest
import mock
from oslo_config import cfg
from neutron.plugins.proxydriver.proxy_neutron_driver import ProxyMechanismDriver
from neutron.plugins.proxydriver.common.rest.znic_l2.mech_znic_l2 import ZnicL2Driver
from neutron.plugins.proxydriver.common.rest import servermanager
from neutron.plugins.proxydriver import driver_context as context
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import db

proxy_opts = [
    cfg.StrOpt(
        'driver_list',
        default='sdn:neutron.plugins.proxydriver.'
                'common.rest.znic_l2.mech_znic_l2.ZnicL2Driver',
        help="Define the drivers of proxy agent"),
]
class test_proxy_neutron_driver(unittest.TestCase):
    def setUp(self):
        CONF = cfg.CONF
        CONF.register_opts(proxy_opts, 'ml2')
        CONF.notify_nova_on_port_status_changes=False
        CONF.ml2.mechanism_drivers = 'neutron.plugins.proxydriver.proxy_neutron_driver:ProxyMechanismDriver'
        self.proxydriver = ProxyMechanismDriver()

    def tearDown(self):
        unittest.TestCase.tearDown(self)
    
    def test_load_driver_provider(self):
       # provider ={'sdn':'<neutron.plugins.proxydriver.common.rest.znic_l2.mech_znic_l2.ZnicL2Driver'}
        self.proxydriver.initialize()
        print("driver_providers = %s",self.proxydriver.driver_provider['sdn'])
        #self.assertEqual(provider['sdn'], self.proxydriver.driver_provider['sdn'])
        self.assertIsNotNone(self.proxydriver.driver_provider['sdn'])

    @mock.patch.object(ZnicL2Driver,'create_network')
    def test_call_on_drivers(self,mock_create_network):
        context = {}
        self.proxydriver.initialize()
        self.proxydriver._call_on_drivers('create_network', context)
        mock_create_network.assert_called_once_with(context)
    
    def test_call_on_drivers_error(self):
        context = {}
        self.proxydriver.initialize()
        self.proxydriver._call_on_drivers('xxx', context)
        self.assertRaises(AttributeError)

    @mock.patch.object(ZnicL2Driver,'create_network')
    def test_call_on_drivers_exception(self,mock_create_network):
        context = {}
        mock_create_network.side_effect = servermanager.RemoteRestError
        self.proxydriver.initialize()
 #       self.proxydriver._call_on_drivers('create_network', context)
        with self.assertRaises(ml2_exc.MechanismDriverError):
            self.proxydriver._call_on_drivers('create_network', context)


network_dict = {'id': u'123445',
               'name': 'networkname',
               'tenant_id': u'6e2112f3ddd84fa7a86df02dab60fc89',
               'admin_state_up':'admin_state_up',
               'mtu': 'mtu',
               'status': 'status',
               'shared': 'shared',
               'subnets': 'subnet'
}
port_dict ={'status': 'ACTIVE',
            'subnets': [],
            'provider:physical_network': None,
            'mtu': 0,
            'id': '9415325c-d2f0-47f2-a899-6132c4693bc5',
            'provider:segmentation_id': 10006L,
            'router:external': False,
            'name': u'test3case',
            'admin_state_up': True,
            'tenant_id': u'6e2112f3ddd84fa7a86df02dab60fc89',
            'provider:network_type': u'vxlan',
            'vlan_transparent': None,
            'shared': False
       }

class FakeNetwork(object):
    def __init__(self):
        pass   
    def session(self):
        return None

class TestPostCommit(unittest.TestCase):
    
    def setUp(self):  
        CONF = cfg.CONF
        CONF.notify_nova_on_port_status_changes=False
        CONF.ml2.mechanism_drivers = 'neutron.plugins.proxydriver.proxy_neutron_driver:ProxyMechanismDriver'
        self.proxyMechanismDriver = ProxyMechanismDriver()
    def tearDown(self):  
        pass

    @mock.patch.object(db,"get_network_segments")
    @mock.patch.object(ProxyMechanismDriver,"_ensure_default_security_group")
    @mock.patch.object(ProxyMechanismDriver,"get_security_group")
    @mock.patch.object(ZnicL2Driver,'create_port')
    @mock.patch.object(ZnicL2Driver,'create_security_group')
    @mock.patch.object(context,"SecurityGroupContext")
    def test_create_port_postcommit(self,mock_sgcontext,mock_create_sg,mock_create_port,mock_get_sg,mock_ensure_sg,mock_segments):   
        plugin_context = FakeNetwork()
        mock_segments.return_code =1
        network_context = driver_context.PortContext(
                    None, plugin_context,port_dict,network_dict,None,None,None)
        mech_context = context.SecurityGroupContext(
                self, network_context._plugin_context, False)
        mock_sgcontext.return_code = mech_context
        self.proxyMechanismDriver.initialize()
        self.proxyMechanismDriver.create_port_postcommit(network_context)
        mock_create_port.assert_called_once_with(network_context)
        mock_create_sg.assert_called_once_with(mech_context)


    @mock.patch.object(db,"get_network_segments")
    @mock.patch.object(ProxyMechanismDriver,"_ensure_default_security_group")
    @mock.patch.object(ProxyMechanismDriver,"get_security_group")
    @mock.patch.object(ZnicL2Driver,"create_security_group")
    def test_create_port_postcommit_exception(self,mock_create_sg,mock_get_sg,mock_ensure_sg,mock_segments):  
        plugin_context = FakeNetwork() 
        network_context = driver_context.PortContext(
                    None, plugin_context,port_dict,network_dict,None,None,None)
       
        mock_create_sg.side_effect = ml2_exc.MechanismDriverError

        self.proxyMechanismDriver.initialize()
        with self.assertRaises(ml2_exc.MechanismDriverError):
            self.proxyMechanismDriver.create_port_postcommit(network_context)
            mock_create_sg.assert_called_once_with(network_context)


    @mock.patch.object(db,"get_network_segments")
    @mock.patch.object(ProxyMechanismDriver,"_ensure_default_security_group")
    @mock.patch.object(ProxyMechanismDriver,"get_security_group")
    @mock.patch.object(ZnicL2Driver,'create_network')
    @mock.patch.object(ZnicL2Driver,'create_security_group')
    @mock.patch.object(context,"SecurityGroupContext")
    def test_create_network_postcommit(self,mock_sgcontext,mock_create_sg,mock_create_network,mock_get_sg,mock_ensure_sg,mock_segments):  
        plugin_context = FakeNetwork() 
        network_context = driver_context.NetworkContext(
                    None, plugin_context,network_dict)
        mech_context = context.SecurityGroupContext(
                self, network_context._plugin_context, False)
        mock_sgcontext.return_code = mech_context
        self.proxyMechanismDriver.initialize()
        self.proxyMechanismDriver.create_network_postcommit(network_context)
        mock_create_network.assert_called_once_with(network_context)
        mock_create_sg.assert_called_once_with(mech_context)


    @mock.patch.object(db,"get_network_segments")
    @mock.patch.object(ProxyMechanismDriver,"_ensure_default_security_group")
    @mock.patch.object(ProxyMechanismDriver,"get_security_group")
    @mock.patch.object(ZnicL2Driver,"create_security_group")
    def test_create_network_postcommit_exception(self,mock_create_sg,mock_get_sg,mock_ensure_sg,mock_segments):  
        plugin_context = FakeNetwork() 
        mock_segments.return_code =1
        network_context = driver_context.NetworkContext(
                    None, plugin_context,network_dict)
        mock_create_sg.side_effect = ml2_exc.MechanismDriverError

        self.proxyMechanismDriver.initialize()
        with self.assertRaises(ml2_exc.MechanismDriverError):
            self.proxyMechanismDriver.create_network_postcommit(network_context)
            mock_create_sg.assert_called_once_with(network_context)  
      
    @mock.patch.object(ZnicL2Driver,'delete_network')
    def test_delete_network_precommit(self,mock_delete_network):
        context = {}
        self.proxyMechanismDriver.initialize()
        self.proxyMechanismDriver.delete_network_precommit(context)
        mock_delete_network.assert_called_once_with(context) 

    @mock.patch.object(ZnicL2Driver,'update_network')
    def test_update_network_postcommit(self,mock_update_network):
        context = {}
        self.proxyMechanismDriver.initialize()
        self.proxyMechanismDriver.update_network_postcommit(context)
        mock_update_network.assert_called_once_with(context)
    
    @mock.patch.object(ZnicL2Driver,'create_subnet')
    def test_create_subnet_postcommit(self,mock_create_subnet):
        context = {}
        self.proxyMechanismDriver.initialize()
        self.proxyMechanismDriver.create_subnet_postcommit(context)
        mock_create_subnet.assert_called_once_with(context)
    
    @mock.patch.object(ZnicL2Driver,'update_subnet')
    def test_update_subnet_postcommit(self,mock_update_subnet):
        context = {}
        self.proxyMechanismDriver.initialize()
        self.proxyMechanismDriver.update_subnet_postcommit(context)
        mock_update_subnet.assert_called_once_with(context)
    
    @mock.patch.object(ZnicL2Driver,'delete_subnet')
    def test_delete_subnet_postcommit(self,mock_delete_network):
        context = {}
        self.proxyMechanismDriver.initialize()
        self.proxyMechanismDriver.delete_subnet_postcommit(context)
        mock_delete_network.assert_called_once_with(context)

    @mock.patch.object(ZnicL2Driver,'update_port')
    def test_update_port_postcommit(self,mock_update_port):
        context = {}
        self.proxyMechanismDriver.initialize()
        self.proxyMechanismDriver.update_port_postcommit(context)
        mock_update_port.assert_called_once_with(context)
    
    @mock.patch.object(ZnicL2Driver,'delete_port')
    def test_delete_port_postcommit(self,mock_delete_port):
        context = {}
        self.proxyMechanismDriver.initialize()
        self.proxyMechanismDriver.delete_port_postcommit(context)
        mock_delete_port.assert_called_once_with(context)

    @mock.patch.object(ZnicL2Driver,'create_security_group')
    def test_create_security_group_postcommit(self,mock_create_security_group):
        context = {}
        self.proxyMechanismDriver.initialize()
        self.proxyMechanismDriver.create_security_group_postcommit(context)
        mock_create_security_group.assert_called_once_with(context)
    
    @mock.patch.object(ZnicL2Driver,'delete_security_group')
    def test_delete_security_group_postcommit(self,mock_delete_security_group):
        context = {}
        self.proxyMechanismDriver.initialize()
        self.proxyMechanismDriver.delete_security_group_postcommit(context)
        mock_delete_security_group.assert_called_once_with(context)
    
    @mock.patch.object(ZnicL2Driver,'create_security_group_rule')
    def test_create_security_group_rule_postcommit(self,mock_create_security_group_rule):
        context = {}
        self.proxyMechanismDriver.initialize()
        self.proxyMechanismDriver.create_security_group_rule_postcommit(context)
        mock_create_security_group_rule.assert_called_once_with(context)
    
    @mock.patch.object(ZnicL2Driver,'delete_security_group_rule')
    def test_delete_security_group_rule_postcommit(self,mock_delete_security_group_rule):
        context = {}
        self.proxyMechanismDriver.initialize()
        self.proxyMechanismDriver.delete_security_group_rule_postcommit(context)
        mock_delete_security_group_rule.assert_called_once_with(context)

if __name__ == "__main__":
    unittest.main()  