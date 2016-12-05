#coding UTF-8
#!/usr/lib/python

import unittest
import mock
import httplib
import socket
import ssl
import os

from neutron.plugins.proxydriver.common.rest.servermanager import ServerPool
from neutron.plugins.proxydriver.common.rest.servermanager import ServerProxy
from neutron.plugins.proxydriver.common.rest.servermanager import HTTPSConnectionWithValidation
from neutron.plugins.proxydriver.common.rest.servermanager import RemoteRestError
from oslo_serialization.jsonutils import loads
from oslo_config import cfg


TOPOLOGY_PATH = "/topology"

class TestServerProxy(unittest.TestCase):
    
    @mock.patch.object(ServerPool,'_get_combined_cert_for_server')
    def setUp(self,mock_get_combined_cert_for_server):    
        self.server = 'server'
        self.port = '10.0.0.1'
        self.ssl = 'ssl'
        self.auth = 'auth'
        self.timeout = 'timeout'
        self.base_uri = '/'
        self.success_codes = range(200, 207)
        self.name = 'name'
        self.combined_cert = ServerPool._get_combined_cert_for_server(self.server, self.port)
        self.ServerProxy = ServerProxy(self.server, self.port, self.ssl, self.auth,
                           self.timeout, self.base_uri, self.success_codes,
                           self.name, combined_cert=self.combined_cert)
    def tearDown(self):  
        pass 
    
    @mock.patch('httplib.HTTPSConnection')
    def test_rest_call(self,mock_HTTPSConnection):   
        mock_HTTPSConnection.return_value = None    
        #if not headers 
        self.ServerProxy.rest_call('POST', TOPOLOGY_PATH, data='')
        #check return 
        self.assertEqual(self.ServerProxy.rest_call('POST', TOPOLOGY_PATH, data=''), (0, None, None, None),)

     
    @mock.patch('httplib.HTTPConnection')
    def test_rest_call_sslFalse(self,mock_HTTPConnection):
        self.ServerProxy.ssl = False
        mock_HTTPConnection.return_value = None
        self.ServerProxy.rest_call('POST', TOPOLOGY_PATH, data='')
        #check return 
        self.assertEqual(self.ServerProxy.rest_call('POST', TOPOLOGY_PATH, data=''), (0, None, None, None),)
        
    @mock.patch('oslo_serialization.jsonutils.loads')
    @mock.patch.object(httplib.HTTPResponse,'read')
    @mock.patch.object(httplib.HTTPConnection,'getresponse')
    @mock.patch.object(httplib.HTTPConnection,'request')
    def test_rest_call_try(self,mock_request,mock_getresponse,mock_read,mock_loads):  
        #check if ssl
        self.ServerProxy.success_codes = [httplib.HTTPConnection.getresponse().status]
        self.ServerProxy.rest_call('POST', TOPOLOGY_PATH, data='',headers={'headers':'headers'})  
        
    @mock.patch('oslo_serialization.jsonutils.loads')
    @mock.patch.object(httplib.HTTPResponse,'read')
    @mock.patch.object(httplib.HTTPConnection,'getresponse')
    @mock.patch.object(httplib.HTTPConnection,'request')
    def test_rest_call_ValueError(self,mock_request,mock_getresponse,mock_read,mock_loads):  
        self.ServerProxy.success_codes = [httplib.HTTPConnection.getresponse().status]
        mock_loads.side_effect = ValueError
        self.ServerProxy.rest_call('POST', TOPOLOGY_PATH, data='',headers={'headers':'headers'})          
        
    @mock.patch.object(httplib.HTTPConnection,'request')
    def test_rest_call_timeoutError(self,mock_request):  
        mock_request.side_effect = socket.timeout
        self.ServerProxy.rest_call('POST', TOPOLOGY_PATH, data='',headers={'headers':'headers'})  
        #check return 
        self.assertEqual(self.ServerProxy.rest_call('POST', TOPOLOGY_PATH, data='',headers={'headers':'headers'}), (9, None, None, None),)
        
    @mock.patch.object(httplib.HTTPConnection,'close')
    @mock.patch.object(httplib.HTTPConnection,'request')
    def test_rest_call_socketError(self,mock_request,mock_close):  
        mock_request.side_effect = socket.error
        self.ServerProxy.rest_call('POST', TOPOLOGY_PATH, data='',headers={'headers':'headers'}) 
        #check close call_count
        self.assertEqual(mock_close.call_count, 1) 
        #check return 
        self.assertEqual(self.ServerProxy.rest_call('POST', TOPOLOGY_PATH, data='',headers={'headers':'headers'}), (0, None, None, None),)
        
        

class TestServerPool(unittest.TestCase):
    
    def setUp(self):
        self.servers = ['10.1.1.1','10.1.1.2']
        self.auth = 'auth'
        self.ssl = 'ssl'
        self.base_uri = 'base_uri'
        self.success_codes = 'range(200, 207)'
        self.failure_codes = [301, 302, 303]
        self.name = 'NeutronRestProxy'
        self.timeout = False
        self.always_reconnect = 'always_reconnect'
        self.consistency_interval = 'consistency_interval'
        self.no_ssl_validation = 'no_ssl_validation'
        self.ssl_cert_directory = 'ssl_cert_directory'
        self.ssl_sticky = 'ssl_sticky'
        self.cache_connections=False
        default_port = 8000

        self.ServerPool = ServerPool(self.servers, self.auth, self.ssl, self.no_ssl_validation, self.ssl_sticky,
                  self.ssl_cert_directory, self.consistency_interval,
                  self.timeout, self.cache_connections,self.base_uri, self.success_codes,self.failure_codes, self.name)
        
    def tearDown(self):
        targetDir = '/home/test/test'
        for file in os.listdir(targetDir): 
            targetFile = os.path.join(targetDir,  file) 
            if os.path.exists(targetFile):
                try: 
                    os.rmdir(targetFile)
                except:
                    assert  'delete folder failed. path:/home/test/test'
    
    def test_get_combined_cert_for_server_sslError(self):
        self.server = 'server'
        self.port = 'port'
        self.ServerPool.no_ssl_validation = None
        #not os.path.exists(base_ssl)
        with self.assertRaises(cfg.Error):
            self.ServerPool._get_combined_cert_for_server(self.server, self.port)
                  
    @mock.patch.object(ServerPool,'_combine_certs_to_file')      
    @mock.patch.object(ServerPool,'_fetch_and_store_cert')
    def test_get_combined_cert_for_server(self,mock_fetch_and_store_cert,mock_combine_certs_to_file):
        self.server = 'server'
        self.port = 'port'
        self.ServerPool.ssl_cert_directory = '/home/test'
        self.ServerPool.no_ssl_validation = None
        # if
        self.ServerPool._get_combined_cert_for_server(self.server, self.port)
        # check return
        self.assertEqual(self.ServerPool._get_combined_cert_for_server(self.server, self.port),'/home/test/combined/server.pem')
        
        # elif 
        self.ServerPool.ssl_cert_directory = '/home/test/test'
        self.ServerPool._get_combined_cert_for_server(self.server, self.port)        
        # check return
        self.assertEqual(self.ServerPool._get_combined_cert_for_server(self.server, self.port), '/home/test/test/combined/server.pem')
        
        
    @mock.patch.object(ServerPool,'_get_ca_cert_paths')
    @mock.patch.object(ServerPool,'_combine_certs_to_file')      
    @mock.patch.object(ServerPool,'_fetch_and_store_cert')
    def test_get_combined_cert_for_server_certsError(self,mock_fetch_and_store_cert,mock_combine_certs_to_file,mock_get_ca_cert_paths):
        self.server = 'server'
        self.port = 'port'
        self.ServerPool.ssl_cert_directory = '/home/test/test'
        self.ServerPool.no_ssl_validation = None
        mock_get_ca_cert_paths.return_value = None
        self.ServerPool.ssl_sticky = None
        # if not certs
        with self.assertRaises(cfg.Error):
            self.ServerPool._get_combined_cert_for_server(self.server, self.port)
         
    @mock.patch.object(ServerPool,'_get_ca_cert_paths')
    def  test_combine_certs_to_file(self,mock_get_ca_cert_paths):
        self.certs = ['/home/test/test1.txt','/home/test/test.txt']
        self.cfile = '/home/test/test.txt'
        self.ServerPool._combine_certs_to_file(self.certs, self.cfile)
         
         
    def test_get_host_cert_path(self):
        self.host_dir = '/home'
        self.server = ['test','test1']
        #if false
        self.ServerPool._get_host_cert_path(self.host_dir, self.server[0])
        self.ServerPool._get_host_cert_path(self.host_dir, self.server[1])
        #return
        self.assertEqual(self.ServerPool._get_host_cert_path(self.host_dir, self.server[0]), ('/home/test.pem', True))
        self.assertEqual(self.ServerPool._get_host_cert_path(self.host_dir, self.server[1]), ('/home/test1.pem', False))
         
         
    def test_get_ca_cert_paths(self):
        self.ca_dir = '/home/test'
        self.ServerPool._get_ca_cert_paths(self.ca_dir)
         
    @mock.patch('ssl.get_server_certificate')
    @mock.patch.object(ServerPool,'_file_put_contents')
    def test_fetch_and_store_cert(self,mock_get_server_certificate,mock_file_put_contents):
        self.server = 'server'
        self.port = '80'
        self.path = 'path'
        self.ServerPool._fetch_and_store_cert(self.server, self.port, self.path)
         
         
    @mock.patch.object(ServerPool,'_file_put_contents')
    def test_fetch_and_store_cert_except(self,mock_file_put_contents):
        self.server = 'server'
        self.port = '80'
        self.path = 'path'
        self.assertRaises(Exception,self.ServerPool._fetch_and_store_cert,self.server, self.port, self.path)
         
    def test_file_put_contents(self):
        self.path = '/home/test/test.txt'
        self.contents = 'this is a test.'
        self.ServerPool._file_put_contents(self.path, self.contents)
         
    def test_server_failure(self):
        self.resp = [301,302,304]
        self.ServerPool.server_failure(self.resp)
        self.ServerPool.server_failure(self.resp)
         
    def test_action_success(self):
        self.resp = ['201','202','207','208']
        self.ServerPool.action_success(self.resp)
        self.ServerPool.action_success(self.resp)
          
    def test_rest_call(self):
        self.action = 'action'
        self.resource = 'resource'
        self.data = 'data'
        self.headers = {'Content-type':'application/json',
                        'Accept' : 'application/json',
                        'NeutronProxy-Agent':'NeutronProxy-Agent'}
        self.ignore_codes = [301]
        self.ServerPool.rest_call(self.action, self.resource, self.data, self.headers, self.ignore_codes)
        # check active_server.failed
        self.good_first = sorted(self.ServerPool.servers, key=lambda x: x.failed)
        self.assertFalse(self.good_first[0].failed)
        # check return
        self.assertEqual(self.ServerPool.rest_call(self.action, self.resource, self.data, self.headers, self.ignore_codes),(0, None, None, None),)      
        
        
    @mock.patch.object(ServerPool,'server_failure')
    def test_rest_call_else(self,mock_server_failure):
        self.action = 'action'
        self.resource = 'resource'
        self.data = 'data'
        self.headers = {'Content-type':'application/json',
                        'Accept' : 'application/json',
                        'NeutronProxy-Agent':'NeutronProxy-Agent'}
        self.ignore_codes = [301]
        mock_server_failure.return_value = True
        self.ServerPool.rest_call(self.action, self.resource, self.data, self.headers, self.ignore_codes)
        # check active_server.failed
        self.good_first = sorted(self.ServerPool.servers, key=lambda x: x.failed)
        self.assertTrue(self.good_first[0].failed)
        # check return
        self.assertEqual(self.ServerPool.rest_call(self.action, self.resource, self.data, self.headers, self.ignore_codes),(0, None, None, None),)
       
    def test_rest_action(self):
        self.action = 'DELETE'
        self.resource = 'resource'
        self.ServerPool.rest_action(self.action, self.resource)
        # check return
        self.assertEqual(self.ServerPool.rest_action(self.action, self.resource), (0,None,None,None),)
        
    @mock.patch.object(ServerPool,'server_failure')
    def test_rest_action_RemoteRestError(self,mock_server_failure):
        self.action = 'DELETE'
        self.resource = 'resource'
        # RemoteRestError
        mock_server_failure.return_value = True
        with self.assertRaises(RemoteRestError):
            self.ServerPool.rest_action(self.action, self.resource)
            
    @mock.patch.object(ServerPool,'rest_call')
    def test_rest_action_Warning(self,mock_rest_call):
        self.action = 'DELETE'
        self.resource = 'resource'
        # RemoteRestError
        mock_rest_call.return_value = (404,None,None,None)
        self.ServerPool.rest_action(self.action, self.resource)
        # check return
        self.assertEqual(self.ServerPool.rest_action(self.action, self.resource), (404,None,None,None),)
        
         
    def test_consistency_watchdog(self):
        self.ServerPool._consistency_watchdog()
        

class TestHTTPSConnectionWithValidation(unittest.TestCase):

    def setUp(self):
        self.host = 'host'
        self.timeout = 'timeout'
        self.HTTPSConnectionWithValidation = HTTPSConnectionWithValidation(self.host,self.timeout)
        
    def tearDown(self):
        pass   
    
    @mock.patch('ssl.wrap_socket')
    @mock.patch('socket.create_connection')
    def test_connect(self,mock_create_connection,mock_wrap_socket): 
        self.HTTPSConnectionWithValidation.connect()
  
        
if __name__ == "__main__":
    unittest.main()