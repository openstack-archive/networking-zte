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
#

"""
This module manages the HTTP and HTTPS connections to the backend controllers.

The main class it provides for external use is ServerPool which manages a set
of ServerProxy objects that correspond to individual backend controllers.

The following functionality is handled by this module:
- Translation of rest_* function calls to HTTP/HTTPS calls to the controllers
- Automatic failover between controllers
- SSL Certificate enforcement
- HTTP Authentication

"""
import base64
import eventlet
import httplib
import json
import os
import re
import socket
import ssl

from oslo_log import log
from oslo_serialization import jsonutils
try:
    from oslo.config import cfg
except Exception:
    from oslo_config import cfg
try:
    from neutron._i18n import _
    from neutron_lib import exceptions
except Exception:
    from neutron.common import exceptions

LOG = log.getLogger(__name__)

TOPOLOGY_PATH = "/topology"
SUCCESS_CODES = range(200, 207)
FAILURE_CODES = [301, 302, 303]
BASE_URI = '/'
response_code = {
    'OK': 200,
    'OK_1': 204,
    'Bad_Request': 400,
    'Unauthorized': 401,
    'Forbidden': 403,
    'Not_Found': 404,
    'Conflict': 409,
}


class RemoteRestError(exceptions.NeutronException):
    message = _("Error in REST call to remote network "
                "controller: %(reason)s")
    status = None

    def __init__(self, **kwargs):
        self.status = kwargs.pop('status', None)
        self.reason = kwargs.get('reason')
        super(RemoteRestError, self).__init__(**kwargs)


class ServerProxy(object):
    """REST server proxy to a network controller."""

    def __init__(self, server, port, ssl, auth, timeout,
                 base_uri, success_codes, name, combined_cert):
        self.server = server
        self.port = port
        self.ssl = ssl
        self.base_uri = base_uri
        self.timeout = timeout
        self.name = name
        self.success_codes = success_codes
        self.auth = auth
        self.failed = False
        self.capabilities = []
        self.currentconn = None
        self.header = {
            "Accept": "application/json",
            "Content-Type": "application/json"}
        self.combined_cert = combined_cert
        self.auth_type = self.get_auth_type()

        self.username, self.password = re.split(':', self.auth)

        if self.auth_type == "BASE64":
            self.auth = "Basic " + \
                base64.b64encode("%s:%s" % (self.username, self.password))
        elif self.auth_type == "AES":
            encrypt_pwd = self.add_aes_encryption(self.password)
            self.auth = "Basic " + \
                base64.b64encode("%s:%s" % (self.username, encrypt_pwd))
            LOG.debug('after base64enc auth=%s' % "****")

        if self.auth is not None:
            self.header["Authorization"] = self.auth
            self.header["Realm"] = 'ZENIC'

    def get_auth_type(self):
        url = '/rest/v1/security/encryption'
        method = "GET"
        body = None
        r = self.send_http_request(method, url, body)
        if r:
            jsn = json.loads(r)
            enc = jsn['content']
            return enc
        else:
            return ""

    def send_http_request(self, method="", url="", body=(), trans=False):
        if self.ssl and not self.combined_cert:
            http = HTTPSConnectionWithValidation(self.server, self.port)
        else:
            http = httplib.HTTPConnection(self.server, self.port)
        if trans:
            payload = body
        else:
            if body:
                payload = json.dumps(body)
            else:
                payload = None

        LOG.debug('servermanager send_http_request, method=%s,header=%s, '
                  'url=%s,payload=%s' % (method, self.header, url, "****"))
        http.request(method, url, payload, self.header)
        res = http.getresponse()
        data = res.read()
        LOG.info(_(
            'servermanager send_http_request --ret code=%s ---'),
            res.status)
        if (res.status not in (response_code['OK'], response_code['OK_1'])):
            if res.status == 404:
                LOG.debug(
                    'servermanager send_http_request finished, '
                    'res code=%s, but get none data' % res.status)
            else:
                LOG.error(_(
                    'servermanager send_http_request failed, res code=%('
                    'code)s, reason=%(data)s'), {'code': res.status,
                                                 'data': data})
            return None
        LOG.info(_('servermanager send_http_request --ret data=%s ---'),
                 "****")

        return data

    def add_aes_encryption(self, pwd=""):
        url = '/rest/v1/security/encrypt/AES'
        method = "POST"
        body = 'pwd=%s' % pwd
        r = self.send_http_request(method, url, body, True)
        return r

    def rest_call(self, action, resource, data='', headers={}, timeout=False,
                  reconnect=False):
        uri = self.base_uri + resource
        body = jsonutils.dumps(data)
        if not headers:
            headers = {}
        headers['Content-type'] = 'application/json'
        headers['Accept'] = 'application/json'
        headers['NeutronProxy-Agent'] = self.name

        if self.auth:
            headers['Authorization'] = self.auth
            headers['Realm'] = 'ZENIC'

        LOG.info(("ServerProxy: server=%(server)s, port=%(port)d, "
                  "ssl=%(ssl)r"),
                 {'server': self.server, 'port': self.port, 'ssl': self.ssl})
        LOG.info(("ServerProxy: resource=%(resource)s, data=%(data)r, "
                  "action=%(action)s"),
                 {'resource': resource, 'data': data,
                  'action': action})

        conn = None
        if self.ssl and not self.combined_cert:
            conn = HTTPSConnectionWithValidation(
                    self.server, self.port, timeout=self.timeout)
            if conn is None:
                LOG.error((
                    'ServerProxy: Could not establish HTTPS connection'))
                return 0, None, None, None
        else:
            conn = httplib.HTTPConnection(
                self.server, self.port, timeout=self.timeout)
            if conn is None:
                LOG.error((
                    'ServerProxy: Could not establish HTTP connection'))
                return 0, None, None, None

        try:
            conn.request(action, uri, body, headers)
            response = conn.getresponse()
            respstr = response.read()
            respdata = respstr
            if response.status in self.success_codes:
                try:
                    respdata = jsonutils.loads(respstr)
                except ValueError:
                    # response was not JSON, ignore the exception
                    pass
            ret = (response.status, response.reason, respstr, respdata)
        except socket.timeout as e1:
            LOG.error(('ServerProxy: %(action)s failure, %(el)r'),
                      {"action": action, "el": e1})
            ret = 9, None, None, None
        except socket.error as e:
            LOG.error(("ServerProxy: %(action)s failure, %(e)r"),
                      {"action": action, "e": e})
            ret = 0, None, None, None
        conn.close()
        LOG.info(_("ServerProxy: status=%(status)d, reason=%(reason)r, "
                   "ret=%(ret)s, data=%(data)r"), {'status': ret[0],
                                                   'reason': ret[1],
                                                   'ret': ret[2],
                                                   'data': ret[3]})
        return ret

        """
        if not self.currentconn or reconnect:
            if self.currentconn:
                self.currentconn.close()
            if self.ssl:
                self.currentconn = HTTPSConnectionWithValidation(
                    self.server, self.port, timeout=timeout)
                if self.currentconn is None:
                    LOG.error(_('ServerProxy: Could not establish HTTPS '
                                'connection'))
                    return 0, None, None, None
                self.currentconn.combined_cert = self.combined_cert
            else:
                self.currentconn = httplib.HTTPConnection(
                    self.server, self.port, timeout=timeout)
                if self.currentconn is None:
                    LOG.error(_('ServerProxy: Could not establish HTTP '
                                'connection'))
                    return 0, None, None, None

        try:
            self.currentconn.request(action, uri, body, headers)
            response = self.currentconn.getresponse()
            respstr = response.read()
            respdata = respstr
            if response.status in self.success_codes:
                try:
                    respdata = json.loads(respstr)
                except ValueError:
                    # response was not JSON, ignore the exception
                    pass
            ret = (response.status, response.reason, respstr, respdata)
        except httplib.HTTPException:
            # If we were using a cached connection, try again with a new one.
            with excutils.save_and_reraise_exception() as ctxt:
                self.currentconn.close()
                if reconnect:
                    # if reconnect is true, this was on a fresh connection so
                    # reraise since this server seems to be broken
                    ctxt.reraise = True
                else:
                    # if reconnect is false, it was a cached connection so
                    # try one more time before re-raising
                    ctxt.reraise = False
            return self.rest_call(action, resource, data, headers,
                                  timeout=timeout, reconnect=True)
        except (socket.timeout, socket.error) as e:
            self.currentconn.close()
            LOG.error(_('ServerProxy: %(action)s failure, %(e)r'),
                      {'action': action, 'e': e})
            ret = 0, None, None, None
        LOG.debug(_("ServerProxy: status=%(status)d, reason=%(reason)r, "
                    "ret=%(ret)s, data=%(data)r"), {'status': ret[0],
                                                    'reason': ret[1],
                                                    'ret': ret[2],
                                                    'data': ret[3]})
        return ret
        """


class ServerPool(object):

    def __init__(self, servers, auth, ssl, no_ssl_validation, ssl_sticky,
                 ssl_cert_directory, consistency_interval,
                 timeout=False, cache_connections=False,
                 base_uri=BASE_URI, success_codes=SUCCESS_CODES,
                 failure_codes=FAILURE_CODES, name='NeutronRestProxy'):
        LOG.debug(_("ServerPool: initializing"))
        # 'servers' is the list of network controller REST end-points
        # (used in order specified till one succeeds, and it is sticky
        # till next failure). Use 'server_auth' to encode api-key
        self.auth = auth
        self.ssl = ssl
        self.base_uri = base_uri
        self.success_codes = success_codes
        self.failure_codes = failure_codes
        self.name = name
        self.timeout = timeout
        self.always_reconnect = not cache_connections
        self.consistency_interval = consistency_interval
        self.no_ssl_validation = no_ssl_validation
        self.ssl_cert_directory = ssl_cert_directory
        self.ssl_sticky = ssl_sticky

        default_port = 8000
        if timeout is not False:
            self.timeout = timeout

        # Function to use to retrieve topology for consistency syncs.
        # Needs to be set by module that uses the servermanager.
        self.get_topo_function = None
        self.get_topo_function_args = {}

        if not servers:
            raise cfg.Error(_('Servers not defined. Aborting server manager.'))
        servers = [s if len(s.rsplit(':', 1)) == 2
                   else "%s:%d" % (s, default_port)
                   for s in servers]
        if any((len(spl) != 2 or not spl[1].isdigit())
               for spl in [sp.rsplit(':', 1)
                           for sp in servers]):
            raise cfg.Error(_('Servers must be defined as <ip>:<port>. '
                              'Configuration was %s') % servers)
        self.servers = [
            self.server_proxy_for(server, int(port))
            for server, port in (s.rsplit(':', 1) for s in servers)
        ]
        eventlet.spawn(self._consistency_watchdog, self.consistency_interval)
        LOG.debug("ServerPool: initialization done")

    def server_proxy_for(self, server, port):
        combined_cert = self._get_combined_cert_for_server(server, port)
        return ServerProxy(server, port, self.ssl, self.auth,
                           self.timeout, self.base_uri, self.success_codes,
                           self.name, combined_cert=combined_cert)

    def _get_combined_cert_for_server(self, server, port):
        # The ssl library requires a combined file with all trusted certs
        # so we make one containing the trusted CAs and the corresponding
        # host cert for this server
        combined_cert = None
        if self.ssl and not self.no_ssl_validation:
            base_ssl = self.ssl_cert_directory
            host_dir = os.path.join(base_ssl, 'host_certs')
            ca_dir = os.path.join(base_ssl, 'ca_certs')
            combined_dir = os.path.join(base_ssl, 'combined')
            combined_cert = os.path.join(combined_dir, '%s.pem' % server)
            if not os.path.exists(base_ssl):
                raise cfg.Error(_('ssl_cert_directory [%s] does not exist. '
                                  'Create it or disable ssl.') % base_ssl)
            for automake in [combined_dir, ca_dir, host_dir]:
                if not os.path.exists(automake):
                    os.makedirs(automake)

            # get all CA certs
            certs = self._get_ca_cert_paths(ca_dir)

            # check for a host specific cert
            hcert, exists = self._get_host_cert_path(host_dir, server)
            if exists:
                certs.append(hcert)
            elif self.ssl_sticky:
                self._fetch_and_store_cert(server, port, hcert)
                certs.append(hcert)
            if not certs:
                raise cfg.Error(_('No certificates were found to verify '
                                  'controller %s') % (server))
            self._combine_certs_to_file(certs, combined_cert)
        return combined_cert

    def _combine_certs_to_file(self, certs, cfile):
        """
        Concatenates the contents of each certificate in a list of
        certificate paths to one combined location for use with ssl
        sockets.
        """
        with open(cfile, 'w') as combined:
            for c in certs:
                with open(c, 'r') as cert_handle:
                    combined.write(cert_handle.read())

    def _get_host_cert_path(self, host_dir, server):
        """
        returns full path and boolean indicating existence
        """
        hcert = os.path.join(host_dir, '%s.pem' % server)
        if os.path.exists(hcert):
            return hcert, True
        return hcert, False

    def _get_ca_cert_paths(self, ca_dir):
        certs = [os.path.join(root, name)
                 for name in [
                     name for (root, dirs, files) in os.walk(ca_dir)
                     for name in files
        ]
            if name.endswith('.pem')]
        return certs

    def _fetch_and_store_cert(self, server, port, path):
        """
        Grabs a certificate from a server and writes it to
        a given path.
        """
        try:
            cert = ssl.get_server_certificate((server, port))
        except Exception as e:
            raise cfg.Error(_('Could not retrieve initial '
                              'certificate from controller %(server)s. '
                              'Error details: %(error)s') %
                            {'server': server, 'error': str(e)})

        LOG.warning("Storing to certificate for host %(server)s "
                    "at %(path)s" % {'server': server, 'path': path})
        self._file_put_contents(path, cert)

        return cert

    def _file_put_contents(self, path, contents):
        # Simple method to write to file.
        # Created for easy Mocking
        with open(path, 'w') as handle:
            handle.write(contents)

    def server_failure(self, resp, ignore_codes=[]):
        """Define failure codes as required.

        Note: We assume 301-303 is a failure, and try the next server in
        the server pool.
        """
        return resp[0] in self.failure_codes and resp[0] not in ignore_codes

    def action_success(self, resp):
        """Defining success codes as required.

        Note: We assume any valid 2xx as being successful response.
        """
        return resp[0] in self.success_codes

    def rest_call(self, action, resource, data, headers, ignore_codes,
                  timeout=False):
        good_first = sorted(self.servers, key=lambda x: x.failed)
        first_response = None
        for active_server in good_first:
            ret = active_server.rest_call(action, resource, data, headers,
                                          timeout,
                                          reconnect=self.always_reconnect)
            # If inconsistent, do a full synchronization
            # if ret[0] == httplib.CONFLICT:
            #    if self.get_topo_function:
            #        data = self.get_topo_function(
            #            **self.get_topo_function_args)
            #        active_server.rest_call('PUT', TOPOLOGY_PATH, data,
            #                                timeout=None)
            # Store the first response as the error to be bubbled up to the
            # user since it was a good server. Subsequent servers will most
            # likely be cluster slaves and won't have a useful error for the
            # user (e.g. 302 redirect to master)
            if not first_response:
                first_response = ret
            if not self.server_failure(ret, ignore_codes):
                active_server.failed = False
                return ret
            else:
                try:
                    LOG.error('ServerProxy: %(action)s failure for '
                              'servers:%(server)r Response: %(response)s',
                              {'action': action,
                               'server': (active_server.server,
                                          active_server.port),
                               'response': unicode(ret[3], "utf-8")})
                    LOG.error("ServerProxy: Error details: status=%(status)d,"
                              " reason=%(reason)r, ret=%(ret)s, data=%(data)r",
                              {'status': ret[0], 'reason': ret[1],
                               'ret': unicode(ret[2], "utf-8"),
                               'data': unicode(ret[3], "utf-8")})
                except Exception as e:
                    LOG.error("fail to display info, err: %(e)s",
                              {'e': e})
                active_server.failed = True

        # All servers failed, reset server list and try again next time
        LOG.error(_('ServerProxy: %(action)s failure for all servers: '
                    '%(server)r'),
                  {'action': action,
                   'server': tuple((s.server,
                                    s.port) for s in self.servers)})
        return first_response

    def rest_action(self, action, resource, data='', errstr='%s',
                    ignore_codes=[], headers={}, timeout=False):
        """
        Wrapper for rest_call that verifies success and raises a
        RemoteRestError on failure with a provided error string
        By default, 404 errors on DELETE calls are ignored because
        they already do not exist on the backend.
        """
        LOG.debug(_("rest_action: %(action)s action to "
                    "resource %(resource)s %(data)s"),
                  {'action': action, 'resource': resource, 'data': data})

        resp = self.rest_call(action, resource, data, headers, ignore_codes,
                              timeout)
        if self.server_failure(resp, ignore_codes):
            try:
                LOG.error(errstr, unicode(resp[2], "utf-8"))  # noqa
            except Exception as e:
                LOG.error("fail to display info, err: %(e)s",
                          {'e': e})
            raise RemoteRestError(reason=resp[2], status=resp[0])
        if resp[0] in ignore_codes:
            LOG.warning(_("NeutronRestProxyV2: Received and ignored error "
                          "code %(code)s on %(action)s action to resource "
                          "%(resource)s"),
                        {'code': resp[2], 'action': action,
                         'resource': resource})
        return resp

    def _consistency_watchdog(self, polling_interval=60):
        return


class HTTPSConnectionWithValidation(httplib.HTTPSConnection):

    # If combined_cert is None, the connection will continue without
    # any certificate validation.
    combined_cert = None

    def connect(self):
        sock = socket.create_connection((self.host, self.port),
                                        self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()

        if self.combined_cert:
            self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                                        cert_reqs=ssl.CERT_REQUIRED,
                                        ca_certs=self.combined_cert)
        else:
            self.sock = ssl.wrap_socket(sock, self.key_file,
                                        self.cert_file,
                                        cert_reqs=ssl.CERT_NONE)
