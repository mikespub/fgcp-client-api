#!/usr/bin/python
#
#  Copyright (C) 2011-2016 Michel Dalle
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""
This is a really basic CGI server that allows you to test the really basic
Relay CGI script, by specifying the following region in your scripts:

    region='relay=http://localhost:8000/cgi-bin/fgcp_relay.py'

In order to use this CGI server for relay testing, you need to adapt the lines
    pem_file = '../client.pem'
    region = 'de'
at the bottom of this script, and specify your own certificate and
region there
"""
from __future__ import print_function

from future import standard_library
standard_library.install_aliases()
from builtins import object
import http.server


class FGCPRelayConfig(object):
    """The actual relay configuration is specified at startup"""
    key_file = 'client.pem'
    region = 'uk'


FGCP_RELAY_CONFIG = FGCPRelayConfig()


class FGCPRelayHTTPRequestHandler(http.server.CGIHTTPRequestHandler):
    """Override the default CGIHTTPRequestHandler to run the relay script here"""
    _relay = None

    def do_POST(self):
        """Version of do_POST() that runs the relay script in place"""
        if self.is_cgi():
            #return self.run_cgi()
            return self.run_cgi_local()
        else:
            self.send_error(501, "Can only POST to CGI scripts")

    def send_head(self):
        """Version of send_head() that only supports CGI scripts"""
        if self.is_cgi():
            #return self.run_cgi()
            return self.run_cgi_local()
        else:
            self.send_error(501, "Can only access CGI scripts")

    def is_cgi(self):
        """Version of is_cgi() that only supports the relay CGI script"""
        if self.path != '/cgi-bin/fgcp_relay.py':
            return False
        return http.server.CGIHTTPRequestHandler.is_cgi(self)

    def run_cgi_local(self):
        """Version of run_cgi() that runs the relay script in place"""
        env = {}
        env['REQUEST_METHOD'] = self.command
        if self.headers.typeheader is None:
            env['CONTENT_TYPE'] = self.headers.type
        else:
            env['CONTENT_TYPE'] = self.headers.typeheader
        length = self.headers.getheader('content-length')
        if length:
            env['CONTENT_LENGTH'] = length
        ua = self.headers.getheader('user-agent')
        if ua:
            env['HTTP_USER_AGENT'] = ua

        if self._relay is None:
            # initialize class variable with relay instance
            from fgcp_relay import FGCPRelayCGIScript
            FGCPRelayHTTPRequestHandler._relay = FGCPRelayCGIScript(FGCP_RELAY_CONFIG.key_file, FGCP_RELAY_CONFIG.region)
            self.log_message("Initialize relay with key_file '%s' and region '%s'" % (FGCP_RELAY_CONFIG.key_file, FGCP_RELAY_CONFIG.region))
        try:
            # set filepointers and environment
            self._relay.set_fp(self.rfile, self.wfile, self.wfile)
            self._relay.set_environ(env)
            # run relay script
            self.send_response(200, "Script output follows")
            self._relay.run()
        except:
            self.send_response(501, "Script error follows")
            self.wfile.write('An error occured')
            self.log_message("Script exited with error")


def run_relay_server(key_file, region):
    # initialize relay config
    FGCP_RELAY_CONFIG.key_file = key_file
    FGCP_RELAY_CONFIG.region = region
    # override default CGIHTTPRequestHandler
    httpd = http.server.HTTPServer(('', 8000), FGCPRelayHTTPRequestHandler)
    httpd.serve_forever()


if __name__ == "__main__":
    import os.path
    import sys
    parent = os.path.dirname(__file__)
    sys.path.append(parent)
    sys.path.append(os.path.join(parent, 'cgi-bin'))
    print("""
This is a really basic CGI server that allows you to test the really basic
Relay CGI script, by specifying the following region in your scripts:

    region='relay=http://localhost:8000/cgi-bin/fgcp_relay.py'

""")
    pem_file = '../client.pem'
    region = 'de'
    run_relay_server(pem_file, region)
