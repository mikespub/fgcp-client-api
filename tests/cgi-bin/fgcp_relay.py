#!/usr/bin/python
#
#  Copyright (C) 2011 Michel Dalle
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
This is a really basic CGI script that allows you to test the relay feature
via a CGI webserver, e.g. by specifying the following region in your scripts:

    region='relay=http://localhost:8000/cgi-bin/fgcp_relay.py'

In order to use this CGI script for relay testing, you need to adapt the lines
    pem_file = '../client.pem'
    region = 'de'
at the bottom of this script, and specify your own certificate and
region there
"""

import cgi
import sys
import os

FGCP_REGIONS = {
    'au': 'api.globalcloud.fujitsu.com.au',     # for Australia and New Zealand
    'de': 'api.globalcloud.de.fujitsu.com',     # for Central Europe, Middle East, Eastern Europe, Africa & India (CEMEA&I)
    'jp': 'api.oviss.jp.fujitsu.com',           # for Japan
    'sg': 'api.globalcloud.sg.fujitsu.com',     # for Singapore, Malaysia, Indonesia, Thailand and Vietnam
    'uk': 'api.globalcloud.uk.fujitsu.com',     # for the UK and Ireland (UK&I)
    'us': 'api.globalcloud.us.fujitsu.com',     # for the Americas
}


class FGCPRelayCGIScript:
    fpin = None
    fpout = None
    environ = None
    key_file = None
    region = None
    host = None
    method = None
    uri = '/ovissapi/endpoint'
    body = None
    headers = None
    _conn = None

    def __init__(self, key_file, region, environ=os.environ, fpin=sys.stdin, fpout=sys.stdout, fperr=sys.stderr):
        """Initialize variables, environment and filepointers for CGI script"""
        self.key_file = key_file
        self.region = region
        self.host = self.get_host(region)
        self.set_environ(environ)
        self.set_fp(fpin, fpout, fperr)
        try:
            import httplib
            self._conn = httplib.HTTPSConnection(self.host, key_file=self.key_file, cert_file=self.key_file)
        except:
            self.raise_error('Oops, cannot connect')

    def get_host(self, region):
        """Get host for this region"""
        if region not in FGCP_REGIONS:
            self.raise_error('Invalid region %s' % region)
        host = FGCP_REGIONS[region]
        return host

    def set_fp(self, fpin=sys.stdin, fpout=sys.stdout, fperr=sys.stderr):
        """Set filepointers for input and output"""
        self.fpin = fpin
        self.fpout = fpout
        # CHECKME: redirect stderr to stdout
        fperr = fpout

    def set_environ(self, environ=os.environ):
        """Set environment variables"""
        self.environ = environ

    def get_headers(self, environ=os.environ):
        """Get request headers"""
        headers = {'REQUEST_METHOD': 'GET', 'CONTENT_LENGTH': 0, 'CONTENT_TYPE': 'text/html', 'HTTP_USER_AGENT': 'Invalid'}
        for header in headers.keys():
            if header in environ:
                headers[header] = environ[header]
        return headers

    def get_header(self, name, default=None):
        """Get a particular header or return default"""
        if name in self.headers:
            return self.headers[name]
        return default

    def get_body(self, fpin=sys.stdin):
        """Get request body"""
        if self.method != 'POST':
            return
        length = int(self.get_header('CONTENT_LENGTH'))
        if length > 0:
            body = fpin.read(length)
        else:
            body = fpin.read()
        return body

    def raise_error(self, text='Unknown'):
        """Write error message with traceback and exit CGI script"""
        # get traceback of exception
        import traceback
        trace = traceback.format_exc()
        # remove local path from traceback just in case
        import re
        trace = re.sub('"[^"]+fgcp_relay\.py"', '"fgcp_relay.py"', trace)
        self.write_output('text/plain', 'Error: %s\n%s' % (text, trace), self.fpout)
        exit()

    def write_output(self, content_type='text/plain', data='Unknown', fpout=sys.stdout):
        """Write Content-type and data"""
        fpout.write("""Content-type: %s

""" % content_type)
        fpout.write(data)

    def run(self):
        """Relay the request to the API server and send back the response"""
        self.headers = self.get_headers(self.environ)
        self.method = self.get_header('REQUEST_METHOD').upper()
        self.body = self.get_body(self.fpin)
        req_headers = {'User-Agent': self.get_header('HTTP_USER_AGENT'), 'Content-Type': self.get_header('CONTENT_TYPE')}
        try:
            self._conn.request(self.method, self.uri, self.body, req_headers)
        except:
            self.raise_error('Oops, cannot request')
        try:
            resp = self._conn.getresponse()
        except:
            self.raise_error('Oops, cannot getresponse')
        if resp.status != 200:
            self.raise_error('Status: %s\nReason: %s\n' % (repr(resp.status), repr(resp.reason)))
        # get data from response
        try:
            data = resp.read()
        except:
            self.raise_error('Oops, cannot read')
        # get content-type from response
        content_type = resp.getheader('content-type', 'text/xml')
        # send back data
        self.write_output(content_type, data, self.fpout)


if __name__ == "__main__":
    pem_file = '../client.pem'
    region = 'de'
    relay = FGCPRelayCGIScript(pem_file, region)
    relay.run()
