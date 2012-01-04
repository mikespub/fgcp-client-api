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
Fujitsu Global Cloud Platform (FGCP) API Server(s)

Example: [see tests/test_*.py for more examples]

# Connect without client certificate to region 'test'
from fgcp.resource import FGCPVDataCenter
vdc = FGCPVDataCenter('client.pem', 'test')

# Do typical resource actions - updates are not supported here
vsystem = vdc.get_vsystem('Demo System')
vsystem.show_status()
for vserver in vsystem.vservers:
    #result = vserver.backup(wait=True)
...

Note: you need to unzip the file 'fixtures.zip' in tests/fixtures first
"""

import httplib
import time
import os.path
import re

from fgcp import FGCPError

FGCP_REGIONS = {
    'au': 'api.globalcloud.fujitsu.com.au',     # for Australia and New Zealand
    'de': 'api.globalcloud.de.fujitsu.com',     # for Central Europe, Middle East, Eastern Europe, Africa & India (CEMEA&I)
    'jp': 'api.oviss.jp.fujitsu.com',           # for Japan
    'sg': 'api.globalcloud.sg.fujitsu.com',     # for Singapore, Malaysia, Indonesia, Thailand and Vietnam
    'uk': 'api.globalcloud.uk.fujitsu.com',     # for the UK and Ireland (UK&I)
    'us': 'api.globalcloud.us.fujitsu.com',     # for the Americas
    'test': 'test',                             # for local client tests with test fixtures
    #'fake': 'fake',                            # for local client tests with fake updates etc. ?
    'relay': 'relay',                           # for remote connection via relay API server
}


class FGCPServerError(FGCPError):
    pass


def FGCPGetServerConnection(key_file='client.pem', region='de'):
    if region == 'test':
        # connect to test API server for local testing
        # format: region = 'test'
        return FGCPTestServerWithFixtures()
    elif region.startswith('relay='):
        # connect to relay API server for remote connection
        # format: region = 'relay=http://127.0.0.1:8000/cgi-bin/fgcp_relay.py'
        relay = region.split('=').pop()
        from urlparse import urlparse
        url = urlparse(relay)
        # TODO: secure access to relay server in some other way, e.g. Basic Auth, OAuth, ...
        if url.scheme == 'https':
            return FGCPRelayServer(url.hostname, port=url.port, path=url.path)
        else:
            return FGCPUnsecureRelayServer(url.hostname, port=url.port, path=url.path)
    elif region in FGCP_REGIONS:
        # connect to real API server
        # format: region = 'uk'
        host = FGCP_REGIONS[region]
        # use the same PEM file for cert and key
        return FGCPRealServer(host, key_file=key_file, cert_file=key_file)
    else:
        raise FGCPServerError('INVALID_REGION', 'Region %s does not exist' % region)


class FGCPRealServer(httplib.HTTPSConnection):
    """
    Connect to the real API server for the Fujitsu Global Cloud Platform in this region
    """
    pass


class FGCPRelayServer(httplib.HTTPSConnection):
    """
    Connect via some relay API server for remote connections, e.g. for Google App Engine
    """
    _relay_host = None
    _relay_port = None
    _relay_path = None

    def __init__(self, host, port=None, path=None, strict=None):
        # TODO: we do not support key_file and cert_file here, so we connect via a relay server
        self._relay_host = host
        self._relay_port = port
        self._relay_path = path
        httplib.HTTPSConnection.__init__(self, host, port=port, strict=strict)

    def connect(self):
        return httplib.HTTPSConnection.connect(self)

    def request(self, method, url, body=None, headers={}):
        # TODO: fix request
        return httplib.HTTPSConnection.request(self, method, self._relay_path, body, headers)

    def getresponse(self):
        # TODO: fix response
        # TODO: fix response.read()
        return httplib.HTTPSConnection.getresponse(self)


class FGCPUnsecureRelayServer(httplib.HTTPConnection):
    """
    Connect via some relay API server for remote connections, e.g. for localhost
    """
    _relay_host = None
    _relay_port = None
    _relay_path = None

    def __init__(self, host, port=None, path=None, strict=None):
        # TODO: we do not support key_file and cert_file here, so we connect via a relay server
        self._relay_host = host
        self._relay_port = port
        self._relay_path = path
        httplib.HTTPConnection.__init__(self, host, port=port)

    def connect(self):
        return httplib.HTTPConnection.connect(self)

    def request(self, method, url, body=None, headers={}):
        # TODO: fix request
        return httplib.HTTPConnection.request(self, method, self._relay_path, body, headers)

    def getresponse(self):
        # TODO: fix response
        # TODO: fix response.read()
        return httplib.HTTPConnection.getresponse(self)


class FGCPTestServer:
    status = 200
    reason = 'OK'
    _testid = None

    def __init__(self, *args, **kwargs):
        pass

    def request(self, method, uri, body, headers):
        pass

    def getresponse(self):
        return self

    def read(self):
        return """<?xml version="1.0" encoding="UTF-8"?>
<Response xmlns="http://apioviss.jp.fujitsu.com">
  <responseMessage>Processing was completed.</responseMessage>
  <responseStatus>SUCCESS</responseStatus>
</Response>
"""

    def close(self):
        pass

    def set_testid(self, testid):
        self._testid = testid


class FGCPTestServerWithFixtures(FGCPTestServer):
    """
    Connect to this test API server for local tests - updates are not supported

    >>> from fgcp.resource import FGCPVDataCenter
    >>> vdc = FGCPVDataCenter('client.pem', 'test')
    >>> vsystem = vdc.get_vsystem('Demo System')
    >>> vsystem.show_status()   #doctest: +NORMALIZE_WHITESPACE
    Status Overview for VSystem Demo System
    VSystem Demo System     NORMAL
    PublicIP        80.70.163.172   ATTACHED
    Firewall        Firewall        RUNNING
    LoadBalancer    SLB1    192.168.0.211   RUNNING
    VServer WebApp1 192.168.0.13    RUNNING
    VServer DB1     192.168.1.12    RUNNING
            VDisk   DISK1   NORMAL
    VServer WebApp2 192.168.0.15    RUNNING
    .

    """
    _path = 'tests/fixtures'
    _file = None

    def __init__(self, *args, **kwargs):
        self._path = os.path.join('tests', 'fixtures')
        if not os.path.isdir(self._path):
            raise FGCPServerError('INVALID_PATH', 'Path %s does not exist' % self._path)

    def request(self, method, uri, body, headers):
        if self._testid is None:
            raise FGCPServerError('INVALID_PATH', 'Invalid test identifier')
        # check if we have a request file
        self._file = os.path.join(self._path, '%s.request.xml' % self._testid)
        if not os.path.isfile(self._file):
            print body
            raise FGCPServerError('INVALID_PATH', 'File %s does not exist' % self._file)
        # compare body with request file
        f = open(self._file, 'rb')
        data = f.read()
        f.close()
        if data != body:
            raise FGCPServerError('INVALID_REQUEST', 'Request for test %s does not match test fixture:\n\
Current body:\n\
====\n\
%s\n\
====\n\
Test fixture:\n\
====\n\
%s\n\
====\n' % (self._testid, body, data))
        return

    def getresponse(self):
        # add some delay to make it more realistic
        time.sleep(0.3)
        # check if we have a response file
        self._file = os.path.join(self._path, '%s.response.xml' % self._testid)
        if os.path.exists(self._file):
            self.status = 200
            self.reason = 'OK'
        else:
            self.status = 404
            self.reason = 'File %s does not exist' % self._file
        return self

    def read(self):
        # send back the response file
        f = open(self._file)
        data = f.read()
        f.close()
        # TODO: transform status if necessary ?
        return data

    def close(self):
        self._file = None
        return

    #=========================================================================

    def save_request(self, testid, body):
        # sanitize accesskeyid and signature for test fixtures
        p = re.compile('<AccessKeyId>[^<]+</AccessKeyId>')
        body = p.sub('<AccessKeyId>...</AccessKeyId>', body)
        p = re.compile('<Signature>[^<]+</Signature>')
        body = p.sub('<Signature>...</Signature>', body)
        # save request in tests/fixtures
        f = open(os.path.join('tests', 'fixtures', '%s.request.xml' % testid), 'wb')
        f.write(body)
        f.close()

    def save_response(self, testid, data):
        # sanitize initialPassword for test fixtures :-)
        if testid.startswith('GetVServerInitialPassword'):
            p = re.compile('<initialPassword>[^<]+</initialPassword>')
            data = p.sub('<initialPassword>...</initialPassword>', data)
        # save response in tests/fixtures
        f = open(os.path.join('tests', 'fixtures', '%s.response.xml' % testid), 'wb')
        f.write(data)
        f.close()


class FGCPTestServerWithRegistry(FGCPTestServer):
    _vdc = None

    def __init__(self, filePath='fgcp_demo_system.txt'):
        if not os.path.isfile(filePath):
            raise FGCPServerError('INVALID_PATH', 'File %s does not exist' % filePath)
        # create registry with dummy VDataCenter
        from fgcp.resource import FGCPVDataCenter
        self._vdc = FGCPVDataCenter()
        self._vdc.vsystems = []
        # load demo vsystem from file
        design = self._vdc.get_vsystem_design()
        design.load_file(filePath)
        # save demo vsystem in registry
        self._vdc.vsystems.append(design.vsystem)


if __name__ == "__main__":
    import doctest
    doctest.testmod()
