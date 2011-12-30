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
Dummy Fujitsu Global Cloud Platform (FGCP) API Server(s) for local client tests
using XML-RPC API Version 2011-01-31
"""

import time
import os.path

from fgcp import FGCPError


class FGCPDummyError(FGCPError):
    pass


class FGCPTestServerWithFixtures:
    """
    Test API server for local client tests - updates are not supported

    >>> from fgcp.client import FGCPClient
    >>> client = FGCPClient('client.pem', 'test')
    >>> client.ShowSystemStatus('Python API Demo System')
    Show System Status for VSYS Python API Demo System
    VSYS:Python API Demo System:NORMAL
    PublicIP:80.70.163.238:ATTACHED
    EFM FW:Firewall:RUNNING
    EFM SLB:LoadBalancer:192.168.3.211:RUNNING
    VServer:Server1:192.168.3.12:RUNNING
    VServer:Server2:192.168.3.13:RUNNING
    VServer:Server3:192.168.4.12:RUNNING
    VServer:Server4:192.168.4.13:RUNNING
    .

    """
    status = 200
    reason = 'OK'
    _path = 'tests/fixtures'
    _file = None
    _testid = None

    def __init__(self, *args, **kwargs):
        self._path = os.path.join('tests', 'fixtures')
        if not os.path.isdir(self._path):
            raise FGCPDummyError('INVALID_PATH', 'Path %s does not exist' % self._path)

    def request(self, method, uri, body, headers):
        if self._testid is None:
            raise FGCPDummyError('INVALID_PATH', 'Invalid test identifier')
        # check if we have a request file
        self._file = os.path.join(self._path, self._testid + '.request.xml')
        if not os.path.isfile(self._file):
            print body
            raise FGCPDummyError('INVALID_PATH', 'File %s does not exist' % self._file)
        # compare body with request file
        f = open(self._file, 'rb')
        data = f.read()
        f.close()
        if data != body:
            raise FGCPDummyError('INVALID_REQUEST', 'Request for test %s does not match test fixture:\n\
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
        self._file = os.path.join(self._path, self._testid + '.response.xml')
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


class FGCPFakeServerWithRegistry:
    pass


if __name__ == "__main__":
    import doctest
    doctest.testmod()
