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
Connection with the Fujitsu Global Cloud Platform (FGCP) API Server
using XML-RPC API Version 2011-01-31

Requirements: this module uses gdata.tlslite.utils to create the key signature,
see http://code.google.com/p/gdata-python-client/ for download and installation
"""

import httplib
import time
import base64
import os.path

try:
    from gdata.tlslite.utils import keyfactory
except:
    print """Requirements: this module uses gdata.tlslite.utils to create the key signature,
see http://code.google.com/p/gdata-python-client/ for download and installation"""
    exit()
from xml.etree import ElementTree

from fgcp import FGCPError
from fgcp.resource import *


class FGCPResponseError(FGCPError):
    pass


class FGCPConnection:
    """
    FGCP XML-RPC Connection

    Example:
    from fgcp_client_api import FGCPConnection
    conn = FGCPConnection('client.pem', 'uk')
    vsystems = conn.do_action('ListVSYS')
    """
    host = 'api.globalcloud.de.fujitsu.com'        # updated based on region argument
    key_file = 'client.pem'                        # updated based on key_file argument
    locale = 'en'                                # TODO: make configurable to 'en' or 'jp' ?
    timezone = 'Central European Time'            # updated based on time.tzname[0] or time.timezone
    verbose = 0                                    # normal script output for users
    debug = 0                                    # for development purposes

    uri = '/ovissapi/endpoint'                    # fixed value for the API version
    api_version = '2011-01-31'                    # fixed value for the API version
    user_agent = 'OViSS-API-CLIENT'                # fixed value for the API version
    _regions = {
        'au': 'api.globalcloud.fujitsu.com.au',        # for Australia and New Zealand
        'de': 'api.globalcloud.de.fujitsu.com',        # for Central Europe, Middle East, Eastern Europe, Africa & India (CEMEA&I)
        'jp': 'api.oviss.jp.fujitsu.com',            # for Japan
        'sg': 'api.globalcloud.sg.fujitsu.com',        # for Singapore, Malaysia, Indonesia, Thailand and Vietnam
        'uk': 'api.globalcloud.uk.fujitsu.com',        # for the UK and Ireland (UK&I)
        'us': 'api.globalcloud.us.fujitsu.com',        # for the Americas
        'test': 'test',                                # for local client tests with test fixtures
        #'fake': 'fake',                            # for local client tests with fake updates etc. ?
    }

    _conn = None                                # actual httplib.HTTPSConnection() or FGCPTestServer()
    _caller = None                                # which FGCPResource() is calling
    _testid = None                                # test identifier for fixtures

    def __init__(self, key_file='client.pem', region='de', verbose=0, debug=0):
        """
        Use the same PEM file for SSL client certificate and RSA key signature

        Note: to convert your .p12 or .pfx file to unencrypted PEM format, you can use
        the following 'openssl' command:

        openssl pkcs12 -in UserCert.p12 -out client.pem -nodes
        """
        self.key_file = key_file
        if region in self._regions:
            self.host = self._regions[region]
        self.verbose = verbose
        self.debug = debug
        # Note: the timezone doesn't seem to matter for the API server,
        # as long as the expires value is set to the current time
        self.timezone = time.tzname[0]
        if len(self.timezone) < 1:
            offset = int(time.timezone / 3600)
            if offset > 0:
                self.timezone = 'Etc/GMT+%s' % offset
            elif offset < 0:
                self.timezone = 'Etc/GMT-%s' % offset
            else:
                self.timezone = 'Etc/GMT'
        self._key = None

    def __repr__(self):
        return '<%s:%s>' % (self.__class__.__name__, self.host)

    def set_region(self, region):
        if region in self._regions:
            # reset connection if necessary
            if self._conn is not None and self.host != self._regions[region]:
                self.close()
            self.host = self._regions[region]

    def connect(self):
        if self._conn is None:
            if self.host == 'test':
                # use test API server for testing
                from fgcp.dummy import FGCPTestServerWithFixtures
                self._conn = FGCPTestServerWithFixtures()
            else:
                # use the same PEM file for cert and key
                self._conn = httplib.HTTPSConnection(self.host, key_file=self.key_file, cert_file=self.key_file)

    def send(self, method, uri, body, headers):
        # initialize connection if necessary
        self.connect()
        # set testid if necessary
        if self.host == 'test':
            self._conn._testid = self._testid
        # send HTTPS request
        self._conn.request(method, uri, body, headers)

    def receive(self):
        # get HTTPS response
        resp = self._conn.getresponse()
        # check response
        if resp.status != 200:
            raise FGCPResponseError(repr(resp.status), repr(resp.reason))
        # return data
        return resp.read()

    def close(self):
        self._conn.close()
        self._conn = None

    def get_headers(self, attachments=None):
        if attachments is None:
            return {'User-Agent': self.user_agent}
        else:
            # use multipart/form-data
            return {'User-Agent': self.user_agent, 'Content-Type': 'multipart/form-data; boundary=BOUNDARY'}

    # see com.fujitsu.oviss.pub.OViSSSignature
    def get_accesskeyid(self):
        t = long(time.time() * 1000)
        acc = base64.b64encode(self.timezone + '&' + str(t) + '&1.0&SHA1withRSA')
        return acc

    # see com.fujitsu.oviss.pub.OViSSSignature
    def get_signature(self, acc=None):
        if acc is None:
            acc = self.get_accesskeyid()
        if self._key is None:
            # Note: we need an unencrypted PEM file for this !
            s = open(self.key_file, 'rb').read()
            self._key = keyfactory.parsePrivateKey(s)
        # RSAKey.hashAndSign() creates an RSA/PKCS1-1.5(SHA-1) signature, and does the equivalent of "SHA1withRSA" Signature method in Java
        # Note: the accesskeyid is already base64-encoded here
        sig = base64.b64encode(self._key.hashAndSign(acc))
        return sig

    def get_body(self, action, params=None, attachments=None):
        if self.host == 'test':
            # sanitize accesskeyid and signature for test fixtures
            acc = '...'
            sig = '...'
        else:
            acc = self.get_accesskeyid()
            sig = self.get_signature(acc)
        CRLF = '\r\n'
        L = []
        if self.host == 'test' or self.debug > 1:
            self._testid = action
        L.append('<?xml version="1.0" encoding="UTF-8"?>')
        L.append('<OViSSRequest>')
        L.append('  <Action>' + action + '</Action>')
        L.append('  <Version>' + self.api_version + '</Version>')
        L.append('  <Locale>' + self.locale + '</Locale>')
        if params is not None:
            for key, val in params.items():
                extra = self.add_param(key, val, 1)
                if extra:
                    L.append(extra)
        L.append('  <AccessKeyId>' + acc + '</AccessKeyId>')
        L.append('  <Signature>' + sig + '</Signature>')
        L.append('</OViSSRequest>')
        body = CRLF.join(L)

        # add request description file for certain EFM Configuration methods and other API commands
        if attachments is None:
            attachments = []
        elif len(attachments) > 0 and isinstance(attachments, dict):
            attachments = [attachments]
        if len(attachments) > 0:
            L = []
            L.append('--BOUNDARY')
            L.append('Content-Type: text/xml; charset=UTF-8')
            L.append('Content-Disposition: form-data; name="Document"')
            L.append('')
            L.append(body)
            L.append('')
            for attachment in attachments:
                if 'body' not in attachment:
                    attachment['body'] = open(attachment['filename'], 'rb').read()
                elif 'filename' not in attachment:
                    attachment['filename'] = 'extra.xml'
                L.append('--BOUNDARY')
                L.append('Content-Type: application/octet-stream')
                L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (attachment['name'], attachment['filename']))
                L.append('')
                L.append(attachment['body'])
                if self.host == 'test' or self.debug > 1:
                    self._testid += '.%s' % attachment['filename']
            L.append('--BOUNDARY--')
            body = CRLF.join(L)
            #if len(attachments) > 1:
            #    print body
            #    exit()

        return body

    def add_param(self, key=None, value=None, depth=0):
        CRLF = '\r\n'
        L = []
        if key is None:
            pass
        elif value is None:
            # CHECKME: we skip None values too
            pass
        elif isinstance(value, str):
            # <prefix>proto</prefix>
            L.append('  ' * depth + '<%s>%s</%s>' % (key, value, key))
            if self.host == 'test' or self.debug > 1:
                self._testid += '.%s' % value
        elif isinstance(value, dict):
            # <order>
            #   <prefix>proto</proto>
            #   <value>tcp</value>
            # </order>
            L.append('  ' * depth + '<%s>' % key)
            for entry, val in value.items():
                extra = self.add_param(entry, val, depth + 1)
                if extra:
                    L.append(extra)
            L.append('  ' * depth + '</%s>' % key)
        elif isinstance(value, list):
            L.append('  ' * depth + '<%s>' % key)
            # <orders>
            #   <order>
            #     ...
            #   </order>
            #   <order>
            #     ...
            #   </order>
            # </orders>
            for item in value:
                # CHECKME: item must be a dict of {'entry': val} !
                for entry, val in item.items():
                    extra = self.add_param(entry, val, depth + 1)
                    if extra:
                        L.append(extra)
            L.append('  ' * depth + '</%s>' % key)
        else:
            # <prefix>proto</prefix>
            L.append('  ' * depth + '<%s>%s</%s>' % (key, value, key))
            if self.host == 'test' or self.debug > 1:
                self._testid += '.%s' % value
        return CRLF.join(L)

    def do_action(self, action, params=None, attachments=None):
        """
        Send the XML-RPC request and get the response
        """
        # prepare headers and body
        headers = self.get_headers(attachments)
        body = self.get_body(action, params, attachments)
        if self.debug > 2 and os.path.isdir(os.path.join('tests', 'fixtures')):
            # sanitize accesskeyid and signature for test fixtures
            import re
            p = re.compile('<AccessKeyId>[^<]+</AccessKeyId>')
            req = p.sub('<AccessKeyId>...</AccessKeyId>', body)
            p = re.compile('<Signature>[^<]+</Signature>')
            req = p.sub('<Signature>...</Signature>', req)
            print 'Saving request for %s' % self._testid
            # save request in tests/fixtures
            f = open(os.path.join('tests', 'fixtures', self._testid + '.request.xml'), 'wb')
            f.write(req)
            f.close()
        elif self.debug > 1:
            print 'XML-RPC Request for %s:' % self._testid
            print body

        # send XML-RPC request
        self.send('POST', self.uri, body, headers)

        # receive XML-RPC response
        data = self.receive()
        if self.debug > 2 and os.path.isdir(os.path.join('tests', 'fixtures')):
            print 'Saving response for %s' % self._testid
            # save response in tests/fixtures
            f = open(os.path.join('tests', 'fixtures', self._testid + '.response.xml'), 'wb')
            f.write(data)
            f.close()
        elif self.debug > 1:
            print 'XML-RPC Response for %s:' % self._testid
            print data

        # analyze XML-RPC response
        resp = FGCPResponseParser().parse_data(data, self)
        if self.debug > 0:
            print 'FGCP Response for %s:' % action
            resp.pprint()
        # CHECKME: raise exception whenever we don't have SUCCESS
        if resp.responseStatus != 'SUCCESS':
            raise FGCPResponseError(resp.responseStatus, resp.responseMessage)

        # return FGCP Response
        return resp


class FGCPResponseParser:
    """
    FGCP Response Parser
    """
    _client = None
    # CHECKME: this assumes all tags are unique - otherwise we'll need to use the path
    _tag2class = {
        'vsysdescriptor': FGCPVSysDescriptor,
        'publicip': FGCPPublicIP,
        'addressrange': FGCPAddressRange,
        'diskimage': FGCPDiskImage,
        'software': FGCPDiskImageSoftware,
        'servertype': FGCPServerType,
        'cpu': FGCPServerTypeCPU,
        'vsys': FGCPVSystem,
        'vserver': FGCPVServer,
        'vdisk': FGCPVDisk,
        'backup': FGCPBackup,
        'vnic': FGCPVNic,
        'efm': FGCPEfm,
        'firewall': FGCPFirewall,
        'rule': FGCPFWNATRule,
        'dns': FGCPFWDns,
        'direction': FGCPFWDirection,
        'policy': FGCPFWPolicy,
        'order': FGCPFWLogOrder,
        'loadbalancer': FGCPLoadBalancer,
        'group': FGCPSLBGroup,
        'target': FGCPSLBTarget,
        'errorStatistics': FGCPSLBErrorStats,
        'cause': FGCPSLBErrorCause,
        'period': FGCPSLBErrorPeriod,
        'servercert': FGCPSLBServerCert,
        'ccacert': FGCPSLBCCACert,
        'usageinfo': FGCPUsageInfo,
        'product': FGCPUsageInfoProduct,
        'response': FGCPResponse,
        'default': FGCPUnknown,
    }

    def parse_data(self, data, client):
        """
        Load the data as XML ElementTree and convert to FGCP Response
        """
        # keep track of the connection client
        self._client = client
        #ElementTree.register_namespace(uri='http://apioviss.jp.fujitsu.com')
        # initialize the XML Element
        root = ElementTree.fromstring(data)
        # convert the XML Element to FGCP Response object - CHECKME: and link to caller !?
        return self.xmlelement_to_object(root, client._caller)

    def clean_tag(self, tag):
        """
        Return the tag without namespace
        """
        if tag is None:
            return tag
        elif tag.startswith('{'):
            return tag[tag.index('}') + 1:]
        else:
            return tag

    def get_tag_object(self, tag):
        tag = self.clean_tag(tag)
        if tag in self._tag2class:
            return self._tag2class[tag]()
        elif tag.endswith('Response'):
            return self._tag2class['response']()
        else:
            #print 'CHECKME: unknown tag ' + tag
            return self._tag2class['default']()

    # CHECKME: get rid of parent here again, and re-parent in resource itself ?
    def xmlelement_to_object(self, root=None, parent=None):
        """
        Convert the XML Element to an FGCP Element
        """
        if root is None:
            return
        # CHECKME: we don't seem to have any attributes here
        #for key, val in root.items():
        #    if key in info:
        #        print "OOPS ! " + key + " attrib is already in " + repr(info)
        #    else:
        #        info[key] = val
        # No children -> return text
        if len(root) < 1:
            if root.text is None:
                return ''
            else:
                return root.text.strip()
        # One child -> return list !?
        elif len(root) == 1:
            info = []
            # if the child returns a string, return that too (cfr. ListServerType - servertype - memory - memorySize)
            for subelem in root:
                # CHECKME: use grand-parent for the child now !
                child = self.xmlelement_to_object(subelem, parent)
                if isinstance(child, str):
                    return child
                else:
                    info.append(child)
            return info
        # More children -> return dict or list !?
        #info = {}
        # FIXME: adapt class based on subelem or tag ?
        info = self.get_tag_object(root.tag)
        # add client to object
        info._client = self._client
        if isinstance(info, FGCPResource):
            # CHECKME: add parent and client to the FGCP Resource
            info._parent = parent
            info._client = self._client
        elif isinstance(info, FGCPResponse):
            # CHECKME: add caller to the FGCP Respone
            info._caller = parent
        for subelem in root:
            key = self.clean_tag(subelem.tag)
            if isinstance(info, list):
                # CHECKME: use grand-parent for the child now !
                info.append(self.xmlelement_to_object(subelem, parent))
            elif hasattr(info, key):
                #print "OOPS ! " + key + " child is already in " + repr(info)
                # convert to list !?
                child = getattr(info, key)
                # CHECKME: re-parent the child
                if child is not None and isinstance(child, FGCPResource):
                    child._parent = parent
                info = [child]
                # CHECKME: use grand-parent for the child now !
                info.append(self.xmlelement_to_object(subelem, parent))
            elif isinstance(info, FGCPResponse):
                # CHECKME: use caller as parent here
                setattr(info, key, self.xmlelement_to_object(subelem, parent))
            else:
                # CHECKME: use current info as parent for now
                setattr(info, key, self.xmlelement_to_object(subelem, info))
        return info
