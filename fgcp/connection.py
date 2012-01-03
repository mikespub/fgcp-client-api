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
XML-RPC Connection with the Fujitsu Global Cloud Platform (FGCP) API Server

Example: [not recommended, use API Commands, Resource Actions and/or Client Methods instead]

# Connect with your client certificate to region 'uk'
from fgcp.connection import FGCPProxyServer
xmlrpc_proxy = FGCPProxyServer('client.pem', 'uk')

# Send XML-RPC actions, request parameters and attachments
vsystems = xmlrpc_proxy.do_action('ListVSYS')
for vsys in vsystems:
    status = xmlrpc_proxy.do_action('GetVSYSStatus', {'vsysId': vsys.vsysId})
    vsysconfig = xmlrpc_proxy.do_action('GetVSYSConfiguration', {'vsysId': vsys.vsysId})
    for vserver in vsysconfig.vservers:
        status = xmlrpc_proxy.do_action('GetVServerStatus', {'vsysId': vsys.vsysId, 'vserverId': vserver.vserverId})
    ...
"""

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
    """
    key_file = 'client.pem'                         # updated based on key_file argument
    region = 'de'                                   # updated based on region argument
    locale = 'en'                                   # TODO: make configurable to 'en' or 'jp' ?
    timezone = 'Central European Time'              # updated based on time.tzname[0] or time.timezone
    verbose = 0                                     # normal script output for users:
                                                    #   0 = quiet
                                                    #   1 = show user output
                                                    #   2 = show status output
    debug = 0                                       # for development purposes:
                                                    #   0 = quiet
                                                    #   1 = show API request
                                                    #   2 = dump response object
                                                    #   3 = dump request/response body
                                                    #  99 = save request/response body for test fixture

    uri = '/ovissapi/endpoint'                      # fixed value for the API version
    api_version = '2011-01-31'                      # fixed value for the API version
    user_agent = 'OViSS-API-CLIENT'                 # fixed value for the API version

    _conn = None                                    # actual httplib.HTTPSConnection() or FGCPTestServerWithFixtures() or ...
    _caller = None                                  # which FGCPResource() is calling
    _testid = None                                  # test identifier for fixtures

    def __init__(self, key_file='client.pem', region='de', verbose=0, debug=0, conn=None):
        """
        Use the same PEM file for SSL client certificate and RSA key signature

        Note: to convert your .p12 or .pfx file to unencrypted PEM format, you can use
        the following 'openssl' command:

        openssl pkcs12 -in UserCert.p12 -out client.pem -nodes
        """
        self.key_file = key_file
        self.region = region
        self.verbose = verbose
        self.debug = debug
        if conn is not None:
            self._conn = conn
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
        return '<%s:%s>' % (self.__class__.__name__, self.region)

    def set_region(self, region):
        # reset connection if necessary
        if self.region != region:
            self.close()
        self.region = region

    def set_conn(self, conn):
        # CHECKME: set connection from elsewhere, e.g. for integration with Apache Libcloud or running on Google App Engine
        self._conn = conn

    def connect(self):
        if self._conn is None:
            # get the right server connection
            from fgcp.server import FGCPGetServerConnection
            self._conn = FGCPGetServerConnection(key_file=self.key_file, region=self.region)

    def send(self, method, uri, body, headers):
        # initialize connection if necessary
        self.connect()
        # set testid if necessary
        if self.region == 'test':
            self._conn.set_testid(self._testid)
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
        if self._conn is not None:
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
        if self.region == 'test':
            # sanitize accesskeyid and signature for test fixtures
            acc = '...'
            sig = '...'
        else:
            acc = self.get_accesskeyid()
            sig = self.get_signature(acc)
        CRLF = '\r\n'
        L = []
        if self.region == 'test' or self.debug > 0:
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
                    if os.path.exists(attachment['filename']):
                        attachment['body'] = open(attachment['filename'], 'rb').read()
                    else:
                        raise FGCPResponseError('INVALID_PATH', 'Attachment file %s does not exist' % attachment['filename'])
                elif 'filename' not in attachment:
                    attachment['filename'] = 'extra.xml'
                L.append('--BOUNDARY')
                L.append('Content-Type: application/octet-stream')
                L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (attachment['name'], attachment['filename']))
                L.append('')
                L.append(attachment['body'])
                if self.region == 'test' or self.debug > 0:
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
            if self.region == 'test' or self.debug > 0:
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
            if self.region == 'test' or self.debug > 0:
                self._testid += '.%s' % value
        return CRLF.join(L)

    def do_action(self, action, params=None, attachments=None):
        """
        Send the XML-RPC request and get the response
        """
        # prepare headers and body
        headers = self.get_headers(attachments)
        body = self.get_body(action, params, attachments)
        if self.debug > 10:
            print 'Saving request for %s' % self._testid
            if not hasattr(self, '_tester'):
                # use test API server for saving tests too
                from fgcp.server import FGCPTestServerWithFixtures
                setattr(self, '_tester', FGCPTestServerWithFixtures())
            self._tester.save_request(self._testid, body)
        elif self.debug > 2:
            print 'XML-RPC Request for %s:' % self._testid
            print body
        elif self.debug > 0:
            print self._testid

        # send XML-RPC request
        self.send('POST', self.uri, body, headers)

        # receive XML-RPC response
        data = self.receive()
        if self.debug > 10:
            print 'Saving response for %s' % self._testid
            self._tester.save_response(self._testid, data)
        elif self.debug > 2:
            print 'XML-RPC Response for %s:' % self._testid
            print data

        # analyze XML-RPC response
        try:
            resp = FGCPResponseParser().parse_data(data, self)
        except:
            print 'Invalid XML-RPC Response:'
            print data
            raise
        if self.debug > 1:
            print 'FGCP Response for %s:' % action
            resp.pprint()
        # CHECKME: raise exception whenever we don't have SUCCESS
        if resp.responseStatus != 'SUCCESS':
            raise FGCPResponseError(resp.responseStatus, resp.responseMessage)

        # return FGCP Response
        return resp


class FGCPProxyServer(FGCPConnection):
    """
    FGCP XML-RPC Proxy Server
    """
    pass


class FGCPResponseParser:
    """
    FGCP Response Parser
    """
    _proxy = None
    # CHECKME: this assumes all tags are unique - otherwise we'll need to use the path
    _tag2class = {
        'vsysdescriptor': FGCPVSysDescriptor,
        'publicip': FGCPPublicIP,
        'addressrange': FGCPAddressRange,
        'diskimage': FGCPDiskImage,
        'software': FGCPImageSoftware,
        'servertype': FGCPServerType,
        'cpu': FGCPServerTypeCPU,
        'vsys': FGCPVSystem,
        'vserver': FGCPVServer,
        'image': FGCPVServerImage,
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
        'cause': FGCPSLBCause,
        'period': FGCPSLBErrorPeriod,
        'servercert': FGCPSLBServerCert,
        'ccacert': FGCPSLBCCACert,
        'usageinfo': FGCPUsageInfo,
        'product': FGCPUsageInfoProduct,
        'response': FGCPResponse,
        'default': FGCPUnknown,
    }

    def parse_data(self, data, proxy):
        """
        Load the data as XML ElementTree and convert to FGCP Response
        """
        # keep track of the connection proxy
        self._proxy = proxy
        #ElementTree.register_namespace(uri='http://apioviss.jp.fujitsu.com')
        # initialize the XML Element
        root = ElementTree.fromstring(data)
        # convert the XML Element to FGCP Response object - CHECKME: and link to caller !?
        return self.xmlelement_to_object(root, proxy._caller)

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
        # add proxy to object
        info._proxy = self._proxy
        if isinstance(info, FGCPResource):
            # CHECKME: add parent and proxy to the FGCP Resource
            info._parent = parent
            info._proxy = self._proxy
        elif isinstance(info, FGCPResponse):
            # CHECKME: add caller to the FGCP Respone
            info._caller = parent
        for subelem in root:
            key = self.clean_tag(subelem.tag)
            if isinstance(info, list):
                # CHECKME: use grand-parent for the child now !
                info.append(self.xmlelement_to_object(subelem, parent))
            elif hasattr(info, key) and key == 'status':
                # special case to avoid overlap with status() method
                setattr(info, '_status', self.xmlelement_to_object(subelem, info))
            elif hasattr(info, key) and getattr(info, key) is not None:
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
