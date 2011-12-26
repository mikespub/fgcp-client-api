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
Client API library for the Fujitsu Global Cloud Platform (FGCP)
using XML-RPC API Version 2011-01-31

Requirements: this module uses gdata.tlslite.utils to create the key signature,
see http://code.google.com/p/gdata-python-client/ for download and installation

Caution: this is a development work in progress - please do not use
for productive systems without adequate testing...
"""

import httplib
import time
import base64

from fgcp.resource import *

try:
	from gdata.tlslite.utils import keyfactory
except:
	print """Requirements: this module uses gdata.tlslite.utils to create the key signature,
see http://code.google.com/p/gdata-python-client/ for download and installation"""
	exit()
from xml.etree import ElementTree

class FGCPConnection:
	"""
	FGCP XML-RPC Connection
	
	Example:
	from fgcp_client_api import FGCPConnection
	conn = FGCPConnection('client.pem', 'uk')
	vsyss = conn.do_action('ListVSYS')
	"""
	host = 'api.globalcloud.de.fujitsu.com'
	uri = '/ovissapi/endpoint'
	api_version = '2011-01-31'
	user_agent = 'OViSS-API-CLIENT'
	locale = 'en'
	timezone = 'Central European Time'			# updated based on time.tzname[0] or time.timezone
	key_file = 'client.pem'
	verbose = 0									# normal script output for users
	debug = 0									# for development purposes
	_regions = {
		'au': 'api.globalcloud.fujitsu.com.au',	# for Australia and New Zealand
		'de': 'api.globalcloud.de.fujitsu.com',	# for Central Europe, Middle East, Eastern Europe, Africa & India (CEMEA&I)
		'jp': 'api.oviss.jp.fujitsu.com',		# for Japan
		'sg': 'api.globalcloud.sg.fujitsu.com',	# for Singapore, Malaysia, Indonesia, Thailand and Vietnam
		'uk': 'api.globalcloud.uk.fujitsu.com',	# for the UK and Ireland (UK&I)
		'us': 'api.globalcloud.us.fujitsu.com',	# for the Americas
	}
	_conn = None

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

	def set_region(self, region):
		if region in self._regions:
			# reset connection if necessary
			if self._conn is not None and self.host != self._regions[region]:
				self.close()
			self.host = self._regions[region]

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
		acc = self.get_accesskeyid()
		sig = self.get_signature(acc)
		CRLF = '\r\n'
		L = []
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
			L.append('--BOUNDARY--')
			body = CRLF.join(L)
			#if len(attachments) > 1:
			#	print body
			#	exit()

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
		return CRLF.join(L)

	def do_action(self, action, params=None, attachments=None):
		"""
		Send the XML-RPC request and get the response
		"""
		if self._conn is None:
			# use the same PEM file for cert and key
			self._conn = httplib.HTTPSConnection(self.host, key_file=self.key_file, cert_file=self.key_file)

		headers = self.get_headers(attachments)
		body = self.get_body(action, params, attachments)
		if self.debug > 1:
			print 'XML-RPC Request for %s:' % action
			print body

		# send XML-RPC request
		self._conn.request('POST', self.uri, body, headers)

		resp = self._conn.getresponse()
		if resp.status != 200:
			raise FGCPResponseError(repr(resp.status), repr(resp.reason))
		data = resp.read()
		if self.debug > 1:
			print 'XML-RPC Response for %s:' % action
			print data

		# analyze XML-RPC response
		resp = FGCPResponseParser().parse_data(data)
		if self.debug > 0:
			print 'FGCP Response for %s:' % action
			resp.dump()
		# FIXME: use todict() first, and then verify responseStatus ?
		if resp.responseStatus != 'SUCCESS':
			raise FGCPResponseError(resp.responseStatus, resp.responseMessage)

		# return FGCP Response
		return resp

class FGCPResponseError(Exception):
	"""
	Exception class for FGCP Response errors
	"""
	def __init__(self, status, message):
		self.status = status
		self.message = message
	def __str__(self):
		return "Status: " + self.status + "\nMessage: " + self.message

class FGCPResponseParser:
	"""
	FGCP Response Parser
	"""
	# CHECKME: this assumes all tags are unique - otherwise we'll need to use the path
	_tag2class = {
		'vsysdescriptor': FGCPVSysDescriptor,
		'publicip': FGCPPublicIP,
		'addressrange': FGCPAddressRange,
		'diskimage': FGCPDiskImage,
		'software': FGCPSoftware,
		'servertype': FGCPServerType,
		'cpu': FGCPServerTypeCPU,
		'vsys': FGCPVSys,
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
		'product': FGCPProduct,
		'response': FGCPResponse,
		'default': FGCPUnknown,
	}

	def parse_data(self, data):
		"""
		Load the data as XML ElementTree and convert to FGCP Response
		"""
		#ElementTree.register_namespace(uri='http://apioviss.jp.fujitsu.com')
		# initialize the XML Element
		root = ElementTree.fromstring(data)
		# convert the XML Element to FGCP Response object
		return self.xmlelement_to_object(root)

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

	def xmlelement_to_object(self, root=None):
		"""
		Convert the XML Element to an FGCP Element
		"""
		if root is None:
			return
		# CHECKME: we don't seem to have any attributes here
		#for key, val in root.items():
		#	if key in info:
		#		print "OOPS ! " + key + " attrib is already in " + repr(info)
		#	else:
		#		info[key] = val
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
				child = self.xmlelement_to_object(subelem)
				if isinstance(child, str):
					return child
				else:
					info.append(child)
			return info
		# More children -> return dict or list !?
		#info = {}
		# FIXME: adapt class based on subelem or tag ?
		info = self.get_tag_object(root.tag)
		for subelem in root:
			key = self.clean_tag(subelem.tag)
			if isinstance(info, list):
				info.append(self.xmlelement_to_object(subelem))
			elif hasattr(info, key):
				#print "OOPS ! " + key + " child is already in " + repr(info)
				# convert to list !?
				old_info = getattr(info,key)
				info = [old_info]
				info.append(self.xmlelement_to_object(subelem))
			else:
				setattr(info, key, self.xmlelement_to_object(subelem))
		return info
