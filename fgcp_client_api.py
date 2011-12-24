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
		resp = FGCPResponse(data)
		if self.debug > 0:
			print 'FGCP Response for %s:' % action
			resp.dump()
		# FIXME: use todict() first, and then verify responseStatus ?
		if resp.responseStatus.text != 'SUCCESS':
			raise FGCPResponseError(resp.responseStatus.text, resp.responseMessage.text)

		# return dictionary
		return resp.todict()

class FGCPResponseError(Exception):
	"""
	Exception class for FGCP Response errors
	"""
	def __init__(self, status, message):
		self.status = status
		self.message = message
	def __str__(self):
		return "Status: " + self.status + "\nMessage: " + self.message

class FGCPResponseElement(object):
	"""
	FIXME: dummy object to access response elements by name
	"""
	_elem = None
	text = 'N/A'
	def __init__(self, elem):
		"""
		Initialize the root element
		"""
		self._elem = elem
		# CHECKME: initialize the text (?)
		if self._elem is not None and self._elem.text is not None:
			self.text = self._elem.text.strip()
	def __getattr__(self, name):
		"""
		Find the first subelement that matches the name
		"""
		found = self._elem.find('{http://apioviss.jp.fujitsu.com}%s' % name)
		if found is not None:
			return FGCPResponseElement(found)
	def __repr__(self):
		"""
		Return the text corresponding to this element
		"""
		if self._elem is None:
			return 'N/A'
		elif self._elem.text:
			text = self._elem.text.strip()
			return self.cleantag(self._elem.tag) + ': "' + text + '"'
		else:
			return self.cleantag(self._elem.tag) + ': N/A'
	def __iter__(self):
		"""
		Return a list of subelements as iterator
		"""
		nodes = []
		for subelem in self._elem:
			nodes.append(FGCPResponseElement(subelem))
		return iter(nodes)
	def dump(self, depth=0):
		"""
		Show dump of the FGCP Response for development
		"""
		#self.printelem(self._elem)
		import pprint
		pprint.pprint(self.todict())
	def todict(self, root=None):
		"""
		Convert the Element to a (semi-)flat dict
		"""
		if root is None:
			root = self._elem
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
				child = self.todict(subelem)
				if isinstance(child, str):
					return child
				else:
					info.append(child)
			return info
		# More children -> return dict or list !?
		info = {}
		is_array = 0
		for subelem in root:
			key = self.cleantag(subelem.tag)
			if key in info:
				#print "OOPS ! " + key + " child is already in " + repr(info)
				# convert to list !?
				old_info = info[key]
				info = []
				info.append(old_info)
				is_array = 1
			if is_array == 1:
				info.append(self.todict(subelem))
			else:
				info[key] = self.todict(subelem)
		return info
	def printelem(self, elem, depth=0):
		"""
		Print out the Element recursively
		"""
		if elem.text:
			print '  ' * depth + self.cleantag(elem.tag) + ': ' + elem.text
		else:
			print '  ' * depth + self.cleantag(elem.tag) + ': '
		# CHECKME: we don't seem to have any attributes here
		for key, val in elem.items():
			print '  ' * depth + '  ' + key + '=' + val
		for child in elem:
			self.printelem(child, depth+1)
	def cleantag(self, tag):
		"""
		Return the tag without namespace
		"""
		if tag is None:
			return tag
		elif tag.startswith('{'):
			return tag[tag.index('}') + 1:]
		else:
			return tag

class FGCPResponse(FGCPResponseElement):
	"""
	FIXME: dummy object to access response elements by name
	"""
	def __init__(self, data):
		"""
		Load the FGCP Response as XML ElementTree
		"""
		#ElementTree.register_namespace(uri='http://apioviss.jp.fujitsu.com')
		# initialize the root element
		self._elem = ElementTree.fromstring(data)


class FGCPCommand(FGCPConnection):
	"""
	FGCP API Commands
	
	Example:
	from fgcp_client_api import FGCPCommand
	cmd = FGCPCommand('client.pem', 'uk')
	vsyss = cmd.ListVSYS()
	for vsys in vsyss:
		print vsys['vsysName']
		vsysconfig = cmd.GetVSYSConfiguration(vsys['vsysId'])
		...
	"""

	def set_verbose(self, verbose=None):
		"""
		Show output (1), status checks (2) or nothing (0)
		"""
		old_verbose = self.verbose
		if verbose is None:
			# don't change current setting
			pass
		elif verbose > 1:
			# start showing output + status
			self.verbose = 2
		elif verbose == 1:
			# start showing output
			self.verbose = 1
		else:
			# stop showing output
			self.verbose = 0
		return old_verbose

	def show_output(self, text=''):
		if self.verbose > 0:
			print text

	def show_status(self, text=''):
		if self.verbose > 1:
			print text

	def ListVSYSDescriptor(self):
		"""
		Usage: vsysdescriptors = client.ListVSYSDescriptor()
		"""
		result = self.do_action('ListVSYSDescriptor')
		return result['vsysdescriptors']

	def GetVSYSDescriptorConfiguration(self, vsysDescriptorId):
		"""
		Usage: vsysdescriptorconfig = client.GetVSYSDescriptorConfiguration(vsysDescriptorId)
		"""
		result = self.do_action('GetVSYSDescriptorConfiguration', {'vsysDescriptorId': vsysDescriptorId})
		return result['vsysdescriptor']

	def GetVSYSDescriptorAttributes(self, vsysDescriptorId):
		"""
		Usage: vsysdescriptorattr = client.GetVSYSDescriptorAttributes(vsysDescriptorId)
		"""
		result = self.do_action('GetVSYSDescriptorAttributes', {'vsysDescriptorId': vsysDescriptorId})
		return result['vsysdescriptor']

	def UpdateVSYSDescriptorAttribute(self, vsysDescriptorId, updateLcId, attributeName, attributeValue):
		result = self.do_action('UpdateVSYSDescriptorAttribute', {'vsysDescriptorId': vsysDescriptorId, 'updateLcId': updateLcId, 'attributeName': attributeName, 'attributeValue': attributeValue})
		return result

	def UnregisterVSYSDescriptor(self, vsysDescriptorId):
		result = self.do_action('UnregisterVSYSDescriptor', {'vsysDescriptorId': vsysDescriptorId})
		return result

	def RegisterPrivateVSYSDescriptor(self, vsysId, name, description, keyword, vservers):
		"""Usage:
		inventory = client.GetSystemInventory('My Existing VSYS')
		client.RegisterPrivateVSYSDescriptor(inventory['vsysId'], 'My New Template', 'This is a new template based on my existing VSYS', 'some key words', inventory['vservers'])
		"""
		filename = 'dummy.xml'
		vsysDescriptorXML = self.get_vsysDescriptorXML(vsysId, name, description, keyword, vservers)
		result = self.do_action('RegisterPrivateVSYSDescriptor', {'vsysDescriptorXMLFilePath': filename}, {'name': 'vsysDescriptorXMLFilePath', 'filename': filename, 'body': vsysDescriptorXML})
		return result

	def get_vsysDescriptorXML(self, vsysId, name, description, keyword, vservers):
		CRLF = '\r\n'
		L = []
		L.append('<?xml version="1.0" encoding="UTF-8"?>')
		L.append('<Request>')
		L.append('  <vsysId>%s</vsysId>' % vsysId)
		L.append('  <locales>')
		L.append('    <locale>')
		L.append('      <lcid>en</lcid>')
		L.append('      <name>%s</name>' % name)
		L.append('      <description>%s</description>' % description)
		L.append('    </locale>')
		L.append('  </locales>')
		L.append('  <keyword>%s</keyword>' % keyword)
		L.append('  <servers>')
		if vservers is not None and len(vservers) > 0:
			# CHECKME: do we need to add name & description for loadbalancers too ?
			for vserver in vservers:
				L.append('    <server>')
				# CHECKME: and what should we use for the id here - is it mandatory ?
				L.append('      <id>%s</id>' % vserver['vserverId'])
				L.append('      <locales>')
				L.append('        <locale>')
				L.append('          <lcid>en</lcid>')
				L.append('          <name>%s</name>' % vserver['vserverName'])
				# CHECKME: what should we use for description ?
				descr = vserver['vserverName'] + ' on ' + vserver['vserverType'] + ' server type'
				L.append('          <description>%s</description>' % descr)
				L.append('        </locale>')
				L.append('      </locales>')
				L.append('    </server>')
				L.append('  </servers>')
				L.append('</Request>')
		return CRLF.join(L)

	def UnregisterPrivateVSYSDescriptor(self, vsysDescriptorId):
		result = self.do_action('UnregisterPrivateVSYSDescriptor', {'vsysDescriptorId': vsysDescriptorId})
		return result

	def ListPublicIP(self, vsysId=None):
		"""
		Usage: publicips = client.ListPublicIP()
		"""
		result = self.do_action('ListPublicIP', {'vsysId': vsysId})
		return result['publicips']

	def GetPublicIPAttributes(self, publicIp):
		"""
		Usage: publicipattr = client.GetPublicIPAttributes(publicIp)
		"""
		result = self.do_action('GetPublicIPStatus', {'publicIp': publicIp})
		return result['publicips']

	def GetPublicIPStatus(self, publicIp):
		"""
		Usage: status = client.GetPublicIPStatus(publicIp)
		"""
		result = self.do_action('GetPublicIPStatus', {'publicIp': publicIp})
		# show status if requested, e.g. for wait operations
		self.show_status(result['publicipStatus'])
		return result['publicipStatus']

	def AllocatePublicIP(self, vsysId):
		result = self.do_action('AllocatePublicIP', {'vsysId': vsysId})
		return result

	def AttachPublicIP(self, vsysId, publicIp):
		result = self.do_action('AttachPublicIP', {'vsysId': vsysId, 'publicIp': publicIp})
		return result

	def DetachPublicIP(self, vsysId, publicIp):
		result = self.do_action('DetachPublicIP', {'vsysId': vsysId, 'publicIp': publicIp})
		return result

	def FreePublicIP(self, vsysId, publicIp):
		result = self.do_action('FreePublicIP', {'vsysId': vsysId, 'publicIp': publicIp})
		return result

	def GetAddressRange(self):
		"""
		Usage: addressranges = client.GetAddressRange()
		"""
		result = self.do_action('GetAddressRange')
		if 'addressranges' in result:
			return result['addressranges']

	def CreateAddressPool(self, pipFrom=None, pipTo=None):
		result = self.do_action('CreateAddressPool', {'pipFrom': pipFrom, 'pipTo': pipTo})
		return result

	def AddAddressRange(self, pipFrom, pipTo):
		result = self.do_action('AddAddressRange', {'pipFrom': pipFrom, 'pipTo': pipTo})
		return result

	def DeleteAddressRange(self, pipFrom, pipTo):
		result = self.do_action('DeleteAddressRange', {'pipFrom': pipFrom, 'pipTo': pipTo})
		return result

	def ListDiskImage(self, serverCategory=None, vsysDescriptorId=None):
		"""
		Usage: diskimages = client.ListDiskImage()
		"""
		result = self.do_action('ListDiskImage', {'serverCategory': serverCategory, 'vsysDescriptorId': vsysDescriptorId})
		return result['diskimages']

	def GetDiskImageAttributes(self, vsysId, diskImageId):
		"""
		Usage: diskimage = client.GetDiskImageAttributes(vsysId, diskImageId)
		"""
		result = self.do_action('GetDiskImageAttributes', {'vsysId': vsysId, 'diskImageId': diskImageId})
		return result['diskimage']

	def UpdateDiskImageAttribute(self, vsysId, diskImageId, updateLcId, attributeName, attributeValue):
		result = self.do_action('UpdateDiskImageAttribute', {'vsysId': vsysId, 'diskImageId': diskImageId, 'updateLcId': updateLcId, 'attributeName': attributeName, 'attributeValue': attributeValue})
		return result

	def RegisterPrivateDiskImage(self, vserverId, name, description):
		filename = 'dummy.xml'
		diskImageXML = self.get_diskImageXML(vserverId, name, description)
		result = self.do_action('RegisterPrivateDiskImage', {'diskImageXMLFilePath': filename}, {'name': 'diskImageXMLFilePath', 'filename': filename, 'body': diskImageXML})
		return result

	def get_diskImageXML(self, vserverId, name, description):
		CRLF = '\r\n'
		L = []
		L.append('<?xml version="1.0" encoding="UTF-8"?>')
		L.append('<Request>')
		L.append('  <vserverId>%s</vserverId>' % vserverId)
		L.append('  <locales>')
		L.append('    <locale>')
		L.append('      <lcid>en</lcid>')
		L.append('      <name>%s</name>' % name)
		L.append('      <description>%s</description>' % description)
		L.append('    </locale>')
		L.append('  </locales>')
		L.append('</Request>')
		return CRLF.join(L)

	def UnregisterDiskImage(self, diskImageId):
		result = self.do_action('UnregisterDiskImage', {'diskImageId': diskImageId})
		return result

	def ListServerType(self, diskImageId):
		"""
		Usage: servertypes = client.ListServerType(diskImageId)
		"""
		result = self.do_action('ListServerType', {'diskImageId': diskImageId})
		return result['servertypes']

	def ListVSYS(self):
		"""
		Usage: vsyss = client.ListVSYS()
		"""
		result = self.do_action('ListVSYS')
		# CHECKME: initialize empty list if necessary
		if 'vsyss' not in result:
			result['vsyss'] = []
		return result['vsyss']

	def GetVSYSConfiguration(self, vsysId):
		"""
		Usage: vsysconfig = client.GetVSYSConfiguration(vsysId)
		"""
		result = self.do_action('GetVSYSConfiguration', {'vsysId': vsysId})
		return result['vsys']

	def UpdateVSYSConfiguration(self, vsysId, configurationName, configurationValue):
		result = self.do_action('UpdateVSYSConfiguration', {'vsysId': vsysId, 'configurationName': configurationName, 'configurationValue': configurationValue})
		return result

	def GetVSYSAttributes(self, vsysId):
		"""
		Usage: vsysattr = client.GetVSYSAttributes(vsysId)
		"""
		result = self.do_action('GetVSYSAttributes', {'vsysId': vsysId})
		return result['vsys']

	def UpdateVSYSAttribute(self, vsysId, attributeName, attributeValue):
		result = self.do_action('UpdateVSYSAttribute', {'vsysId': vsysId, 'attributeName': attributeName, 'attributeValue': attributeValue})
		return result

	def GetVSYSStatus(self, vsysId):
		"""
		Usage: status = client.GetVSYSStatus(vsysId)
		"""
		result = self.do_action('GetVSYSStatus', {'vsysId': vsysId})
		# show status if requested, e.g. for wait operations
		self.show_status(result['vsysStatus'])
		return result['vsysStatus']

	def CreateVSYS(self, vsysDescriptorId, vsysName):
		"""
		Usage: vsysId = client.CreateVSYS(vsysDescriptorId, vsysName)
		"""
		result = self.do_action('CreateVSYS', {'vsysDescriptorId': vsysDescriptorId, 'vsysName': vsysName})
		return result['vsysId']

	def DestroyVSYS(self, vsysId):
		result = self.do_action('DestroyVSYS', {'vsysId': vsysId})
		return result

	def ListVServer(self, vsysId):
		"""
		Usage: vservers = client.ListVServer(vsysId)
		"""
		result = self.do_action('ListVServer', {'vsysId': vsysId})
		return result['vservers']

	def GetVServerConfiguration(self, vsysId, vserverId):
		"""
		Usage: vserverconfig = client.GetVServerConfiguration(vsysId, vserverId)
		"""
		result = self.do_action('GetVServerConfiguration', {'vsysId': vsysId, 'vserverId': vserverId})
		return result['vserver']

	def GetVServerAttributes(self, vsysId, vserverId):
		"""
		Usage: vserverattr = client.GetVServerAttributes(vsysId, vserverId)
		"""
		result = self.do_action('GetVServerAttributes', {'vsysId': vsysId, 'vserverId': vserverId})
		return result['vserver']

	def UpdateVServerAttribute(self, vsysId, vserverId, attributeName, attributeValue):
		result = self.do_action('UpdateVServerAttribute', {'vsysId': vsysId, 'vserverId': vserverId, 'attributeName': attributeName, 'attributeValue': attributeValue})
		return result

	def GetVServerInitialPassword(self, vsysId, vserverId):
		"""
		Usage: initialpwd = client.GetVServerInitialPassword(vsysId, vserverId)
		"""
		result = self.do_action('GetVServerInitialPassword', {'vsysId': vsysId, 'vserverId': vserverId})
		return result['initialPassword']

	def GetVServerStatus(self, vsysId, vserverId):
		"""
		Usage: status = client.GetVServerStatus(vsysId, vserverId)
		"""
		result = self.do_action('GetVServerStatus', {'vsysId': vsysId, 'vserverId': vserverId})
		# show status if requested, e.g. for wait operations
		self.show_status(result['vserverStatus'])
		return result['vserverStatus']

	def CreateVServer(self, vsysId, vserverName, vserverType, diskImageId, networkId):
		"""
		Usage: vserverId = client.CreateVServer(self, vsysId, vserverName, vserverType, diskImageId, networkId)
		"""
		result = self.do_action('CreateVServer', {'vsysId': vsysId, 'vserverName': vserverName, 'vserverType': vserverType, 'diskImageId': diskImageId, 'networkId': networkId})
		return result['vserverId']

	def StartVServer(self, vsysId, vserverId):
		result = self.do_action('StartVServer', {'vsysId': vsysId, 'vserverId': vserverId})
		return result

	def StopVServer(self, vsysId, vserverId, force=None):
		result = self.do_action('StopVServer', {'vsysId': vsysId, 'vserverId': vserverId, 'force': force})
		return result

	def DestroyVServer(self, vsysId, vserverId):
		result = self.do_action('DestroyVServer', {'vsysId': vsysId, 'vserverId': vserverId})
		return result

	def ListVDisk(self, vsysId):
		"""
		Usage: vdisks = client.ListVDisk(vsysId)
		"""
		result = self.do_action('ListVDisk', {'vsysId': vsysId})
		return result['vdisks']

	def GetVDiskAttributes(self, vsysId, vdiskId):
		"""
		Usage: vdiskattr = client.GetVDiskAttributes(vsysId, vdiskId)
		"""
		result = self.do_action('GetVDiskAttributes', {'vsysId': vsysId, 'vdiskId': vdiskId})
		return result['vdisk']

	def UpdateVDiskAttribute(self, vsysId, vdiskId, attributeName, attributeValue):
		result = self.do_action('UpdateVDiskAttribute', {'vsysId': vsysId, 'vdiskId': vdiskId, 'attributeName': attributeName, 'attributeValue': attributeValue})
		return result

	def GetVDiskStatus(self, vsysId, vdiskId):
		"""
		Usage: status = client.GetVDiskStatus(vsysId, vdiskId)
		"""
		result = self.do_action('GetVDiskStatus', {'vsysId': vsysId, 'vdiskId': vdiskId})
		# show status if requested, e.g. for wait operations
		self.show_status(result['vdiskStatus'])
		return result['vdiskStatus']

	def CreateVDisk(self, vsysId, vdiskName, size):
		"""
		Usage: vdiskId = client.CreateVDisk(self, vsysId, vdiskName, size)
		"""
		result = self.do_action('CreateVDisk', {'vsysId': vsysId, 'vdiskName': vdiskName, 'size': size})
		return result['vdiskId']

	def AttachVDisk(self, vsysId, vserverId, vdiskId):
		result = self.do_action('AttachVDisk', {'vsysId': vsysId, 'vserverId': vserverId, 'vdiskId': vdiskId})
		return result

	def DetachVDisk(self, vsysId, vserverId, vdiskId):
		result = self.do_action('DetachVDisk', {'vsysId': vsysId, 'vserverId': vserverId, 'vdiskId': vdiskId})
		return result

	def DestroyVDisk(self, vsysId, vdiskId):
		result = self.do_action('DestroyVDisk', {'vsysId': vsysId, 'vdiskId': vdiskId})
		return result

	def ListVDiskBackup(self, vsysId, vdiskId, timeZone=None, countryCode=None):
		"""
		Usage: backups = client.ListVDiskBackup(vsysId, vdiskId)
		"""
		result = self.do_action('ListVDiskBackup', {'vsysId': vsysId, 'vdiskId': vdiskId, 'timeZone': timeZone, 'countryCode': countryCode})
		return result['backups']

	def BackupVDisk(self, vsysId, vdiskId):
		result = self.do_action('BackupVDisk', {'vsysId': vsysId, 'vdiskId': vdiskId})
		return result

	def RestoreVDisk(self, vsysId, backupId):
		result = self.do_action('RestoreVDisk', {'vsysId': vsysId, 'backupId': backupId})
		return result

	def DestroyVDiskBackup(self, vsysId, backupId):
		result = self.do_action('DestroyVDiskBackup', {'vsysId': vsysId, 'backupId': backupId})
		return result

	def ListEFM(self, vsysId, efmType):
		"""Usage:
		firewalls = client.ListEFM(vsysId, "FW")
		loadbalancers = client.ListEFM(vsysId, "SLB")
		"""
		result = self.do_action('ListEFM', {'vsysId': vsysId, 'efmType': efmType})
		return result['efms']

	def GetEFMConfiguration(self, vsysId, efmId, configurationName, configurationXML=None):
		"""Generic method for all GetEFMConfiguration methods"""
		if configurationXML is None:
			result = self.do_action('GetEFMConfiguration', {'vsysId': vsysId, 'efmId': efmId, 'configurationName':  configurationName})
		else:
			result = self.do_action('GetEFMConfiguration', {'vsysId': vsysId, 'efmId': efmId, 'configurationName':  configurationName}, {'name': 'configurationXMLFilePath', 'body': configurationXML})
		return result['efm']

	def GetEFMConfigHandler(self, vsysId, efmId):
		"""Handler for specific GetEFMConfiguration methods, see FGCPGetEFMConfigHandler for details
		Usage: fw_policy = client.GetEFMConfigHandler(vsysId, efmId).FW_POLICY(from_zone, to_zone)
		"""
		return FGCPGetEFMConfigHandler(self, vsysId, efmId)

	def UpdateEFMConfiguration(self, vsysId, efmId, configurationName, configurationXML=None, filePath=None):
		"""Generic method for all UpdateEFMConfiguration methods"""
		if configurationXML is None:
			result = self.do_action('UpdateEFMConfiguration', {'vsysId': vsysId, 'efmId': efmId, 'configurationName':  configurationName})
		elif filePath is None:
			result = self.do_action('UpdateEFMConfiguration', {'vsysId': vsysId, 'efmId': efmId, 'configurationName':  configurationName}, {'name': 'configurationXMLFilePath', 'body': configurationXML})
		else:
			# when adding SLB server/cca certificates, configurationXML contains the filePath for the actual certificate to be uploaded
			result = self.do_action('UpdateEFMConfiguration', {'vsysId': vsysId, 'efmId': efmId, 'configurationName':  configurationName}, [{'name': 'configurationXMLFilePath', 'body': configurationXML}, {'name': 'filePath', 'filename': filePath}])
		return result

	def UpdateEFMConfigHandler(self, vsysId, efmId):
		"""Handler for specific UpdateEFMConfiguration methods, see FGCPUpdateEFMConfigHandler for details
		Usage: client.UpdateEFMConfigHandler(vsysId, efmId).FW_DNS('AUTO')
		"""
		return FGCPUpdateEFMConfigHandler(self, vsysId, efmId)

	def get_configurationXML(self, configName, params=None):
		CRLF = '\r\n'
		L = []
		L.append('<?xml version="1.0" encoding="UTF-8"?>')
		L.append('<Request>')
		L.append('  <configuration>')
		L.append(self.add_param(configName, params, 2))
		L.append('  </configuration>')
		L.append('</Request>')
		return CRLF.join(L)

	def GetEFMAttributes(self, vsysId, efmId):
		"""
		Usage: efmattr = client.GetEFMAttributes(vsysId, efmId)
		"""
		result = self.do_action('GetEFMAttributes', {'vsysId': vsysId, 'efmId': efmId})
		return result['efm']

	def UpdateEFMAttribute(self, vsysId, efmId, attributeName, attributeValue):
		result = self.do_action('UpdateEFMAttribute', {'vsysId': vsysId, 'efmId': efmId, 'attributeName': attributeName, 'attributeValue': attributeValue})
		return result

	def GetEFMStatus(self, vsysId, efmId):
		"""
		Usage: status = client.GetEFMStatus(vsysId, efmId)
		"""
		result = self.do_action('GetEFMStatus', {'vsysId': vsysId, 'efmId': efmId})
		# show status if requested, e.g. for wait operations
		self.show_status(result['efmStatus'])
		return result['efmStatus']

	def CreateEFM(self, vsysId, efmType, efmName, networkId):
		"""
		Usage: efmId = client.CreateEFM(self, vsysId, efmType, efmName, networkId)
		"""
		result = self.do_action('CreateEFM', {'vsysId': vsysId, 'efmType': efmType, 'efmName': efmName, 'networkId': networkId})
		return result['efmId']

	def StartEFM(self, vsysId, efmId):
		result = self.do_action('StartEFM', {'vsysId': vsysId, 'efmId': efmId})
		return result

	def StopEFM(self, vsysId, efmId):
		result = self.do_action('StopEFM', {'vsysId': vsysId, 'efmId': efmId})
		return result

	def DestroyEFM(self, vsysId, efmId):
		result = self.do_action('DestroyEFM', {'vsysId': vsysId, 'efmId': efmId})
		return result

	def ListEFMBackup(self, vsysId, efmId, timeZone=None, countryCode=None):
		"""
		Usage: backups = client.ListEFMBackup(vsysId, efmId)
		"""
		result = self.do_action('ListEFMBackup', {'vsysId': vsysId, 'efmId': efmId, 'timeZone': timeZone, 'countryCode': countryCode})
		return result['backups']

	def BackupEFM(self, vsysId, efmId):
		result = self.do_action('BackupEFM', {'vsysId': vsysId, 'efmId': efmId})
		return result

	def RestoreEFM(self, vsysId, efmId, backupId):
		result = self.do_action('RestoreEFM', {'vsysId': vsysId, 'efmId': efmId, 'backupId': backupId})
		return result

	def DestroyEFMBackup(self, vsysId, efmId, backupId):
		result = self.do_action('DestroyEFMBackup', {'vsysId': vsysId, 'efmId': efmId, 'backupId': backupId})
		return result

	def StandByConsole(self, vsysId, networkId):
		"""
		Usage: url = client.StandByConsole(vsysId, networkId)
		"""
		result = self.do_action('StandByConsole', {'vsysId': vsysId, 'networkId': networkId})
		return result['url']

	def GetSystemUsage(self, vsysIds=None):
		"""NOTE: extra 'date' element on top-level compared to other API calls !
		Usage: date, usage = client.GetSystemUsage()
		"""
		result = self.do_action('GetSystemUsage', {'vsysIds': vsysIds})
		return result['date'], result['usageinfos']

class FGCPGenericEFMHandler:
	"""
	Generic Handler for FGCP Get/Update EFM Configuration methods
	"""
	_client = None
	vsysId = None
	efmId = None

	def __init__(self, client, vsysId=None, efmId=None):
		# initialize client
		self._client = client
		self.vsysId = vsysId
		self.efmId = efmId

class FGCPGetEFMConfigHandler(FGCPGenericEFMHandler):
	"""
	Handler for FGCP GetEFMConfiguration methods
	
	Example: fw_policy = client.GetEFMConfigHandler(vsysId, efmId).FW_POLICY(from_zone, to_zone)
	"""
	def FW_NAT_RULE(self):
		"""
		Usage: fw_nat_rule = client.GetEFMConfigHandler(vsysId, efmId).FW_NAT_RULE()
		"""
		firewall = self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'FW_NAT_RULE')['firewall']
		if 'nat' in firewall:
			return firewall['nat']

	def FW_DNS(self):
		"""
		Usage: fw_dns = client.GetEFMConfigHandler(vsysId, efmId).FW_DNS()
		"""
		firewall = self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'FW_DNS')['firewall']
		if 'dns' in firewall:
			return firewall['dns']

	def FW_POLICY(self, from_zone=None, to_zone=None):
		"""CHECKME: for network identifiers besides INTERNET and INTRANET, see GetVSYSConfiguration()
		Usage: fw_policy = client.GetEFMConfigHandler(vsysId, efmId).FW_POLICY(from_zone, to_zone)
		"""
		configurationXML = self._client.get_configurationXML('firewall_policy', {'from': from_zone, 'to': to_zone})
		firewall = self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'FW_POLICY', configurationXML)['firewall']
		if 'directions' in firewall:
			return firewall['directions']

	def FW_LOG(self, num=None, orders=None):
		"""CHECKME: for network identifiers besides INTERNET and INTRANET, see GetVSYSConfiguration()
		Usage:
		ipaddress = inventory['publicips'][0]['address']
		orders = [{'order': {'prefix': 'dst', 'value': ipaddress, 'from': None, 'to': None}}]
		fw_log = client.GetEFMConfigHandler(vsysId, efmId).FW_LOG(num, orders)
		"""
		configurationXML = self._client.get_configurationXML('firewall_log', {'num': num, 'orders': orders})
		return self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'FW_LOG', configurationXML)['firewall']

	def FW_LIMIT_POLICY(self, from_zone=None, to_zone=None):
		"""CHECKME: for network identifiers besides INTERNET and INTRANET, see GetVSYSConfiguration()
		Usage: fw_limit_policy = client.GetEFMConfigHandler(vsysId, efmId).FW_LIMIT_POLICY(from_zone, to_zone)
		"""
		configurationXML = self._client.get_configurationXML('firewall_limit_policy', {'from': from_zone, 'to': to_zone})
		return self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'FW_LIMIT_POLICY', configurationXML)['firewall']

	def SLB_RULE(self):
		"""
		Usage: slb_rule = client.GetEFMConfigHandler(vsysId, efmId).SLB_RULE()
		"""
		return self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'SLB_RULE')['loadbalancer']

	def SLB_LOAD(self):
		"""
		Usage: slb_load_stats = client.GetEFMConfigHandler(vsysId, efmId).SLB_RULE()
		"""
		# FIXME: this generates an exception with status NONE_LB_RULE if no SLB rules are defined
		return self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'SLB_LOAD_STATISTICS')['loadbalancer']['loadStatistics']

	def SLB_ERROR(self):
		"""
		Usage: slb_error_stats = client.GetEFMConfigHandler(vsysId, efmId).SLB_RULE()
		"""
		# FIXME: this generates an exception with status NONE_LB_RULE if no SLB rules are defined
		return self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'SLB_ERROR_STATISTICS')['loadbalancer']['errorStatistics']

	def SLB_CERT_LIST(self, certCategory=None, detail=None):
		"""
		Usage: slb_cert_list = client.GetEFMConfigHandler(vsysId, efmId).SLB_CERT_LIST()
		"""
		configurationXML = self._client.get_configurationXML('loadbalancer_certificate_list', {'certCategory': certCategory, 'detail': detail})
		return self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'SLB_CERTIFICATE_LIST', configurationXML)['loadbalancer']

	def EFM_UPDATE(self):
		"""
		Common method for FW and SLB EFM_UPDATE returns firewall or loadbalancer
		"""
		return self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'EFM_UPDATE')

	def FW_UPDATE(self):
		"""
		Usage: fw_update = client.GetEFMConfigHandler(vsysId, efmId).FW_UPDATE()
		"""
		return self.EFM_UPDATE()['firewall']

	def SLB_UPDATE(self):
		"""
		Usage: slb_update = client.GetEFMConfigHandler(vsysId, efmId).SLB_UPDATE()
		"""
		return self.EFM_UPDATE()['loadbalancer']

class FGCPUpdateEFMConfigHandler(FGCPGenericEFMHandler):
	"""
	Handler for FGCP UpdateEFMConfiguration methods
	
	Example: client.UpdateEFMConfigHandler(vsysId, efmId).FW_DNS('AUTO')
	"""
	def FW_NAT_RULE(self, rules=None):
		"""Usage:
		fw_nat_rules = [{'rule': {'publicIp': '80.70.163.172', 'snapt': 'true', 'privateIp': '192.168.0.211'}}]
		client.UpdateEFMConfigHandler(vsysId, efmId).FW_NAT_RULE(fw_nat_rules)
		"""
		if rules is None or len(rules) < 1:
			# this resets the NAT and SNAPT rules
			configurationXML = self._client.get_configurationXML('firewall_nat', '')
		elif isinstance(rules, dict) and 'rule' not in rules:
			# single rule: you can use {'publicIp': '80.70.163.172', 'snapt': 'true', 'privateIp': '192.168.0.211'}
			configurationXML = self._client.get_configurationXML('firewall_nat', {'rule': rules})
		else:
			# multiple rules: you must use [{'rule': {...}}, {'rule': {...}}, ...]
			configurationXML = self._client.get_configurationXML('firewall_nat', rules)
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'FW_NAT_RULE', configurationXML)

	def FW_DNS(self, dnstype='AUTO', primary=None, secondary=None):
		"""
		Usage: client.UpdateEFMConfigHandler(vsysId, efmId).FW_DNS('AUTO')
		"""
		configurationXML = self._client.get_configurationXML('firewall_dns', {'type': dnstype, 'primary': primary, 'secondary': secondary})
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'FW_DNS', configurationXML)

	def FW_POLICY(self, log='On', directions=None):
		"""Usage:
		directions = client.GetEFMConfigHandler(vsysId, efmId).FW_POLICY()
		client.UpdateEFMConfigHandler(vsysId, efmId).FW_POLICY(log, directions)

		Warning: this overrides the complete firewall configuration, so you need to specify all the policies at once !
		"""
		# TODO: add firewall policy builder
		if directions is None:
			directions = []
		else:
			# round-trip support
			directions = self.convert_fw_directions(directions)
		# add default log policy to directions
		directions.append({'direction': {'policies': {'policy': {'log': log}}}})
		configurationXML = self._client.get_configurationXML('firewall_policy', {'directions': directions})
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'FW_POLICY', configurationXML)

	def convert_fw_directions(self, directions):
		# CHECKME: for round-trip support, we need to:
		new_directions = []
		for direction in directions:
			# a. add {'direction': {...}} for each {from, to, policies}
			if 'direction' in direction:
				new_direction = direction
			else:
				new_direction = {'direction': direction}
			# b. replace 'UU62ICIP-AQYOXXRXS-N-INTERNET' by 'INTERNET' in each from and to
			if 'from' not in new_direction['direction']:
				pass
			elif new_direction['direction']['from'].endswith('-INTERNET'):
				new_direction['direction']['from'] = 'INTERNET'
			elif new_direction['direction']['from'].endswith('-INTRANET'):
				new_direction['direction']['from'] = 'INTRANET'
			if 'to' not in new_direction['direction']:
				pass
			elif new_direction['direction']['to'].endswith('-INTERNET'):
				new_direction['direction']['to'] = 'INTERNET'
			elif new_direction['direction']['to'].endswith('-INTRANET'):
				new_direction['direction']['to'] = 'INTRANET'
			new_policies = []
			# c. add {'policy': {...}} for each policy
			for policy in new_direction['direction']['policies']:
				if 'policy' in policy:
					new_policy = policy
				else:
					new_policy = {'policy': policy}
				# d. remove all policies with id 50000 = default rule
				if new_policy['policy']['id'] == '50000':
					pass
				# e. replace each policy id 46999 by id 999
				elif len(new_policy['policy']['id']) > 3:
					new_policy['policy']['id'] = new_policy['policy']['id'][2:]
					new_policies.append(new_policy)
				else:
					new_policies.append(new_policy)
			# if we have anything left, add it to the new directions
			if len(new_policies) > 0:
				new_direction['direction']['policies'] = new_policies
				new_directions.append(new_direction)
		return new_directions

	def SLB_RULE(self, groups=None, force=None, webAccelerator=None):
		"""Usage:
		slb_rule = client.GetEFMConfigHandler(vsysId, efmId).SLB_RULE()
		client.UpdateEFMConfigHandler(vsysId, efmId).SLB_RULE(slb_rule['groups'])

		Warning: this overrides the complete loadbalancer configuration, so you need to specify all the groups at once !
		"""
		# TODO: add loadbalancer group builder
		if groups is None:
			groups = []
		else:
			# round-trip support
			groups = self.convert_slb_groups(groups)
		configurationXML = self._client.get_configurationXML('loadbalancer_rule', {'groups': groups, 'force': force, 'webAccelerator': webAccelerator})
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_RULE', configurationXML)

	def convert_slb_groups(self, groups):
		# CHECKME: for round-trip support, we need to:
		new_groups = []
		for group in groups:
			# a. add {'group': {...}} for each {id, protocol, ..., targets}
			if 'group' in group:
				new_group = group
			else:
				new_group = {'group': group}
			# b. CHECKME: remove causes ?
			if 'causes' in new_group['group']:
				del new_group['group']['causes']
			new_targets = []
			# c. add {'target': {...}} for each target
			for target in new_group['group']['targets']:
				if 'target' in target:
					new_target = target
				else:
					new_target = {'target': target}
				# d. remove ipAddress and serverName from each target
				if 'ipAddress' in new_target['target']:
					del new_target['target']['ipAddress']
				if 'serverName' in new_target['target']:
					del new_target['target']['serverName']
				new_targets.append(new_target)
			# ...
			# if we have anything left, add it to the new groups
			if len(new_targets) > 0:
				new_group['group']['targets'] = new_targets
				new_groups.append(new_group)
		return new_groups

	def SLB_LOAD_CLEAR(self):
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_LOAD_STATISTICS_CLEAR')

	def SLB_ERROR_CLEAR(self):
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_ERROR_STATISTICS_CLEAR')

	def SLB_START_MAINT(self, id, ipAddress, time=None, unit=None):
		configurationXML = self._client.get_configurationXML('loadbalancer_start_maintenance', {'id': id, 'ipAddress': ipAddress, 'time': time, 'unit': unit})
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_START_MAINTENANCE', configurationXML)

	def SLB_STOP_MAINT(self, id, ipAddress):
		configurationXML = self._client.get_configurationXML('loadbalancer_stop_maintenance', {'id': id, 'ipAddress': ipAddress})
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_STOP_MAINTENANCE', configurationXML)

	def SLB_CERT_ADD(self, certNum, filePath, passphrase):
		"""
		Note: server certificates in unencrypted PEM format are NOT supported here, use PKCS12 format (and others ?)
		"""
		# when adding SLB server/cca certificates, configurationXML contains the filePath for the actual certificate to be uploaded
		configurationXML = self._client.get_configurationXML('loadbalancer_certificate', {'certNum': certNum, 'filePath': filePath, 'passphrase': passphrase})
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_CERTIFICATE_ADD', configurationXML, filePath)

	def SLB_CERT_SET(self, certNum, id):
		configurationXML = self._client.get_configurationXML('loadbalancer_certificate', {'certNum': certNum, 'id': id})
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_CERTIFICATE_SET', configurationXML)

	def SLB_CERT_RELEASE(self, certNum):
		configurationXML = self._client.get_configurationXML('loadbalancer_certificate', {'certNum': certNum})
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_CERTIFICATE_RELEASE', configurationXML)

	def SLB_CERT_DELETE(self, certNum, force=None):
		configurationXML = self._client.get_configurationXML('loadbalancer_certificate', {'certNum': certNum, 'force': force})
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_CERTIFICATE_DELETE', configurationXML)

	def SLB_CCA_ADD(self, ccacertNum, filePath):
		"""
		Note: cca certificates in .crt or .pem format ARE supported here (and others ?)
		"""
		# when adding SLB server/cca certificates, configurationXML contains the filePath for the actual certificate to be uploaded
		configurationXML = self._client.get_configurationXML('loadbalancer_cca_certificate', {'ccacertNum': ccacertNum, 'filePath': filePath})
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_CCA_CERTIFICATE_ADD', configurationXML, filePath)

	def SLB_CCA_DELETE(self, ccacertNum):
		configurationXML = self._client.get_configurationXML('loadbalancer_cca_certificate', {'ccacertNum': ccacertNum})
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_CCA_CERTIFICATE_DELETE', configurationXML)

	def EFM_UPDATE(self):
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'EFM_UPDATE')

	def EFM_BACKOUT(self):
		return self._client.UpdateEFMConfiguration(self.vsysId, self.efmId, 'EFM_BACKOUT')

		
"""
FGCP API Commands that are not supported in the current API version

class FGCPCommandNotSupported(FGCPCommand):
	def GetVSYSDescriptor(self):
		raise FGCPResponseError('UNSUPPORT_ERROR', 'Unable to use the specified API')

	def CreateVSYSDescriptor(self):
		raise FGCPResponseError('UNSUPPORT_ERROR', 'Unable to use the specified API')

	def RegisterVSYSDescriptor(self):
		raise FGCPResponseError('UNSUPPORT_ERROR', 'Unable to use the specified API')

	def ListVNet(self):
		raise FGCPResponseError('UNSUPPORT_ERROR', 'Unable to use the specified API')

	def CreateVNet(self):
		raise FGCPResponseError('UNSUPPORT_ERROR', 'Unable to use the specified API')

	def GetINet(self):
		raise FGCPResponseError('UNSUPPORT_ERROR', 'Unable to use the specified API')

	def ListProductID(self):
		raise FGCPResponseError('UNSUPPORT_ERROR', 'Unable to use the specified API')

	def RegisterProductID(self):
		raise FGCPResponseError('UNSUPPORT_ERROR', 'Unable to use the specified API')

	def CreateDiskImage(self):
		raise FGCPResponseError('UNSUPPORT_ERROR', 'Unable to use the specified API')

	def RegisterDiskImage(self):
		raise FGCPResponseError('UNSUPPORT_ERROR', 'Unable to use the specified API')

	def ListVNIC(self):
		raise FGCPResponseError('UNSUPPORT_ERROR', 'Unable to use the specified API')

	def CreateVNIC(self):
		raise FGCPResponseError('UNSUPPORT_ERROR', 'Unable to use the specified API')
"""

class FGCPMonitor(FGCPCommand):
	"""
	FGCP Monitoring Methods
	"""

	def FindSystemByName(self, vsysName):
		"""
		Find VSYS by vsysName
		"""
		vsyss = self.ListVSYS()
		if len(vsyss) < 1:
			raise FGCPResponseError('RESOURCE_NOT_FOUND', 'No VSYS are defined')
		for vsys in vsyss:
			if vsysName == vsys['vsysName']:
				return vsys
		raise FGCPResponseError('ILLEGAL_VSYS_ID', 'Invalid vsysName %s' % vsysName)

	def GetSystemInventory(self, vsysName=None):
		"""
		Get VSYS inventory (by vsysName)
		"""
		if vsysName is None:
			vsyss = self.ListVSYS()
		else:
			vsyss = []
			vsyss.append(self.FindSystemByName(vsysName))
		if len(vsyss) < 1:
			self.show_output('No VSYS are defined')
			return
		inventory = {}
		inventory['vsys'] = {}
		for vsys in vsyss:
			vsysconfig = self.GetVSYSConfiguration(vsys['vsysId'])
			vsysconfig['firewalls'] = self.ListEFM(vsys['vsysId'], "FW")
			vsysconfig['loadbalancers'] = self.ListEFM(vsys['vsysId'], "SLB")
			# CHECKME: remove firewalls and loadbalancers from vservers list
			seenId = {}
			if vsysconfig['firewalls']:
				for firewall in vsysconfig['firewalls']:
					seenId[firewall['efmId']] = 1
			if vsysconfig['loadbalancers']:
				for loadbalancer in vsysconfig['loadbalancers']:
					seenId[loadbalancer['efmId']] = 1
			todo = []
			if 'vservers' in vsysconfig:
				for vserver in vsysconfig['vservers']:
					# skip servers we've already seen, i.e. firewalls and loadbalancers
					if vserver['vserverId'] in seenId:
						continue
					todo.append(vserver)
			vsysconfig['vservers'] = todo
			if 'vdisks' not in vsysconfig:
				vsysconfig['vdisks'] = []
			if 'publicips' not in vsysconfig:
				vsysconfig['publicips'] = []
			inventory['vsys'][vsys['vsysName']] = vsysconfig
			# TODO: transform vsysconfig ?
			#vservers = self.ListVServer(vsys['vsysId'])
			#inventory['vsys'][vsys['vsysName']]['vserver'] = {}
			#for vserver in vservers:
				#inventory['vsys'][vsys['vsysName']]['vserver'][vserver['vserverName']] = vserver
		#publicips = self.ListPublicIP()
		# TODO: add vsysdescriptors, diskimages etc. ?
		if vsysName is None:
			return inventory
		else:
			return inventory['vsys'][vsysName]

	def GetSystemStatus(self, vsysName=None, verbose=None):
		"""
		Get the overall system status (for a particular VSYS)
		"""
		# set output
		old_verbose = self.set_verbose(verbose)
		if vsysName is None:
			self.show_output('Show System Status for all VSYS')
			inventory = self.GetSystemInventory()
		else:
			self.show_output('Show System Status for VSYS %s' % vsysName)
			inventory = {}
			inventory['vsys'] = {}
			inventory['vsys'][vsysName] = self.GetSystemInventory(vsysName)
		if inventory is None or len(inventory['vsys']) < 1:
			self.show_output('No VSYS are defined')
			return
		# CHECKME: keep track of status in new_inventory
		new_inventory = inventory
		for name, vsysconfig in inventory['vsys'].iteritems():
			# get status of vsys overall
			status = self.GetVSYSStatus(vsysconfig['vsysId'])
			self.show_output('VSYS\t%s\t%s' % (vsysconfig['vsysName'], status))
			new_inventory['vsys'][name]['vsysStatus'] = status
			# get status of public ips
			new_publicips = []
			for publicip in vsysconfig['publicips']:
				status = self.GetPublicIPStatus(publicip['address'])
				self.show_output('PublicIP\t%s\t%s' % (publicip['address'], status))
				publicip['publicipStatus'] = status
				new_publicips.append(publicip)
			new_inventory['vsys'][name]['publicips'] = new_publicips
			# get status of firewalls
			new_firewalls = []
			for firewall in vsysconfig['firewalls']:
				status = self.GetEFMStatus(vsysconfig['vsysId'], firewall['efmId'])
				self.show_output('EFM FW\t%s\t%s' % (firewall['efmName'], status))
				firewall['efmStatus'] = status
				new_firewalls.append(firewall)
			new_inventory['vsys'][name]['firewalls'] = new_firewalls
			# get status of loadbalancers
			new_loadbalancers = []
			for loadbalancer in vsysconfig['loadbalancers']:
				status = self.GetEFMStatus(vsysconfig['vsysId'], loadbalancer['efmId'])
				self.show_output('EFM SLB\t%s\t%s\t%s' % (loadbalancer['efmName'], loadbalancer['slbVip'], status))
				loadbalancer['efmStatus'] = status
				new_loadbalancers.append(loadbalancer)
			new_inventory['vsys'][name]['loadbalancers'] = new_loadbalancers
			# get status of vservers (excl. firewalls and loadbalancers)
			new_vservers = []
			seenId = {}
			for vserver in vsysconfig['vservers']:
				status = self.GetVServerStatus(vsysconfig['vsysId'], vserver['vserverId'])
				self.show_output('VServer\t%s\t%s\t%s' % (vserver['vserverName'], vserver['vnics'][0]['privateIp'], status))
				vserver['vserverStatus'] = status
				# get status of attached disks
				new_vdisks = []
				for vdisk in vserver['vdisks']:
					status = self.GetVDiskStatus(vsysconfig['vsysId'], vdisk['vdiskId'])
					self.show_output('\tVDisk\t%s\t%s' % (vdisk['vdiskName'], status))
					seenId[vdisk['vdiskId']] = 1
					vdisk['vdiskStatus'] = status
					new_vdisks.append(vdisk)
				vserver['vdisks'] = new_vdisks
				new_vservers.append(vserver)
			new_inventory['vsys'][name]['vservers'] = new_vservers
			# get status of unattached disks
			todo = []
			new_vdisks = []
			for vdisk in vsysconfig['vdisks']:
				# skip disks we've already seen, i.e. attached to a server
				if vdisk['vdiskId'] in seenId:
					new_vdisks.append(vdisk)
					continue
				todo.append(vdisk)
			if len(todo) > 0:
				self.show_output('Unattached Disks')
				for vdisk in todo:
					status = self.GetVDiskStatus(vsysconfig['vsysId'], vdisk['vdiskId'])
					self.show_output('\tVDisk\t%s\t%s' % (vdisk['vdiskName'], status))
					seenId[vdisk['vdiskId']] = 1
					vdisk['vdiskStatus'] = status
					new_vdisks.append(vdisk)
			new_inventory['vsys'][name]['vdisks'] = new_vdisks
			self.show_output()
		# reset output
		self.set_verbose(old_verbose)
		# return inventory with updated status for each component
		if vsysName is None:
			return new_inventory
		else:
			return new_inventory['vsys'][vsysName]

	def ShowSystemStatus(self, vsysName=None):
		"""
		Show the overall system status (for a particular VSYS)
		"""
		self.GetSystemStatus(vsysName, 1)

class FGCPOperator(FGCPMonitor):
	"""
	FGCP Operator Methods
	"""
	def check_status(self, done_status, pass_status, status_method, *args):
		"""
		Call status_method(*args) to see if we get done_status, or something other than pass_status
		"""
		if not hasattr(self, status_method):
			raise FGCPResponseError('ILLEGAL_METHOD', 'Invalid method %s for checking status' % status_method)
		check_status = getattr(self, status_method, None)
		if not callable(check_status):
			raise FGCPResponseError('ILLEGAL_METHOD', 'Invalid method %s for checking status' % status_method)
		if isinstance(done_status, str):
			done_list = [done_status]
		else:
			done_list = done_status
		if isinstance(pass_status, str):
			pass_list = [pass_status]
		else:
			pass_list = pass_status
		status = check_status(*args)
		if status in done_list:
			# we're already done so return the status
			return status
		elif status in pass_list:
			# we can continue with whatever needs doing
			return
		else:
			raise FGCPResponseError('ILLEGAL_STATE', 'Invalid status %s for %s' % (status, status_method))

	def wait_for_status(self, done_status, wait_status, status_method, *args):
		"""
		Call status_method(*args) repeatedly until we get done_status (or something else than wait_status)
		"""
		if not hasattr(self, status_method):
			raise FGCPResponseError('ILLEGAL_METHOD', 'Invalid method %s for checking status' % status_method)
		check_status = getattr(self, status_method, None)
		if not callable(check_status):
			raise FGCPResponseError('ILLEGAL_METHOD', 'Invalid method %s for checking status' % status_method)
		if isinstance(done_status, str):
			done_list = [done_status]
		else:
			done_list = done_status
		if isinstance(wait_status, str):
			wait_list = [wait_status]
		else:
			wait_list = wait_status
		# wait until we get the done_status - TODO: add some timeout
		while True:
			time.sleep(10)
			status = check_status(*args)
			if status in done_list:
				return status
			elif status in wait_list:
				pass
			else:
				raise FGCPResponseError('ILLEGAL_STATE', '%s returned unexpected status %s while %s' % (status_method, status, wait_status))
		return status

	def StartVServerAndWait(self, vsysId, vserverId):
		"""
		Start VServer and wait until it's running
		"""
		# check current status
		status = self.check_status('RUNNING', ['STOPPED', 'UNEXPECTED_STOP'], 'GetVServerStatus', vsysId, vserverId)
		if status is not None:
			return status
		# start vserver
		result = self.StartVServer(vsysId, vserverId)
		# wait until starting is done - TODO: add some timeout
		status = self.wait_for_status('RUNNING', 'STARTING', 'GetVServerStatus', vsysId, vserverId)
		return status

	def StopVServerAndWait(self, vsysId, vserverId, force=None):
		"""
		Stop VServer and wait until it's stopped
		"""
		# check current status
		status = self.check_status(['STOPPED', 'UNEXPECTED_STOP'], 'RUNNING', 'GetVServerStatus', vsysId, vserverId)
		if status is not None:
			return status
		# stop vserver
		result = self.StopVServer(vsysId, vserverId, force)
		# wait until stopping is done - TODO: add some timeout
		status = self.wait_for_status(['STOPPED', 'UNEXPECTED_STOP'], 'STOPPING', 'GetVServerStatus', vsysId, vserverId)
		return status

	def StartEFMAndWait(self, vsysId, efmId):
		"""
		Start EFM and wait until it's running
		"""
		# check current status
		status = self.check_status('RUNNING', ['STOPPED', 'UNEXPECTED_STOP'], 'GetEFMStatus', vsysId, efmId)
		if status is not None:
			return status
		# start efm
		result = self.StartEFM(vsysId, efmId)
		# wait until starting is done - TODO: add some timeout
		status = self.wait_for_status('RUNNING', 'STARTING', 'GetEFMStatus', vsysId, efmId)
		return status

	def StopEFMAndWait(self, vsysId, efmId):
		"""
		Stop EFM and wait until it's stopped
		"""
		# check current status
		status = self.check_status(['STOPPED', 'UNEXPECTED_STOP'], 'RUNNING', 'GetEFMStatus', vsysId, efmId)
		if status is not None:
			return status
		# CHECKME: for firewalls, we need to detach the publicIPs first !?
		# stop efm
		result = self.StopEFM(vsysId, efmId)
		# wait until stopping is done - TODO: add some timeout
		status = self.wait_for_status(['STOPPED', 'UNEXPECTED_STOP'], 'STOPPING', 'GetEFMStatus', vsysId, efmId)
		return status

	def AttachPublicIPAndWait(self, vsysId, publicIp):
		"""
		Attach PublicIP and wait until it's attached
		"""
		# check current status
		status = self.check_status('ATTACHED', 'DETACHED', 'GetPublicIPStatus', publicIp)
		if status is not None:
			return status
		# attach publicIP
		result = self.AttachPublicIP(vsysId, publicIp)
		# wait until attaching is done - TODO: add some timeout
		status = self.wait_for_status('ATTACHED', 'ATTACHING', 'GetPublicIPStatus', publicIp)
		return status

	def DetachPublicIPAndWait(self, vsysId, publicIp):
		"""
		Detach PublicIP and wait until it's detached
		"""
		# check current status
		status = self.check_status('DETACHED', 'ATTACHED', 'GetPublicIPStatus', publicIp)
		if status is not None:
			return status
		# detach publicIP
		result = self.DetachPublicIP(vsysId, publicIp)
		# wait until detaching is done - TODO: add some timeout
		status = self.wait_for_status('DETACHED', 'DETACHING', 'GetPublicIPStatus', publicIp)
		return status

	def BackupVDiskAndWait(self, vsysId, vdiskId):
		"""
		Take Backup of VDisk and wait until it's finished (this might take a while)
		"""
		# check current status - CHECKME: we don't return here !
		status = self.check_status('N/A', ['STOPPED', 'NORMAL'], 'GetVDiskStatus', vsysId, vdiskId)
		if status is not None:
			return status
		# backup vdisk
		result = self.BackupVDisk(vsysId, vdiskId)
		# wait until backup is done - TODO: add some timeout
		status = self.wait_for_status(['STOPPED', 'NORMAL'], 'BACKUP_ING', 'GetVDiskStatus', vsysId, vdiskId)
		return status

	def BackupVServerAndRestart(self, vsysId, vserverId):
		"""
		Backup all VDisks of a VServer and restart the VServer (this might take a while)
		"""
		# stop server and wait
		status = self.StopVServerAndWait(vsysId, vserverId)
		if status != 'STOPPED':
			print 'Unable to stop vserver: %s' % status
			return status
		# get server configuration
		config = self.GetVServerConfiguration(vsysId, vserverId)
		todo = []
		# the system disk has the same id as the server
		todo.append(config['vserverId'])
		if config['vdisks'] != '':
			# add other disks if necessary
			for vdisk in config['vdisks']:
				todo.append(vdisk['vdiskId'])
		# backup the different disks
		for vdiskId in todo:
			status = self.BackupVDiskAndWait(vsysId, vdiskId)
			if status != 'STOPPED' and status != 'NORMAL':
				print 'Unable to backup vdisk %s: %s' % (vdiskId, status)
				return status
		# start server and wait
		status = self.StartVServerAndWait(vsysId, vserverId)
		if status != 'RUNNING':
			print 'Unable to start vserver: %s' % status
			return status
		return status

	# TODO: set expiration date + max. number
	def CleanupBackups(self, vsysId, vdiskId=None):
		"""
		Clean up old VDisk backups e.g. to minimize disk space
		"""
		todo = []
		if vdiskId is None:
			vdisks = self.ListVDisk(vsysId)
			for vdisk in vdisks:
				todo.append(vdisk['vdiskId'])
		else:
			todo.append(vdiskId)
		for vdiskId in todo:
			backups = self.ListVDiskBackup(vsysId, vdiskId)
			if len(backups) > 10:
				newlist = []
				for backup in backups:
					# convert weird time format to time value
					backup['timeval'] = time.mktime(time.strptime(backup['backupTime'], "%b %d, %Y %I:%M:%S %p"))
					newlist.append(backup)
				# Sort list of dictionaries: http://stackoverflow.com/questions/652291/sorting-a-list-of-dictionary-values-by-date-in-python
				from operator import itemgetter
				newlist.sort(key=itemgetter('timeval'), reverse=True)
				# TODO: remove oldest backup(s) ?
				backup = newlist.pop()
				#client.DestroyVDiskBackup(vsysId, backup['backupId'])

	def StartSystem(self, vsysName, verbose=None):
		"""
		Start VSYS and wait until all VServers and EFMs are started (TODO: define start sequence for vservers)
		"""
		# Get inventory of the vsys
		inventory = self.GetSystemInventory(vsysName)
		vsysId = inventory['vsysId']
		# Set output
		old_verbose = self.set_verbose(verbose)
		self.show_output('Starting VSYS %s' % vsysName)
		# CHECKME: start firewall if necessary
		self.show_output('Start Firewalls')
		for firewall in inventory['firewalls']:
			self.StartEFMAndWait(vsysId, firewall['efmId'])
		# CHECKME: attach publicip if necessary
		self.show_output('Attach PublicIPs')
		for publicip in inventory['publicips']:
			self.AttachPublicIPAndWait(vsysId, publicip['address'])
		# CHECKME: start loadbalancers if necessary
		self.show_output('Start Loadbalancers')
		for loadbalancer in inventory['loadbalancers']:
			self.StartEFMAndWait(vsysId, loadbalancer['efmId'])
		# CHECKME: start servers if necessary
		self.show_output('Start VServers')
		for vserver in inventory['vservers']:
			self.StartVServerAndWait(vsysId, vserver['vserverId'])
		self.show_output('Started VSYS %s' % vsysName)
		# Reset output
		self.set_verbose(old_verbose)

	def StopSystem(self, vsysName, verbose=None):
		"""
		Stop VSYS and wait until all VServers and EFMs are stopped (TODO: define stop sequence for vservers)
		"""
		# Get system inventory
		inventory = self.GetSystemInventory(vsysName)
		vsysId = inventory['vsysId']
		# Set output
		old_verbose = self.set_verbose(verbose)
		self.show_output('Stopping VSYS %s' % vsysName)
		# Stop all vservers
		self.show_output('Stop VServers')
		for vserver in inventory['vservers']:
			self.show_output(vserver['vserverName'])
			status = self.StopVServerAndWait(vsysId, vserver['vserverId'])
		# Stop all loadbalancers
		self.show_output('Stop Loadbalancers')
		for loadbalancer in inventory['loadbalancers']:
			self.show_output(loadbalancer['efmName'])
			status = self.StopEFMAndWait(vsysId, loadbalancer['efmId'])
		# Detach publicip - cfr. sequence3 in java sdk
		self.show_output('Detach PublicIPs')
		for publicip in inventory['publicips']:
			self.show_output(publicip['address'])
			status = self.DetachPublicIPAndWait(vsysId, publicip['address'])
		# Stop all firewalls
		self.show_output('Stop Firewalls')
		for firewall in inventory['firewalls']:
			self.show_output(firewall['efmName'])
			status = self.StopEFMAndWait(vsysId, firewall['efmId'])
		self.show_output('Stopped VSYS %s' % vsysName)
		# Reset output
		self.set_verbose(old_verbose)


class FGCPDesigner(FGCPOperator):
	"""
	FGCP Designer Methods
	"""
	def FindDiskImageByName(self, diskimageName):
		"""
		Find DiskImage by diskimageName
		"""
		# CHECKME: is baseDescriptor always = vsysDescriptorId ?
		#diskimages = self.ListDiskImage('GENERAL', inventory['baseDescriptor'])
		diskimages = self.ListDiskImage()
		if len(diskimages) < 1:
			raise FGCPResponseError('RESOURCE_NOT_FOUND', 'No diskimages are defined')
		for diskimage in diskimages:
			if diskimageName == diskimage['diskimageName']:
				return diskimage
		raise FGCPResponseError('ILLEGAL_NAME', 'Invalid diskimageName')

	def FindVSYSDescriptorByName(self, vsysdescriptorName):
		"""
		Find VSYSDescriptor by vsysdescriptorName
		"""
		vsysdescriptors = self.ListVSYSDescriptor()
		if len(vsysdescriptors) < 1:
			raise FGCPResponseError('RESOURCE_NOT_FOUND', 'No vsysdescriptors are defined')
		for vsysdescriptor in vsysdescriptors:
			if vsysdescriptorName == vsysdescriptor['vsysdescriptorName']:
				return vsysdescriptor
		raise FGCPResponseError('ILLEGAL_NAME', 'Invalid vsysdescriptorName')

	def FindServerTypeByName(self, name):
		"""
		Find ServerType by name - CHECKME: do we actually need this for CreateVServer() ?
		"""
		return name
		# CHECKME: do all diskimages have the same servertypes (for now) ?
		# pick some random diskimage to get its servertypes ?
		diskimage = self.ListDiskImage().pop()
		servertypes = self.ListServerType(diskimage['diskimageId'])
		if len(servertypes) < 1:
			raise FGCPResponseError('RESOURCE_NOT_FOUND', 'No servertypes are defined')
		for servertype in servertypes:
			if name == servertype['name']:
				return servertype
		raise FGCPResponseError('ILLEGAL_NAME', 'Invalid servertype name')

	def CreateSystem(self, vsysName, vsysdescriptorName, verbose=None):
		"""
		Create VSYS based on descriptor and wait until it's deployed
		"""
		# Set output
		old_verbose = self.set_verbose(verbose)
		self.show_output('Creating VSYS %s' % vsysName)
		# Try to find vsys or create it
		try:
			vsys = self.FindSystemByName(vsysName)
		except FGCPResponseError:
			vsysdescriptor = self.FindVSYSDescriptorByName(vsysdescriptorName)
			vsysId = self.CreateVSYS(vsysdescriptor['vsysdescriptorId'], vsysName)
			self.show_output('Created VSYS %s: %s' % (vsysName, vsysId))
			# wait until vsys deploying is done - TODO: add some timeout
			self.wait_for_status('NORMAL', 'DEPLOYING', 'GetVSYSStatus', vsysId)
			self.show_output('Deployed VSYS %s: %s' % (vsysName, vsysId))
			pass
		else:
			vsysId = vsys['vsysId']
			self.show_output('Existing VSYS %s: %s' % (vsysName, vsysId))
		# Reset output
		self.set_verbose(old_verbose)
		return vsysId

	def ConfigureSystem(self, vsysName, vsysConfig, verbose=None):
		"""
		TODO: Configure VSYS based on some configuration options
		"""
		print 'TODO: Configure VSYS based on some configuration options'
		return
		# Get inventory of the vsys
		inventory = self.GetSystemInventory(vsysName)
		vsysId = inventory['vsysId']
		# Set output
		old_verbose = self.set_verbose(verbose)
		self.show_output('Configuring VSYS %s' % vsysName)
		# CHECKME: start firewall if necessary
		if len(inventory['firewalls']) > 0:
			self.show_output('Start Firewalls')
			for firewall in inventory['firewalls']:
				self.StartEFMAndWait(vsysId, firewall['efmId'])
		# CHECKME: allocate publicip if necessary
		if len(inventory['publicips']) < 1:
			self.show_output('Allocate PublicIP')
			self.AllocatePublicIP(vsysId)
			# CHECKME: we need to wait a bit before retrieving the new list !
			time.sleep(10)
			# update list of publicips
			inventory['publicips'] = self.ListPublicIP(vsysId)
			publicip = inventory['publicips'][0]
			# wait until publicip deploying is done - TODO: add some timeout
			self.wait_for_status(['DETACHED', 'ATTACHED'], 'DEPLOYING', 'GetPublicIPStatus', publicip['address'])
		# CHECKME: attach publicip if necessary
		self.show_output('Attach PublicIPs')
		for publicip in inventory['publicips']:
			self.AttachPublicIPAndWait(vsysId, publicip['address'])
		# TODO: add vserver etc. based on configuration
		if len(inventory['vservers']) < len(inventory['vnets']):
			diskimage = self.FindDiskImageByName('CentOS 5.4 32bit(EN)')
			print diskimage
			# CHECKME: do we actually need this for CreateVServer ?
			servertype = self.FindServerTypeByName('economy')
			print servertype
			# TODO CreateVServer
			self.show_output('Create VServers')
			idx = 1
			for vnetId in inventory['vnets']:
				print vnetId
				# CHECKME: add vservers to the network zone
				vserverId = self.CreateVServer(vsysId, 'Server%s' % idx, 'economy', diskimage['diskimageId'], vnetId)
				# wait until vserver deploying is done - TODO: add some timeout
				status = self.wait_for_status('STOPPED', 'DEPLOYING', 'GetVServerStatus', vsysId, vserverId)
				idx += 1
				vserverId = self.CreateVServer(vsysId, 'Server%s' % idx, 'economy', diskimage['diskimageId'], vnetId)
				# wait until vserver deploying is done - TODO: add some timeout
				status = self.wait_for_status('STOPPED', 'DEPLOYING', 'GetVServerStatus', vsysId, vserverId)
				idx += 1
				# CHECKME: add loadbalancer to the DMZ
				if vnetId.endswith('-DMZ') and len(inventory['loadbalancers']) < 1:
					self.show_output('Create Loadbalancer')
					efmId = self.CreateEFM(vsysId, 'SLB', 'LoadBalancer', vnetId)
					# wait until efm deploying is done - TODO: add some timeout
					self.wait_for_status('STOPPED', 'DEPLOYING', 'GetEFMStatus', vsysId, efmId)
					# update list of loadbalancers
					inventory['loadbalancers'] = self.ListEFM(vsysId, "SLB")
		self.show_output('Configured VSYS %s' % vsysName)
		# Reset output
		self.set_verbose(old_verbose)

	def DestroySystem(self, vsysName, verbose=None):
		"""
		Destroy VSYS after stopping all VServers and EFMs
		"""
		# Get system inventory
		inventory = self.GetSystemInventory(vsysName)
		vsysId = inventory['vsysId']
		# Set output
		old_verbose = self.set_verbose(verbose)
		self.show_output('Destroying VSYS %s' % vsysName)
		# CHECKME: should we stop the VSYS here ?
		# Destroy the VSYS
		result = self.DestroyVSYS(vsysId)
		self.show_output(result['responseStatus'])
		# TODO: wait until it's really gone ?
		self.show_output('Destroyed VSYS %s' % vsysName)
		# Reset output
		self.set_verbose(old_verbose)

class FGCPClient(FGCPDesigner):
	"""
	FGCP Client Methods
	
	Example:
	# Get FGCP client with your certificate in region 'uk'
	from fgcp_client_api import FGCPClient
	client = FGCPClient('client.pem', 'uk')

	# Backup all VServers in some VSYS
	inventory = client.GetSystemInventory('Python API Demo System')
	for vserver in inventory['vservers']:
		client.BackupVServerAndRestart(inventory['vsysId'], vserver['vserverId'])
	client.CleanupBackups(inventory['vsysId'])

	# Note: you can also use all API commands from FGCPCommand()
	vsyss = client.ListVSYS()
	for vsys in vsyss:
		vsysconfig = client.GetVSYSConfiguration(vsys['vsysId'])
		...
	"""
	pass


def fgcp_run_sample(pem_file, region):
	# Get FGCP client with your certificate in this region
	#from fgcp_client_api import FGCPClient
	client = FGCPClient(pem_file, region)
	# Hint: set debug=1 to dump the FGCP Response for further development
	#client = FGCPClient(pem_file, region, debug=1)
	client.ShowSystemStatus()
	#
	# Backup all VServers in some VSYS
	#inventory = client.GetSystemInventory('Python API Demo System')
	#for vserver in inventory['vservers']:
	#	client.BackupVServerAndRestart(inventory['vsysId'], vserver['vserverId'])
	#client.CleanupBackups(inventory['vsysId'])
	#
	# Create and start a complete VSYS
	#client.set_verbose(2) # show output and status checks during script execution
	#client.CreateSystem('Python API Demo System', '2-tier Skeleton')
	#client.ConfigureSystem('Python API Demo System', myconfig_todo)
	#client.StartSystem('Python API Demo System')
	# Stop and destroy a complete VSYS
	#client.StopSystem('Python API Demo System')
	#client.DestroySystem('Python API Demo System')
	#
	# Note: you can also use all API commands from FGCPCommand()
	#vsyss = client.ListVSYS()
	#for vsys in vsyss:
	#	vsysconfig = client.GetVSYSConfiguration(vsys['vsysId'])
	#	...
	#vsysdescriptors = client.ListVSYSDescriptor()
	#print vsysdescriptors
	#for vsysdescriptor in vsysdescriptors:
	#	if vsysdescriptor['vsysdescriptorName'] == '2-tier Skeleton':
	#		vsysId = client.CreateVSYS(vsysdescriptor['vsysdescriptorId'], 'Python API Demo System')
	#		print 'New VSYS Created: %s' % vsysId
	#		break
	exit()

def fgcp_show_usage(name='fgcp_client_api.py'):
	print """Client API library for the Fujitsu Global Cloud Platform (FGCP)

Usage: %s [pem_file] [region]

from fgcp_client_api import FGCPClient
client = FGCPClient('client.pem', 'uk')
inventory = client.GetSystemInventory('Python API Demo System')
...

Requirements: this module uses gdata.tlslite.utils to create the key signature,
see http://code.google.com/p/gdata-python-client/ for download and installation

Note: to convert your .p12 or .pfx file to unencrypted PEM format, you can use
the following 'openssl' command:

openssl pkcs12 -in UserCert.p12 -out client.pem -nodes
""" % name

if __name__ == "__main__":
	"""
	Check if we have an existing 'client.pem' file or command line argument specifying the PEM file
	"""
	import os.path, sys
	pem_file = 'client.pem'
	region = 'de'
	if len(sys.argv) > 1:
		pem_file = sys.argv[1]
		if len(sys.argv) > 2:
			region = sys.argv[2]
	if os.path.exists(pem_file):
		fgcp_run_sample(pem_file, region)
	else:
		fgcp_show_usage(os.path.basename(sys.argv[0]))
