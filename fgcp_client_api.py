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
	conn = FGCPConnection('client.pem')
	vsyss = conn.do_action('ListVSYS')
	"""
	host = 'api.globalcloud.de.fujitsu.com' # for Central Europe (CEMEA&I)
	#host = 'api.globalcloud.uk.fujitsu.com' # for the UK and Ireland
	#host = 'api.globalcloud.us.fujitsu.com' # for the Americas
	#host = 'api.globalcloud.sg.fujitsu.com' # for Singapore, Malaysia, Indonesia, Thailand and Vietnam
	#host = 'api.globalcloud.fujitsu.com.au' # for Australia and New Zealand
	#host = 'api.oviss.jp.fujitsu.com'       # for Japan
	uri = '/ovissapi/endpoint'
	api_version = '2011-01-31'
	user_agent = 'OViSS-API-CLIENT'
	locale = 'en'
	timezone = 'Central European Time'       # TODO: adapt as needed !
	key_file = 'client.pem'
	verbose = 0
	show_status = 0
	_conn = None

	def __init__(self, key_file='client.pem', verbose=0):
		"""
		Use the same PEM file for SSL client certificate and RSA key signature
		
		Note: to convert your .p12 or .pfx file to unencrypted PEM format, you can use
		the following 'openssl' command:
		
		openssl pkcs12 -in UserCert.p12 -out client.pem -nodes
		"""
		self.key_file = key_file
		self.verbose = verbose
		# CHECKME: replace host here if needed ?
		# CHECKME: replace timezone here if needed ?
		self._key = None

	def close(self):
		# CHECKME: do we really want to close this ?
		self._conn.close()

	def get_headers(self, attachment=None):
		if attachment is None:
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
			s = open(self.key_file).read()
			self._key = keyfactory.parsePrivateKey(s)
		# RSAKey.hashAndSign() creates an RSA/PKCS1-1.5(SHA-1) signature, and does the equivalent of "SHA1withRSA" Signature method in Java
		# Note: the accesskeyid is already base64-encoded here
		sig = base64.b64encode(self._key.hashAndSign(acc))
		return sig

	def get_body(self, action, params=None, attachment=None):
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
				if val is not None:
					L.append('  <' + key + '>' + val + '</' + key + '>')
		L.append('  <AccessKeyId>' + acc + '</AccessKeyId>')
		L.append('  <Signature>' + sig + '</Signature>')
		L.append('</OViSSRequest>')
		body = CRLF.join(L)

		# add request description file for certain GetEFMConfiguration options
		if attachment is not None:
			L = []
			L.append('--BOUNDARY')
			L.append('Content-Type: text/xml; charset=UTF-8')
			L.append('Content-Disposition: form-data; name="Document"')
			L.append('')
			L.append(body)
			L.append('')
			L.append('--BOUNDARY')
			L.append('Content-Type: application/octet-stream')
			L.append('Content-Disposition: form-data; name="configurationXMLFilePath"; filename="extra.xml"')
			L.append('')
			L.append(attachment)
			L.append('--BOUNDARY--')
			body = CRLF.join(L)

		return body

	def do_action(self, action, params=None, attachment=None):
		"""
		Send the XML-RPC request and get the response
		"""
		if self._conn is None:
			# use the same PEM file for cert and key
			self._conn = httplib.HTTPSConnection(self.host, key_file=self.key_file, cert_file=self.key_file)

		headers = self.get_headers(attachment)
		body = self.get_body(action, params, attachment)
		if self.verbose > 1:
			print 'XML-RPC Request for %s:' % action
			print body

		# send XML-RPC request
		self._conn.request('POST', self.uri, body, headers)

		resp = self._conn.getresponse()
		if resp.status != 200:
			raise FGCPResponseError(repr(resp.status), repr(resp.reason))
		data = resp.read()
		if self.verbose > 1:
			print 'XML-RPC Response for %s:' % action
			print data

		# analyze XML-RPC response
		resp = FGCPResponse(data)
		if self.verbose > 0:
			print 'FGCP Response for %s:' % action
			resp.dump()
		# FIXME: use todict() first, and then verify responseStatus ?
		if resp.responseStatus.text != 'SUCCESS':
			raise FGCPResponseError(resp.responseStatus.text, resp.responseMessage.text)

		# return dictionary
		return resp.todict()

class FGCPCommand(FGCPConnection):
	"""
	FGCP API Commands
	
	Example:
	from fgcp_client_api import FGCPCommand
	cmd = FGCPCommand('client.pem')
	vsyss = cmd.ListVSYS()
	for vsys in vsyss:
		print vsys['vsysName']
		vsysconfig = cmd.GetVSYSConfiguration(vsys['vsysId'])
		...
	"""
	def ListVSYSDescriptor(self):
		"""
		Usage: vsysdescriptors = client.ListVSYSDescriptor()
		"""
		result = self.do_action('ListVSYSDescriptor')
		return result['vsysdescriptors']

	def GetVSYSDescriptorConfiguration(self, vsysDescriptorId):
		"""
		Usage: vsysdescriptor = client.GetVSYSDescriptorConfiguration(vsysDescriptorId)
		"""
		result = self.do_action('GetVSYSDescriptorConfiguration', {'vsysDescriptorId': vsysDescriptorId})
		return result['vsysdescriptor']

	def ListPublicIP(self, vsysId=None):
		"""
		Usage: publicips = client.ListPublicIP()
		"""
		result = self.do_action('ListPublicIP', {'vsysId': vsysId})
		return result['publicips']

	def GetPublicIPStatus(self, publicIp):
		"""
		Usage: status = client.GetPublicIPStatus(publicIp)
		"""
		result = self.do_action('GetPublicIPStatus', {'publicIp': publicIp})
		if self.show_status:
			print result['publicipStatus']
		return result['publicipStatus']

	def AllocatePublicIP(self, vsysId):
		"""Usage:
		try:
			client.AllocatePublicIP(vsysId)
		except FGCPResponseError:
			print 'Unable to allocate PublicIP'
			raise
		"""
		result = self.do_action('AllocatePublicIP', {'vsysId': vsysId})
		return result

	def AttachPublicIP(self, vsysId, publicIp):
		"""Usage:
		try:
			client.AttachPublicIP(vsysId, publicIp)
		except FGCPResponseError:
			print 'Unable to attach PublicIP'
			raise
		"""
		result = self.do_action('AttachPublicIP', {'vsysId': vsysId, 'publicIp': publicIp})
		return result

	def DetachPublicIP(self, vsysId, publicIp):
		"""Usage:
		try:
			client.DetachPublicIP(vsysId, publicIp)
		except FGCPResponseError:
			print 'Unable to detach PublicIP'
			raise
		"""
		result = self.do_action('DetachPublicIP', {'vsysId': vsysId, 'publicIp': publicIp})
		return result

	def FreePublicIP(self, vsysId, publicIp):
		"""Usage:
		try:
			client.FreePublicIP(vsysId, publicIp)
		except FGCPResponseError:
			print 'Unable to free PublicIP'
			raise
		"""
		result = self.do_action('FreePublicIP', {'vsysId': vsysId, 'publicIp': publicIp})
		return result

	def GetAddressRange(self):
		"""
		Usage: addressranges = client.GetAddressRange()
		"""
		result = self.do_action('GetAddressRange')
		if 'addressranges' in result:
			return result['addressranges']

	def ListDiskImage(self):
		"""
		Usage: diskimages = client.ListDiskImage()
		"""
		result = self.do_action('ListDiskImage')
		return result['diskimages']

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
		Usage: vsys = client.GetVSYSConfiguration(vsysId)
		"""
		result = self.do_action('GetVSYSConfiguration', {'vsysId': vsysId})
		return result['vsys']

	def GetVSYSStatus(self, vsysId):
		"""
		Usage: status = client.GetVSYSStatus(vsysId)
		"""
		result = self.do_action('GetVSYSStatus', {'vsysId': vsysId})
		if self.show_status:
			print result['vsysStatus']
		return result['vsysStatus']

	def CreateVSYS(self, vsysDescriptorId, vsysName):
		"""
		Usage: vsysId = client.CreateVSYS(vsysDescriptorId, vsysName)
		"""
		result = self.do_action('CreateVSYS', {'vsysDescriptorId': vsysDescriptorId, 'vsysName': vsysName})
		return result['vsysId']

	def DestroyVSYS(self, vsysId):
		"""Usage:
		try:
			client.DestroyVSYS(vsysId)
		 except FGCPResponseError:
			print 'Unable to destroy VSYS'
			raise
		"""
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
		Usage: vserver = client.GetVServerConfiguration(vsysId, vserverId)
		"""
		result = self.do_action('GetVServerConfiguration', {'vsysId': vsysId, 'vserverId': vserverId})
		return result['vserver']

	def GetVServerStatus(self, vsysId, vserverId):
		"""
		Usage: status = client.GetVServerStatus(vsysId, vserverId)
		"""
		result = self.do_action('GetVServerStatus', {'vsysId': vsysId, 'vserverId': vserverId})
		if self.show_status:
			print result['vserverStatus']
		return result['vserverStatus']

	def StartVServer(self, vsysId, vserverId):
		"""Usage:
		try:
			client.StartVServer(vsysId, vserverId)
		 except FGCPResponseError:
			print 'Unable to start VServer'
			raise
		"""
		result = self.do_action('StartVServer', {'vsysId': vsysId, 'vserverId': vserverId})
		return result

	def StopVServer(self, vsysId, vserverId, force=None):
		"""Usage:
		try:
			client.StopVServer(vsysId, vserverId)
		except FGCPResponseError:
			print 'Unable to stop VServer'
			raise
		"""
		result = self.do_action('StopVServer', {'vsysId': vsysId, 'vserverId': vserverId, 'force': force})
		return result

	def ListVDisk(self, vsysId):
		"""
		Usage: vdisks = client.ListVDisk(vsysId)
		"""
		result = self.do_action('ListVDisk', {'vsysId': vsysId})
		return result['vdisks']

	def GetVDiskStatus(self, vsysId, vdiskId):
		"""
		Usage: status = client.GetVDiskStatus(vsysId, vdiskId)
		"""
		result = self.do_action('GetVDiskStatus', {'vsysId': vsysId, 'vdiskId': vdiskId})
		if self.show_status:
			print result['vdiskStatus']
		return result['vdiskStatus']

	def ListVDiskBackup(self, vsysId, vdiskId):
		"""
		Usage: backups = client.ListVDiskBackup(vsysId, vdiskId)
		"""
		result = self.do_action('ListVDiskBackup', {'vsysId': vsysId, 'vdiskId': vdiskId})
		return result['backups']

	def BackupVDisk(self, vsysId, vdiskId):
		"""Usage:
		try:
			client.BackupVDisk(vsysId, vdiskId)
		except FGCPResponseError:
			print 'Unable to backup VDisk'
			raise
		"""
		result = self.do_action('BackupVDisk', {'vsysId': vsysId, 'vdiskId': vdiskId})
		return result

	def DestroyVDiskBackup(self, vsysId, backupId):
		"""Usage:
		try:
			client.DestroyVDiskBackup(vsysId, backupId)
		except FGCPResponseError:
			print 'Unable to destroy VDisk backup'
			raise
		"""
		result = self.do_action('DestroyVDiskBackup', {'vsysId': vsysId, 'backupId': backupId})
		return result

	def ListEFM(self, vsysId, efmType):
		"""Usage:
		firewalls = client.ListEFM(vsysId, "FW")
		loadbalancers = client.ListEFM(vsysId, "SLB")
		"""
		result = self.do_action('ListEFM', {'vsysId': vsysId, 'efmType': efmType})
		return result['efms']

	def GetEFMConfiguration(self, vsysId, efmId, configurationName, request_description_file=None):
		"""Generic method for all EFM configurations"""
		result = self.do_action('GetEFMConfiguration', {'vsysId': vsysId, 'efmId': efmId, 'configurationName':  configurationName}, request_description_file)
		return result['efm']

	def GetEFMConfigHandler(self, vsysId, efmId):
		"""Handler for specific EFM configuration methods, see EFMConfigurationHandler for details
		Usage: fw_policy = client.GetEFMConfigHandler(vsysId, efmId).FW_POLICY(from_zone, to_zone)
		"""
		return EFMConfigurationHandler(self, vsysId, efmId)

	def GetEFMStatus(self, vsysId, efmId):
		"""
		Usage: status = client.GetEFMStatus(vsysId, efmId)
		"""
		result = self.do_action('GetEFMStatus', {'vsysId': vsysId, 'efmId': efmId})
		if self.show_status:
			print result['efmStatus']
		return result['efmStatus']

	def StartEFM(self, vsysId, efmId):
		"""Usage:
		try:
			client.StartEFM(vsysId, efmId)
		 except FGCPResponseError:
			print 'Unable to start EFM'
			raise
		"""
		result = self.do_action('StartEFM', {'vsysId': vsysId, 'efmId': efmId})
		return result

	def StopEFM(self, vsysId, efmId):
		"""Usage:
		try:
			client.StopEFM(vsysId, efmId)
		 except FGCPResponseError:
			print 'Unable to stop EFM'
		"""
		result = self.do_action('StopEFM', {'vsysId': vsysId, 'efmId': efmId})
		return result

	def GetSystemUsage(self):
		"""NOTE: extra 'date' element on top-level compared to other API calls !
		Usage: date, usage = client.GetSystemUsage()
		"""
		result = self.do_action('GetSystemUsage')
		return result['date'], result['usageinfos']

class EFMConfigurationHandler:
	"""
	Handler for EFM Configuration methods
	
	Example: fw_policy = client.GetEFMConfigHandler(vsysId, efmId).FW_POLICY(from_zone, to_zone)
	"""
	_client = None
	vsysId = None
	efmId = None

	def __init__(self, client, vsysId=None, efmId=None):
		"""
		Usage: efm_handler = client.GetEFMConfigHandler(vsysId, efmId)
		"""
		self._client = client
		self.vsysId = vsysId
		self.efmId = efmId

	def FW_NAT_RULE(self):
		"""
		Usage: fw_nat_rule = client.GetEFMConfigHandler(vsysId, efmId).FW_NAT_RULE()
		"""
		return self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'FW_NAT_RULE')['firewall']['nat']

	def FW_DNS(self):
		"""
		Usage: fw_dns = client.GetEFMConfigHandler(vsysId, efmId).FW_DNS()
		"""
		return self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'FW_DNS')['firewall']['dns']

	def FW_POLICY(self, from_zone=None, to_zone=None):
		"""CHECKME: for network identifiers besides INTERNET and INTRANET, see GetVSYSConfiguration()
		Usage: fw_policy = client.GetEFMConfigHandler(vsysId, efmId).FW_POLICY(from_zone, to_zone)
		"""
		CRLF = '\r\n'
		L = []
		L.append('<?xml version="1.0" encoding="UTF-8"?>')
		L.append('<Request>')
		L.append('  <configuration>')
		L.append('    <firewall_policy>')
		if from_zone is not None:
			L.append('      <from>' + from_zone + '</from>')
		if to_zone is not None:
			L.append('      <to>' + to_zone + '</to>')
		L.append('    </firewall_policy>')
		L.append('  </configuration>')
		L.append('</Request>')
		descr = CRLF.join(L)
		return self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'FW_POLICY', descr)['firewall']['directions']

	def FW_LIMIT_POLICY(self, from_zone=None, to_zone=None):
		"""CHECKME: for network identifiers besides INTERNET and INTRANET, see GetVSYSConfiguration()
		Usage: fw_limit_policy = client.GetEFMConfigHandler(vsysId, efmId).FW_LIMIT_POLICY(from_zone, to_zone)
		"""
		CRLF = '\r\n'
		L = []
		L.append('<?xml version="1.0" encoding="UTF-8"?>')
		L.append('<Request>')
		L.append('  <configuration>')
		L.append('    <firewall_limit_policy>')
		if from_zone is not None:
			L.append('      <from>' + from_zone + '</from>')
		if to_zone is not None:
			L.append('      <to>' + to_zone + '</to>')
		L.append('    </firewall_limit_policy>')
		L.append('  </configuration>')
		L.append('</Request>')
		descr = CRLF.join(L)
		return self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'FW_LIMIT_POLICY', descr)['firewall']

	def SLB_RULE(self):
		"""
		Usage: slb_rule = client.GetEFMConfigHandler(vsysId, efmId).SLB_RULE()
		"""
		return self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'SLB_RULE')['loadbalancer']

	def SLB_LOAD(self):
		"""
		Usage: slb_load_stats = client.GetEFMConfigHandler(vsysId, efmId).SLB_RULE()
		"""
		return self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'SLB_LOAD_STATISTICS')['loadbalancer']['loadStatistics']

	def SLB_ERROR(self):
		"""
		Usage: slb_error_stats = client.GetEFMConfigHandler(vsysId, efmId).SLB_RULE()
		"""
		return self._client.GetEFMConfiguration(self.vsysId, self.efmId, 'SLB_ERROR_STATISTICS')['loadbalancer']['errorStatistics']

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

class FGCPClient(FGCPCommand):
	"""
	FGCP User Functions
	
	Example:
	from fgcp_client_api import FGCPClient
	client = FGCPClient('client.pem')
	inventory = client.GetSystemInventory('Python API Demo System')
	for vserver in inventory['vservers']:
		client.BackupVServerAndRestart(inventory['vsysId'], vserver['vserverId'])
	client.CleanupBackups(inventory['vsysId'])
	# Note: this also inherits all API commands from FGCPCommand()
	vsyss = client.ListVSYS()
	...
	"""
	def GetSystemByName(self, vsysName):
		"""
		Get VSYS by vsysName
		"""
		vsyss = self.ListVSYS()
		if len(vsyss) < 1:
			print 'No VSYS are defined'
			return
		for vsys in vsyss:
			if vsysName == vsys['vsysName']:
				return vsys
		raise FGCPResponseError('ILLEGAL_VSYS_NAME', 'Invalid vsysName in GetSystemByName')

	def GetSystemInventory(self, vsysName=None):
		"""
		Get VSYS inventory (by vsysName)
		"""
		if vsysName is None:
			vsyss = self.ListVSYS()
		else:
			vsyss = []
			vsyss.append(self.GetSystemByName(vsysName))
		if len(vsyss) < 1:
			print 'No VSYS are defined'
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

	def ShowSystemStatus(self, vsysName=None):
		"""
		Show the overall system status (for a particular VSYS)
		"""
		if vsysName is None:
			print 'Show System Status for all VSYS'
			inventory = self.GetSystemInventory()
		else:
			print 'Show System Status for VSYS %s' % vsysName
			inventory = {}
			inventory['vsys'] = {}
			inventory['vsys'][vsysName] = self.GetSystemInventory(vsysName)
		if inventory is None or len(inventory['vsys']) < 1:
			print 'No VSYS are defined'
			return
		for name, vsysconfig in inventory['vsys'].iteritems():
			# get status of vsys overall
			status = self.GetVSYSStatus(vsysconfig['vsysId'])
			print 'VSYS\t' + vsysconfig['vsysName'] + '\t' + status
			# get status of public ips
			for publicip in vsysconfig['publicips']:
				status = self.GetPublicIPStatus(publicip['address'])
				print 'PublicIP\t' + publicip['address'] + '\t' + status
			# get status of firewalls
			for firewall in vsysconfig['firewalls']:
				status = self.GetEFMStatus(vsysconfig['vsysId'], firewall['efmId'])
				print 'EFM FW\t' + firewall['efmName'] + '\t' + status
			# get status of loadbalancers
			for loadbalancer in vsysconfig['loadbalancers']:
				status = self.GetEFMStatus(vsysconfig['vsysId'], loadbalancer['efmId'])
				print 'EFM SLB\t' + loadbalancer['efmName'] + '\t' + loadbalancer['slbVip'] + '\t' + status
			# get status of vservers (excl. firewalls and loadbalancers)
			seenId = {}
			for vserver in vsysconfig['vservers']:
				status = self.GetVServerStatus(vsysconfig['vsysId'], vserver['vserverId'])
				print 'VServer\t' + vserver['vserverName'] + '\t' + vserver['vnics'][0]['privateIp'] + '\t' + status
				# get status of attached disks
				for vdisk in vserver['vdisks']:
					status = self.GetVDiskStatus(vsysconfig['vsysId'], vdisk['vdiskId'])
					print '\tVDisk\t' + vdisk['vdiskName'] + '\t' + status
					seenId[vdisk['vdiskId']] = 1
			# get status of unattached disks
			todo = []
			for vdisk in vsysconfig['vdisks']:
				# skip disks we've already seen, i.e. attached to a server
				if vdisk['vdiskId'] in seenId:
					continue
				todo.append(vdisk)
			if len(todo) > 0:
				print 'Unattached Disks'
				for vdisk in todo:
					status = self.GetVDiskStatus(vsysconfig['vsysId'], vdisk['vdiskId'])
					print '\tVDisk\t' + vdisk['vdiskName'] + '\t' + status
					seenId[vdisk['vdiskId']] = 1
			print

	def StartVServerAndWait(self, vsysId, vserverId):
		"""
		Start VServer and wait until it's running
		"""
		# check current status
		status = self.GetVServerStatus(vsysId, vserverId)
		if status == 'RUNNING':
			return status
		elif status == 'STOPPED':
			pass
		elif status == 'UNEXPECTED_STOP':
			pass
		else:
			raise FGCPResponseError('ILLEGAL_STATE', 'Invalid vserver status %s for starting' % status)
		# start vserver
		result = self.StartVServer(vsysId, vserverId)
		# wait until starting is done - TODO: add some timeout
		while True:
			time.sleep(5)
			status = self.GetVServerStatus(vsysId, vserverId)
			if status == 'STARTING':
				pass
			elif status == 'RUNNING':
				return status
			else:
				raise FGCPResponseError('ILLEGAL_STATE', 'Unexpected vserver status %s while starting' % status)
		return status

	def StopVServerAndWait(self, vsysId, vserverId, force=None):
		"""
		Stop VServer and wait until it's stopped
		"""
		# check current status
		status = self.GetVServerStatus(vsysId, vserverId)
		if status == 'STOPPED':
			return status
		elif status == 'UNEXPECTED_STOP':
			return status
		elif status == 'RUNNING':
			pass
		else:
			raise FGCPResponseError('ILLEGAL_STATE', 'Invalid vserver status %s for stopping' % status)
		# stop vserver
		result = self.StopVServer(vsysId, vserverId, force)
		# wait until stopping is done - TODO: add some timeout
		while True:
			time.sleep(5)
			status = self.GetVServerStatus(vsysId, vserverId)
			if status == 'STOPPING':
				pass
			elif status == 'STOPPED':
				return status
			else:
				raise FGCPResponseError('ILLEGAL_STATE', 'Unexpected vserver status %s while stopping' % status)
		return status

	def StartEFMAndWait(self, vsysId, efmId):
		"""
		Start EFM and wait until it's running
		"""
		# check current status
		status = self.GetEFMStatus(vsysId, efmId)
		if status == 'RUNNING':
			return status
		elif status == 'STOPPED':
			pass
		elif status == 'UNEXPECTED_STOP': # CHECKME: this is what happens when calling StopEFM() !?
			pass
		else:
			raise FGCPResponseError('ILLEGAL_STATE', 'Invalid efm status %s for starting' % status)
		# start efm
		result = self.StartEFM(vsysId, efmId)
		# wait until starting is done - TODO: add some timeout
		while True:
			time.sleep(5)
			status = self.GetEFMStatus(vsysId, efmId)
			if status == 'STARTING':
				pass
			elif status == 'RUNNING':
				return status
			else:
				raise FGCPResponseError('ILLEGAL_STATE', 'Unexpected efm status %s while starting' % status)
		return status

	def StopEFMAndWait(self, vsysId, efmId):
		"""
		Stop EFM and wait until it's stopped
		"""
		# check current status
		status = self.GetEFMStatus(vsysId, efmId)
		if status == 'STOPPED':
			return status
		elif status == 'UNEXPECTED_STOP': # CHECKME: this is what happens when calling StopEFM() !?
			return status
		elif status == 'RUNNING':
			pass
		else:
			raise FGCPResponseError('ILLEGAL_STATE', 'Invalid efm status %s for stopping' % status)
		# CHECKME: for firewalls, we need to detach the publicIPs first !?
		# stop efm
		result = self.StopEFM(vsysId, efmId)
		# wait until stopping is done - TODO: add some timeout
		while True:
			time.sleep(5)
			status = self.GetEFMStatus(vsysId, efmId)
			if status == 'STOPPING':
				pass
			elif status == 'STOPPED':
				return status
			elif status == 'UNEXPECTED_STOP': # CHECKME: this is what happens when calling StopEFM() !?
				return status
			else:
				raise FGCPResponseError('ILLEGAL_STATE', 'Unexpected efm status %s while stopping' % status)
		return status

	def BackupVDiskAndWait(self, vsysId, vdiskId):
		"""
		Take Backup of VDisk and wait until it's finished (this might take a while)
		"""
		# check current status
		status = self.GetVDiskStatus(vsysId, vdiskId)
		# CHECKME: for system disk !?
		if status == 'STOPPED':
			pass
		# for other disks
		elif status == 'NORMAL':
			pass
		else:
			raise FGCPResponseError('ILLEGAL_STATE', 'Invalid vdisk status %s for backup' % status)
		# backup vdisk
		result = self.BackupVDisk(vsysId, vdiskId)
		# wait until backup is done - TODO: add some timeout
		while True:
			time.sleep(5)
			status = self.GetVDiskStatus(vsysId, vdiskId)
			if status == 'BACKUP_ING':
				pass
			# CHECKME: for system disk !?
			elif status == 'STOPPED':
				return status
			elif status == 'NORMAL':
				return status
			else:
				raise FGCPResponseError('ILLEGAL_STATE', 'Unexpected vdisk status %s during backup' % status)

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

	def AttachPublicIPAndWait(self, vsysId, publicIp):
		"""
		Attach PublicIP and wait until it's attached
		"""
		# check current status
		status = self.GetPublicIPStatus(publicIp)
		if status == 'ATTACHED':
			return status
		elif status == 'DETACHED':
			pass
		else:
			raise FGCPResponseError('ILLEGAL_STATE', 'Invalid publicip status %s for attaching' % status)
		# attach publicIP
		result = self.AttachPublicIP(vsysId, publicIp)
		# wait until attaching is done - TODO: add some timeout
		while True:
			time.sleep(5)
			status = self.GetPublicIPStatus(publicIp)
			if status == 'ATTACHING':
				pass
			elif status == 'ATTACHED':
				return status
			else:
				raise FGCPResponseError('ILLEGAL_STATE', 'Unexpected publicip status %s while attaching' % status)
		return status

	def DetachPublicIPAndWait(self, vsysId, publicIp):
		"""
		Detach PublicIP and wait until it's detached
		"""
		# check current status
		status = self.GetPublicIPStatus(publicIp)
		if status == 'DETACHED':
			return status
		elif status == 'ATTACHED':
			pass
		else:
			raise FGCPResponseError('ILLEGAL_STATE', 'Invalid publicip status %s for detaching' % status)
		# detach publicIP
		result = self.DetachPublicIP(vsysId, publicIp)
		# wait until detaching is done - TODO: add some timeout
		while True:
			time.sleep(5)
			status = self.GetPublicIPStatus(publicIp)
			if status == 'DETACHING':
				pass
			elif status == 'DETACHED':
				return status
			else:
				raise FGCPResponseError('ILLEGAL_STATE', 'Unexpected publicip status %s while detaching' % status)
		return status

	def StopSystemAndDestroy(self, vsysName, show_output=0):
		"""
		Destroy VSYS after stopping all VServers and EFMs
		"""
		if show_output:
			print 'Destroying VSYS %s' % vsysName
			# start showing status
			old_show_status = self.show_status
			self.show_status = 1
		inventory = self.GetSystemInventory(vsysName)
		#print inventory
		# Stop all vservers
		for vserver in inventory['vservers']:
			if show_output:
				print vserver['vserverName']
			status = self.StopVServerAndWait(inventory['vsysId'], vserver['vserverId'])
		# Stop all loadbalancers
		for loadbalancer in inventory['loadbalancers']:
			if show_output:
				print loadbalancer['efmName']
			status = self.StopEFMAndWait(inventory['vsysId'], loadbalancer['efmId'])
		# Detach publicip - cfr. sequence3 in java sdk
		for publicip in inventory['publicips']:
			if show_output:
				print publicip['address']
			status = self.DetachPublicIPAndWait(inventory['vsysId'], publicip['address'])
		return
		# Stop all firewalls
		for firewall in inventory['firewalls']:
			if show_output:
				print firewall['efmName']
			status = self.StopEFMAndWait(inventory['vsysId'], firewall['efmId'])
		# Destroy the VSYS
		result = self.DestroyVSYS(inventory['vsysId'])
		if show_output:
			print result['responseStatus']
			# stop showing status
			self.show_status = old_show_status
		# TODO: wait until it's gone ?

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

def fgcp_run_sample(pem_file):
	#from fgcp_client_api import FGCPClient
	client = FGCPClient(pem_file)
	# Hint: set verbose=1 to dump the FGCP Response for further development
	#client = FGCPClient(pem_file, 1)
	client.ShowSystemStatus()
	#inventory = client.GetSystemInventory('Python API Demo System')
	#for vserver in inventory['vservers']:
	#	client.BackupVServerAndRestart(inventory['vsysId'], vserver['vserverId'])
	#client.CleanupBackups(inventory['vsysId'])
	#client.StopSystemAndDestroy('Python API Demo System', 1)
	#...
	#
	# Note: you can also use all API commands from FGCPCommand() here
	#vsyss = client.ListVSYS()
	#for vsys in vsyss:
	#	vsysconfig = client.GetVSYSConfiguration(vsys['vsysId'])
	#	...
	#vsysdescriptors = client.ListVSYSDescriptor()
	#for vsysdescriptor in vsysdescriptors:
	#	if vsysdescriptor['vsysdescriptorName'] == '1-tier Skeleton':
	#		vsysId = client.CreateVSYS(vsysdescriptor['vsysdescriptorId'], 'Python API Demo System')
	#		print 'New VSYS Created: %s' % vsysId
	#		break
	exit()

def fgcp_show_usage(name='fgcp_client_api.py'):
	print """Client API library for the Fujitsu Global Cloud Platform (FGCP)

Usage: %s [pem_file]

from fgcp_client_api import FGCPClient
client = FGCPClient('client.pem')
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
	if len(sys.argv) > 1:
		pem_file = sys.argv[1]
	else:
		pem_file = 'cliont.pem'
	if os.path.exists(pem_file):
		fgcp_run_sample(pem_file)
	else:
		fgcp_show_usage(os.path.basename(sys.argv[0]))
