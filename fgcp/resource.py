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

class FGCPElement(object):
	def __init__(self, **kwargs):
		for key in kwargs:
			setattr(self, key, kwargs[key])

	def pformat(self, what, depth=0):
		if isinstance(what, str):
			return '  ' * depth + "'%s'" % what
		CRLF = '\r\n'
		L = []
		if isinstance(what, list):
			L.append('  ' * depth + '[')
			for val in what:
				L.append(self.pformat(val, depth + 1) + ',')
			L.append('  ' * depth + ']')
			return CRLF.join(L)
		L.append('  ' * depth + '%s(' % type(what).__name__)
		depth += 1
		for key in what.__dict__:
			if isinstance(what.__dict__[key], FGCPElement):
				L.append('  ' * depth + '%s=' % key)
				L.append(self.pformat(what.__dict__[key], depth + 1) + ',')
			elif isinstance(what.__dict__[key], list):
				L.append('  ' * depth + '%s=[' % key)
				for val in what.__dict__[key]:
					L.append(self.pformat(val, depth + 1) + ',')
				L.append('  ' * depth + '],')
			elif isinstance(what.__dict__[key], str):
				L.append('  ' * depth + "%s='%s'," % (key, what.__dict__[key]))
			elif what.__dict__[key] is None:
				#L.append('  ' * depth + "%s=None," % key)
				pass
			else:
				L.append('  ' * depth + "%s=?%s?," % (key, what.__dict__[key]))
		depth -= 1
		L.append('  ' * depth + ')')
		return CRLF.join(L)

	def dump(self):
		"""
		Show dump of the FGCP Element for development
		"""
		print self.pformat(self)

class FGCPResponse(FGCPElement):
	"""
	FGCP Response
	"""
	pass

class FGCPResource(FGCPResponse):
	"""
	Generic FGCP Resource
	"""
	_client = None

class FGCPVDataCenter(FGCPResource):
	pass

class FGCPVSysDescriptor(FGCPResource):
	pass

class FGCPPublicIP(FGCPResource):
	pass

class FGCPAddressRange(FGCPResource):
	pass

class FGCPDiskImage(FGCPResource):
	pass

class FGCPSoftware(FGCPDiskImage):
	# CHECKME: this is used as internal response element for ListDiskImage
	pass

class FGCPServerType(FGCPResource):
	pass

class FGCPServerTypeCPU(FGCPServerType):
	# CHECKME: this is used as internal response element for ListServerType
	pass

class FGCPVSys(FGCPResource):
	pass

class FGCPVServer(FGCPResource):
	pass

class FGCPVDisk(FGCPResource):
	pass

class FGCPVNic(FGCPVServer):
	pass

class FGCPEfm(FGCPResource):
	pass

class FGCPBackup(FGCPVDisk, FGCPEfm):
	pass

class FGCPFirewall(FGCPEfm):
	# CHECKME: this is not used as subclass of EFM, but as internal response element for GetEFMConfiguration
	pass

class FGCPFWNATRule(FGCPFirewall):
	pass

class FGCPFWDns(FGCPFirewall):
	pass

class FGCPFWDirection(FGCPFirewall):
	pass

class FGCPFWPolicy(FGCPFWDirection):
	pass

class FGCPFWLogOrder(FGCPFirewall):
	def __init__(self, **kwargs):
		for key in kwargs:
			# CHECKME: replace from_zone and to_zone, because from=... is restricted
			setattr(self, key.replace('_zone',''), kwargs[key])

class FGCPLoadBalancer(FGCPEfm):
	# CHECKME: this is not used as subclass of EFM, but as internal response element for GetEFMConfiguration
	pass

class FGCPSLBGroup(FGCPLoadBalancer):
	pass

class FGCPSLBTarget(FGCPSLBGroup):
	pass

class FGCPSLBErrorStats(FGCPLoadBalancer):
	pass

class FGCPSLBErrorCause(FGCPSLBErrorStats):
	pass

class FGCPSLBErrorPeriod(FGCPSLBErrorStats):
	pass

class FGCPSLBServerCert(FGCPLoadBalancer):
	pass

class FGCPSLBCCACert(FGCPLoadBalancer):
	pass

class FGCPUsageInfo(FGCPResponse):
	pass

class FGCPProduct(FGCPUsageInfo):
	# CHECKME: this is used as internal response element for GetSystemUsage
	pass

class FGCPUnknown(FGCPResponse):
	pass

