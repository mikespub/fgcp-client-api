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
Resources on the Fujitsu Global Cloud Platform (FGCP)
using XML-RPC API Version 2011-01-31

TODO: review class inheritance vs. composition
"""

class FGCPElement(object):
	def __init__(self, **kwargs):
		# initialize object attributes, cfr. FGCPDesigner().LoadSystemDesign
		for key in kwargs.keys():
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
		# initialize object attributes, cfr. FGCPDesigner().SaveSystemDesign
		L.append('  ' * depth + '%s(' % type(what).__name__)
		depth += 1
		for key in what.__dict__:
			# TODO: skip _caller and _parent for output later ?
			if key == '_caller' or key == '_parent':
				if isinstance(what.__dict__[key], FGCPResource):
					L.append('  ' * depth + "%s='%s'," % (key, repr(what.__dict__[key])))
				elif isinstance(what.__dict__[key], str):
					L.append('  ' * depth + "%s='%s'," % (key, what.__dict__[key]))
				else:
					L.append('  ' * depth + '%s=%s,' % (key, what.__dict__[key]))
			# TODO: skip _client for output later ?
			elif key == '_client':
				#if what.__dict__[key] is not None:
				#	L.append('  ' * depth + "%s='%s'," % (key, repr(what.__dict__[key])))
				#else:
				#	L.append('  ' * depth + '%s=None,' % key)
				pass
			elif isinstance(what.__dict__[key], FGCPElement):
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

	def pprint(self):
		"""
		Show dump of the FGCP Element for development
		"""
		print self.pformat(self)

class FGCPResponse(FGCPElement):
	"""
	FGCP Response
	"""
	_caller = None

class FGCPResource(FGCPElement):
	"""
	Generic FGCP Resource
	"""
	_idname = None
	_parent = None
	_client = None
	#_actions = {}

	def __init__(self, **kwargs):
		# initialize object attributes, cfr. FGCPDesigner().LoadSystemDesign
		for key in kwargs.keys():
			setattr(self, key, kwargs[key])
		# CHECKME: special case for id=123 and/or parentid=12 ?

	def __repr__(self):
		return '<%s:%s>' % (type(self).__name__, self.getid())

	def create(self):
		pass

	def retrieve(self):
		pass

	def update(self):
		pass

	def replace(self):
		pass

	def destroy(self):
		pass

	def status(self):
		pass

	def getid(self):
		if self._idname is not None and hasattr(self, self._idname):
			return getattr(self, self._idname)

	def getparentid(self):
		if self._parent is not None:
			if isinstance(self._parent, FGCPResource):
				return self._parent.getid()
			elif isinstance(self._parent, str):
				return self._parent

	def getclient(self):
		if self._client is not None:
			# CHECKME: set the caller here !?
			self._client._caller = self
			return self._client

	# convert *args and **kwargs from other method to dict
	def _args2dict(self, argslist=[], kwargsdict={}):
		tododict = {}
		if len(argslist) == 2:
			# CHECKME: we assume a key, val pair - cfr. attributeName, attributeValue etc. !?
			tododict[argslist[0]] = argslist[1]
		elif len(argslist) == 1:
			# CHECKME: we got an object, use its __dict__
			if isinstance(argslist[0], FGCPResource):
				tododict = argslist[0].__dict__
			# CHECKME: we got key, val pairs
			elif isinstance(argslist[0], dict):
				tododict = argslist[0]
			elif isinstance(argslist[0], list):
				# now what ?
				return argslist[0]
			else:
				# now what ?
				return argslist[0]
		if len(kwargslist) > 0:
			tododict.update(kwargs)
		return tododict

	# CHECKME: no longer needed since we do it in FGCPResponseParser() based on conn._caller
	def _reparent(self, child=None, parent=None):
		if child is None:
			return child
		elif isinstance(child, str):
			return child
		elif isinstance(child, list):
			new_child = []
			for item in child:
				new_child.append(self._reparent(item, parent))
			return new_child
		elif isinstance(child, dict):
			new_child = {}
			for key, val in child:
				new_child[key] = self._reparent(val, parent)
			return new_child
		elif isinstance(child, FGCPResponse):
			child._caller = parent
			for key, val in child.__dict__:
				if key == '_caller':
					continue
				# CHECKME: use caller as parent here
				setattr(child, key, self._reparent(val, parent))
			return child
		elif isinstance(child, FGCPResource):
			child._parent = parent
			for key, val in child.__dict__:
				if key == '_parent' or key == '_client':
					continue
				# CHECKME: use child as parent here
				setattr(child, key, self._reparent(val, child))
			return child
		else:
			return child

	#def action(self, what=None):
	#	pass

class FGCPVDataCenter(FGCPResource):
	_idname=None

	def get_vsysdescriptors(self):
		if not hasattr(self, 'vsysdescriptors'):
			setattr(self, 'vsysdescriptors', self.getclient().ListVSYSDescriptor())
		return getattr(self, 'vsysdescriptors')

	def get_vsystems(self):
		if not hasattr(self, 'vsystems'):
			setattr(self, 'vsystems', self.getclient().ListVSYS())
		return getattr(self, 'vsystems')

	def get_publicips(self):
		if not hasattr(self, 'publicips'):
			setattr(self, 'publicips', self.ListPublicIP())
		return getattr(self, 'publicips')

	def get_addressranges(self):
		if not hasattr(self, 'addressranges'):
			setattr(self, 'addressranges', self.getclient().GetAddressRange())
		return getattr(self, 'addressranges')

	def get_diskimages(self, vsysdescriptor=None, category='GENERAL'):
		# CHECKME: reversed order of arguments here
		# get all diskimages
		if vsysdescriptor is None:
			if not hasattr(self, 'diskimages'):
				setattr(self, 'diskimages', self.getclient().ListDiskImage())
			return getattr(self, 'diskimages')
		# get specific diskimages
		elif isinstance(vsysdescriptor, FGCPResource):
			# let the vsysdescriptor handle it
			return vsysdescriptor.get_diskimages(category)
		else:
			return self.getclient().ListDiskImage(category, vsysdescriptor)

	def get_servertypes(self, diskimage=None):
		# CHECKME: all diskimages support the same servertypes at the moment !?
		if hasattr(self, 'servertypes'):
			return getattr(self, 'servertypes')
		# pick the first diskimage that's available
		if diskimage is None:
			diskimage = self.get_diskimages()[0]
		if isinstance(diskimage, FGCPResource):
			# let the diskimage handle it
			setattr(self, 'servertypes', diskimage.get_servertypes())
		else:
			setattr(self, 'servertypes', self.getclient().ListServerType(diskimage))
		return getattr(self, 'servertypes')

class FGCPVSysDescriptor(FGCPResource):
	_idname='vsysdescriptorId'

	def get_diskimages(self, category='GENERAL'):
		if not hasattr(self, 'diskimages'):
			setattr(self, 'diskimages', self.getclient().ListDiskImage(self.getid(), category))
		return getattr(self, 'diskimages')

class FGCPPublicIP(FGCPResource):
	_idname='address'

class FGCPAddressRange(FGCPResource):
	pass

class FGCPDiskImage(FGCPResource):
	_idname='diskimageId'

	def get_softwares(self):
		if not hasattr(self, 'softwares'):
			# CHECKME: initialize to None or list here ?
			setattr(self, 'softwares', None)
		return getattr(self, 'softwares')

	def get_servertypes(self):
		if not hasattr(self, 'servertypes'):
			setattr(self, 'servertypes', self.getclient().ListServerType(self.getid()))
		return getattr(self, 'servertypes')

class FGCPDiskImageSoftware(FGCPResource):
	_idname='name'

class FGCPServerType(FGCPResource):
	# this is what we actually pass to CreateVServer
	_idname='name'

class FGCPServerTypeCPU(FGCPResource):
	# CHECKME: this is used as internal response element for ListServerType
	pass

class FGCPVSys(FGCPResource):
	_idname='vsysId'

	def get_vservers(self):
		if not hasattr(self, 'vservers'):
			setattr(self, 'vservers', self.getclient().ListVServer(self.getid()))
		return getattr(self, 'vservers')

	def get_vdisks(self):
		if not hasattr(self, 'vdisks'):
			setattr(self, 'vdisks', self.getclient().ListVDisk(self.getid()))
		return getattr(self, 'vdisks')

	def get_publicips(self):
		if not hasattr(self, 'publicips'):
			setattr(self, 'publicips', self.getclient().ListPublicIP(self.getid()))
		return getattr(self, 'publicips')

	def get_firewalls(self):
		if not hasattr(self, 'firewalls'):
			setattr(self, 'firewalls', self.getclient().ListEFM(self.getid(), "FW"))
		return getattr(self, 'firewalls')

	def get_loadbalancers(self):
		if not hasattr(self, 'loadbalancers'):
			setattr(self, 'loadbalancers', self.getclient().ListEFM(self.getid(), "SLB"))
		return getattr(self, 'loadbalancers')

	def get_vnets(self):
		if not hasattr(self, 'vnets'):
			self.retrieve()
		return getattr(self, 'vnets')

	def get_console(self, vnet=None):
		pass

class FGCPVServer(FGCPResource):
	_idname='vserverId'

	def create(self, *args, **kwargs):
		# convert arguments to dict
		tododict = self._args2dict(args, kwargs)
		# TODO: set attributes based on tododict
		for key in tododict.keys():
			setattr(self, key, tododict[key])
		# CHECKME: what if we didn't initialize the object yet ?
		return self.getclient().CreateVServer(self.getparentid(), self.vserverName, self.vserverType, self.diskimageId, self.vnics[0].getid())

	def retrieve(self):
		return self.getclient().GetVServerConfiguration(self.getparentid(), self.getid())

	def update(self, *args, **kwargs):
		# convert arguments to dict
		tododict = self._args2dict(args, kwargs)
		# CHECKME: what if we updated the object attributes directly ?
		status = None
		for key in tododict.keys():
			status = self.getclient().UpdateVServerAttribute(self.getparentid(), self.getid(), key, tododict[key])
		return status

	def destroy(self):
		return self.getclient().DestroyVServer(self.getparentid(), self.getid())

	def start(self):
		return self.getclient().StartVServer(self.getparentid(), self.getid())

	def stop(self, force=None):
		return self.getclient().StopVServer(self.getparentid(), self.getid(), force)

	def get_disks(self):
		pass

	def attach(self, vdisk):
		if isinstance(vdisk, FGCPResource):
			return self.getclient().AttachVDisk(self.getparentid(), self.getid(), vdisk.getid())
		else:
			return self.getclient().AttachVDisk(self.getparentid(), self.getid(), vdisk)

	def detach(self, vdisk):
		if isinstance(vdisk, FGCPResource):
			return self.getclient().DetachVDisk(self.getparentid(), self.getid(), vdisk.getid())
		else:
			return self.getclient().DetachVDisk(self.getparentid(), self.getid(), vdisk)

	def get_vnics(self):
		pass

	def password(self):
		return self.getclient().GetVServerInitialPassword(self.getparentid(), self.getid())

class FGCPVDisk(FGCPResource):
	_idname='vdiskId'

	def attach(self, vserver):
		# note: the parent of a vdisk may be a vserver or a vsys, so we use the vserver's parent instead
		return self.getclient().AttachVDisk(vserver.getparentid(), vserver.getid(), self.getid())

	def detach(self, vserver):
		# note: the parent of a vdisk may be a vserver or a vsys, so we use the vserver's parent instead
		return self.getclient().DetachVDisk(vserver.getparentid(), vserver.getid(), self.getid())

	def get_backups(self, timeZone=None, countryCode=None):
		if not hasattr(self, 'backups'):
			setattr(self, 'backups', self.getclient().ListVDiskBackup(self.getparentid(), self.getid(), timeZone, countryCode))
		return getattr(self, 'backups')

class FGCPVNic(FGCPVServer):
	_idname='networkId'

class FGCPEfm(FGCPResource):
	_idname='efmId'

	def start(self, what=None):
		pass

	def stop(self, what=None):
		pass

class FGCPBackup(FGCPVDisk, FGCPEfm):
	_idname='backupId'

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
	_idname='certNum'

class FGCPSLBCCACert(FGCPLoadBalancer):
	_idname='ccacertNum'

class FGCPUsageInfo(FGCPResource):
	_idname='vsysId'

class FGCPUsageInfoProduct(FGCPResource):
	_idname='productName'

class FGCPUnknown(FGCPResource):
	pass

