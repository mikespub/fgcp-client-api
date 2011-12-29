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
Client library for the Fujitsu Global Cloud Platform (FGCP)
using XML-RPC API Version 2011-01-31
"""

import time

from fgcp.command import FGCPCommand

from fgcp import FGCPError

class FGCPClientError(FGCPError):
	pass

class FGCPMonitor(FGCPCommand):
	"""
	FGCP Monitoring Methods
	"""

	def FindSystemByName(self, vsysName):
		"""
		Find VSYS by vsysName
		"""
		vsystems = self.ListVSYS()
		if len(vsystems) < 1:
			raise FGCPClientError('RESOURCE_NOT_FOUND', 'No VSYS are defined')
		for vsys in vsystems:
			if vsysName == vsys.vsysName:
				return vsys
		raise FGCPClientError('ILLEGAL_VSYS_ID', 'Invalid vsysName %s' % vsysName)

	def GetSystemInventory(self, vsysName=None):
		"""
		Get VSYS inventory (by vsysName)
		"""
		if vsysName is None:
			vsystems = self.ListVSYS()
		else:
			vsystems = []
			vsystems.append(self.FindSystemByName(vsysName))
		if len(vsystems) < 1:
			self.show_output('No VSYS are defined')
			return
		inventory = {}
		inventory['vsys'] = {}
		for vsys in vsystems:
			# get configuration for this vsys
			vsys = self.GetVSYSConfiguration(vsys.vsysId)
			# CHECKME: set vsys as parent for next commands ?
			self._caller = vsys
			setattr(vsys, 'firewalls', self.ListEFM(vsys.vsysId, "FW"))
			setattr(vsys, 'loadbalancers', self.ListEFM(vsys.vsysId, "SLB"))
			# CHECKME: remove firewalls and loadbalancers from vservers list
			seenId = {}
			if hasattr(vsys, 'firewalls'):
				for firewall in vsys.firewalls:
					seenId[firewall.efmId] = 1
			if hasattr(vsys, 'loadbalancers'):
				for loadbalancer in vsys.loadbalancers:
					seenId[loadbalancer.efmId] = 1
			todo = []
			if hasattr(vsys, 'vservers'):
				for vserver in vsys.vservers:
					# skip servers we've already seen, i.e. firewalls and loadbalancers
					if vserver.vserverId in seenId:
						continue
					todo.append(vserver)
			setattr(vsys, 'vservers', todo)
			if not hasattr(vsys, 'vdisks'):
				setattr(vsys, 'vdisks', [])
			if not hasattr(vsys, 'publicips'):
				setattr(vsys, 'publicips', [])
			inventory['vsys'][vsys.vsysName] = vsys
			# TODO: transform vsys ?
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
		for name, vsys in inventory['vsys'].iteritems():
			# get status of vsys overall
			status = self.GetVSYSStatus(vsys.vsysId)
			self.show_output('VSYS:%s:%s' % (vsys.vsysName, status))
			setattr(new_inventory['vsys'][name], 'vsysStatus', status)
			# get status of public ips
			new_publicips = []
			for publicip in vsys.publicips:
				status = self.GetPublicIPStatus(publicip.address)
				self.show_output('PublicIP:%s:%s' % (publicip.address, status))
				setattr(publicip, 'publicipStatus', status)
				new_publicips.append(publicip)
			setattr(new_inventory['vsys'][name], 'publicips', new_publicips)
			# get status of firewalls
			new_firewalls = []
			for firewall in vsys.firewalls:
				status = self.GetEFMStatus(vsys.vsysId, firewall.efmId)
				self.show_output('EFM FW:%s:%s' % (firewall.efmName, status))
				setattr(firewall, 'efmStatus', status)
				new_firewalls.append(firewall)
			setattr(new_inventory['vsys'][name], 'firewalls', new_firewalls)
			# get status of loadbalancers
			new_loadbalancers = []
			for loadbalancer in vsys.loadbalancers:
				status = self.GetEFMStatus(vsys.vsysId, loadbalancer.efmId)
				self.show_output('EFM SLB:%s:%s:%s' % (loadbalancer.efmName, loadbalancer.slbVip, status))
				setattr(loadbalancer, 'efmStatus', status)
				new_loadbalancers.append(loadbalancer)
			setattr(new_inventory['vsys'][name], 'loadbalancers', new_loadbalancers)
			# get status of vservers (excl. firewalls and loadbalancers)
			new_vservers = []
			seenId = {}
			for vserver in vsys.vservers:
				status = self.GetVServerStatus(vsys.vsysId, vserver.vserverId)
				self.show_output('VServer:%s:%s:%s' % (vserver.vserverName, vserver.vnics[0].privateIp, status))
				setattr(vserver, 'vserverStatus', status)
				# get status of attached disks
				new_vdisks = []
				for vdisk in vserver.vdisks:
					status = self.GetVDiskStatus(vsys.vsysId, vdisk.vdiskId)
					self.show_output(':VDisk:%s:%s' % (vdisk.vdiskName, status))
					seenId[vdisk.vdiskId] = 1
					setattr(vdisk, 'vdiskStatus', status)
					new_vdisks.append(vdisk)
				vserver.vdisks = new_vdisks
				new_vservers.append(vserver)
			setattr(new_inventory['vsys'][name], 'vservers', new_vservers)
			# get status of unattached disks
			todo = []
			new_vdisks = []
			for vdisk in vsys.vdisks:
				# skip disks we've already seen, i.e. attached to a server
				if vdisk.vdiskId in seenId:
					new_vdisks.append(vdisk)
					continue
				todo.append(vdisk)
			if len(todo) > 0:
				self.show_output('Unattached Disks')
				for vdisk in todo:
					status = self.GetVDiskStatus(vsys.vsysId, vdisk.vdiskId)
					self.show_output(':VDisk:%s:%s' % (vdisk.vdiskName, status))
					seenId[vdisk.vdiskId] = 1
					setattr(vdisk, 'vdiskStatus', status)
					new_vdisks.append(vdisk)
			setattr(new_inventory['vsys'][name], 'vdisks', new_vdisks)
			self.show_output('.')
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
			raise FGCPClientError('ILLEGAL_METHOD', 'Invalid method %s for checking status' % status_method)
		check_status = getattr(self, status_method, None)
		if not callable(check_status):
			raise FGCPClientError('ILLEGAL_METHOD', 'Invalid method %s for checking status' % status_method)
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
			raise FGCPClientError('ILLEGAL_STATE', 'Invalid status %s for %s' % (status, status_method))

	def wait_for_status(self, done_status, wait_status, status_method, *args):
		"""
		Call status_method(*args) repeatedly until we get done_status (or something else than wait_status)
		"""
		if not hasattr(self, status_method):
			raise FGCPClientError('ILLEGAL_METHOD', 'Invalid method %s for checking status' % status_method)
		check_status = getattr(self, status_method, None)
		if not callable(check_status):
			raise FGCPClientError('ILLEGAL_METHOD', 'Invalid method %s for checking status' % status_method)
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
				raise FGCPClientError('ILLEGAL_STATE', '%s returned unexpected status %s while %s' % (status_method, status, wait_status))
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
		vserver = self.GetVServerConfiguration(vsysId, vserverId)
		todo = []
		# the system disk has the same id as the server
		todo.append(vserver.vserverId)
		if vserver.vdisks != '':
			# add other disks if necessary
			for vdisk in vserver.vdisks:
				todo.append(vdisk.vdiskId)
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
				todo.append(vdisk.vdiskId)
		else:
			todo.append(vdiskId)
		for vdiskId in todo:
			backups = self.ListVDiskBackup(vsysId, vdiskId)
			if len(backups) > 10:
				# Sort list of dictionaries: http://stackoverflow.com/questions/652291/sorting-a-list-of-dictionary-values-by-date-in-python
				#from operator import itemgetter
				#backups.sort(key=itemgetter('timeval'), reverse=True)
				# Sort list of objects: http://stackoverflow.com/questions/2338531/python-sorting-a-list-of-objects
				from operator import attrgetter
				backups.sort(key=attrgetter('timeval'), reverse=True)
				# TODO: remove oldest backup(s) ?
				backup = backups.pop()
				#client.DestroyVDiskBackup(vsysId, backup['backupId'])

	def StartSystem(self, vsysName, verbose=None):
		"""
		Start VSYS and wait until all VServers and EFMs are started (TODO: define start sequence for vservers)
		"""
		# Get inventory of the vsys
		vsys = self.GetSystemInventory(vsysName)
		# Set output
		old_verbose = self.set_verbose(verbose)
		self.show_output('Starting VSYS %s' % vsysName)
		# CHECKME: start firewall if necessary
		self.show_output('Start Firewalls')
		for firewall in vsys.firewalls:
			self.StartEFMAndWait(vsys.vsysId, firewall.efmId)
		# CHECKME: attach publicip if necessary
		self.show_output('Attach PublicIPs')
		for publicip in vsys.publicips:
			self.AttachPublicIPAndWait(vsys.vsysId, publicip.address)
		# CHECKME: start loadbalancers if necessary
		self.show_output('Start Loadbalancers')
		for loadbalancer in vsys.loadbalancers:
			self.StartEFMAndWait(vsys.vsysId, loadbalancer.efmId)
		# CHECKME: start servers if necessary
		self.show_output('Start VServers')
		for vserver in vsys.vservers:
			self.StartVServerAndWait(vsys.vsysId, vserver.vserverId)
		self.show_output('Started VSYS %s' % vsysName)
		# Reset output
		self.set_verbose(old_verbose)

	def StopSystem(self, vsysName, verbose=None):
		"""
		Stop VSYS and wait until all VServers and EFMs are stopped (TODO: define stop sequence for vservers)
		"""
		# Get system inventory
		vsys = self.GetSystemInventory(vsysName)
		# Set output
		old_verbose = self.set_verbose(verbose)
		self.show_output('Stopping VSYS %s' % vsysName)
		# Stop all vservers
		self.show_output('Stop VServers')
		for vserver in vsys.vservers:
			self.show_output(vserver.vserverName)
			status = self.StopVServerAndWait(vsys.vsysId, vserver.vserverId)
		# Stop all loadbalancers
		self.show_output('Stop Loadbalancers')
		for loadbalancer in vsys.loadbalancers:
			self.show_output(loadbalancer.efmName)
			status = self.StopEFMAndWait(vsys.vsysId, loadbalancer.efmId)
		# Detach publicip - cfr. sequence3 in java sdk
		self.show_output('Detach PublicIPs')
		for publicip in vsys.publicips:
			self.show_output(publicip.address)
			status = self.DetachPublicIPAndWait(vsys.vsysId, publicip.address)
		# Stop all firewalls
		self.show_output('Stop Firewalls')
		for firewall in vsys.firewalls:
			self.show_output(firewall.efmName)
			status = self.StopEFMAndWait(vsys.vsysId, firewall.efmId)
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
		#diskimages = self.ListDiskImage('GENERAL', vsys.baseDescriptor)
		diskimages = self.ListDiskImage()
		if len(diskimages) < 1:
			raise FGCPClientError('RESOURCE_NOT_FOUND', 'No diskimages are defined')
		for diskimage in diskimages:
			if diskimageName == diskimage.diskimageName:
				return diskimage
		raise FGCPClientError('ILLEGAL_NAME', 'Invalid diskimageName')

	def FindVSYSDescriptorByName(self, vsysdescriptorName):
		"""
		Find VSYSDescriptor by vsysdescriptorName
		"""
		vsysdescriptors = self.ListVSYSDescriptor()
		if len(vsysdescriptors) < 1:
			raise FGCPClientError('RESOURCE_NOT_FOUND', 'No vsysdescriptors are defined')
		for vsysdescriptor in vsysdescriptors:
			if vsysdescriptorName == vsysdescriptor.vsysdescriptorName:
				return vsysdescriptor
		raise FGCPClientError('ILLEGAL_NAME', 'Invalid vsysdescriptorName')

	def FindServerTypeByName(self, name):
		"""
		Find ServerType by name - CHECKME: do we actually need this for CreateVServer() ?
		"""
		return name
		# CHECKME: do all diskimages have the same servertypes (for now) ?
		# pick some random diskimage to get its servertypes ?
		diskimage = self.ListDiskImage().pop()
		servertypes = self.ListServerType(diskimage.diskimageId)
		if len(servertypes) < 1:
			raise FGCPClientError('RESOURCE_NOT_FOUND', 'No servertypes are defined')
		for servertype in servertypes:
			if name == servertype.name:
				return servertype
		raise FGCPClientError('ILLEGAL_NAME', 'Invalid servertype name')

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
		except FGCPClientError:
			vsysdescriptor = self.FindVSYSDescriptorByName(vsysdescriptorName)
			vsysId = self.CreateVSYS(vsysdescriptor.vsysdescriptorId, vsysName)
			self.show_output('Created VSYS %s: %s' % (vsysName, vsysId))
			# wait until vsys deploying is done - TODO: add some timeout
			self.wait_for_status('NORMAL', 'DEPLOYING', 'GetVSYSStatus', vsysId)
			self.show_output('Deployed VSYS %s: %s' % (vsysName, vsysId))
			pass
		else:
			vsysId = vsys.vsysId
			self.show_output('Existing VSYS %s: %s' % (vsysName, vsysId))
		# Reset output
		self.set_verbose(old_verbose)
		return vsysId

	def ConfigureSystem(self, vsysName, systemDesign, verbose=None):
		"""
		TODO: Configure VSYS based on some systemDesign - see LoadSystemDesign()
		"""
		print 'TODO: Configure VSYS based on some vsysDesign - see LoadSystemDesign()'
		return
		# Get inventory of the vsys
		vsys = self.GetSystemInventory(vsysName)
		# Set output
		old_verbose = self.set_verbose(verbose)
		self.show_output('Configuring VSYS %s' % vsysName)
		# CHECKME: start firewall if necessary
		if len(vsys.firewalls) > 0:
			self.show_output('Start Firewalls')
			for firewall in vsys.firewalls:
				self.StartEFMAndWait(vsys.vsysId, firewall.efmId)
		# CHECKME: allocate publicip if necessary
		if len(vsys.publicips) < 1:
			self.show_output('Allocate PublicIP')
			self.AllocatePublicIP(vsys.vsysId)
			# CHECKME: we need to wait a bit before retrieving the new list !
			time.sleep(30)
			# update list of publicips
			vsys.publicips = self.ListPublicIP(vsys.vsysId)
			if len(vsys.publicips) > 0:
				publicip = vsys.publicips[0]
				# wait until publicip deploying is done - TODO: add some timeout
				self.wait_for_status(['DETACHED', 'ATTACHED'], 'DEPLOYING', 'GetPublicIPStatus', publicip.address)
		# CHECKME: attach publicip if necessary
		self.show_output('Attach PublicIPs')
		for publicip in vsys.publicips:
			self.AttachPublicIPAndWait(vsys.vsysId, publicip.address)

		# TODO: add vserver etc. based on configuration
		if len(vsys.vservers) < len(vsys.vnets):
			diskimage = self.FindDiskImageByName('CentOS 5.4 32bit(EN)')
			print diskimage.diskimageName
			# CHECKME: do we actually need this for CreateVServer ?
			servertype = self.FindServerTypeByName('economy')
			print servertype
			# TODO CreateVServer
			self.show_output('Create VServers')
			idx = 1
			for vnetId in vsys.vnets:
				print vnetId
				# CHECKME: add vservers to the network zone
				vserverId = self.CreateVServer(vsys.vsysId, 'Server%s' % idx, 'economy', diskimage.diskimageId, vnetId)
				# wait until vserver deploying is done - TODO: add some timeout
				status = self.wait_for_status('STOPPED', 'DEPLOYING', 'GetVServerStatus', vsys.vsysId, vserverId)
				idx += 1
				vserverId = self.CreateVServer(vsys.vsysId, 'Server%s' % idx, 'economy', diskimage.diskimageId, vnetId)
				# wait until vserver deploying is done - TODO: add some timeout
				status = self.wait_for_status('STOPPED', 'DEPLOYING', 'GetVServerStatus', vsys.vsysId, vserverId)
				idx += 1
				# CHECKME: add loadbalancer to the DMZ
				if vnetId.endswith('-DMZ') and len(vsys.loadbalancers) < 1:
					self.show_output('Create Loadbalancer')
					efmId = self.CreateEFM(vsys.vsysId, 'SLB', 'LoadBalancer', vnetId)
					# wait until efm deploying is done - TODO: add some timeout
					self.wait_for_status('STOPPED', 'DEPLOYING', 'GetEFMStatus', vsys.vsysId, efmId)
					# update list of loadbalancers
					vsys.loadbalancers = self.ListEFM(vsys.vsysId, "SLB")
		self.show_output('Configured VSYS %s' % vsysName)
		# Reset output
		self.set_verbose(old_verbose)

	def DestroySystem(self, vsysName, verbose=None):
		"""
		Destroy VSYS after stopping all VServers and EFMs
		"""
		# Get system inventory
		vsys = self.GetSystemInventory(vsysName)
		# Set output
		old_verbose = self.set_verbose(verbose)
		self.show_output('Destroying VSYS %s' % vsysName)
		# CHECKME: should we stop the VSYS here ?
		# Destroy the VSYS
		result = self.DestroyVSYS(vsys.vsysId)
		self.show_output(result)
		# TODO: wait until it's really gone ?
		self.show_output('Destroyed VSYS %s' % vsysName)
		# Reset output
		self.set_verbose(old_verbose)

	def SaveSystemDesign(self, vsysName, filePath):
		"""
		TODO: Save (fixed parts of) VSYS design to file
		"""
		# Get system inventory
		vsys = self.GetSystemInventory(vsysName)
		self.show_output('Saving VSYS design for %s to file %s' % (vsysName, filePath))
		# CHECKME: is description always the name correspoding to baseDescriptor ?
		seenip = {}
		# Replace addresses and other variable information
		idx = 1
		#new_publicips = []
		for publicip in vsys.publicips:
			seenip[publicip.address] = 'publicip.%s' % idx
			idx += 1
			#publicip.address = 'xxx.xxx.xxx.xxx'
			#new_publicips.append(publicip)
		#vsys.publicips = new_publicips
		from fgcp.resource import FGCPFirewall
		new_firewalls = []
		for firewall in vsys.firewalls:
			# TODO: Add FW and SLB configurations
			setattr(firewall, 'firewall', FGCPFirewall())
			setattr(firewall.firewall, 'nat', self.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_nat_rule())
			setattr(firewall.firewall, 'dns', self.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_dns())
			setattr(firewall.firewall, 'directions', self.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_policy())
			new_firewalls.append(firewall)
		vsys.firewalls = new_firewalls
		new_loadbalancers = []
		for loadbalancer in vsys.loadbalancers:
			seenip[loadbalancer.slbVip] = loadbalancer.efmName
			#loadbalancer.slbVip = 'xxx.xxx.xxx.xxx'
			# TODO: Add FW and SLB configurations
			setattr(loadbalancer, 'loadbalancer', self.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_rule())
			new_loadbalancers.append(loadbalancer)
		vsys.loadbalancers = new_loadbalancers
		# Get mapping of diskimage id to name
		diskimages = self.ListDiskImage()
		imageid2name = {}
		for diskimage in diskimages:
			imageid2name[diskimage.diskimageId] = diskimage.diskimageName
		new_vservers = []
		for vserver in vsys.vservers:
			# CHECKME: use diskimage name as reference across regions !?
			setattr(vserver, 'diskimageName', imageid2name[vserver.diskimageId])
			#new_vnics = []
			for vnic in vserver.vnics:
				seenip[vnic.privateIp] = vserver.vserverName
				#vnic.privateIp = 'xxx.xxx.xxx.xxx'
				#new_vnics.append(vnic)
			#vserver.vnics = new_vnics
			#new_vdisks = []
			#for vdisk in vserver.vdisks:
			#	new_vdisks.append(vdisk)
			#vserver.vdisks = new_vdisks
			new_vservers.append(vserver)
		vsys.vservers = new_vservers
		#new_vdisks = []
		#for vdisk in vsys.vdisks:
		#	new_vdisks.append(vdisk)
		#vsys.vdisks = new_vdisks
		# Prepare for output - FGCPElement().pformat() writes objects initialized with the right values
		lines = vsys.pformat(vsys)
		# Replace vsysId and creator everywhere (including Id's)
		lines = lines.replace(vsys.vsysId, 'DEMO-VSYS')
		lines = lines.replace(vsys.creator, 'DEMO')
		# CHECKME: replace ip addresses with names everywhere, including firewall policies and loadbalancer rules
		for ip in seenip.keys():
			lines = lines.replace(ip, seenip[ip])
		# CHECKME: fix from=... issue for firewall policies
		lines = lines.replace('from=', 'from_zone=')
		lines = lines.replace('to=', 'to_zone=')
		# Write configuration to file
		f = open(filePath, 'wb')
		f.write(lines)
		f.close()
		self.show_output('Saved VSYS design for %s to file %s' % (vsysName, filePath))

	def LoadSystemDesign(self, filePath):
		"""
		Load VSYS design from file, for use e.g. in ConfigureSystem()
		"""
		self.show_output('Loading VSYS design from file %s' % filePath)
		import os.path
		if not os.path.exists(filePath):
			self.show_output('File %s does not seem to exist' % filePath)
			return
		f = open(filePath, 'r')
		lines = f.read()
		f.close()
		# Check if we have something we need, i.e. a FGCPSys() instance
		if not lines.startswith('FGCPVSystem('):
			self.show_output('File %s does not seem to start with FGCPSystem(' % filePath)
			return
		# CHECKME: add line continuations before exec() !?
		try:
			# See above - FGCPElement().pformat() writes objects initialized with the right values
			exec 'vsys = ' + lines.replace("\r\n","\\\r\n")
		except:
			self.show_output('File %s seems to have some syntax errors' % filePath)
			raise
		self.show_output('Loaded VSYS design for %s from file %s' % (vsys.vsysName, filePath))
		try:
			found = self.FindSystemByName(vsys.vsysName)
			self.show_output('Caution: you already have a VSYS called %s' % vsys.vsysName)
		except FGCPClientError:
			pass
		# Return system inventory
		return vsys

class FGCPClient(FGCPDesigner):
	"""
	FGCP Client Methods
	
	Example:
	# Get FGCP client with your certificate in region 'uk'
	from fgcp.client import FGCPClient
	client = FGCPClient('client.pem', 'uk')

	# Backup all VServers in some VSYS
	vsys = client.GetSystemInventory('Python API Demo System')
	for vserver in vsys.vservers:
		client.BackupVServerAndRestart(vsys.vsysId, vserver.vserverId)
	client.CleanupBackups(vsys.vsysId)

	# Note: you can also use all API commands from FGCPCommand()
	vsystems = client.ListVSYS()
	for vsys in vsystems:
		vsysconfig = client.GetVSYSConfiguration(vsys.vsysId)
		...
	"""
	pass
