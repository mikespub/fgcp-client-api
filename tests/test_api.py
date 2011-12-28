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
Test API Commands
"""

def fgcp_api_walker(pem_file, region):
	"""
	Test API commands using test server (or generate .xml test fixtures using real API server)
	"""

	#from fgcp.client import FGCPClient
	from fgcp.command import FGCPCommand
	region = 'test'

	#
	# Virtual Data Center (VDC)
	#
	#client = FGCPClient(pem_file, region)
	client = FGCPCommand(pem_file, region)
	client.debug = 1

	client.GetSystemUsage()
	
	#
	# Virtual System Descriptor (VSYSDescriptor)
	#
	vsysdescriptors = client.ListVSYSDescriptor()
	for vsysdescriptor in vsysdescriptors:
		#client.UnregisterPrivateVSYSDescriptor(vsysdescriptor.vsysdescriptorId)
		#client.UnregisterVSYSDescriptor(vsysdescriptor.vsysdescriptorId)
		client.GetVSYSDescriptorAttributes(vsysdescriptor.vsysdescriptorId)
		# only allowed on private vsysdescriptors
		#client.UpdateVSYSDescriptorAttribute(vsysdescriptor.vsysdescriptorId, 'en', 'updateName', vsysdescriptor.vsysdescriptorName)
		#client.UpdateVSYSDescriptorAttribute(vsysdescriptor.vsysdescriptorId, 'en', 'updateDescription', vsysdescriptor.description)
		#client.UpdateVSYSDescriptorAttribute(vsysdescriptor.vsysdescriptorId, 'en', 'updateKeyword', vsysdescriptor.keyword)
		client.GetVSYSDescriptorConfiguration(vsysdescriptor.vsysdescriptorId)

		#client.CreateVSYS(vsysdescriptor.vsysdescriptorId, vsysdescriptor.vsysdescriptorName)

		client.ListDiskImage('GENERAL', vsysdescriptor.vsysdescriptorId)
	
	#
	# Virtual System (VSYS)
	#
	vsystems = client.ListVSYS()
	for vsys in vsystems:
		#client.DestroyVSYS(vsys.vsysId)
		client.GetVSYSAttributes(vsys.vsysId)
		client.UpdateVSYSAttribute(vsys.vsysId, 'vsysName', vsys.vsysName)
		vsysconfig = client.GetVSYSConfiguration(vsys.vsysId)
		try:
			client.UpdateVSYSConfiguration(vsys.vsysId, 'CLOUD_CATEGORY', vsysconfig.cloudCategory)
		except:
			pass
		client.GetVSYSStatus(vsys.vsysId)

		#
		# Virtual Server (VServer)
		#
		#client.CreateVServer(vsys.vsysId, vserverName, vserverType, diskImageId, networkId)

		vservers = client.ListVServer(vsys.vsysId)
		for vserver in vservers:
			#client.StartVServer(vsys.vsysId, vserver.vserverId)
			#client.StopVServer(vsys.vsysId, vserver.vserverId, None)
			#client.DestroyVServer(vsys.vsysId, vserver.vserverId)
			client.GetVServerAttributes(vsys.vsysId, vserver.vserverId)
			client.UpdateVServerAttribute(vsys.vsysId, vserver.vserverId, 'vserverName', vserver.vserverName)
			try:
				client.UpdateVServerAttribute(vsys.vsysId, vserver.vserverId, 'vserverType', vserver.vserverType)
			except:
				pass
			vserver = client.GetVServerConfiguration(vsys.vsysId, vserver.vserverId)
			client.GetVServerInitialPassword(vsys.vsysId, vserver.vserverId)
			client.GetVServerStatus(vsys.vsysId, vserver.vserverId) 

			#
			# Virtual Disk (VDisk) attached to this server
			#
			for vdisk in vserver.vdisks:
				#client.AttachVDisk(vsys.vsysId, vserver.vserverId, vdisk.vdiskId)
				#client.DetachVDisk(vsys.vsysId, vserver.vserverId, vdisk.vdiskId)
				pass

			#
			# Virtual Network Interface (VNIC)
			#

			#client.RegisterPrivateDiskImage(vserver.vserverId, name, description)

		#client.RegisterPrivateVSYSDescriptor(vsys.vsysId, name, description, keyword, vservers)
		
		#
		# Virtual Disk (VDisk)
		#
		#client.CreateVDisk(vsys.vsysId, vdiskName, size)

		vdisks = client.ListVDisk(vsys.vsysId)
		for vdisk in vdisks:
			#client.DestroyVDisk(vsys.vsysId, vdisk.vdiskId)
			client.GetVDiskAttributes(vsys.vsysId, vdisk.vdiskId)
			#client.UpdateVDiskAttribute(vsys.vsysId, vdisk.vdiskId, 'vdiskName', vdisk.vdiskName)
			client.GetVDiskStatus(vsys.vsysId, vdisk.vdiskId)

			#client.BackupVDisk(vsys.vsysId, vdisk.vdiskId)

			backups = client.ListVDiskBackup(vsys.vsysId, vdisk.vdiskId)
			for backup in backups:
				#client.RestoreVDisk(vsys.vsysId, backup.backupId)
				#client.DestroyVDiskBackup(vsys.vsysId, backup.backupId)
				pass
	
		#
		# Public IP (PublicIP) for this vsys
		#
		#client.AllocatePublicIP(vsys.vsysId)

		publicips = client.ListPublicIP(vsys.vsysId)
		for publicip in publicips:
			#client.AttachPublicIP(vsys.vsysId, publicip.address)
			#client.DetachPublicIP(vsys.vsysId, publicip.address)
			#client.FreePublicIP(vsys.vsysId, publicip.address)
			client.GetPublicIPAttributes(publicip.address)
			client.GetPublicIPStatus(publicip.address) 

		#
		# Virtual Network (VNet)
		#
		#vsysconfig = client.GetVSYSConfiguration(vsys.vsysId)
		for networkId in vsysconfig.vnets:
			#
			# Other (SSL-VPN)
			#
			client.StandByConsole(vsys.vsysId, networkId) 
		
		#
		# Extended Function Module (EFM)
		#
		efmType = 'FW'
		#client.CreateEFM(vsys.vsysId, efmType, efmName, networkId)

		firewalls = client.ListEFM(vsys.vsysId, efmType)
		for firewall in firewalls:
			#client.StartEFM(vsys.vsysId, firewall.efmId)
			#client.StopEFM(vsys.vsysId, firewall.efmId)
			#client.DestroyEFM(vsys.vsysId, firewall.efmId)
			client.GetEFMAttributes(vsys.vsysId, firewall.efmId)
			#client.GetEFMConfigHandler(vsys.vsysId, firewall.efmId)
			#client.GetEFMConfiguration(vsys.vsysId, firewall.efmId, configurationName, configurationXML=None)
			client.UpdateEFMAttribute(vsys.vsysId, firewall.efmId, 'efmName', firewall.efmName)
			#client.UpdateEFMConfigHandler(vsys.vsysId, firewall.efmId)
			#client.UpdateEFMConfiguration(vsys.vsysId, firewall.efmId, configurationName, configurationXML=None, filePath=None)
			client.GetEFMStatus(vsys.vsysId, firewall.efmId)

			#client.BackupEFM(vsys.vsysId, firewall.efmId)
			backups = client.ListEFMBackup(vsys.vsysId, firewall.efmId, timeZone=None, countryCode=None)
			for backup in backups:
				#client.RestoreEFM(vsys.vsysId, firewall.efmId, backup.backupId)
				#client.DestroyEFMBackup(vsys.vsysId, firewall.efmId, backup.backupId)
				pass
			client.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).efm_update()
			#client.UpdateEFMConfigHandler(vsys.vsysId, firewall.efmId).efm_update()
			#client.UpdateEFMConfigHandler(vsys.vsysId, firewall.efmId).efm_backout() 

			#
			# EFM Firewall (FW)
			#
			client.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_nat_rule()
			#client.UpdateEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_nat_rule(rules=None)
			client.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_dns()
			#client.UpdateEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_dns(dnstype='AUTO', primary=None, secondary=None)
			client.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_policy(from_zone=None, to_zone=None)
			#client.UpdateEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_policy(log='On', directions=None)
			client.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_log(num=10, orders=None)
			client.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_limit_policy(from_zone=None, to_zone=None)
			client.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_update() 
	
		efmType = 'SLB'
		#client.CreateEFM(vsys.vsysId, efmType, efmName, networkId)

		loadbalancers = client.ListEFM(vsys.vsysId, efmType)
		for loadbalancer in loadbalancers:
			#client.StartEFM(vsys.vsysId, loadbalancer.efmId)
			#client.StopEFM(vsys.vsysId, loadbalancer.efmId)
			#client.DestroyEFM(vsys.vsysId, loadbalancer.efmId)
			client.GetEFMAttributes(vsys.vsysId, loadbalancer.efmId)
			#client.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId)
			#client.GetEFMConfiguration(vsys.vsysId, loadbalancer.efmId, configurationName, configurationXML=None)
			client.UpdateEFMAttribute(vsys.vsysId, loadbalancer.efmId, 'efmName', loadbalancer.efmName)
			#client.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId)
			#client.UpdateEFMConfiguration(vsys.vsysId, loadbalancer.efmId, configurationName, configurationXML=None, filePath=None)
			client.GetEFMStatus(vsys.vsysId, loadbalancer.efmId)

			#client.BackupEFM(vsys.vsysId, loadbalancer.efmId)
			backups = client.ListEFMBackup(vsys.vsysId, loadbalancer.efmId, timeZone=None, countryCode=None)
			for backup in backups:
				#client.RestoreEFM(vsys.vsysId, loadbalancer.efmId, backup.backupId)
				#client.DestroyEFMBackup(vsys.vsysId, loadbalancer.efmId, backup.backupId)
				pass
			client.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).efm_update()
			#client.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).efm_update()
			#client.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).efm_backout() 

			#
			# EFM Load Balancer (SLB)
			#
			try:
				client.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_rule()
			except:
				pass
			#client.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_rule(groups=None, force=None, webAccelerator=None)
			try:
				client.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_load()
			except:
				pass
			#client.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_load_clear()
			try:
				client.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_error()
			except:
				pass
			#client.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_error_clear()
			client.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_cert_list(certCategory=None, detail=None)
			#client.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_cert_add(certNum, filePath, passphrase)
			#client.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_cert_set(certNum, id)
			#client.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_cert_release(certNum)
			#client.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_cert_delete(certNum, force=None)
			#client.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_cca_add(ccacertNum, filePath)
			#client.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_cca_delete(ccacertNum)
			#client.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_start_maint(id, ipAddress, time=None, unit=None)
			#client.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_stop_maint(id, ipAddress)
			client.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_update() 
	
	#
	# Public IP (PublicIP) overall
	#
	publicips = client.ListPublicIP(None)
	
	#
	# Address Range (AddressRange)
	#
	client.GetAddressRange()
	#client.CreateAddressPool(pipFrom=None, pipTo=None)
	#client.AddAddressRange(pipFrom, pipTo)
	#client.DeleteAddressRange(pipFrom, pipTo) 
	
	#
	# Disk Image (DiskImage)
	#
	diskimages = client.ListDiskImage(serverCategory=None, vsysDescriptorId=None)
	for diskimage in diskimages:
		#client.UnregisterDiskImage(diskimage.diskimageId)
		client.GetDiskImageAttributes(diskimage.diskimageId)
		# only allowed on private diskimages
		#client.UpdateDiskImageAttribute(diskimage.diskimageId, 'en', 'updateName', diskimage.diskimageName) 
		#client.UpdateDiskImageAttribute(diskimage.diskimageId, 'en', 'updateDescription', diskimage.description) 
		#
		# Server Type (ServerType)
		#
		client.ListServerType(diskimage.diskimageId) 

	return


if __name__ == "__main__":
	import sys, os.path
	parent = os.path.dirname(os.path.dirname(__file__))
	sys.path.append(parent)
	pem_file = 'client.pem'
	region = 'de'
	fgcp_api_walker(pem_file, region)
