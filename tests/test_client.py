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
Test Client Methods
"""

def fgcp_client_walker(key_file, region):
	"""
	Test client methods using test server (or generate .xml test fixtures using real API server)
	"""

	from fgcp.client import FGCPMonitor, FGCPOperator, FGCPDesigner, FGCPClient
	region = 'test'
	vsysName = 'Python API Demo System'
	
	#
	# Monitor
	#
	client = FGCPMonitor(key_file, region)
	client.debug = 0

	vsys = client.FindSystemByName(vsysName)
	vsys = client.GetSystemInventory(vsysName)
	vsys = client.GetSystemStatus(vsysName)
	client.ShowSystemStatus(vsysName)

	#
	# Operator
	#
	client = FGCPOperator(key_file, region)
	client.debug = 0
	vsys = client.GetSystemInventory(vsysName)
	client.StartSystem(vsysName, verbose=1)
	#client.StopSystem(vsysName, verbose=1) 
	for vserver in vsys.vservers:
		#client.BackupVServerAndRestart(vsys.vsysId, vserver.vserverId)
		#client.StopVServerAndWait(vsys.vsysId, vserver.vserverId, force=None)
		for vdisk in vserver.vdisks:
			#client.BackupVDiskAndWait(vsys.vsysId, vdisk.vdiskId)
			pass
		#client.StartVServerAndWait(vsys.vsysId, vserver.vserverId)
	client.CleanupBackups(vsys.vsysId)
	for publicip in vsys.publicips:
		#client.DetachPublicIPAndWait(vsys.vsysId, publicIp)
		#client.AttachPublicIPAndWait(vsys.vsysId, publicIp)
		pass
	for firewall in vsys.firewalls:
		#client.StopEFMAndWait(vsys.vsysId, firewall.efmId)
		#client.StartEFMAndWait(vsys.vsysId, firewall.efmId)
		pass
	for loadbalancer in vsys.loadbalancers:
		#client.StopEFMAndWait(vsys.vsysId, loadbalancer.efmId)
		#client.StartEFMAndWait(vsys.vsysId, loadbalancer.efmId)
		pass

	#
	# Designer
	#
	client = FGCPDesigner(key_file, region)
	client.debug = 0
	vsys = client.GetSystemInventory(vsysName)

	client.verbose = 1
	#client.FindVSYSDescriptorByName(vsysdescriptorName)
	#client.FindDiskImageByName(diskimageName)
	#client.FindServerTypeByName('economy')
	#client.CreateSystem(vsysName, vsysdescriptorName, verbose=1)
	#client.ConfigureSystem(vsysName, systemDesign, verbose=1)
	#client.DestroySystem(vsysName, verbose=1)
	#client.LoadSystemDesign(filePath)
	client.SaveSystemDesign(vsysName, 'test_demo_system.txt') 

	#
	# Client
	#
	client = FGCPClient(key_file, region)

	# all of the above

	return


if __name__ == "__main__":
	import sys, os.path
	parent = os.path.dirname(os.path.dirname(__file__))
	sys.path.append(parent)
	pem_file = 'client.pem'
	region = 'de'
	fgcp_client_walker(pem_file, region)
