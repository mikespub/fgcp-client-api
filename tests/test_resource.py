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
Test Resource Actions
"""

def fgcp_resource_walker(pem_file, region):
	"""
	Test resource actions using test server (or generate .xml test fixtures using real API server)
	"""
	print 'This is not done yet'
	return

	from fgcp.client import FGCPClient
	region = 'test'
	vsysName = 'Python API Demo System'
	
	#
	# VDataCenter
	#
 	client = FGCPClient(pem_file, region)
	client.debug = 0
	...

	#
	# VSys
	#

	vsystem.create()
	vsystem.retrieve()
	vsystem.update()
	vsystem.destroy()
	vsystem.status()
	
	vsystem.get_vservers()
	vsystem.get_vdisks()
	vsystem.get_publicips()
	vsystem.get_firewalls()
	vsystem.get_loadbalancers()
	vsystem.get_vnets()
	vsystem.get_console(self, vnet)
	...

	#
	# VServer
	#

	vserver.create()
	vserver.retrieve()
	vserver.update()
	vserver.destroy()
	vserver.status()
	
	vserver.start()
	vserver.stop(force=None)
	vserver.get_vdisks()
	vserver.attach(vdisk)
	vserver.detach(vdisk)
	vserver.get_vnics()
	vserver.password()
	...

	#
	# VDisk
	#

	vdisk.create()
	vdisk.retrieve()
	vdisk.update()
	vdisk.destroy()
	vdisk.status()
	...
	
	#
	# Firewall
	#

	firewall.create()
	firewall.retrieve()
	firewall.update()
	firewall.destroy()
	firewall.status()
	...
	
	#
	# LoadBalancer
	#

	loadbalancer.create()
	loadbalancer.retrieve()
	loadbalancer.update()
	loadbalancer.destroy()
	loadbalancer.status()
	...
	
	#
	# PublicIP
	#

	...

	#
	# AddressRange
	#

	...
	
	#
	# VSyDescriptor
	#

	...
	
	#
	# DiskImage
	#

	...
	
	#
	# ServerType
	#

	...
	return


if __name__ == "__main__":
	import sys, os.path
	parent = os.path.dirname(os.path.dirname(__file__))
	sys.path.append(parent)
	pem_file = 'client.pem'
	region = 'de'
	fgcp_resource_walker(pem_file, region)
