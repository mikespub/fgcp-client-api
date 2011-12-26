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

def fgcp_run_sample(pem_file, region):
	# Get FGCP client with your certificate in this region
	from fgcp.client import FGCPClient
	client = FGCPClient(pem_file, region)
	# Hint: set debug=1 to dump the FGCP Response for further development
	#client = FGCPClient(pem_file, region, debug=1)
	client.ShowSystemStatus()
	#
	# Backup all VServers in some VSYS
	#vsys = client.GetSystemInventory('Python API Demo System')
	#for vserver in vsys.vservers:
	#	client.BackupVServerAndRestart(vsys.vsysId, vserver.vserverId)
	#client.CleanupBackups(vsys.vsysId)
	#
	# Create and start a complete VSYS based on an existing configuration
	#client.set_verbose(2) # show output and status checks during script execution
	#vsysdesign = client.LoadSystemDesign('fgcp_demo_system.txt')
	#client.CreateSystem('Python API Demo System', vsysdesign.baseDescriptor)
	#client.ConfigureSystem('Python API Demo System', vsysdesign)
	#client.StartSystem('Python API Demo System')
	#
	# Stop and destroy a complete VSYS
	#client.StopSystem('Python API Demo System')
	#client.DestroySystem('Python API Demo System')
	#
	# Note: you can also use all API commands from FGCPCommand()
	#vsyss = client.ListVSYS()
	#for vsys in vsyss:
	#	vsysconfig = client.GetVSYSConfiguration(vsys.vsysId)
	#	...
	#vsysdescriptors = client.ListVSYSDescriptor()
	#for vsysdescriptor in vsysdescriptors:
	#	if vsysdescriptor.vsysdescriptorName == '2-tier Skeleton':
	#		vsysId = client.CreateVSYS(vsysdescriptor.vsysdescriptorId, 'Python API Demo System')
	#		print 'New VSYS Created: %s' % vsysId
	#		break
	exit()

def fgcp_show_usage(name='fgcp_demo.py'):
	print """Client API library for the Fujitsu Global Cloud Platform (FGCP)

Usage: %s [pem_file] [region]

from fgcp.client import FGCPClient
client = FGCPClient('client.pem', 'uk')
vsys = client.GetSystemInventory('Python API Demo System')
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
