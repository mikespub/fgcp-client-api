Client API library for the Fujitsu Global Cloud Platform (FGCP)
===============================================================
using XML-RPC API Version 2011-01-31

Using this library
------------------
If you already have access to the Fujitsu Global Cloud Platform (FGCP), have a look at the demo script::

	**Usage:** fgcp_demo.py [pem_file] [region]

If not, register on one of the Service Portals from the list below. Afterwards, you can access your resources
via command-line scripts, web interfaces etc. as you prefer.

.. code:: python

	# Get FGCP client with your certificate in region 'uk'
	from fgcp.client import FGCPClient
	client = FGCPClient('client.pem', 'uk')

	# Backup all VServers in some VSYS
	vsys = client.GetSystemInventory('Python API Demo System')
	for vserver in vsys.vservers:
			client.BackupVServerAndRestart(vsys.vsysId, vserver.vserverId)
	client.CleanupBackups(vsys.vsysId)

	# Note: you can also use all API commands from FGCPCommand()
	vsyss = client.ListVSYS()
	for vsys in vsyss:
			vsysconfig = client.GetVSYSConfiguration(vsys.vsysId)
			...

Note: this client API library provides higher-level Client Methods, intermediate Resource Actions and lower-level API Commands.

Fujitsu Global Cloud Platform (FGCP)
------------------------------------

.. image:: http://mikespub.net/fgcp_client_api.png

Service Portal:

* for Australia and New Zealand: http://globalcloud.fujitsu.com.au/
* for Central Europe (CEMEA&I): http://globalcloud.de.fujitsu.com/
* for Japan: http://oviss.jp.fujitsu.com/
* for Singapore, Malaysia, Indonesia, Thailand and Vietnam: http://globalcloud.sg.fujitsu.com/
* for the UK and Ireland: http://globalcloud.uk.fujitsu.com/
* for the Americas: http://globalcloud.us.fujitsu.com/

Requirements
------------
This module uses gdata.tlslite.utils to create the key signature, see http://code.google.com/p/gdata-python-client/ for download and installation

Note: to convert your .p12 or .pfx client certificate to unencrypted PEM format, you can use the following 'openssl' command::

	openssl pkcs12 -in UserCert.p12 -out client.pem -nodes

