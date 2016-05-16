#!/usr/bin/python
#
#  Copyright (C) 2011-2016 Michel Dalle
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
using XML-RPC API Version 2015-01-30

# Register FGCP as third party driver for libcloud
from libcloud.compute.providers import set_driver
from libcloud.compute.providers import get_driver
set_driver('fgcp',
           'fgcp.libcloud.compute',
           'FGCPNodeDriver')
cls = get_driver('fgcp')

# Connect with your client certificate to region 'uk' and work in location 'Demo VSystem'
driver = cls('client.pem', region='uk', location='Demo VSystem')

#regions = driver.list_regions()
#locations = driver.list_locations()
#nodes = driver.list_nodes()
#images = driver.list_images()
#sizes = driver.list_sizes()
#volumes = driver.list_volumes()
#for volume in volumes:
#    snapshots = driver.list_volume_snapshots(volume)
#    snapshots_and_backups = driver.list_volume_snapshots(volume, ex_include_backups=True)
#    backups = driver.ex_list_volume_backups(volume)


Requirements: this module uses tlslite.utils or gdata.tlslite.utils to create
the key signature, see https://pypi.python.org/pypi/tlslite-ng or
https://pypi.python.org/pypi/tlslite for download and installation

Note: to convert your .p12 or .pfx file to unencrypted PEM format, you can use
the following 'openssl' command:

openssl pkcs12 -in UserCert.p12 -out client.pem -nodes
"""
