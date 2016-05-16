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

Requirements: this module uses tlslite.utils or gdata.tlslite.utils to create
the key signature, see https://pypi.python.org/pypi/tlslite-ng or
https://pypi.python.org/pypi/tlslite for download and installation
"""

def fgcp_via_libcloud():
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


def fgcp_run_sample(pem_file, region, private_key=None):
    # Connect with your client certificate to this region
    from fgcp.resource import FGCPVDataCenter
    vdc = FGCPVDataCenter(pem_file, region)

    # Set your private key for signatures if you use the relay server
    if region.startswith('relay') and private_key:
        vdc.getproxy().set_key(private_key)

    # Do typical actions on resources
    vsystem = vdc.get_vsystem('Demo System')
    vsystem.show_status()
    #for vserver in vsystem.vservers:
    #	result = vserver.backup(wait=True)
    #...
    # See tests/test_resource.py for more examples


def fgcp_show_usage(name='fgcp_demo.py'):
    print """Client API library for the Fujitsu Global Cloud Platform (FGCP)

Usage: %s [pem_file] [region]

# Connect with your client certificate to region 'uk'
from fgcp.resource import FGCPVDataCenter

# Do typical actions on resources
vdc = FGCPVDataCenter('client.pem', 'uk')
vsystem = vdc.get_vsystem('Demo System')
vsystem.show_status()
#for vserver in vsystem.vservers:
#	result = vserver.backup(wait=True)
#...
# See tests/test_resource.py for more examples

Requirements: this module uses tlslite.utils or gdata.tlslite.utils to create
the key signature, see https://pypi.python.org/pypi/tlslite-ng or
https://pypi.python.org/pypi/tlslite for download and installation

Note: to convert your .p12 or .pfx file to unencrypted PEM format, you can use
the following 'openssl' command:

openssl pkcs12 -in UserCert.p12 -out client.pem -nodes
""" % name


if __name__ == "__main__":
    """
    Check if we have an existing 'client.pem' file or command line argument specifying the PEM file,
    or get your private key from some configuration if you use the relay server
    """
    import os.path
    import sys
    pem_file = 'client.pem'
    #region = 'de'
    region = 'test'
    #region = 'relay=http://localhost:8000/cgi-bin/fgcp_relay.py'
    # Get your private key from somewhere if you use the relay server
    private_key = """
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
"""
    #private_key = open(pem_file).read()
    if len(sys.argv) > 1:
        pem_file = sys.argv[1]
        if len(sys.argv) > 2:
            region = sys.argv[2]
    if region.startswith('relay') and private_key:
        fgcp_run_sample(pem_file, region, private_key)
    elif os.path.exists(pem_file):
        fgcp_run_sample(pem_file, region)
    else:
        fgcp_show_usage(os.path.basename(sys.argv[0]))
