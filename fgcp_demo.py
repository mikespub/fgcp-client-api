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
"""


def fgcp_run_sample(pem_file, region):
    # Connect with your client certificate to this region
    from fgcp.resource import FGCPVDataCenter
    vdc = FGCPVDataCenter(pem_file, region)

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
    import os.path
    import sys
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
