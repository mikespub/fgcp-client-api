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
Test Client Methods - please check the source code of this file to see how the client methods can used

The client methods below are organized by client role, i.e. Monitor, Operator, Designer and Client.

Note: with version 1.0.x and later of the library, most of these client methods can now directly be
replaced by corresponding resource actions.
"""
from __future__ import print_function


def fgcp_client_walker(key_file, region):
    """
    Test client methods using test server (or generate .xml test fixtures using real API server)
    """

    #vsysName = 'Python API Demo System'
    vsysName = 'Demo System'

    debug = 0   # 1 = show the API commands being sent, 2 = dump the response objects (99 = save test fixtures)

    test_monitor(key_file, region, vsysName, debug)
    test_operator(key_file, region, vsysName, debug)
    test_designer(key_file, region, vsysName, debug)
    test_client(key_file, region, vsysName, debug)


def test_monitor(key_file, region, vsysName, debug):
    """
    FGCP Monitor
    """
    from fgcp.client import FGCPMonitor
    client = FGCPMonitor(key_file, region)

    print('\nUsing %s\n' % repr(client))

    client.debug = debug

    vsys = client.FindSystemByName(vsysName)
    vsys = client.GetSystemInventory(vsysName)
    vsys = client.GetSystemStatus(vsysName)
    client.ShowSystemStatus(vsysName, ':')


def test_operator(key_file, region, vsysName, debug):
    """
    FGCP Operator
    """
    from fgcp.client import FGCPOperator
    client = FGCPOperator(key_file, region)

    print('\nUsing %s\n' % repr(client))

    client.debug = debug

    result = client.StartSystem(vsysName, verbose=1)
    #result = client.StopSystem(vsysName, verbose=1)

    vsys = client.GetSystemInventory(vsysName)
    for vserver in vsys.vservers:
        #result = client.BackupVServerAndRestart(vsys.vsysId, vserver.vserverId)
        #result = client.StopVServerAndWait(vsys.vsysId, vserver.vserverId, force=None)
        for vdisk in vserver.vdisks:
            #result = client.BackupVDiskAndWait(vsys.vsysId, vdisk.vdiskId)
            pass
        #result = client.StartVServerAndWait(vsys.vsysId, vserver.vserverId)
    for publicip in vsys.publicips:
        #result = client.DetachPublicIPAndWait(vsys.vsysId, publicIp)
        #result = client.AttachPublicIPAndWait(vsys.vsysId, publicIp)
        pass
    for firewall in vsys.firewalls:
        #result = client.StopEFMAndWait(vsys.vsysId, firewall.efmId)
        #result = client.StartEFMAndWait(vsys.vsysId, firewall.efmId)
        pass
    for loadbalancer in vsys.loadbalancers:
        #result = client.StopEFMAndWait(vsys.vsysId, loadbalancer.efmId)
        #result = client.StartEFMAndWait(vsys.vsysId, loadbalancer.efmId)
        pass
    result = client.CleanupBackups(vsys.vsysId)


def test_designer(key_file, region, vsysName, debug):
    """
    FGCP Designer
    """
    from fgcp.client import FGCPDesigner
    client = FGCPDesigner(key_file, region)

    print('\nUsing %s\n' % repr(client))

    client.debug = debug
    client.verbose = 1

    vsysdescriptorName = '2-tier Skeleton'
    diskimageName = 'CentOS 5.4 32bit(EN)'
    servertypeName = 'economy'
    filePath = 'fgcp_demo_system.txt'

    vsysdescriptor = client.FindVSYSDescriptorByName(vsysdescriptorName)
    diskimage = client.FindDiskImageByName(diskimageName)
    servertype = client.FindServerTypeByName(servertypeName)
    #client.CreateSystem(vsysName, vsysdescriptorName, verbose=1)
    #vsysDesign = client.LoadSystemDesign(filePath, verbose=1)
    #client.ConfigureSystem(vsysName, vsysDesign, verbose=1)
    client.LoadSystemDesign(filePath)
    #client.SaveSystemDesign(vsysName, filePath)
    #client.StopSystem(vsysName, verbose=1)
    #client.DestroySystem(vsysName, verbose=1)


def test_client(key_file, region, vsysName, debug):
    """
    FGCP Client
    """
    from fgcp.client import FGCPClient
    client = FGCPClient(key_file, region)

    print('\nUsing %s\n' % repr(client))

    print('All of the above')


if __name__ == "__main__":
    import os.path
    import sys
    parent = os.path.dirname(os.path.dirname(__file__))
    sys.path.append(parent)
    pem_file = 'client.pem'
    #region = 'de'
    region = 'test'
    #region = 'relay=http://localhost:8000/cgi-bin/fgcp_relay.py'
    fgcp_client_walker(pem_file, region)
