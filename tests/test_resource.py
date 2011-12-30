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
Test Resource Actions - please check the source code of this file to see how the resource actions can be used

The test functions are organised by resource class, i.e. VDataCenter, VSystem, VServer, VDisk etc.
"""


def fgcp_resource_walker(key_file, region):
    """
    Test resource actions using test server (or generate .xml test fixtures using real API server)
    """
    #region = 'test'
    verbose = 1     # 1 = show any user output the library might generate (nothing much except vsystem.show_status())
    debug = 1       # 1 = show the API commands being sent, 2 = dump the response objects (99 = save test fixtures)

    from fgcp.resource import FGCPVDataCenter
    vdc = FGCPVDataCenter(key_file, region, verbose, debug)

    test_vdatacenter(vdc)
    #test_in_progress(vdc)


def test_in_progress(vdc):
    vsystem = vdc.get_vsystem('Demo System')
    vsystem.create_vserver(vserverName='My New Server', servertype='economy', diskimage='CentOS 5.4 32bit(EN)', vnet='DMZ')
    exit()


def test_vdatacenter(vdc):
    """
    FGCP VDataCenter
    """
    #from fgcp.resource import FGCPVDataCenter
    #vdc = FGCPVDataCenter(key_file, region)

    status = vdc.status()

    usage = vdc.get_system_usage()

    vsystems = vdc.list_vsystems()
    #vsystem = vdc.get_vsystem('Python API Demo System')
    vsystem = vdc.get_vsystem('Demo System')
    #vsysId = vdc.create_vsystem('Python API Demo System', '2-tier Skeleton', wait=None)
    #result = vdc.destroy_vsystem('Python API Demo System', wait=None)
    test_vsystem(vsystem)

    publicips = vdc.list_publicips()
    publicip = vdc.get_publicip(publicips[0].address)
    test_publicip(publicip)

    addressranges = vdc.list_addressranges()
    #result = vdc.create_addresspool(pipFrom=None, pipTo=None)
    #result = vcd.add_addressrange(pipFrom, pipTo)
    #result = delete_addressrange(pipFrom, pipTo)

    vsysdescriptors = vdc.list_vsysdescriptors()
    vsysdescriptor = vdc.get_vsysdescriptor('2-tier Skeleton')
    test_vsysdescriptor(vsysdescriptor)

    diskimages = vdc.list_diskimages()
    diskimages = vdc.list_diskimages(vsysdescriptor)
    diskimage = vdc.get_diskimage('CentOS 5.4 32bit(EN)')
    test_diskimage(diskimage)

    servertypes = vdc.list_servertypes()
    servertypes = vdc.list_servertypes(diskimage)
    servertype = vdc.get_servertype('economy')
    test_servertype(servertype)


def test_vsystem(vsystem):
    """
    FGCP VSystem
    """
    #vsystem = vdc.get_vsystem('Python API Demo System')

    status = vsystem.status()

    usage = vsystem.get_system_usage()

    #result = vsystem.start(wait=None)
    #result = vsystem.stop(wait=None, force=None)

    inventory = vsystem.get_inventory()

    vservers = vsystem.list_vservers()
    for vserver in vsystem.vservers:
        pass
    #vserver = vsystem.get_vserver('Server1')
    vserver = vsystem.get_vserver('DB1')
    test_vserver(vserver)
    #vsystem.create_vserver(vserverName='My New Server', servertype='economy', diskimage='CentOS 5.4 32bit(EN)', vnet='DMZ')

    vdisks = vsystem.list_vdisks()
    for vdisk in vsystem.vdisks:
        pass
    vdisk = vsystem.get_vdisk('DISK1')
    test_vdisk(vdisk)

    test_vserver_vdisk(vserver, vdisk)

    publicips = vsystem.list_publicips()
    for publicip in vsystem.publicips:
        pass
    publicip = vsystem.get_publicip(publicips[0].address)
    test_publicip(publicip)

    firewalls = vsystem.list_firewalls()
    for firewall in vsystem.firewalls:
        pass
    firewall = vsystem.get_firewall('Firewall')
    test_firewall(firewall)

    loadbalancers = vsystem.list_loadbalancers()
    for loadbalancer in vsystem.loadbalancers:
        pass
    loadbalancer = vsystem.get_loadbalancer('SLB1')
    test_loadbalancer(loadbalancer)

    vnets = vsystem.list_vnets()
    for vnet in vsystem.vnets:
        pass

    console = vsystem.get_console_url(vnets[0])

    vsystem.get_status()
    vsystem.show_status()

    """
    vsystem.create()
    vsystem.retrieve()
    vsystem.update()
    vsystem.destroy()
    vsystem.status()
    """


def test_vserver(vserver):
    """
    FGCP VServer
    """
    status = vserver.status()
    #result = vserver.start(wait=None)
    #result = vserver.stop(wait=None, force=None)

    config = vserver.get_configuration()
    vdisks = vserver.list_vdisks()
    #result = vserver.attach(vdisk)
    #result = vserver.detach(vdisk)
    vnics = vserver.list_vnics()

    backups = vserver.list_backups()
    #result = vserver.backup(wait=None)

    initialpwd = vserver.get_password()


def test_vdisk(vdisk):
    """
    FGCP VDisk
    """
    backups = vdisk.list_backups()
    #result = vdisk.backup(wait=None)


def test_backup(backup):
    """
    FGCP Backup
    """
    pass


def test_vserver_vdisk(vserver, vdisk):
    """
    FGCP VServer + FGCP VDisk Combinations
    """
    #result = vdisk.attach(vserver)
    #result = vdisk.detach(vserver)


def test_firewall(firewall):
    """
    FGCP Firewall
    """
    status = firewall.status()
    #result = firewall.start(wait=None)
    #result = firewall.stop(wait=None)


def test_loadbalancer(loadbalancer):
    """
    FGCP LoadBalancer
    """
    status = loadbalancer.status()
    #result = loadbalancer.start(wait=None)
    #result = loadbalancer.stop(wait=None)


def test_publicip(publicip):
    """
    FGCP PublicIP
    """
    status = publicip.status()
    #result = publicip.attach(wait=None)
    #result = publicip.detach(wait=None)


def test_addressrange(addressrange):
    """
    FGCP AddressRange
    """
    #addressrange.pool(...)
    #addressrange.add(...)
    #addressrange.delete(...)
    pass


def test_vsysdescriptor(vsysdescriptor):
    """
    FGCP VSysDescriptor
    """
    diskimages = vsysdescriptor.list_diskimages()
    #vsysId = vsysdescriptor.create_vsystem('Python API Demo System', wait=None)


def test_diskimage(diskimage):
    """
    FGCP DiskImage
    """
    softwares = diskimage.list_softwares()
    servertypes = diskimage.list_servertypes()


def test_servertype(servertype):
    """
    FGCP ServerType
    """
    pass


if __name__ == "__main__":
    import os.path
    import sys
    parent = os.path.dirname(os.path.dirname(__file__))
    sys.path.append(parent)
    pem_file = 'client.pem'
    region = 'de'
    fgcp_resource_walker(pem_file, region)
