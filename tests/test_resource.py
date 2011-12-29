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


def fgcp_resource_walker(key_file, region):
    """
    Test resource actions using test server (or generate .xml test fixtures using real API server)
    """

    from fgcp.resource import FGCPVDataCenter
    region = 'test'
    vsysName = 'Python API Demo System'
    vsysName = 'Demo System'

    #
    # VDataCenter
    #
    vdc = FGCPVDataCenter(key_file, region, verbose=1, debug=1)

    vsystems = vdc.list_vsystems()
    print vdc.status()
    return
    """
    vsystems = vdc.list_vsystems()
    publicips = vdc.list_publicips()
    addressranges = vdc.list_addressranges()
    vsysdescriptors = vdc.list_vsysdescriptors()
    diskimages = vdc.list_diskimages()
    diskimages = vdc.list_diskimages(vsysdescriptors[0])
    servertypes = vdc.list_servertypes()
    servertypes = vdc.list_servertypes(diskimages[0])

    vsystem = vdc.get_vsystem('Python API Demo System')
    publicip = vdc.get_publicip(publicips[0].address)
    vsysdescriptor = vdc.get_vsysdescriptor('2-tier Skeleton')
    diskimage = vdc.get_diskimage('CentOS 5.4 32bit(EN)')
    servertype = vdc.get_servertype('economy')

    #vsysId = vdc.create_vsystem('Python API Demo System', '2-tier Skeleton', wait=None)
    #result = vdc.destroy_vsystem('Python API Demo System', wait=None)
    """

    #
    # VSystem
    #
    """
    vsystem = vdc.get_vsystem('Python API Demo System')

    status = vsystem.status()
    #result = vsystem.start(wait=None)
    #result = vsystem.stop(wait=None, force=None)

    inventory = vsystem.get_inventory()
    vservers = vsystem.list_vservers()
    vdisks = vsystem.list_vdisks()
    publicips = vsystem.list_publicips()
    firewalls = vsystem.list_firewalls()
    loadbalancers = vsystem.list_loadbalancers()
    vnets = vsystem.list_vnets()

    console = vsystem.get_console_url(vnets[0])

    vsystem.get_status()
    vsystem.show_status()

    """
    vsystem = vdc.get_vsystem(vsysName)
    vsystem.retrieve()
    vsystem.get_system_usage()
    return
    for vserver in vsystem.vservers:
        vserver.cleanup_backups()
    #for vdisk in vsystem.vdisks:
    #    vdisk.cleanup_backups()
    return
    #vsystem.show_status()
    for vserver in vsystem.vservers:
        if vserver.vserverStatus == 'RUNNING':
            continue
        #vserver.pprint()
        #vserver.backup(1)
        for backup in vserver.list_backups():
            backup.pprint()
    return

    """
    vsystem.create()
    vsystem.retrieve()
    vsystem.update()
    vsystem.destroy()
    vsystem.status()

    #
    # VServer
    #

    status = vserver.status()
    result = vserver.start(wait=None)
    result = vserver.stop(wait=None, force=None)

    config = vserver.get_configuration()
    vdisks = vserver.list_vdisks()
    result = vserver.attach(vdisk)
    result = vserver.detach(vdisk)
    vnics = vserver.list_vnics()

    backups = vserver.list_backups()
    result = vserver.backup(wait=None)

    initialpwd = vserver.password()

    #
    # VDisk
    #

    result = vdisk.attach(vserver)
    result = vdisk.detach(vserver)

    backups = vdisk.list_backups()
    result = vdisk.backup(wait=None)

    #
    # Firewall
    #

    status = firewall.status()
    result = firewall.start(wait=None)
    result = firewall.stop(wait=None)

    #
    # LoadBalancer
    #

    status = loadbalancer.status()
    result = loadbalancer.start(wait=None)
    result = loadbalancer.stop(wait=None)

    #
    # PublicIP
    #

    status = publicip.status()
    result = publicip.attach(wait=None)
    result = publicip.detach(wait=None)

    #
    # AddressRange
    #

    addressrange.pool(...)
    addressrange.add(...)
    addressrange.delete(...)

    #
    # VSyDescriptor
    #

    diskimages = vsysdescriptor.list_diskimages()
    #vsysId = vsysdescriptor.create_vsystem('Python API Demo System', wait=None)

    #
    # DiskImage
    #

    softwares = diskimage.list_softwares()
    servertypes = diskimage.list_servertypes()

    #
    # ServerType
    #

    return
    """


if __name__ == "__main__":
    import os.path
    import sys
    parent = os.path.dirname(os.path.dirname(__file__))
    sys.path.append(parent)
    pem_file = 'client.pem'
    region = 'de'
    fgcp_resource_walker(pem_file, region)
