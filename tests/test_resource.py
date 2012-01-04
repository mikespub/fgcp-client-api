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
    verbose = 1     # 1 = show any user output the library might generate (nothing much except vsystem.show_status())
    debug = 0       # 1 = show the API commands being sent, 2 = dump the response objects (99 = save test fixtures)

    from fgcp.resource import FGCPVDataCenter
    vdc = FGCPVDataCenter(key_file, region, verbose, debug)

    test_vdatacenter(vdc)


def test_vdatacenter(vdc):
    """
    FGCP VDataCenter
    """
    #from fgcp.resource import FGCPVDataCenter
    #vdc = FGCPVDataCenter(key_file, region)

    vdc.show_output('Test: %s' % vdc)
    status = vdc.status()
    #vdc.show_vsystem_status()

    date, usagelist = vdc.get_vsystem_usage(vsysNames=None)
    #vdc.show_vsystem_usage(vsysNames=None)

    vsystems = vdc.list_vsystems()
    #vsystem = vdc.get_vsystem('Python API Demo System')
    vsystem = vdc.get_vsystem('Demo System')
    test_vsystem(vsystem)

    #vsysId = vdc.create_vsystem('Python API Demo System', '2-tier Skeleton', wait=True)
    #result = vdc.destroy_vsystem('Python API Demo System', wait=True)

    publicips = vdc.list_publicips()
    publicip = vdc.get_publicip(publicips[0].address)
    test_publicip(publicip)

    addressranges = vdc.list_addressranges()
    #result = vdc.create_addresspool(pipFrom=None, pipTo=None)
    #result = vdc.add_addressrange(pipFrom, pipTo)
    #result = vdc.delete_addressrange(pipFrom, pipTo)

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

    design = vdc.get_vsystem_design('Demo System')
    test_design(design)


def test_vsystem(vsystem):
    """
    FGCP VSystem
    """
    vsystem.show_output('Test: %s' % vsystem)
    #vsystem = vdc.get_vsystem('Python API Demo System')

    status = vsystem.status()

    date, usage = vsystem.get_usage()

    info = vsystem.get_status()
    vsystem.show_status()

    #result = vsystem.start(wait=True)
    #result = vsystem.stop(wait=True, force=None)

    #result = vsystem.update(vsysName='New Demo System', cloudCategory='PUBLIC')

    inventory = vsystem.get_inventory()

    vservers = vsystem.list_vservers()
    for vserver in vsystem.vservers:
        pass
    #vserver = vsystem.get_vserver('Server1')
    vserver = vsystem.get_vserver('DB1')
    test_vserver(vserver)

    #vserverId = vsystem.create_vserver('My New Server', 'economy', 'CentOS 5.4 32bit(EN)', 'DMZ')
    #result = vsystem.start_vserver('My New Server', wait=True)
    #result = vsystem.stop_vserver('My New Server', wait=True)
    #result = vsystem.destroy_vserver('My New Server', wait=True)

    vdisks = vsystem.list_vdisks()
    for vdisk in vsystem.vdisks:
        pass
    vdisk = vsystem.get_vdisk('DISK1')
    test_vdisk(vdisk)
    #result = vsystem.create_vdisk('DISK2', size=1500, wait=True)
    #result = vsystem.attach_vdisk('DISK2', 'My New Server', wait=True)
    #result = vsystem.detach_vdisk('DISK2', 'My New Server', wait=True)
    #result = vsystem.destroy_vdisk('DISK2', wait=True)

    test_vserver_vdisk(vserver, vdisk)

    loadbalancers = vsystem.list_loadbalancers()
    for loadbalancer in vsystem.loadbalancers:
        pass
    loadbalancer = vsystem.get_loadbalancer('SLB1')
    test_loadbalancer(loadbalancer)
    #result = vsystem.create_loadbalancer('SLB2', 'DMZ', wait=True)

    firewalls = vsystem.list_firewalls()
    for firewall in vsystem.firewalls:
        pass
    firewall = vsystem.get_firewall('Firewall')
    test_firewall(firewall)

    publicips = vsystem.list_publicips()
    for publicip in vsystem.publicips:
        pass
    publicip = vsystem.get_publicip(publicips[0].address)
    test_publicip(publicip)
    #result = vsystem.allocate_publicip(wait=True)

    vnets = vsystem.list_vnets()
    for vnet in vsystem.vnets:
        pass

    console = vsystem.get_console_url(vnets[0])

    #vsystem.vsysName = 'Copy of %s' % vsystem.vsysName
    #result = vsystem.create()

    #result = vsystem.detroy(wait=True)


def test_vserver(vserver):
    """
    FGCP VServer
    """
    vserver.show_output('Test: %s' % vserver)
    status = vserver.status()

    #result = vserver.start(wait=True)
    #result = vserver.stop(wait=True, force=None)

    #result = vserver.update(vserverName='New Server', vserverType='economy')

    config = vserver.get_configuration()
    vdisks = vserver.list_vdisks()
    for vdisk in vdisks:
        test_vdisk(vdisk)
        break
    #result = vserver.attach_vdisk(vdisk)
    #result = vserver.detach_vdisk(vdisk)

    vnics = vserver.list_vnics()
    for vnic in vnics:
        test_vnic(vnic)
        break

    backups = vserver.list_backups(timeZone=None, countryCode=None)
    for backup in backups:
        test_backup(backup)
        break
    #result = vserver.backup(wait=True)

    initialpwd = vserver.get_password()

    #vserver.vserverName = 'Copy of %s' % vserver.vserverName
    #result = vserver.create()

    #result = vserver.detroy(wait=True)


def test_vdisk(vdisk):
    """
    FGCP VDisk
    """
    vdisk.show_output('Test: %s' % vdisk)
    status = vdisk.status()

    backups = vdisk.list_backups(timeZone=None, countryCode=None)
    for backup in backups:
        test_backup(backup)
        break
    #result = vdisk.backup(wait=True)

    #result = vdisk.update(vdiskName='New Disk')

    #vdisk.vdiskName = 'Copy of %s' % vdisk.vdiskName
    #result = vdisk.create()

    #result = vdisk.detroy(wait=True)


def test_backup(backup):
    """
    FGCP Backup
    """
    backup.show_output('Test: %s' % backup)
    #backup.restore(wait=True)
    #backup.destroy()
    pass


def test_vserver_vdisk(vserver, vdisk):
    """
    FGCP VServer + FGCP VDisk Combination
    """
    vserver.show_output('Test: %s + %s' % (vserver, vdisk))
    #result = vdisk.attach(vserver)
    #result = vdisk.detach(vserver)
    pass


def test_vnic(vnic):
    """
    FGCP VNic
    """
    vnic.show_output('Test: %s' % vnic)
    pass


def test_firewall(firewall):
    """
    FGCP Firewall
    """
    firewall.show_output('Test: %s' % firewall)
    status = firewall.status()
    #result = firewall.start(wait=True)
    #result = firewall.stop(wait=True)

    #efmName = firewall.efmName
    #result = firewall.update(efmName=efmName)

    backups = firewall.list_backups(timeZone=None, countryCode=None)
    #result = firewall.backup(wait=True)

    nat_rules = firewall.get_nat_rules()
    #result = firewall.set_nat_rules(rules=nat_rules)

    dns = firewall.get_dns()
    #result = firewall.set_dns(dnstype='AUTO', primary=None, secondary=None)

    policies = firewall.get_policies(from_zone=None, to_zone=None)
    #result = firewall.set_policies(log='On', policies=policies)

    logs = firewall.get_log(num=10, orders=None)

    limit_policies = firewall.get_limit_policies(from_zone=None, to_zone=None)

    update_info = firewall.get_update_info()
    #result = firewall.apply_update()
    #result = firewall.revert_update()


def test_loadbalancer(loadbalancer):
    """
    FGCP LoadBalancer
    """
    loadbalancer.show_output('Test: %s' % loadbalancer)
    status = loadbalancer.status()

    #result = loadbalancer.start(wait=True)
    #result = loadbalancer.stop(wait=True)

    #efmName = loadbalancer.efmName
    #result = loadbalancer.update(efmName=efmName)

    backups = loadbalancer.list_backups(timeZone=None, countryCode=None)
    for backup in backups:
        test_backup(backup)
        break
    #result = loadbalancer.backup(wait=True)

    rules = loadbalancer.get_rules()
    #result = loadbalancer.set_rules(groups=rules.groups, force=None, webAccelerator=None)
    #vserver1 = vsystem.get_vserver('WebApp1')
    #vserver2 = vsystem.get_vserver('WebApp2')
    #loadbalancer.add_group(id=10, protocol='http', targets=[vserver1, vserver2])
    #loadbalancer.delete_group(id=20)

    load_stats = loadbalancer.get_load_stats()
    #result = loadbalancer.clear_load_stats()
    error_stats = loadbalancer.get_error_stats()
    #result = loadbalancer.clear_error_stats()

    servercerts = loadbalancer.list_servercerts(detail=None)
    #result = loadbalancer.add_cert(certNum=5, filePath="server.pfx", passphrase='changeit')
    #result = loadbalancer.set_cert(certNum=5, groupId=10)
    #result = loadbalancer.release_cert(certNum=10)
    #result = loadbalancer.delete_cert(certNum=10, force=None)
    ccacerts = loadbalancer.list_ccacerts(detail=None)
    #result = loadbalancer.add_cca(ccacertNum=101, filePath='cacert.crt')
    #result = loadbalancer.delete_cca(ccacertNum=101)
    cert_list = loadbalancer.get_cert_list(certCategory=None, detail=None)

    #result = loadbalancer.start_maintenance(groupId=10, ipAddress='192.168.0.13', time=None, unit=None)
    #result = loadbalancer.stop_maintenance(groupId=10, ipAddress='192.168.0.13')

    update_info = loadbalancer.get_update_info()
    #result = loadbalancer.apply_update()
    #result = loadbalancer.revert_update()


def test_publicip(publicip):
    """
    FGCP PublicIP
    """
    publicip.show_output('Test: %s' % publicip)
    status = publicip.status()
    #result = publicip.attach(wait=True)
    #result = publicip.detach(wait=True)
    #result = publicip.free(wait=True)


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
    vsysdescriptor.show_output('Test: %s' % vsysdescriptor)
    diskimages = vsysdescriptor.list_diskimages()
    #vsysId = vsysdescriptor.create_vsystem('Python API Demo System', wait=True)

    #vsysdescriptor.update(vsysdescriptorName='New VSYSDescriptor', description='This is a new vsysdescriptor', keyword='2-tier Skeleton')


def test_diskimage(diskimage):
    """
    FGCP DiskImage
    """
    diskimage.show_output('Test: %s' % diskimage)
    softwares = diskimage.list_softwares()
    servertypes = diskimage.list_servertypes()

    #diskimage.update(diskimageName='New Disk Image', description='This is a new disk image')


def test_servertype(servertype):
    """
    FGCP ServerType
    """
    servertype.show_output('Test: %s' % servertype)
    pass


def test_design(design):
    """
    FGCP VSystem Design
    """
    design.show_output('Test: %s' % design)
    #vsystem = design.load_file('fgcp_demo_system.txt')
    vsystem = design.load_vsystem('Demo System')
    #result = design.build_vsystem('My New VSystem')
    design.save_file('new_demo_system.txt')
    design.load_file('new_demo_system.txt')
    #design.save_file('new_demo_system.yaml', 'yaml')
    #design.load_file('new_demo_system.yaml')


if __name__ == "__main__":
    import os.path
    import sys
    parent = os.path.dirname(os.path.dirname(__file__))
    sys.path.append(parent)
    pem_file = 'client.pem'
    #region = 'de'
    region = 'test'
    #region = 'relay=http://localhost:8000/cgi-bin/fgcp_relay.py'
    fgcp_resource_walker(pem_file, region)
