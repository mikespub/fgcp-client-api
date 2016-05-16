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
Test FGCP via Libcloud - please check the source code of this file to see how libcloud can be used

The test functions are organised by class, i.e. NodeDriver, NodeImage, Node, VolumeStorage etc.
"""


def fgcp_libcloud_walker(key_file, region):
    """
    Test libcloud calls using test server (or generate .xml test fixtures using real API server)
    """
    verbose = 1     # 1 = show any user output the library might generate (nothing much)
    debug = 0       # 1 = show the API commands being sent, 2 = dump the response objects (99 = save test fixtures)

    from libcloud.compute.providers import set_driver
    from libcloud.compute.providers import get_driver
    set_driver('fgcp',
               'fgcp.libcloud.compute',
               'FGCPNodeDriver')
    cls = get_driver('fgcp')
    driver = cls(key_file, region=region)

    test_driver(driver)


def test_driver(driver):
    """
    FGCP NodeDriver
    """

    print 'Test: %s' % driver

    print 'Regions:'
    regions = driver.list_regions()
    print regions

    print 'Locations:'
    locations = driver.list_locations()
    for location in locations:
        print location
    test_location(location)

    # CHECKME: set driver location for vsystem calls
    driver.location = location.name

    print 'Images:'
    images = driver.list_images()
    for image in images:
        print image
    #image = driver.get_image('CentOS 5.4 32bit(EN)')
    test_image(image)

    print 'Sizes:'
    sizes = driver.list_sizes()
    for size in sizes:
        print size
    #size = driver.ex_get_size('economy')
    test_size(size)

    print 'Nodes:'
    nodes = driver.list_nodes()
    for node in nodes:
        print node
    #node = driver.ex_get_node_details('DB1')
    test_node(node)

    #nodeId = driver.create_node('My New Server', 'economy', 'CentOS 5.4 32bit(EN)', 'DMZ')
    #result = driver.start_node('My New Server', wait=True)
    #result = driver.stop_node('My New Server', wait=True)
    #result = driver.destroy_node('My New Server', wait=True)

    print 'Volumes:'
    volumes = driver.list_volumes()
    volumes_by_name = {}
    for volume in volumes:
        volumes_by_name[volume.name] = volume
        print volume
    volume = volumes_by_name['DISK1']
    test_volume(volume)
    #result = driver.create_volume('DISK2', size=1500, wait=True)
    #result = driver.attach_volume('DISK2', 'My New Server', wait=True)
    #result = driver.detach_volume('DISK2', 'My New Server', wait=True)
    #result = driver.destroy_volume('DISK2', wait=True)

    print 'Snapshots:' + ' (not in test fixtures)'
    #volume = volumes_by_name['WebApp2']
    #snapshots = driver.list_volume_snapshots(volume)
    #for snapshot in snapshots:
    #    print snapshot
    #test_snapshot(snapshot)

    print 'Backups:'
    volume = volumes_by_name['DB1']
    backups = driver.ex_list_volume_backups(volume)
    for backup in backups:
        print backup
    test_backup(backup)

    #test_node_volume(node, volume)

    """
    #vsysId = driver.create_location('Python API Demo System', '2-tier Skeleton', wait=True)
    #result = driver.destroy_location('Python API Demo System', wait=True)

    floating_ips = driver.ex_list_floating_ips()
    floating_ip = driver.get_floating_ip(floating_ips[0].address)
    test_floating_ip(floating_ip)
    #result = driver.allocate_floating_ip(wait=True)

    floating_ip_pools = driver.ex_list_floating_ip_pools()
    #result = driver.create_addresspool(pipFrom=None, pipTo=None)
    #result = driver.add_floating_ip_pool(pipFrom, pipTo)
    #result = driver.delete_floating_ip_pool(pipFrom, pipTo)

    loadbalancers = driver.list_loadbalancers()
    for loadbalancer in driver.loadbalancers:
        pass
    loadbalancer = driver.get_loadbalancer('SLB1')
    test_loadbalancer(loadbalancer)
    #result = driver.create_loadbalancer('SLB2', 'DMZ', wait=True)

    firewalls = driver.list_firewalls()
    for firewall in driver.firewalls:
        pass
    firewall = driver.get_firewall('Firewall')
    test_firewall(firewall)

    networks = driver.ex_list_networks()
    for network in networks:
        pass

    console = driver.get_console_url(networks[0])
    """


def test_location(location):
    """
    FGCP NodeLocation
    """
    print 'Test: %s' % location
    #location = driver.get_location('Python API Demo System')

    """
    status = location.status()

    date, usage = location.get_usage()

    info = location.get_status()
    location.show_status()

    #result = location.start(wait=True)
    #result = location.stop(wait=True, force=None)

    #result = location.update(vsysName='New Demo System', cloudCategory='PUBLIC')

    inventory = location.get_inventory()

    #location.vsysName = 'Copy of %s' % location.vsysName
    #result = location.create()

    #result = location.detroy(wait=True)
    """


def test_image(image):
    """
    FGCP NodeImage
    """
    print 'Test: %s' % image
    #softwares = image.list_softwares()
    #sizes = image.list_sizes()

    #image.update(imageName='New Disk Image', description='This is a new disk image')


def test_size(size):
    """
    FGCP NodeSize
    """
    print 'Test: %s' % size
    pass


def test_node(node):
    """
    FGCP Node
    """
    print 'Test: %s' % node
    #status = node.status()

    """
    #result = node.start(wait=True)
    #result = node.stop(wait=True, force=None)

    #result = node.update(nodeName='New Server', nodeType='economy')

    config = node.get_configuration()
    volumes = node.list_volumes()
    for volume in volumes:
        test_volume(volume)
        break
    #result = node.attach_volume(volume)
    #result = node.detach_volume(volume)

    vnics = node.list_vnics()
    for vnic in vnics:
        test_vnic(vnic)
        break

    backups = node.list_backups(timeZone=None, countryCode=None)
    for backup in backups:
        test_backup(backup)
        break
    #result = node.backup(wait=True)

    initialpwd = node.get_password()

    #node.nodeName = 'Copy of %s' % node.nodeName
    #result = node.create()

    #result = node.detroy(wait=True)
    """


def test_volume(volume):
    """
    FGCP StorageVolume
    """
    print 'Test: %s' % volume
    #status = volume.status()

    """
    backups = volume.list_backups(timeZone=None, countryCode=None)
    for backup in backups:
        test_backup(backup)
        break
    #result = volume.backup(wait=True)

    #result = volume.update(volumeName='New Disk')

    #volume.volumeName = 'Copy of %s' % volume.volumeName
    #result = volume.create()

    #result = volume.detroy(wait=True)
    """


def test_snapshot(snapshot):
    """
    FGCP VolumeSnapshot
    """
    print 'Test: %s' % snapshot
    #backup.restore(wait=True)
    #backup.destroy()
    pass


def test_backup(backup):
    """
    FGCP VolumeSnapshot (or BackupTargetJob)
    """
    print 'Test: %s' % backup
    #backup.restore(wait=True)
    #backup.destroy()
    pass


def test_node_volume(node, volume):
    """
    FGCP Node + FGCP StorageVolume Combination
    """
    print 'Test: %s + %s' % (node, volume)
    #result = volume.attach(node)
    #result = volume.detach(node)
    pass


def test_vnic(vnic):
    """
    FGCP VNic - TODO
    """
    print 'Test: %s' % vnic
    pass


def test_firewall(firewall):
    """
    FGCP Firewall - TODO
    """
    print 'Test: %s' % firewall
    #status = firewall.status()
    """
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
    """


def test_loadbalancer(loadbalancer):
    """
    FGCP LoadBalancer - TODO
    """
    print 'Test: %s' % loadbalancer
    #status = loadbalancer.status()
    """
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
    #node1 = location.get_node('WebApp1')
    #node2 = location.get_node('WebApp2')
    #loadbalancer.add_group(id=10, protocol='http', targets=[node1, node2])
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
    """


def test_floating_ip(floating_ip):
    """
    FGCP floating_ip - TODO
    """
    print 'Test: %s' % floating_ip
    #status = floating_ip.status()
    #result = floating_ip.attach(wait=True)
    #result = floating_ip.detach(wait=True)
    #result = floating_ip.free(wait=True)


def test_floating_ip_pool(floating_ip_pool):
    """
    FGCP floating_ip_pool - TODO
    """
    #floating_ip_pool.pool(...)
    #floating_ip_pool.add(...)
    #floating_ip_pool.delete(...)
    pass


if __name__ == "__main__":
    import os.path
    import sys
    parent = os.path.dirname(os.path.dirname(__file__))
    sys.path.append(parent)
    pem_file = 'client.pem'
    #region = 'de'
    region = 'test'
    #region = 'relay=http://localhost:8000/cgi-bin/fgcp_relay.py'
    fgcp_libcloud_walker(pem_file, region)
