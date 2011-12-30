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
Test API Commands - please check the source code of this file to see how the API commands can be used

The test functions are organised by logical "resource type", i.e. general, vsys, vserver, vdisk etc.
"""


def fgcp_api_walker(key_file, region):
    """
    Test API commands using test server (or generate .xml test fixtures using real API server)
    """
    region = 'test'

    test_api_command(key_file, region)


def test_api_command(key_file, region):
    """
    FGCP Command
    """
    # we only need FGCPCommand here, but FGCPClient/FGCPDesigner/FGCPOperator/FGCPMonitor would work just as well
    #from fgcp.client import FGCPClient
    #client = FGCPClient(key_file, region)

    from fgcp.command import FGCPCommand
    client = FGCPCommand(key_file, region)

    client.verbose = 1  # 1 = show any user output the library might generate (nothing much)
    client.debug = 1    # 1 = show the API commands being sent, 2 = dump the response objects (99 = save test fixtures)

    date, usage = client.GetSystemUsage()
    #print 'Usage Report on %s' % date
    #for entry in usage:
    #    #entry.pprint()
    #    print
    #    print 'VSystem %s [%s]' % (entry.vsysName, entry.vsysId)
    #    for product in entry.products:
    #        print '  %s: %s %s' % (product.productName, product.usedPoints, product.unitName)

    vsystems = client.ListVSYS()
    for vsys in vsystems:
        test_vsys(client, vsys.vsysId)

    publicips = client.ListPublicIP(None)
    for publicip in publicips:
        test_publicip(client, publicip.address)

    test_addressrange(client)

    vsysdescriptors = client.ListVSYSDescriptor()
    for vsysdescriptor in vsysdescriptors:
        test_vsysdescriptor(client, vsysdescriptor.vsysdescriptorId)

    diskimages = client.ListDiskImage()
    for diskimage in diskimages:
        test_diskimage(client, diskimage.diskimageId)


def test_vsys(client, vsysId):
    """
    Virtual System (VSYS)
    """
    #result = client.DestroyVSYS(vsysId)

    vsys_attr = client.GetVSYSAttributes(vsysId)
    vsysName = vsys_attr.vsysName
    result = client.UpdateVSYSAttribute(vsysId, 'vsysName', vsysName)
    try:
        cloudCategory = vsys_attr.cloudCategory
        result = client.UpdateVSYSConfiguration(vsysId, 'CLOUD_CATEGORY', cloudCategory)
    except:
        pass

    status = client.GetVSYSStatus(vsysId)

    vservers = client.ListVServer(vsysId)
    for vserver in vservers:
        test_vsys_vserver(client, vsysId, vserver.vserverId)

    #result = client.CreateVDisk(vsysId, vdiskName, size)
    vdisks = client.ListVDisk(vsysId)
    for vdisk in vdisks:
        test_vsys_vdisk(client, vsysId, vdisk.vdiskId)

    #result = client.AllocatePublicIP(vsysId)
    publicips = client.ListPublicIP(vsysId)
    for publicip in publicips:
        test_vsys_publicip(client, vsysId, publicip.address)

    vsys_config = client.GetVSYSConfiguration(vsysId)
    for networkId in vsys_config.vnets:
        test_vsys_vnet(client, vsysId, networkId)

    efmType = 'FW'
    #result = client.CreateEFM(vsysId, efmType, efmName, networkId)
    firewalls = client.ListEFM(vsysId, efmType)
    for firewall in firewalls:
        test_vsys_efm_generic(client, vsysId, firewall.efmId)
        test_vsys_efm_firewall(client, vsysId, firewall.efmId)

    efmType = 'SLB'
    #result = client.CreateEFM(vsysId, efmType, efmName, networkId)
    loadbalancers = client.ListEFM(vsysId, efmType)
    for loadbalancer in loadbalancers:
        test_vsys_efm_generic(client, vsysId, loadbalancer.efmId)
        test_vsys_efm_loadbalancer(client, vsysId, loadbalancer.efmId)

    #result = client.CreateVServer(vsysId, vserverName, vserverType, diskImageId, networkId)

    # only allowed on private vsysdescriptors
    name = 'My New VSYS Template'
    description = 'This is a 3-tier web application database template'
    keyword = '3-tier web application database'
    vservers = client.ListVServer(vsysId)
    #result = client.RegisterPrivateVSYSDescriptor(vsysId, name, description, keyword, vservers)


def test_vsys_vserver(client, vsysId, vserverId):
    """
    Virtual Server (VServer)
    """
    #result = client.StartVServer(vsysId, vserverId)
    #result = client.StopVServer(vsysId, vserverId, force=None)
    #result = client.DestroyVServer(vsysId, vserverId)

    vserver_attr = client.GetVServerAttributes(vsysId, vserverId)
    vserverName = vserver_attr.vserverName
    result = client.UpdateVServerAttribute(vsysId, vserverId, 'vserverName', vserverName)
    try:
        vserverType = vserver_attr.vserverType
        result = client.UpdateVServerAttribute(vsysId, vserverId, 'vserverType', vserverType)
    except:
        pass

    status = client.GetVServerStatus(vsysId, vserverId)
    password = client.GetVServerInitialPassword(vsysId, vserverId)

    vserver_config = client.GetVServerConfiguration(vsysId, vserverId)

    for vdisk in vserver_config.vdisks:
        test_vsys_vserver_vdisk(client, vsysId, vserverId, vdisk.vdiskId)

    for vnic in vserver_config.vnics:
        test_vsys_vserver_vnic(client, vsysId, vserverId, vnic.networkId)

    #result = client.RegisterPrivateDiskImage(vserverId, name, description)


def test_vsys_vserver_vdisk(client, vsysId, vserverId, vdiskId):
    """
    Virtual Disk (VDisk) attached to this server
    """
    #result = client.AttachVDisk(vsysId, vserverId, vdiskId)
    #result = client.DetachVDisk(vsysId, vserverId, vdiskId)
    #test_vsys_vdisk(vsysId, vdiskId)
    pass


def test_vsys_vserver_vnic(client, vsysId, vserverId, networkId):
    """
    Virtual Network Interface (VNIC)
    """
    pass


def test_vsys_vdisk(client, vsysId, vdiskId):
    """
    Virtual Disk (VDisk)
    """
    #result = client.DestroyVDisk(vsysId, vdiskId)

    client.GetVDiskAttributes(vsysId, vdiskId)
    #result = client.UpdateVDiskAttribute(vsysId, vdiskId, 'vdiskName', vdisk.vdiskName)
    client.GetVDiskStatus(vsysId, vdiskId)

    #result = client.BackupVDisk(vsysId, vdiskId)
    backups = client.ListVDiskBackup(vsysId, vdiskId)
    for backup in backups:
        test_vsys_backup(client, vsysId, backup.backupId)


def test_vsys_backup(client, vsysId, backupId):
    """
    Virtual Disk (VDisk) Backup
    """
    #result = client.RestoreVDisk(vsysId, backupId)
    #result = client.DestroyVDiskBackup(vsysId, backupId)
    pass


def test_vsys_publicip(client, vsysId, publicipAddress):
    """
    Public IP (PublicIP) for this vsys
    """
    #result = client.AttachPublicIP(vsysId, publicipAddress)
    #result = client.DetachPublicIP(vsysId, publicipAddress)
    #result = client.FreePublicIP(vsysId, publicipAddress)
    #test_publicip(publicipAddress)


def test_vsys_vnet(client, vsysId, networkId):
    """
    Virtual Network (VNet)
    """
    test_vsys_vnet_console(client, vsysId, networkId)


def test_vsys_vnet_console(client, vsysId, networkId):
    """
    Other (SSL-VPN)
    """
    console_url = client.StandByConsole(vsysId, networkId)


def test_vsys_efm_generic(client, vsysId, efmId):
    """
    Extended Function Module (EFM) Generic
    """
    #result = client.StartEFM(vsysId, efmId)
    #result = client.StopEFM(vsysId, efmId)
    #result = client.DestroyEFM(vsysId, efmId)

    efm_attr = client.GetEFMAttributes(vsysId, efmId)
    efmName = efm_attr.efmName
    result = client.UpdateEFMAttribute(vsysId, efmId, 'efmName', efmName)
    #handler = client.GetEFMConfigHandler(vsysId, efmId)
    #config = client.GetEFMConfiguration(vsysId, efmId, configurationName, configurationXML=None)
    #handler = client.UpdateEFMConfigHandler(vsysId, efmId)
    #result = client.UpdateEFMConfiguration(vsysId, efmId, configurationName, configurationXML=None, filePath=None)
    status = client.GetEFMStatus(vsysId, efmId)
    update_info = client.GetEFMConfigHandler(vsysId, efmId).efm_update()
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).efm_update()
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).efm_backout()

    #result = client.BackupEFM(vsysId, efmId)
    backups = client.ListEFMBackup(vsysId, efmId, timeZone=None, countryCode=None)
    for backup in backups:
        test_vsys_efm_backup(client, vsysId, efmId, backup.backupId)


def test_vsys_efm_backup(client, vsysId, efmId, backupId):
    """
    Extended Function Module (EFM) Backup
    """
    #result = client.RestoreEFM(vsysId, efmId, backup.backupId)
    #result = client.DestroyEFMBackup(vsysId, efmId, backup.backupId)
    pass


def test_vsys_efm_firewall(client, vsysId, efmId):
    """
    Extended Function Module (EFM) Firewall
    """
    nat_rules = client.GetEFMConfigHandler(vsysId, efmId).fw_nat_rule()
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).fw_nat_rule(rules=None)
    dns = client.GetEFMConfigHandler(vsysId, efmId).fw_dns()
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).fw_dns(dnstype='AUTO', primary=None, secondary=None)
    fw_policy = client.GetEFMConfigHandler(vsysId, efmId).fw_policy(from_zone=None, to_zone=None)
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).fw_policy(log='On', directions=None)
    logs = client.GetEFMConfigHandler(vsysId, efmId).fw_log(num=10, orders=None)
    fw_limit_policy = client.GetEFMConfigHandler(vsysId, efmId).fw_limit_policy(from_zone=None, to_zone=None)
    update_info = client.GetEFMConfigHandler(vsysId, efmId).fw_update()


def test_vsys_efm_loadbalancer(client, vsysId, efmId):
    """
    Extended Function Module (EFM) LoadBalancer
    """
    try:
        rules = client.GetEFMConfigHandler(vsysId, efmId).slb_rule()
    except:
        pass
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).slb_rule(groups=None, force=None, webAccelerator=None)
    try:
        load_stats = client.GetEFMConfigHandler(vsysId, efmId).slb_load()
    except:
        pass
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).slb_load_clear()
    try:
        error_stats = client.GetEFMConfigHandler(vsysId, efmId).slb_error()
    except:
        pass
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).slb_error_clear()
    cert_list = client.GetEFMConfigHandler(vsysId, efmId).slb_cert_list(certCategory=None, detail=None)
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).slb_cert_add(certNum, filePath, passphrase)
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).slb_cert_set(certNum, id)
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).slb_cert_release(certNum)
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).slb_cert_delete(certNum, force=None)
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).slb_cca_add(ccacertNum, filePath)
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).slb_cca_delete(ccacertNum)
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).slb_start_maint(id, ipAddress, time=None, unit=None)
    #result = client.UpdateEFMConfigHandler(vsysId, efmId).slb_stop_maint(id, ipAddress)
    update_info = client.GetEFMConfigHandler(vsysId, efmId).slb_update()


def test_publicip(client, publicipAddress):
    """
    Public IP (PublicIP) overall
    """
    publicip_attr = client.GetPublicIPAttributes(publicipAddress)
    status = client.GetPublicIPStatus(publicipAddress)


def test_addressrange(client):
    """
    Address Range (AddressRange)
    """
    addressranges = client.GetAddressRange()
    #result = client.CreateAddressPool(pipFrom=None, pipTo=None)
    #result = client.AddAddressRange(pipFrom, pipTo)
    #result = client.DeleteAddressRange(pipFrom, pipTo)


def test_vsysdescriptor(client, vsysdescriptorId):
    """
    Virtual System Descriptor (VSYSDescriptor)
    """
    vsysdescriptor_attr = client.GetVSYSDescriptorAttributes(vsysdescriptorId)
    # only allowed on private vsysdescriptors
    vsysdescriptorName = vsysdescriptor_attr.vsysdescriptorName
    description = vsysdescriptor_attr.description
    keyword = vsysdescriptor_attr.keyword
    #result = client.UpdateVSYSDescriptorAttribute(vsysdescriptorId, 'en', 'updateName', vsysdescriptorName)
    #result = client.UpdateVSYSDescriptorAttribute(vsysdescriptorId, 'en', 'updateDescription', description)
    #result = client.UpdateVSYSDescriptorAttribute(vsysdescriptorId, 'en', 'updateKeyword', keyword)
    vsysdescriptor_config = client.GetVSYSDescriptorConfiguration(vsysdescriptorId)

    #result = client.CreateVSYS(vsysdescriptorId, vsysdescriptorName)

    diskimages = client.ListDiskImage('GENERAL', vsysdescriptorId)
    #for diskimage in diskimages:
    #    test_diskimage(client, diskimage.diskimageId)

    #result = client.UnregisterPrivateVSYSDescriptor(vsysdescriptorId)
    #result = client.UnregisterVSYSDescriptor(vsysdescriptorId)


def test_diskimage(client, diskimageId):
    """
    Disk Image (DiskImage)
    """
    #result = client.UnregisterDiskImage(diskimageId)
    diskimage_attr = client.GetDiskImageAttributes(diskimageId)
    # only allowed on private diskimages
    diskimageName = diskimage_attr.diskimageName
    #result = client.UpdateDiskImageAttribute(diskimageId, 'en', 'updateName', diskimageName)
    description = diskimage_attr.description
    #result = client.UpdateDiskImageAttribute(diskimageId, 'en', 'updateDescription', description)

    servertypes = client.ListServerType(diskimageId)
    for servertype in servertypes:
        test_diskimage_servertype(client, diskimageId, servertype.name)


def test_diskimage_servertype(client, diskimageId, servertypeName):
    """
    Server Type (ServerType)
    """
    pass


if __name__ == "__main__":
    import os.path
    import sys
    parent = os.path.dirname(os.path.dirname(__file__))
    sys.path.append(parent)
    pem_file = 'client.pem'
    region = 'de'
    fgcp_api_walker(pem_file, region)
