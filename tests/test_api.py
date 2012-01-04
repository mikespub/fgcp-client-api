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
    test_api_command(key_file, region)


def test_api_command(key_file, region):
    """
    FGCP Command
    """
    # we only need FGCPCommand here, but FGCPClient/FGCPDesigner/FGCPOperator/FGCPMonitor would work just as well
    #from fgcp.client import FGCPClient
    #proxy = FGCPClient(key_file, region)

    from fgcp.command import FGCPCommand
    proxy = FGCPCommand(key_file, region)

    proxy.verbose = 1  # 1 = show any user output the library might generate (nothing much)
    proxy.debug = 1    # 1 = show the API commands being sent, 2 = dump the response objects (99 = save test fixtures)

    date, usage = proxy.GetSystemUsage()

    vsystems = proxy.ListVSYS()
    for vsys in vsystems:
        test_vsys(proxy, vsys.vsysId)
        break

    publicips = proxy.ListPublicIP(None)
    for publicip in publicips:
        test_publicip(proxy, publicip.address)
        break

    test_addressrange(proxy)

    vsysdescriptors = proxy.ListVSYSDescriptor()
    for vsysdescriptor in vsysdescriptors:
        test_vsysdescriptor(proxy, vsysdescriptor.vsysdescriptorId)
        break

    diskimages = proxy.ListDiskImage()
    for diskimage in diskimages:
        test_diskimage(proxy, diskimage.diskimageId)
        break


def test_vsys(proxy, vsysId):
    """
    Virtual System (VSYS)
    """
    #result = proxy.DestroyVSYS(vsysId)

    vsys_attr = proxy.GetVSYSAttributes(vsysId)
    vsysName = vsys_attr.vsysName
    result = proxy.UpdateVSYSAttribute(vsysId, 'vsysName', vsysName)
    try:
        cloudCategory = vsys_attr.cloudCategory
        #result = proxy.UpdateVSYSConfiguration(vsysId, 'CLOUD_CATEGORY', cloudCategory)
    except:
        pass

    status = proxy.GetVSYSStatus(vsysId)

    vservers = proxy.ListVServer(vsysId)
    for vserver in vservers:
        test_vsys_vserver(proxy, vsysId, vserver.vserverId)
        break

    #result = proxy.CreateVDisk(vsysId, vdiskName, size)
    vdisks = proxy.ListVDisk(vsysId)
    for vdisk in vdisks:
        test_vsys_vdisk(proxy, vsysId, vdisk.vdiskId)
        break

    #result = proxy.AllocatePublicIP(vsysId)
    publicips = proxy.ListPublicIP(vsysId)
    for publicip in publicips:
        test_vsys_publicip(proxy, vsysId, publicip.address)
        break

    vsys_config = proxy.GetVSYSConfiguration(vsysId)
    for networkId in vsys_config.vnets:
        test_vsys_vnet(proxy, vsysId, networkId)
        break

    efmType = 'FW'
    #result = proxy.CreateEFM(vsysId, efmType, efmName, networkId)
    firewalls = proxy.ListEFM(vsysId, efmType)
    for firewall in firewalls:
        test_vsys_efm_generic(proxy, vsysId, firewall.efmId)
        test_vsys_efm_firewall(proxy, vsysId, firewall.efmId)
        break

    efmType = 'SLB'
    #result = proxy.CreateEFM(vsysId, efmType, efmName, networkId)
    loadbalancers = proxy.ListEFM(vsysId, efmType)
    for loadbalancer in loadbalancers:
        test_vsys_efm_generic(proxy, vsysId, loadbalancer.efmId)
        test_vsys_efm_loadbalancer(proxy, vsysId, loadbalancer.efmId)
        break

    #result = proxy.CreateVServer(vsysId, vserverName, vserverType, diskImageId, networkId)

    # only allowed on private vsysdescriptors
    name = 'My New VSYS Template'
    description = 'This is a 3-tier web application database template'
    keyword = '3-tier web application database'
    vservers = proxy.ListVServer(vsysId)
    #result = proxy.RegisterPrivateVSYSDescriptor(vsysId, name, description, keyword, vservers)


def test_vsys_vserver(proxy, vsysId, vserverId):
    """
    Virtual Server (VServer)
    """
    #result = proxy.StartVServer(vsysId, vserverId)
    #result = proxy.StopVServer(vsysId, vserverId, force=None)
    #result = proxy.DestroyVServer(vsysId, vserverId)

    vserver_attr = proxy.GetVServerAttributes(vsysId, vserverId)
    vserverName = vserver_attr.vserverName
    result = proxy.UpdateVServerAttribute(vsysId, vserverId, 'vserverName', vserverName)
    try:
        vserverType = vserver_attr.vserverType
        result = proxy.UpdateVServerAttribute(vsysId, vserverId, 'vserverType', vserverType)
    except:
        pass

    status = proxy.GetVServerStatus(vsysId, vserverId)
    password = proxy.GetVServerInitialPassword(vsysId, vserverId)

    vserver_config = proxy.GetVServerConfiguration(vsysId, vserverId)

    for vdisk in vserver_config.vdisks:
        test_vsys_vserver_vdisk(proxy, vsysId, vserverId, vdisk.vdiskId)
        break

    for vnic in vserver_config.vnics:
        test_vsys_vserver_vnic(proxy, vsysId, vserverId, vnic.networkId)
        break

    #result = proxy.RegisterPrivateDiskImage(vserverId, name, description)


def test_vsys_vserver_vdisk(proxy, vsysId, vserverId, vdiskId):
    """
    Virtual Disk (VDisk) attached to this server
    """
    #result = proxy.AttachVDisk(vsysId, vserverId, vdiskId)
    #result = proxy.DetachVDisk(vsysId, vserverId, vdiskId)
    #test_vsys_vdisk(vsysId, vdiskId)
    pass


def test_vsys_vserver_vnic(proxy, vsysId, vserverId, networkId):
    """
    Virtual Network Interface (VNIC)
    """
    pass


def test_vsys_vdisk(proxy, vsysId, vdiskId):
    """
    Virtual Disk (VDisk)
    """
    #result = proxy.DestroyVDisk(vsysId, vdiskId)

    proxy.GetVDiskAttributes(vsysId, vdiskId)
    #result = proxy.UpdateVDiskAttribute(vsysId, vdiskId, 'vdiskName', vdisk.vdiskName)
    proxy.GetVDiskStatus(vsysId, vdiskId)

    #result = proxy.BackupVDisk(vsysId, vdiskId)
    backups = proxy.ListVDiskBackup(vsysId, vdiskId)
    for backup in backups:
        test_vsys_backup(proxy, vsysId, backup.backupId)
        break


def test_vsys_backup(proxy, vsysId, backupId):
    """
    Virtual Disk (VDisk) Backup
    """
    #result = proxy.RestoreVDisk(vsysId, backupId)
    #result = proxy.DestroyVDiskBackup(vsysId, backupId)
    pass


def test_vsys_publicip(proxy, vsysId, publicipAddress):
    """
    Public IP (PublicIP) for this vsys
    """
    #result = proxy.AttachPublicIP(vsysId, publicipAddress)
    #result = proxy.DetachPublicIP(vsysId, publicipAddress)
    #result = proxy.FreePublicIP(vsysId, publicipAddress)
    #test_publicip(publicipAddress)


def test_vsys_vnet(proxy, vsysId, networkId):
    """
    Virtual Network (VNet)
    """
    test_vsys_vnet_console(proxy, vsysId, networkId)


def test_vsys_vnet_console(proxy, vsysId, networkId):
    """
    Other (SSL-VPN)
    """
    console_url = proxy.StandByConsole(vsysId, networkId)


def test_vsys_efm_generic(proxy, vsysId, efmId):
    """
    Extended Function Module (EFM) Generic
    """
    #result = proxy.StartEFM(vsysId, efmId)
    #result = proxy.StopEFM(vsysId, efmId)
    #result = proxy.DestroyEFM(vsysId, efmId)

    efm_attr = proxy.GetEFMAttributes(vsysId, efmId)
    efmName = efm_attr.efmName
    result = proxy.UpdateEFMAttribute(vsysId, efmId, 'efmName', efmName)
    get_handler = proxy.GetEFMConfigHandler(vsysId, efmId)
    #config = proxy.GetEFMConfiguration(vsysId, efmId, configurationName, configurationXML=None)
    update_handler = proxy.UpdateEFMConfigHandler(vsysId, efmId)
    #result = proxy.UpdateEFMConfiguration(vsysId, efmId, configurationName, configurationXML=None, filePath=None)
    status = proxy.GetEFMStatus(vsysId, efmId)
    update_info = proxy.GetEFMConfigHandler(vsysId, efmId).efm_update()
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).efm_update()
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).efm_backout()

    #result = proxy.BackupEFM(vsysId, efmId)
    backups = proxy.ListEFMBackup(vsysId, efmId, timeZone=None, countryCode=None)
    for backup in backups:
        test_vsys_efm_backup(proxy, vsysId, efmId, backup.backupId)
        break


def test_vsys_efm_backup(proxy, vsysId, efmId, backupId):
    """
    Extended Function Module (EFM) Backup
    """
    #result = proxy.RestoreEFM(vsysId, efmId, backupId)
    #result = proxy.DestroyEFMBackup(vsysId, efmId, backupId)
    pass


def test_vsys_efm_firewall(proxy, vsysId, efmId):
    """
    Extended Function Module (EFM) Firewall
    """
    nat_rules = proxy.GetEFMConfigHandler(vsysId, efmId).fw_nat_rule()
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).fw_nat_rule(rules=nat_rules)
    dns = proxy.GetEFMConfigHandler(vsysId, efmId).fw_dns()
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).fw_dns(dnstype='AUTO', primary=None, secondary=None)
    policies = proxy.GetEFMConfigHandler(vsysId, efmId).fw_policy(from_zone=None, to_zone=None)
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).fw_policy(log='On', directions=policies)
    logs = proxy.GetEFMConfigHandler(vsysId, efmId).fw_log(num=10, orders=None)
    limit_policies = proxy.GetEFMConfigHandler(vsysId, efmId).fw_limit_policy(from_zone=None, to_zone=None)
    update_info = proxy.GetEFMConfigHandler(vsysId, efmId).fw_update()


def test_vsys_efm_loadbalancer(proxy, vsysId, efmId):
    """
    Extended Function Module (EFM) LoadBalancer
    """
    rules = proxy.GetEFMConfigHandler(vsysId, efmId).slb_rule()
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).slb_rule(groups=rules.groups, force=None, webAccelerator=None)
    load_stats = proxy.GetEFMConfigHandler(vsysId, efmId).slb_load()
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).slb_load_clear()
    error_stats = proxy.GetEFMConfigHandler(vsysId, efmId).slb_error()
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).slb_error_clear()
    cert_list = proxy.GetEFMConfigHandler(vsysId, efmId).slb_cert_list(certCategory=None, detail=None)
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).slb_cert_add(certNum, filePath, passphrase)
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).slb_cert_set(certNum, id)
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).slb_cert_release(certNum)
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).slb_cert_delete(certNum, force=None)
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).slb_cca_add(ccacertNum, filePath)
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).slb_cca_delete(ccacertNum)
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).slb_start_maint(id, ipAddress, time=None, unit=None)
    #result = proxy.UpdateEFMConfigHandler(vsysId, efmId).slb_stop_maint(id, ipAddress)
    update_info = proxy.GetEFMConfigHandler(vsysId, efmId).slb_update()


def test_publicip(proxy, publicipAddress):
    """
    Public IP (PublicIP) overall
    """
    publicip_attr = proxy.GetPublicIPAttributes(publicipAddress)
    status = proxy.GetPublicIPStatus(publicipAddress)


def test_addressrange(proxy):
    """
    Address Range (AddressRange)
    """
    addressranges = proxy.GetAddressRange()
    #result = proxy.CreateAddressPool(pipFrom=None, pipTo=None)
    #result = proxy.AddAddressRange(pipFrom, pipTo)
    #result = proxy.DeleteAddressRange(pipFrom, pipTo)


def test_vsysdescriptor(proxy, vsysdescriptorId):
    """
    Virtual System Descriptor (VSYSDescriptor)
    """
    vsysdescriptor_attr = proxy.GetVSYSDescriptorAttributes(vsysdescriptorId)
    # only allowed on private vsysdescriptors
    vsysdescriptorName = vsysdescriptor_attr.vsysdescriptorName
    description = vsysdescriptor_attr.description
    keyword = vsysdescriptor_attr.keyword
    #result = proxy.UpdateVSYSDescriptorAttribute(vsysdescriptorId, 'en', 'updateName', vsysdescriptorName)
    #result = proxy.UpdateVSYSDescriptorAttribute(vsysdescriptorId, 'en', 'updateDescription', description)
    #result = proxy.UpdateVSYSDescriptorAttribute(vsysdescriptorId, 'en', 'updateKeyword', keyword)
    vsysdescriptor_config = proxy.GetVSYSDescriptorConfiguration(vsysdescriptorId)

    #result = proxy.CreateVSYS(vsysdescriptorId, vsysdescriptorName)

    diskimages = proxy.ListDiskImage('GENERAL', vsysdescriptorId)
    #for diskimage in diskimages:
    #    test_diskimage(proxy, diskimage.diskimageId)

    #result = proxy.UnregisterPrivateVSYSDescriptor(vsysdescriptorId)
    #result = proxy.UnregisterVSYSDescriptor(vsysdescriptorId)


def test_diskimage(proxy, diskimageId):
    """
    Disk Image (DiskImage)
    """
    #result = proxy.UnregisterDiskImage(diskimageId)
    diskimage_attr = proxy.GetDiskImageAttributes(diskimageId)
    # only allowed on private diskimages
    diskimageName = diskimage_attr.diskimageName
    #result = proxy.UpdateDiskImageAttribute(diskimageId, 'en', 'updateName', diskimageName)
    description = diskimage_attr.description
    #result = proxy.UpdateDiskImageAttribute(diskimageId, 'en', 'updateDescription', description)

    servertypes = proxy.ListServerType(diskimageId)
    for servertype in servertypes:
        test_diskimage_servertype(proxy, diskimageId, servertype.name)
        break


def test_diskimage_servertype(proxy, diskimageId, servertypeName):
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
    #region = 'de'
    region = 'test'
    #region = 'relay=http://localhost:8000/cgi-bin/fgcp_relay.py'
    fgcp_api_walker(pem_file, region)
