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
API Commands to the Fujitsu Global Cloud Platform (FGCP)

Example: [see tests/test_api.py for more examples]

# Connect with your client certificate to region 'uk'
from fgcp.command import FGCPCommand
api_proxy = FGCPCommand('client.pem', 'uk')

# Call standard API commands with identifiers
vsystems = api_proxy.ListVSYS()
for vsys in vsystems:
    status = api_proxy.GetVSYSStatus(vsys.vsysId)
    vsysconfig = api_proxy.GetVSYSConfiguration(vsys.vsysId)
    for vserver in vsysconfig.vservers:
        status = api_proxy.GetVServerStatus(vsys.vsysId, vserver.vserverId)
    ...
"""

from fgcp import FGCPError

from fgcp.connection import FGCPProxyServer, FGCPResponseError


class FGCPCommandError(FGCPError):
    pass


class FGCPCommand(FGCPProxyServer):
    """
    Proxy for FGCP API Commands
    """

    def set_verbose(self, verbose=None):
        """
        Show output (1), status checks (2) or nothing (0)
        """
        old_verbose = self.verbose
        if verbose is None:
            # don't change current setting
            pass
        elif verbose > 1:
            # start showing output + status
            self.verbose = 2
        elif verbose == 1:
            # start showing output
            self.verbose = 1
        else:
            # stop showing output
            self.verbose = 0
        return old_verbose

    def show_output(self, text=''):
        if self.verbose > 0:
            print text

    def show_status(self, text=''):
        if self.verbose > 1:
            print text

    def ListVSYSDescriptor(self):
        """
        Usage: vsysdescriptors = proxy.ListVSYSDescriptor()
        """
        result = self.do_action('ListVSYSDescriptor')
        return result.vsysdescriptors

    def GetVSYSDescriptorConfiguration(self, vsysDescriptorId):
        """
        Usage: vsysdescriptorconfig = proxy.GetVSYSDescriptorConfiguration(vsysdescriptor.vsysdescriptorId)
        """
        result = self.do_action('GetVSYSDescriptorConfiguration', {'vsysDescriptorId': vsysDescriptorId})
        return result.vsysdescriptor

    def GetVSYSDescriptorAttributes(self, vsysDescriptorId):
        """
        Usage: vsysdescriptorattr = proxy.GetVSYSDescriptorAttributes(vsysdescriptor.vsysdescriptorId)
        """
        result = self.do_action('GetVSYSDescriptorAttributes', {'vsysDescriptorId': vsysDescriptorId})
        return result.vsysdescriptor

    def UpdateVSYSDescriptorAttribute(self, vsysDescriptorId, updateLcId, attributeName, attributeValue):
        result = self.do_action('UpdateVSYSDescriptorAttribute', {'vsysDescriptorId': vsysDescriptorId, 'updateLcId': updateLcId, 'attributeName': attributeName, 'attributeValue': attributeValue})
        return result.responseStatus

    def UnregisterVSYSDescriptor(self, vsysDescriptorId):
        result = self.do_action('UnregisterVSYSDescriptor', {'vsysDescriptorId': vsysDescriptorId})
        return result.responseStatus

    def RegisterPrivateVSYSDescriptor(self, vsysId, name, description, keyword, vservers):
        """Usage:
        vsys = proxy.GetSystemInventory('My Existing VSYS')
        proxy.RegisterPrivateVSYSDescriptor(vsys.vsysId, 'My New Template', 'This is a new template based on my existing VSYS', 'some key words', vsys.vservers)
        """
        filename = 'dummy.xml'
        vsysDescriptorXML = self._get_vsysDescriptorXML(vsysId, name, description, keyword, vservers)
        result = self.do_action('RegisterPrivateVSYSDescriptor', {'vsysDescriptorXMLFilePath': filename}, {'name': 'vsysDescriptorXMLFilePath', 'filename': filename, 'body': vsysDescriptorXML})
        return result.responseStatus

    def _get_vsysDescriptorXML(self, vsysId, name, description, keyword, vservers):
        CRLF = '\r\n'
        L = []
        L.append('<?xml version="1.0" encoding="UTF-8"?>')
        L.append('<Request>')
        L.append('  <vsysId>%s</vsysId>' % vsysId)
        L.append('  <locales>')
        L.append('    <locale>')
        L.append('      <lcid>en</lcid>')
        L.append('      <name>%s</name>' % name)
        L.append('      <description>%s</description>' % description)
        L.append('    </locale>')
        L.append('  </locales>')
        L.append('  <keyword>%s</keyword>' % keyword)
        L.append('  <servers>')
        if vservers is not None and len(vservers) > 0:
            # CHECKME: do we need to add name & description for loadbalancers too ?
            for vserver in vservers:
                L.append('    <server>')
                # CHECKME: and what should we use for the id here - is it mandatory ?
                L.append('      <id>%s</id>' % vserver.vserverId)
                L.append('      <locales>')
                L.append('        <locale>')
                L.append('          <lcid>en</lcid>')
                L.append('          <name>%s</name>' % vserver.vserverName)
                # CHECKME: what should we use for description ?
                descr = vserver.vserverName + ' on ' + vserver.vserverType + ' server type'
                L.append('          <description>%s</description>' % descr)
                L.append('        </locale>')
                L.append('      </locales>')
                L.append('    </server>')
                L.append('  </servers>')
                L.append('</Request>')
        return CRLF.join(L)

    def UnregisterPrivateVSYSDescriptor(self, vsysDescriptorId):
        result = self.do_action('UnregisterPrivateVSYSDescriptor', {'vsysDescriptorId': vsysDescriptorId})
        return result.responseStatus

    def ListPublicIP(self, vsysId=None):
        """
        Usage: publicips = proxy.ListPublicIP()
        """
        result = self.do_action('ListPublicIP', {'vsysId': vsysId})
        return result.publicips

    def GetPublicIPAttributes(self, publicIp):
        """
        Usage: publicipattr = proxy.GetPublicIPAttributes(publicip.address)
        """
        result = self.do_action('GetPublicIPAttributes', {'publicIp': publicIp})
        return result.publicips

    def GetPublicIPStatus(self, publicIp):
        """
        Usage: status = proxy.GetPublicIPStatus(publicip.address)
        """
        result = self.do_action('GetPublicIPStatus', {'publicIp': publicIp})
        # show status if requested, e.g. for wait operations
        self.show_status(result.publicipStatus)
        return result.publicipStatus

    def AllocatePublicIP(self, vsysId):
        result = self.do_action('AllocatePublicIP', {'vsysId': vsysId})
        return result.responseStatus

    def AttachPublicIP(self, vsysId, publicIp):
        result = self.do_action('AttachPublicIP', {'vsysId': vsysId, 'publicIp': publicIp})
        return result.responseStatus

    def DetachPublicIP(self, vsysId, publicIp):
        result = self.do_action('DetachPublicIP', {'vsysId': vsysId, 'publicIp': publicIp})
        return result.responseStatus

    def FreePublicIP(self, vsysId, publicIp):
        result = self.do_action('FreePublicIP', {'vsysId': vsysId, 'publicIp': publicIp})
        return result.responseStatus

    def GetAddressRange(self):
        """
        Usage: addressranges = proxy.GetAddressRange()
        """
        result = self.do_action('GetAddressRange')
        if hasattr(result, 'addressranges'):
            return result.addressranges

    def CreateAddressPool(self, pipFrom=None, pipTo=None):
        result = self.do_action('CreateAddressPool', {'pipFrom': pipFrom, 'pipTo': pipTo})
        return result

    def AddAddressRange(self, pipFrom, pipTo):
        result = self.do_action('AddAddressRange', {'pipFrom': pipFrom, 'pipTo': pipTo})
        return result.responseStatus

    def DeleteAddressRange(self, pipFrom, pipTo):
        result = self.do_action('DeleteAddressRange', {'pipFrom': pipFrom, 'pipTo': pipTo})
        return result.responseStatus

    def ListDiskImage(self, serverCategory=None, vsysDescriptorId=None):
        """
        Usage: diskimages = proxy.ListDiskImage()
        """
        result = self.do_action('ListDiskImage', {'serverCategory': serverCategory, 'vsysDescriptorId': vsysDescriptorId})
        return result.diskimages

    def GetDiskImageAttributes(self, diskImageId):
        """
        Usage: diskimage = proxy.GetDiskImageAttributes(diskimage.diskimageId)
        """
        result = self.do_action('GetDiskImageAttributes', {'diskImageId': diskImageId})
        return result.diskimage

    def UpdateDiskImageAttribute(self, diskImageId, updateLcId, attributeName, attributeValue):
        result = self.do_action('UpdateDiskImageAttribute', {'diskImageId': diskImageId, 'updateLcId': updateLcId, 'attributeName': attributeName, 'attributeValue': attributeValue})
        return result.responseStatus

    def RegisterPrivateDiskImage(self, vserverId, name, description):
        filename = 'dummy.xml'
        diskImageXML = self._get_diskImageXML(vserverId, name, description)
        result = self.do_action('RegisterPrivateDiskImage', {'diskImageXMLFilePath': filename}, {'name': 'diskImageXMLFilePath', 'filename': filename, 'body': diskImageXML})
        return result.responseStatus

    def _get_diskImageXML(self, vserverId, name, description):
        CRLF = '\r\n'
        L = []
        L.append('<?xml version="1.0" encoding="UTF-8"?>')
        L.append('<Request>')
        L.append('  <vserverId>%s</vserverId>' % vserverId)
        L.append('  <locales>')
        L.append('    <locale>')
        L.append('      <lcid>en</lcid>')
        L.append('      <name>%s</name>' % name)
        L.append('      <description>%s</description>' % description)
        L.append('    </locale>')
        L.append('  </locales>')
        L.append('</Request>')
        return CRLF.join(L)

    def UnregisterDiskImage(self, diskImageId):
        result = self.do_action('UnregisterDiskImage', {'diskImageId': diskImageId})
        return result.responseStatus

    def ListServerType(self, diskImageId):
        """
        Usage: servertypes = proxy.ListServerType(diskimage.diskimageId)
        """
        result = self.do_action('ListServerType', {'diskImageId': diskImageId})
        return result.servertypes

    def ListVSYS(self):
        """
        Usage: vsystems = proxy.ListVSYS()
        """
        result = self.do_action('ListVSYS')
        # CHECKME: initialize empty list if necessary
        if not hasattr(result, 'vsyss'):
            setattr(result, 'vsyss', [])
        return result.vsyss

    def GetVSYSConfiguration(self, vsysId):
        """
        Usage: vsysconfig = proxy.GetVSYSConfiguration(vsys.vsysId)
        """
        result = self.do_action('GetVSYSConfiguration', {'vsysId': vsysId})
        # FIXME: we seem to have ghosts in VSYSConfiguration.publicips compared to the overall ListPublicIP(vsys.vsysId) !
        setattr(result.vsys, 'publicips', self.ListPublicIP(vsysId))
        return result.vsys

    def UpdateVSYSConfiguration(self, vsysId, configurationName, configurationValue):
        result = self.do_action('UpdateVSYSConfiguration', {'vsysId': vsysId, 'configurationName': configurationName, 'configurationValue': configurationValue})
        return result.responseStatus

    def GetVSYSAttributes(self, vsysId):
        """
        Usage: vsysattr = proxy.GetVSYSAttributes(vsys.vsysId)
        """
        result = self.do_action('GetVSYSAttributes', {'vsysId': vsysId})
        return result.vsys

    def UpdateVSYSAttribute(self, vsysId, attributeName, attributeValue):
        result = self.do_action('UpdateVSYSAttribute', {'vsysId': vsysId, 'attributeName': attributeName, 'attributeValue': attributeValue})
        return result.responseStatus

    def GetVSYSStatus(self, vsysId):
        """
        Usage: status = proxy.GetVSYSStatus(vsys.vsysId)
        """
        result = self.do_action('GetVSYSStatus', {'vsysId': vsysId})
        # show status if requested, e.g. for wait operations
        self.show_status(result.vsysStatus)
        return result.vsysStatus

    def CreateVSYS(self, vsysDescriptorId, vsysName):
        """
        Usage: vsysId = proxy.CreateVSYS(vsysdescriptor.vsysdescriptorId, 'My New System')
        """
        result = self.do_action('CreateVSYS', {'vsysDescriptorId': vsysDescriptorId, 'vsysName': vsysName})
        return result.vsysId

    def DestroyVSYS(self, vsysId):
        result = self.do_action('DestroyVSYS', {'vsysId': vsysId})
        return result.responseStatus

    def ListVServer(self, vsysId):
        """
        Usage: vservers = proxy.ListVServer(vsys.vsysId)
        """
        result = self.do_action('ListVServer', {'vsysId': vsysId})
        return result.vservers

    def GetVServerConfiguration(self, vsysId, vserverId):
        """
        Usage: vserverconfig = proxy.GetVServerConfiguration(vsys.vsysId, vserver.vserverId)
        """
        result = self.do_action('GetVServerConfiguration', {'vsysId': vsysId, 'vserverId': vserverId})
        return result.vserver

    def GetVServerAttributes(self, vsysId, vserverId):
        """
        Usage: vserverattr = proxy.GetVServerAttributes(vsys.vsysId, vserver.vserverId)
        """
        result = self.do_action('GetVServerAttributes', {'vsysId': vsysId, 'vserverId': vserverId})
        return result.vserver

    def UpdateVServerAttribute(self, vsysId, vserverId, attributeName, attributeValue):
        result = self.do_action('UpdateVServerAttribute', {'vsysId': vsysId, 'vserverId': vserverId, 'attributeName': attributeName, 'attributeValue': attributeValue})
        return result.responseStatus

    def GetVServerInitialPassword(self, vsysId, vserverId):
        """
        Usage: initialpwd = proxy.GetVServerInitialPassword(vsys.vsysId, vserver.vserverId)
        """
        result = self.do_action('GetVServerInitialPassword', {'vsysId': vsysId, 'vserverId': vserverId})
        return result.initialPassword

    def GetVServerStatus(self, vsysId, vserverId):
        """
        Usage: status = proxy.GetVServerStatus(vsys.vsysId, vserver.vserverId)
        """
        result = self.do_action('GetVServerStatus', {'vsysId': vsysId, 'vserverId': vserverId})
        # show status if requested, e.g. for wait operations
        self.show_status(result.vserverStatus)
        return result.vserverStatus

    def CreateVServer(self, vsysId, vserverName, vserverType, diskImageId, networkId):
        """
        Usage: vserverId = proxy.CreateVServer(self, vsys.vsysId, 'My New Server', servertype.name, diskimage.diskimageId, vsys.vnets[0])
        """
        result = self.do_action('CreateVServer', {'vsysId': vsysId, 'vserverName': vserverName, 'vserverType': vserverType, 'diskImageId': diskImageId, 'networkId': networkId})
        return result.vserverId

    def StartVServer(self, vsysId, vserverId):
        result = self.do_action('StartVServer', {'vsysId': vsysId, 'vserverId': vserverId})
        return result.responseStatus

    def StopVServer(self, vsysId, vserverId, force=None):
        result = self.do_action('StopVServer', {'vsysId': vsysId, 'vserverId': vserverId, 'force': force})
        return result.responseStatus

    def DestroyVServer(self, vsysId, vserverId):
        result = self.do_action('DestroyVServer', {'vsysId': vsysId, 'vserverId': vserverId})
        return result.responseStatus

    def ListVDisk(self, vsysId):
        """
        Usage: vdisks = proxy.ListVDisk(vsys.vsysId)
        """
        result = self.do_action('ListVDisk', {'vsysId': vsysId})
        return result.vdisks

    def GetVDiskAttributes(self, vsysId, vdiskId):
        """
        Usage: vdiskattr = proxy.GetVDiskAttributes(vsys.vsysId, vdisk.vdiskId)
        """
        result = self.do_action('GetVDiskAttributes', {'vsysId': vsysId, 'vdiskId': vdiskId})
        return result.vdisk

    def UpdateVDiskAttribute(self, vsysId, vdiskId, attributeName, attributeValue):
        result = self.do_action('UpdateVDiskAttribute', {'vsysId': vsysId, 'vdiskId': vdiskId, 'attributeName': attributeName, 'attributeValue': attributeValue})
        return result.responseStatus

    def GetVDiskStatus(self, vsysId, vdiskId):
        """
        Usage: status = proxy.GetVDiskStatus(vsys.vsysId, vdisk.vdiskId)
        """
        result = self.do_action('GetVDiskStatus', {'vsysId': vsysId, 'vdiskId': vdiskId})
        # show status if requested, e.g. for wait operations
        self.show_status(result.vdiskStatus)
        return result.vdiskStatus

    def CreateVDisk(self, vsysId, vdiskName, size):
        """
        Usage: vdiskId = proxy.CreateVDisk(self, vsys.vsysId, vdiskName, size)
        """
        result = self.do_action('CreateVDisk', {'vsysId': vsysId, 'vdiskName': vdiskName, 'size': size})
        return result.vdiskId

    def AttachVDisk(self, vsysId, vserverId, vdiskId):
        result = self.do_action('AttachVDisk', {'vsysId': vsysId, 'vserverId': vserverId, 'vdiskId': vdiskId})
        return result.responseStatus

    def DetachVDisk(self, vsysId, vserverId, vdiskId):
        result = self.do_action('DetachVDisk', {'vsysId': vsysId, 'vserverId': vserverId, 'vdiskId': vdiskId})
        return result.responseStatus

    def DestroyVDisk(self, vsysId, vdiskId):
        result = self.do_action('DestroyVDisk', {'vsysId': vsysId, 'vdiskId': vdiskId})
        return result.responseStatus

    def ListVDiskBackup(self, vsysId, vdiskId, timeZone=None, countryCode=None):
        """
        Usage: backups = proxy.ListVDiskBackup(vsys.vsysId, vdisk.vdiskId)
        """
        result = self.do_action('ListVDiskBackup', {'vsysId': vsysId, 'vdiskId': vdiskId, 'timeZone': timeZone, 'countryCode': countryCode})
        # convert weird time format to time value
        for backup in result.backups:
            backup.get_timeval()
        return result.backups

    def BackupVDisk(self, vsysId, vdiskId):
        result = self.do_action('BackupVDisk', {'vsysId': vsysId, 'vdiskId': vdiskId})
        return result.responseStatus

    def RestoreVDisk(self, vsysId, backupId):
        result = self.do_action('RestoreVDisk', {'vsysId': vsysId, 'backupId': backupId})
        return result.responseStatus

    def DestroyVDiskBackup(self, vsysId, backupId):
        result = self.do_action('DestroyVDiskBackup', {'vsysId': vsysId, 'backupId': backupId})
        return result.responseStatus

    def ListEFM(self, vsysId, efmType):
        """Usage:
        firewalls = proxy.ListEFM(vsys.vsysId, "FW")
        loadbalancers = proxy.ListEFM(vsys.vsysId, "SLB")
        """
        result = self.do_action('ListEFM', {'vsysId': vsysId, 'efmType': efmType})
        # CHECKME: return child firewall or loadbalancer objects
        child_efms = []
        for efm in result.efms:
            child_efms.append(efm.get_child_object())
        return child_efms

    def GetEFMConfiguration(self, vsysId, efmId, configurationName, configurationXML=None):
        """Generic method for all GetEFMConfiguration methods"""
        if configurationXML is None:
            result = self.do_action('GetEFMConfiguration', {'vsysId': vsysId, 'efmId': efmId, 'configurationName': configurationName})
        else:
            result = self.do_action('GetEFMConfiguration', {'vsysId': vsysId, 'efmId': efmId, 'configurationName': configurationName}, {'name': 'configurationXMLFilePath', 'body': configurationXML})
        # CHECKME: return child firewall or loadbalancer object
        return result.efm.get_child_object()

    def GetEFMConfigHandler(self, vsysId, efmId):
        """Handler for specific GetEFMConfiguration methods, see FGCPGetEFMConfigHandler for details
        Usage: fw_policies = proxy.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_policy(from_zone, to_zone)
        """
        return FGCPGetEFMConfigHandler(self, vsysId, efmId)

    def UpdateEFMConfiguration(self, vsysId, efmId, configurationName, configurationXML=None, filePath=None):
        """Generic method for all UpdateEFMConfiguration methods"""
        if configurationXML is None:
            result = self.do_action('UpdateEFMConfiguration', {'vsysId': vsysId, 'efmId': efmId, 'configurationName': configurationName})
        elif filePath is None:
            result = self.do_action('UpdateEFMConfiguration', {'vsysId': vsysId, 'efmId': efmId, 'configurationName': configurationName}, {'name': 'configurationXMLFilePath', 'body': configurationXML})
        else:
            # when adding SLB server/cca certificates, configurationXML contains the filePath for the actual certificate to be uploaded
            result = self.do_action('UpdateEFMConfiguration', {'vsysId': vsysId, 'efmId': efmId, 'configurationName': configurationName}, [{'name': 'configurationXMLFilePath', 'body': configurationXML}, {'name': 'filePath', 'filename': filePath}])
        return result.responseStatus

    def UpdateEFMConfigHandler(self, vsysId, efmId):
        """Handler for specific UpdateEFMConfiguration methods, see FGCPUpdateEFMConfigHandler for details
        Usage: proxy.UpdateEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_dns('AUTO')
        """
        return FGCPUpdateEFMConfigHandler(self, vsysId, efmId)

    def _get_configurationXML(self, configName, params=None):
        CRLF = '\r\n'
        L = []
        L.append('<?xml version="1.0" encoding="UTF-8"?>')
        L.append('<Request>')
        L.append('  <configuration>')
        L.append(self.add_param(configName, params, 2))
        L.append('  </configuration>')
        L.append('</Request>')
        return CRLF.join(L)

    def GetEFMAttributes(self, vsysId, efmId):
        """
        Usage: efmattr = proxy.GetEFMAttributes(vsys.vsysId, loadbalancer.efmId)
        """
        result = self.do_action('GetEFMAttributes', {'vsysId': vsysId, 'efmId': efmId})
        # CHECKME: return child firewall or loadbalancer object
        return result.efm.get_child_object()

    def UpdateEFMAttribute(self, vsysId, efmId, attributeName, attributeValue):
        result = self.do_action('UpdateEFMAttribute', {'vsysId': vsysId, 'efmId': efmId, 'attributeName': attributeName, 'attributeValue': attributeValue})
        return result.responseStatus

    def GetEFMStatus(self, vsysId, efmId):
        """
        Usage: status = proxy.GetEFMStatus(vsys.vsysId, loadbalancer.efmId)
        """
        result = self.do_action('GetEFMStatus', {'vsysId': vsysId, 'efmId': efmId})
        # show status if requested, e.g. for wait operations
        self.show_status(result.efmStatus)
        return result.efmStatus

    def CreateEFM(self, vsysId, efmType, efmName, networkId):
        """
        Usage: efmId = proxy.CreateEFM(self, vsys.vsysId, 'SLB', 'My LoadBalancer', vsys.vnets[0])
        """
        result = self.do_action('CreateEFM', {'vsysId': vsysId, 'efmType': efmType, 'efmName': efmName, 'networkId': networkId})
        return result.efmId

    def StartEFM(self, vsysId, efmId):
        result = self.do_action('StartEFM', {'vsysId': vsysId, 'efmId': efmId})
        return result.responseStatus

    def StopEFM(self, vsysId, efmId):
        result = self.do_action('StopEFM', {'vsysId': vsysId, 'efmId': efmId})
        return result.responseStatus

    def DestroyEFM(self, vsysId, efmId):
        result = self.do_action('DestroyEFM', {'vsysId': vsysId, 'efmId': efmId})
        return result.responseStatus

    def ListEFMBackup(self, vsysId, efmId, timeZone=None, countryCode=None):
        """
        Usage: backups = proxy.ListEFMBackup(vsys.vsysId, firewall.efmId)
        """
        result = self.do_action('ListEFMBackup', {'vsysId': vsysId, 'efmId': efmId, 'timeZone': timeZone, 'countryCode': countryCode})
        return result.backups

    def BackupEFM(self, vsysId, efmId):
        result = self.do_action('BackupEFM', {'vsysId': vsysId, 'efmId': efmId})
        return result.responseStatus

    def RestoreEFM(self, vsysId, efmId, backupId):
        result = self.do_action('RestoreEFM', {'vsysId': vsysId, 'efmId': efmId, 'backupId': backupId})
        return result.responseStatus

    def DestroyEFMBackup(self, vsysId, efmId, backupId):
        result = self.do_action('DestroyEFMBackup', {'vsysId': vsysId, 'efmId': efmId, 'backupId': backupId})
        return result.responseStatus

    def StandByConsole(self, vsysId, networkId):
        """
        Usage: url = proxy.StandByConsole(vsys.vsysId, vsys.vnets[0])
        """
        result = self.do_action('StandByConsole', {'vsysId': vsysId, 'networkId': networkId})
        return result.url

    def GetSystemUsage(self, vsysIds=None):
        """NOTE: extra 'date' element on top-level compared to other API calls !
        Usage: date, usage = proxy.GetSystemUsage()
        """
        if isinstance(vsysIds, list):
            vsysIds = ' '.join(vsysIds)
        result = self.do_action('GetSystemUsage', {'vsysIds': vsysIds})
        return result.date, result.usageinfos


class FGCPGenericEFMHandler:
    """
    Generic Handler for FGCP Get/Update EFM Configuration methods
    """
    _proxy = None
    vsysId = None
    efmId = None

    def __init__(self, proxy, vsysId=None, efmId=None):
        # initialize proxy
        self._proxy = proxy
        self.vsysId = vsysId
        self.efmId = efmId


class FGCPGetEFMConfigHandler(FGCPGenericEFMHandler):
    """
    Handler for FGCP GetEFMConfiguration methods

    Example: fw_nat_rules = proxy.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_nat_rule()
    """
    # CHECKME: pass back the complete firewall or loadbalancer response instead of filtering it out here ?
    def fw_nat_rule(self):
        """
        Usage: fw_nat_rules = proxy.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_nat_rule()
        """
        firewall = self._proxy.GetEFMConfiguration(self.vsysId, self.efmId, 'FW_NAT_RULE')
        if hasattr(firewall, 'nat'):
            # CHECKME: remove <rules> part first
            if isinstance(firewall.nat, list) and len(firewall.nat) == 1:
                return firewall.nat[0]

    def fw_dns(self):
        """
        Usage: fw_dns = proxy.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_dns()
        """
        firewall = self._proxy.GetEFMConfiguration(self.vsysId, self.efmId, 'FW_DNS')
        if hasattr(firewall, 'dns'):
            return firewall.dns

    def fw_policy(self, from_zone=None, to_zone=None):
        """CHECKME: for network identifiers besides INTERNET and INTRANET, see GetVSYSConfiguration()
        Usage: fw_policies = proxy.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_policy(from_zone, to_zone)
        """
        configurationXML = self._proxy._get_configurationXML('firewall_policy', {'from': from_zone, 'to': to_zone})
        firewall = self._proxy.GetEFMConfiguration(self.vsysId, self.efmId, 'FW_POLICY', configurationXML)
        if hasattr(firewall, 'directions') and isinstance(firewall.directions, list):
            #return firewall.directions
            # CHECKME: filter out all general rules with id='50000' ?
            return self._filter_fw_policies(firewall.directions)

    def _filter_fw_policies(self, directions=[]):
        new_directions = []
        for direction in directions:
            if getattr(direction, 'policies', None) is None:
                continue
            new_policies = []
            for policy in direction.policies:
                # CHECKME: filter out all general rules with id='50000' ?
                if getattr(policy, 'id', None) == '50000':
                    continue
                new_policies.append(policy)
            if len(new_policies) > 0:
                direction.policies = new_policies
                new_directions.append(direction)
        return new_directions

    def fw_log(self, num=100, orders=None):
        """CHECKME: for network identifiers besides INTERNET and INTRANET, see GetVSYSConfiguration()
        Usage:
        ipaddress = vsys.publicips[0].address
        orders = [FGCPFWLogOrder(prefix='dst', value=ipaddress, from_zone=None, to_zone=None)]
        fw_log = proxy.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_log(100, orders)
        """
        orders = self._convert_fw_log_orders(orders)
        configurationXML = self._proxy._get_configurationXML('firewall_log', {'num': num, 'orders': orders})
        return self._proxy.GetEFMConfiguration(self.vsysId, self.efmId, 'FW_LOG', configurationXML)

    def _convert_fw_log_orders(self, orders=None):
        if orders is None or len(orders) < 1:
            return None
        new_orders = []
        for order in orders:
            new_orders.append({'order': order.__dict__})
        return new_orders

    def fw_limit_policy(self, from_zone=None, to_zone=None):
        """CHECKME: for network identifiers besides INTERNET and INTRANET, see GetVSYSConfiguration()
        Usage: fw_limit_policy = proxy.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_limit_policy(from_zone, to_zone)
        """
        configurationXML = self._proxy._get_configurationXML('firewall_limit_policy', {'from': from_zone, 'to': to_zone})
        result = self._proxy.GetEFMConfiguration(self.vsysId, self.efmId, 'FW_LIMIT_POLICY', configurationXML)
        # CHECKME: remove <directions> part first
        if isinstance(result, list) and len(result) == 1:
            return result[0]

    def slb_rule(self):
        """
        Usage: slb_rule = proxy.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_rule()
        """
        return self._proxy.GetEFMConfiguration(self.vsysId, self.efmId, 'SLB_RULE')

    def slb_try_getaction(self, action):
        try:
            return self._proxy.GetEFMConfiguration(self.vsysId, self.efmId, action)
        except FGCPResponseError:
            import sys
            e = sys.exc_info()[1]
            if e.status == 'NONE_LB_RULE':
                return
            raise

    def slb_load(self):
        """
        Usage: slb_load_stats = proxy.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_load()
        """
        # CHECKME: this generates an exception with status NONE_LB_RULE if no SLB rules are defined
        #stats = self._proxy.GetEFMConfiguration(self.vsysId, self.efmId, 'SLB_LOAD_STATISTICS').loadStatistics
        result = self.slb_try_getaction('SLB_LOAD_STATISTICS')
        if result is not None and hasattr(result, 'loadStatistics') and len(result.loadStatistics) == 1:
            # CHECKME: remove <groups> part first
            return result.loadStatistics[0]

    def slb_error(self):
        """
        Usage: slb_error_stats = proxy.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_error()
        """
        # CHECKME: this generates an exception with status NONE_LB_RULE if no SLB rules are defined
        #return self._proxy.GetEFMConfiguration(self.vsysId, self.efmId, 'SLB_ERROR_STATISTICS').errorStatistics
        result = self.slb_try_getaction('SLB_ERROR_STATISTICS')
        if result is not None and hasattr(result, 'errorStatistics'):
            return result.errorStatistics

    def slb_cert_list(self, certCategory=None, detail=None):
        """
        Usage: slb_cert_list = proxy.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_cert_list()
        """
        configurationXML = self._proxy._get_configurationXML('loadbalancer_certificate_list', {'certCategory': certCategory, 'detail': detail})
        return self._proxy.GetEFMConfiguration(self.vsysId, self.efmId, 'SLB_CERTIFICATE_LIST', configurationXML)

    def efm_update(self):
        """
        Common method for FW and SLB EFM_UPDATE returns firewall or loadbalancer
        """
        return self._proxy.GetEFMConfiguration(self.vsysId, self.efmId, 'EFM_UPDATE')

    def fw_update(self):
        """
        Usage: fw_update = proxy.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_update()
        """
        return self.efm_update()

    def slb_update(self):
        """
        Usage: slb_update = proxy.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_update()
        """
        return self.efm_update()


class FGCPUpdateEFMConfigHandler(FGCPGenericEFMHandler):
    """
    Handler for FGCP UpdateEFMConfiguration methods

    Example: proxy.UpdateEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_dns('AUTO')
    """
    def fw_nat_rule(self, rules=None):
        """Usage:
        fw_nat_rules = proxy.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_nat_rule()
        proxy.UpdateEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_nat_rule(fw_nat_rules)
        """
        # TODO: add firewall nat rule builder ?
        # round-trip support
        rules = self._convert_fw_nat_rules(rules)
        configurationXML = self._proxy._get_configurationXML('firewall_nat', rules)
        return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'FW_NAT_RULE', configurationXML)

    def _convert_fw_nat_rules(self, rules=None):
        # CHECKME: for round-trip support, we need to:
        clean_rule = ['_proxy', '_parent']
        if rules is None or len(rules) < 1:
            # this resets the NAT and SNAPT rules
            return ''
        elif len(rules) == 1:
            # single rule: use {'rule': {'publicIp': '80.70.163.172', 'snapt': 'true', 'privateIp': '192.168.0.211'}}
            rule = rules[0]
            for key in clean_rule:
                if hasattr(rule, key):
                    delattr(rule, key)
            return {'rule': rule.__dict__}
        else:
            # multiple rules: use [{'rule': {...}}, {'rule': {...}}, ...]
            new_rules = []
            for rule in rules:
                for key in clean_rule:
                    if hasattr(rule, key):
                        delattr(rule, key)
                new_rules.append({'rule': rule.__dict__})
            return new_rules

    def fw_dns(self, dnstype='AUTO', primary=None, secondary=None):
        """
        Usage: proxy.UpdateEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_dns('AUTO')
        """
        configurationXML = self._proxy._get_configurationXML('firewall_dns', {'type': dnstype, 'primary': primary, 'secondary': secondary})
        return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'FW_DNS', configurationXML)

    def fw_policy(self, log='On', directions=None):
        """Usage:
        policies = proxy.GetEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_policy()
        proxy.UpdateEFMConfigHandler(vsys.vsysId, firewall.efmId).fw_policy('On', policies)

        Warning: this overrides the complete firewall configuration, so you need to specify all the policies at once !
        """
        # TODO: add firewall policy builder
        # round-trip support
        directions = self._convert_fw_directions(log, directions)
        configurationXML = self._proxy._get_configurationXML('firewall_policy', {'directions': directions})
        return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'FW_POLICY', configurationXML)

    def _convert_fw_directions(self, log, directions=None):
        # CHECKME: for round-trip support, we need to:
        clean_policy = ['_proxy', '_parent']
        new_directions = []
        # add default log policy to directions
        new_directions.append({'direction': {'policies': {'policy': {'log': log}}}})
        if directions is None:
            return new_directions
        # CHECKME: for round-trip support, we need to:
        for direction in directions:
            # a. add {'direction': {...}} for each {from, to, policies}
            new_direction = {'direction': {}}
            # b. replace 'UU62ICIP-AQYOXXRXS-N-INTERNET' by 'INTERNET' in each from and to
            # CHECKME: direction.from is restricted, so we use getattr() here instead !?
            if not hasattr(direction, 'from') or getattr(direction, 'from') is None:
                pass
            elif getattr(direction, 'from').endswith('-INTERNET'):
                new_direction['direction']['from'] = 'INTERNET'
            elif getattr(direction, 'from').endswith('-INTRANET'):
                new_direction['direction']['from'] = 'INTRANET'
            else:
                new_direction['direction']['from'] = getattr(direction, 'from')
            if not hasattr(direction, 'to') or getattr(direction, 'to') is None:
                pass
            elif direction.to.endswith('-INTERNET'):
                new_direction['direction']['to'] = 'INTERNET'
            elif direction.to.endswith('-INTRANET'):
                new_direction['direction']['to'] = 'INTRANET'
            else:
                new_direction['direction']['to'] = direction.to
            # c. add {'policy': {...}} for each policy
            new_policies = []
            for policy in direction.policies:
                # d. remove all policies with id 50000 = default rule
                if policy.id == '50000':
                    continue
                # e. replace each policy id 46999 by id 999
                elif len(policy.id) > 3:
                    policy.id = policy.id[2:]
                # CHECKME: dump the whole dictionary here ?
                for key in clean_policy:
                    if hasattr(policy, key):
                        delattr(policy, key)
                new_policies.append({'policy': policy.__dict__})
            # if we have anything left, add it to the new directions
            if len(new_policies) > 0:
                new_direction['direction']['policies'] = new_policies
                new_directions.append(new_direction)
        return new_directions

    def slb_rule(self, groups=None, force=None, webAccelerator=None):
        """Usage:
        slb_rule = proxy.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_rule()
        proxy.UpdateEFMConfigHandler(vsys.vsysId, loadbalancer.efmId).slb_rule(slb_rule.groups)

        Warning: this overrides the complete loadbalancer configuration, so you need to specify all the groups at once !
        """
        # TODO: add loadbalancer group builder
        # round-trip support
        groups = self._convert_slb_groups(groups)
        configurationXML = self._proxy._get_configurationXML('loadbalancer_rule', {'groups': groups, 'force': force, 'webAccelerator': webAccelerator})
        return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_RULE', configurationXML)

    def _convert_slb_groups(self, groups=None):
        new_groups = []
        if groups is None:
            return new_groups
        # CHECKME: for round-trip support, we need to:
        clean_group = ['causes', '_proxy', '_parent', 'targets']
        clean_target = ['ipAddress', 'serverName', '_proxy', '_parent']
        for group in groups:
            # a. add {'group': {...}} for each {id, protocol, ..., targets}
            new_group = {'group': {}}
            # b. CHECKME: remove causes ?
            for key in group.__dict__:
                if key not in clean_group:
                    new_group['group'][key] = group.__dict__[key]
            new_targets = []
            # c. add {'target': {...}} for each target
            for target in group.targets:
                new_target = {'target': {}}
                # d. remove ipAddress and serverName from each target
                for key in target.__dict__:
                    if key not in clean_target:
                        new_target['target'][key] = target.__dict__[key]
                new_targets.append(new_target)
            # ...
            # if we have anything left, add it to the new groups
            #if len(new_targets) > 0:
            new_group['group']['targets'] = new_targets
            new_groups.append(new_group)
        return new_groups

    def slb_try_updateaction(self, action):
        try:
            return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, action)
        except FGCPResponseError:
            import sys
            e = sys.exc_info()[1]
            if e.status == 'NONE_LB_RULE':
                return
            raise

    def slb_load_clear(self):
        # CHECKME: this generates an exception with status NONE_LB_RULE if no SLB rules are defined
        #return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_LOAD_STATISTICS_CLEAR')
        return self.slb_try_updateaction('SLB_LOAD_STATISTICS_CLEAR')

    def slb_error_clear(self):
        # CHECKME: this generates an exception with status NONE_LB_RULE if no SLB rules are defined
        #return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_ERROR_STATISTICS_CLEAR')
        return self.slb_try_updateaction('SLB_ERROR_STATISTICS_CLEAR')

    def slb_start_maint(self, id, ipAddress, time=None, unit=None):
        configurationXML = self._proxy._get_configurationXML('loadbalancer_start_maintenance', {'id': id, 'ipAddress': ipAddress, 'time': time, 'unit': unit})
        return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_START_MAINTENANCE', configurationXML)

    def slb_stop_maint(self, id, ipAddress):
        configurationXML = self._proxy._get_configurationXML('loadbalancer_stop_maintenance', {'id': id, 'ipAddress': ipAddress})
        return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_STOP_MAINTENANCE', configurationXML)

    def slb_cert_add(self, certNum, filePath, passphrase):
        """
        Note: server certificates in unencrypted PEM format are NOT supported here, use PKCS12 format (and others ?)
        """
        # when adding SLB server/cca certificates, configurationXML contains the filePath for the actual certificate to be uploaded
        configurationXML = self._proxy._get_configurationXML('loadbalancer_certificate', {'certNum': certNum, 'filePath': filePath, 'passphrase': passphrase})
        return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_CERTIFICATE_ADD', configurationXML, filePath)

    def slb_cert_set(self, certNum, id):
        configurationXML = self._proxy._get_configurationXML('loadbalancer_certificate', {'certNum': certNum, 'id': id})
        return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_CERTIFICATE_SET', configurationXML)

    def slb_cert_release(self, certNum):
        configurationXML = self._proxy._get_configurationXML('loadbalancer_certificate', {'certNum': certNum})
        return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_CERTIFICATE_RELEASE', configurationXML)

    def slb_cert_delete(self, certNum, force=None):
        configurationXML = self._proxy._get_configurationXML('loadbalancer_certificate', {'certNum': certNum, 'force': force})
        return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_CERTIFICATE_DELETE', configurationXML)

    def slb_cca_add(self, ccacertNum, filePath):
        """
        Note: cca certificates in .crt or .pem format ARE supported here (and others ?)
        """
        # when adding SLB server/cca certificates, configurationXML contains the filePath for the actual certificate to be uploaded
        configurationXML = self._proxy._get_configurationXML('loadbalancer_cca_certificate', {'ccacertNum': ccacertNum, 'filePath': filePath})
        return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_CCA_CERTIFICATE_ADD', configurationXML, filePath)

    def slb_cca_delete(self, ccacertNum):
        configurationXML = self._proxy._get_configurationXML('loadbalancer_cca_certificate', {'ccacertNum': ccacertNum})
        return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'SLB_CCA_CERTIFICATE_DELETE', configurationXML)

    def efm_update(self):
        return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'EFM_UPDATE')

    def efm_backout(self):
        return self._proxy.UpdateEFMConfiguration(self.vsysId, self.efmId, 'EFM_BACKOUT')


"""
FGCP API Commands that are not supported in the current API version

class FGCPCommandNotSupported(FGCPCommand):
    def GetVSYSDescriptor(self):
        raise FGCPCommandError('UNSUPPORT_ERROR', 'Unable to use the specified API')

    def CreateVSYSDescriptor(self):
        raise FGCPCommandError('UNSUPPORT_ERROR', 'Unable to use the specified API')

    def RegisterVSYSDescriptor(self):
        raise FGCPCommandError('UNSUPPORT_ERROR', 'Unable to use the specified API')

    def ListVNet(self):
        raise FGCPCommandError('UNSUPPORT_ERROR', 'Unable to use the specified API')

    def CreateVNet(self):
        raise FGCPCommandError('UNSUPPORT_ERROR', 'Unable to use the specified API')

    def GetINet(self):
        raise FGCPCommandError('UNSUPPORT_ERROR', 'Unable to use the specified API')

    def ListProductID(self):
        raise FGCPCommandError('UNSUPPORT_ERROR', 'Unable to use the specified API')

    def RegisterProductID(self):
        raise FGCPCommandError('UNSUPPORT_ERROR', 'Unable to use the specified API')

    def CreateDiskImage(self):
        raise FGCPCommandError('UNSUPPORT_ERROR', 'Unable to use the specified API')

    def RegisterDiskImage(self):
        raise FGCPCommandError('UNSUPPORT_ERROR', 'Unable to use the specified API')

    def ListVNIC(self):
        raise FGCPCommandError('UNSUPPORT_ERROR', 'Unable to use the specified API')

    def CreateVNIC(self):
        raise FGCPCommandError('UNSUPPORT_ERROR', 'Unable to use the specified API')
"""
