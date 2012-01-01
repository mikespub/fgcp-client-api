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
Client Methods for the Fujitsu Global Cloud Platform (FGCP)

Example: [see tests/test_client.py for more examples]

# Connect with your client certificate to region 'uk'
from fgcp.client import FGCPClient
client = FGCPClient('client.pem', 'uk')

# Call custom client methods
client.ShowSystemStatus()

The client methods below are organized by client role, i.e. Monitor, Operator, Designer and Client.

Note: with version 1.0.x and later of the library, most of these client methods can now directly be
replaced by corresponding resource actions.
"""

import time

from fgcp.command import FGCPCommand

from fgcp import FGCPError


class FGCPClientError(FGCPError):
    pass


class FGCPMonitor(FGCPCommand):
    """
    FGCP Monitoring Methods
    """
    _vdc = None

    def getvdc(self):
        if self._vdc is None:
            # get a new VDataCenter object
            from fgcp.resource import FGCPVDataCenter
            self._vdc = FGCPVDataCenter()
            # link it to the current client
            self._vdc._proxy = self
            # cosmetic for repr(vdc)
            self._vdc.config = '%s:%s' % (self.region, self.key_file)
        return self._vdc

    def FindSystemByName(self, vsysName):
        """
        Find VSystem by vsysName

        vsystem = vdc.get_vsystem(vsysName)
        """
        vdc = self.getvdc()
        return vdc.get_vsystem(vsysName)

    def GetSystemInventory(self, vsysName=None):
        """
        Get VSystem inventory (by vsysName)

        vsystems = vdc.list_vsystems()
        inventory = vsystem.get_inventory()
        """
        vdc = self.getvdc()
        if vsysName is None:
            inventory = {}
            inventory['vsys'] = {}
            vsystems = vdc.list_vsystems()
            if len(vsystems) < 1:
                self.show_output('No VSystems are defined')
                return
            for vsystem in vsystems:
                inventory['vsys'][vsystem.vsysName] = vsystem.get_inventory()
            return inventory
        else:
            vsystem = vdc.get_vsystem(vsysName)
            return vsystem.get_inventory()

    def GetSystemStatus(self, vsysName=None, verbose=None):
        """
        Get the overall system status (for a particular VSystem)

        status = vsystem.get_status()
        """
        vdc = self.getvdc()
        # set output
        old_verbose = self.set_verbose(verbose)
        if vsysName is None:
            self.show_output('Show System Status for all VSystems')
            inventory = {}
            inventory['vsys'] = {}
            vsystems = vdc.list_vsystems()
            if len(vsystems) < 1:
                self.show_output('No VSystems are defined')
                return
            for vsystem in vsystems:
                inventory['vsys'][vsystem.vsysName] = vsystem.get_status()
        else:
            vsystem = vdc.get_vsystem(vsysName)
            inventory = vsystem.get_status()
        # reset output
        self.set_verbose(old_verbose)
        # return inventory with status
        return inventory

    def ShowSystemStatus(self, vsysName=None, sep='\t'):
        """
        Show the overall system status (for a particular VSystem)

        vdc.show_vsystem_status()
        vsystem.show_status()
        """
        vdc = self.getvdc()
        if vsysName is None:
            vdc.show_vsystem_status(sep)
        else:
            vsystem = vdc.get_vsystem(vsysName)
            vsystem.show_status(sep)


class FGCPOperator(FGCPMonitor):
    """
    FGCP Operator Methods
    """
    def check_status(self, done_status, pass_status, status_method, *args):
        """
        Call status_method(*args) to see if we get done_status, or something other than pass_status

        Obsolete - included in resource actions
        """
        if not hasattr(self, status_method):
            raise FGCPClientError('ILLEGAL_METHOD', 'Invalid method %s for checking status' % status_method)
        check_status = getattr(self, status_method, None)
        if not callable(check_status):
            raise FGCPClientError('ILLEGAL_METHOD', 'Invalid method %s for checking status' % status_method)
        if isinstance(done_status, str):
            done_list = [done_status]
        else:
            done_list = done_status
        if isinstance(pass_status, str):
            pass_list = [pass_status]
        else:
            pass_list = pass_status
        status = check_status(*args)
        if status in done_list:
            # we're already done so return the status
            return status
        elif status in pass_list:
            # we can continue with whatever needs doing
            return
        else:
            raise FGCPClientError('ILLEGAL_STATE', 'Invalid status %s for %s' % (status, status_method))

    def wait_for_status(self, done_status, wait_status, status_method, *args):
        """
        Call status_method(*args) repeatedly until we get done_status (or something else than wait_status)

        Obsolete - included in resource actions
        """
        if not hasattr(self, status_method):
            raise FGCPClientError('ILLEGAL_METHOD', 'Invalid method %s for checking status' % status_method)
        check_status = getattr(self, status_method, None)
        if not callable(check_status):
            raise FGCPClientError('ILLEGAL_METHOD', 'Invalid method %s for checking status' % status_method)
        if isinstance(done_status, str):
            done_list = [done_status]
        else:
            done_list = done_status
        if isinstance(wait_status, str):
            wait_list = [wait_status]
        else:
            wait_list = wait_status
        # wait until we get the done_status - TODO: add some timeout
        while True:
            time.sleep(10)
            status = check_status(*args)
            if status in done_list:
                return status
            elif status in wait_list:
                pass
            else:
                raise FGCPClientError('ILLEGAL_STATE', '%s returned unexpected status %s while %s' % (status_method, status, wait_status))
        return status

    def StartVServerAndWait(self, vsysId, vserverId):
        """
        Start VServer and wait until it's running

        result = vserver.start(wait=True)
        """
        vdc = self.getvdc()
        vsystem = vdc.get_vsystem(vsysId)
        vserver = vsystem.get_vserver(vserverId)
        # start vserver
        status = vserver.start(wait=True)
        return status

    def StopVServerAndWait(self, vsysId, vserverId, force=None):
        """
        Stop VServer and wait until it's stopped

        result = vserver.stop(wait=True, force=None)
        """
        vdc = self.getvdc()
        vsystem = vdc.get_vsystem(vsysId)
        vserver = vsystem.get_vserver(vserverId)
        # stop vserver
        status = vserver.stop(wait=True, force=force)
        return status

    def StartEFMAndWait(self, vsysId, efmId):
        """
        Start EFM and wait until it's running

        result = loadbalancer.start(wait=True)
        """
        vdc = self.getvdc()
        vsystem = vdc.get_vsystem(vsysId)
        try:
            efm = vsystem.get_loadbalancer(efmId)
        except:
            efm = vsystem.get_firewall(efmId)
        # start efm
        status = efm.start(wait=True)
        return status

    def StopEFMAndWait(self, vsysId, efmId):
        """
        Stop EFM and wait until it's stopped

        result = loadbalancer.stop(wait=True)
        """
        vdc = self.getvdc()
        vsystem = vdc.get_vsystem(vsysId)
        try:
            efm = vsystem.get_loadbalancer(efmId)
        except:
            efm = vsystem.get_firewall(efmId)
        # stop efm
        status = efm.stop(wait=True)
        return status

    def AttachPublicIPAndWait(self, vsysId, publicIp):
        """
        Attach PublicIP and wait until it's attached

        result = publicip.attach(wait=True)
        """
        vdc = self.getvdc()
        vsystem = vdc.get_vsystem(vsysId)
        ip = vsystem.get_publicip(publicIp)
        # attach publicip
        status = ip.attach(wait=True)
        return status

    def DetachPublicIPAndWait(self, vsysId, publicIp):
        """
        Detach PublicIP and wait until it's detached

        result = publicip.detach(wait=True)
        """
        vdc = self.getvdc()
        vsystem = vdc.get_vsystem(vsysId)
        ip = vsystem.get_publicip(publicIp)
        # detach publicip
        status = ip.detach(wait=True)
        return status

    def BackupVDiskAndWait(self, vsysId, vdiskId):
        """
        Take Backup of VDisk and wait until it's finished (this might take a while)

        result = vdisk.backup(wait=True)
        """
        vdc = self.getvdc()
        vsystem = vdc.get_vsystem(vsysId)
        vdisk = vsystem.get_vdisk(vdiskId)
        # backup vdisk
        status = vdisk.backup(wait=True)
        return status

    def BackupVServerAndRestart(self, vsysId, vserverId):
        """
        Backup all VDisks of a VServer and restart the VServer (this might take a while)

        result = vserver.backup(wait=True)
        for vdisk in vserver.list_vdisks():
            result = vdisk.backup(wait=True)
        result = vserver.start(wait=True)
        """
        vdc = self.getvdc()
        vsystem = vdc.get_vsystem(vsysId)
        vserver = vsystem.get_vserver(vserverId)
        # stop server and backup system disk
        status = vserver.backup(wait=True)
        # backup other vdisks
        for vdisk in vserver.list_vdisks():
            status = vdisk.backup(wait=True)
        # start server
        status = vserver.start(wait=True)
        return status

    # TODO: set expiration date + max. number
    def CleanupBackups(self, vsysId, vdiskId=None):
        """
        Clean up old VDisk backups e.g. to minimize disk space

        result = vdisk.cleanup_backups(max_num=100, max_age=None)
        """
        vdc = self.getvdc()
        vsystem = vdc.get_vsystem(vsysId)
        if vdiskId is None:
            vdisks = vsystem.list_vdisks()
            for vdisk in vdisks:
                vdisk.cleanup_backups()
        else:
            vdisk = vsystem.get_vdisk(vdiskId)
            vdisk.cleanup_backups()

    def StartSystem(self, vsysName, verbose=None):
        """
        Start VSystem and wait until all VServers and EFMs are started (TODO: define start sequence for vservers)

        vsystem.boot(wait=True)
        vsystem.start(wait=True)
        """
        vdc = self.getvdc()
        vsystem = vdc.get_vsystem(vsysName)
        # Set output
        old_verbose = self.set_verbose(verbose)
        vsystem.boot(wait=True)
        vsystem.start(wait=True)
        # Reset output
        self.set_verbose(old_verbose)

    def StopSystem(self, vsysName, verbose=None):
        """
        Stop VSystem and wait until all VServers and EFMs are stopped (TODO: define stop sequence for vservers)

        vsystem.stop(wait=True)
        vsystem.shutdown(wait=True)
        """
        vdc = self.getvdc()
        vsystem = vdc.get_vsystem(vsysName)
        # Set output
        old_verbose = self.set_verbose(verbose)
        vsystem.stop(wait=True)
        vsystem.shutdown(wait=True)
        # Reset output
        self.set_verbose(old_verbose)


class FGCPDesigner(FGCPOperator):
    """
    FGCP Designer Methods
    """
    def FindDiskImageByName(self, diskimageName):
        """
        Find DiskImage by diskimageName

        diskimage = vdc.get_diskimage(diskimageName)
        """
        vdc = self.getvdc()
        diskimage = vdc.get_diskimage(diskimageName)
        return diskimage

    def FindVSYSDescriptorByName(self, vsysdescriptorName):
        """
        Find VSYSDescriptor by vsysdescriptorName

        vsysdescriptor = vdc.get_vsysdescriptor(vsysdescriptorName)
        """
        vdc = self.getvdc()
        vsysdescriptor = vdc.get_vsysdescriptor(vsysdescriptorName)
        return vsysdescriptor

    def FindServerTypeByName(self, name):
        """
        Find ServerType by name

        servertype = vdc.get_servertype(name)
        """
        #vdc = self.getvdc()
        #servertype = vdc.get_servertype(name)
        return name

    def CreateSystem(self, vsysName, vsysdescriptorName, verbose=None):
        """
        Create VSystem based on descriptor and wait until it's deployed

        vsysId = vdc.create_vsystem(vsysName, vsysdescriptorName, wait=True)
        """
        vdc = self.getvdc()
        # Set output
        old_verbose = self.set_verbose(verbose)
        # Create VSystem
        vsysId = vdc.create_vsystem(vsysName, vsysdescriptorName, wait=True)
        # Reset output
        self.set_verbose(old_verbose)
        return vsysId

    def DestroySystem(self, vsysName, verbose=None):
        """
        Destroy VSystem after stopping all VServers and EFMs

        vdc.destroy_vsystem(vsysName, wait=True)
        """
        vdc = self.getvdc()
        # Set output
        old_verbose = self.set_verbose(verbose)
        # Destroy VSystem
        vdc.destroy_vsystem(vsysName, wait=True)
        # Reset output
        self.set_verbose(old_verbose)

    def LoadSystemDesign(self, filePath, verbose=None):
        """
        Load VSystem design from file, for use e.g. in ConfigureSystem()

        design = vdc.get_vsystem_design()
        design.load_file(filePath)
        #design.build_vsystem(vsysName)
        """
        vdc = self.getvdc()
        # Set output
        old_verbose = self.set_verbose(verbose)
        # Load system design from file
        design = vdc.get_vsystem_design()
        design.load_file(filePath)
        # Reset output
        self.set_verbose(old_verbose)
        # Return system design
        return design

    def ConfigureSystem(self, vsysName, systemDesign, verbose=None):
        """
        Configure VSystem based on some systemDesign - see LoadSystemDesign()

        #design = vdc.get_vsystem_design()
        #design.load_file(filePath)
        design.build_vsystem(vsysName)
        """
        # Set output
        old_verbose = self.set_verbose(verbose)
        # Build VSystem
        systemDesign.build_vsystem(vsysName)
        # Reset output
        self.set_verbose(old_verbose)

    def SaveSystemDesign(self, vsysName, filePath, verbose=None):
        """
        Save (fixed parts of) VSystem design to file

        design = vdc.get_vsystem_design()
        design.load_vsystem(vsysName)
        design.save_file(filePath)
        """
        vdc = self.getvdc()
        # Set output
        old_verbose = self.set_verbose(verbose)
        # Save system design to file
        design = vdc.get_vsystem_design()
        design.load_vsystem(vsysName)
        design.save_file(filePath)
        # Reset output
        self.set_verbose(old_verbose)


class FGCPClient(FGCPDesigner):
    """
    FGCP Client Methods

    Example:
    # Connect with your client certificate in region 'uk'
    from fgcp.client import FGCPClient
    client = FGCPClient('client.pem', 'uk')

    # Backup all VServers in some VSystem
    vsys = client.GetSystemInventory('Python API Demo System')
    for vserver in vsys.vservers:
        client.BackupVServerAndRestart(vsys.vsysId, vserver.vserverId)
    client.CleanupBackups(vsys.vsysId)

    # Note: you can also use all API commands from FGCPCommand()
    vsystems = client.ListVSYS()
    for vsys in vsystems:
        vsysconfig = client.GetVSYSConfiguration(vsys.vsysId)
        ...
    """
    pass
