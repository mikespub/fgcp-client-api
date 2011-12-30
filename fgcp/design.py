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
VSystem Design for the Fujitsu Global Cloud Platform (FGCP)

Example: [see tests/test_resource.py for more examples]

# Connect with your client certificate to region 'uk'
from fgcp.resource import FGCPVDataCenter
vdc = FGCPVDataCenter('client.pem', 'uk')

# Get VSystem Design from file and build new VSystem based on it (TODO)
design = vdc.get_vsystem_design('fgcp_demo_system.txt')
#design.build('My New VSystem')
#design.save('My New VSystem', 'new_demo_system.txt')
"""

import time

from fgcp import FGCPError
from fgcp.resource import FGCPResource, FGCPResourceError


class FGCPDesignError(FGCPError):
    """
    Exception class for FGCP Design Errors
    """
    def __init__(self, status, message, resource=None):
        self.status = status
        self.message = message
        self.resource = resource

    def __str__(self):
        return '\nStatus: %s\nMessage: %s\nResource: %s' % (self.status, self.message, repr(self.resource))


class FGCPDesign(FGCPResource):
    """
    FGCP VSystem Design
    """
    _idname = 'filePath'

    def load(self, filePath=None):
        if filePath is not None:
            self.filePath = filePath
        self.show_output('Loading VSystem design from file %s' % self.filePath)
        import os.path
        if not os.path.exists(self.filePath):
            raise FGCPDesignError('INVALID_PATH', 'File %s does not seem to exist' % self.filePath)
        f = open(self.filePath, 'r')
        lines = f.read()
        f.close()
        # check if we have something we need, i.e. a FGCPSys() instance
        if not lines.startswith('FGCPVSystem('):
            raise FGCPDesignError('INVALID_FORMAT', 'File %s does not seem to start with FGCPSystem(' % self.filePath)
        # CHECKME: add line continuations before exec() !?
        try:
            # Note: FGCPElement().pformat() writes objects initialized with the right values
            exec 'from fgcp.resource import *\nvsystem = ' + lines.replace("\r\n", "\\\r\n")
        except:
            #raise FGCPDesignError('INVALID_FORMAT', 'File %s seems to have some syntax errors' % self.filePath)
            raise
        self.show_output('Loaded VSystem design for %s from file %s' % (vsystem.vsysName, self.filePath))
        try:
            # check if VDataCenter already has a vsystem with the same name
            found = self._parent.get_vsystem(vsystem.vsysName)
            self.show_output('CAUTION: you already have a VSystem called %s' % vsystem.vsysName)
        except FGCPResourceError:
            pass
        # set the vsystem parent to the vdatacenter
        vsystem.setparent(self._parent)
        # return vsystem
        self.vsystem = vsystem
        return vsystem

    def build(self, vsystem=None):
        # if we already have a vsystem in the design, see if the one we got here is different ?
        if hasattr(self, 'vsystem'):
            pass

    def save(self, vsystem=None, filePath=None):
        if vsystem is not None:
            # let VDataCenter find the right vsystem
            self.vsystem = self._parent.get_vsystem(vsystem)
        if filePath is not None:
            self.filePath = filePath
        self.show_output('Saving VSystem design for %s to file %s' % (vsystem.vsysName, self.filePath))
        """
        TODO: Save (fixed parts of) VSystem design to file
        """
        # get system inventory
        vsys = self.GetSystemInventory(vsysName)
        # set output
        old_verbose = self.set_verbose(verbose)
        self.show_output('Saving VSystem design for %s to file %s' % (vsysName, filePath))
        # CHECKME: is description always the name correspoding to baseDescriptor ?
        seenip = {}
        # replace addresses and other variable information
        idx = 1
        #new_publicips = []
        for publicip in vsys.publicips:
            seenip[publicip.address] = 'publicip.%s' % idx
            idx += 1
            #publicip.address = 'xxx.xxx.xxx.xxx'
            #new_publicips.append(publicip)
        #vsys.publicips = new_publicips
        from fgcp.resource import FGCPFirewall
        new_firewalls = []
        for firewall in vsys.firewalls:
            # TODO: Add FW and SLB configurations
            setattr(firewall, 'firewall', FGCPFirewall())
            handler = self.GetEFMConfigHandler(vsys.vsysId, firewall.efmId)
            setattr(firewall.firewall, 'nat', handler.fw_nat_rule())
            setattr(firewall.firewall, 'dns', handler.fw_dns())
            setattr(firewall.firewall, 'directions', handler.fw_policy())
            new_firewalls.append(firewall)
        vsys.firewalls = new_firewalls
        #from fgcp.resource import FGCPLoadBalancer
        new_loadbalancers = []
        for loadbalancer in vsys.loadbalancers:
            seenip[loadbalancer.slbVip] = loadbalancer.efmName
            #loadbalancer.slbVip = 'xxx.xxx.xxx.xxx'
            # TODO: Add FW and SLB configurations
            handler = self.GetEFMConfigHandler(vsys.vsysId, loadbalancer.efmId)
            setattr(loadbalancer, 'loadbalancer', handler.slb_rule())
            new_loadbalancers.append(loadbalancer)
        vsys.loadbalancers = new_loadbalancers
        # get mapping of diskimage id to name
        diskimages = self.ListDiskImage()
        imageid2name = {}
        for diskimage in diskimages:
            imageid2name[diskimage.diskimageId] = diskimage.diskimageName
        new_vservers = []
        for vserver in vsys.vservers:
            # CHECKME: use diskimage name as reference across regions !?
            setattr(vserver, 'diskimageName', imageid2name[vserver.diskimageId])
            #new_vnics = []
            for vnic in vserver.vnics:
                seenip[vnic.privateIp] = vserver.vserverName
                #vnic.privateIp = 'xxx.xxx.xxx.xxx'
                #new_vnics.append(vnic)
            #vserver.vnics = new_vnics
            #new_vdisks = []
            #for vdisk in vserver.vdisks:
            #    new_vdisks.append(vdisk)
            #vserver.vdisks = new_vdisks
            new_vservers.append(vserver)
        vsys.vservers = new_vservers
        #new_vdisks = []
        #for vdisk in vsys.vdisks:
        #    new_vdisks.append(vdisk)
        #vsys.vdisks = new_vdisks
        # Prepare for output - FGCPElement().pformat() writes objects initialized with the right values
        lines = vsys.pformat(vsys)
        # Replace vsysId and creator everywhere (including Id's)
        lines = lines.replace(vsys.vsysId, 'DEMO-VSYSTEM')
        lines = lines.replace(vsys.creator, 'DEMO')
        # CHECKME: replace ip addresses with names everywhere, including firewall policies and loadbalancer rules
        for ip in seenip.keys():
            lines = lines.replace(ip, seenip[ip])
        # CHECKME: fix from=... issue for firewall policies
        lines = lines.replace('from=', 'from_zone=')
        lines = lines.replace('to=', 'to_zone=')
        # Write configuration to file
        f = open(filePath, 'wb')
        f.write(lines)
        f.close()
        self.show_output('Saved VSystem design for %s to file %s' % (vsysName, filePath))
        # Reset output
        self.set_verbose(old_verbose)
