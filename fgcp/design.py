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

# Get VSystem Design from an existing vsystem or file, and build a new vsystem with it (TODO)
design = vdc.get_vsystem_design('Demo System')
#design.load_file('fgcp_demo_system.txt')
#design.build_vsystem('My New Demo System')
#design.load_vsystem('Demo System')
design.save_file('new_demo_system.txt')
"""

import time

from fgcp import FGCPError
from fgcp.resource import FGCPElement, FGCPResource, FGCPResourceError


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
    _idname = 'vsysName'
    filePath = None
    vsysName = None
    vsystem = None

    def from_code(self, lines):
        # CHECKME: add line continuations before exec() !?
        try:
            # Note: FGCPElement().pformat() writes objects initialized with the right values
            exec 'from fgcp.resource import *\nvsystem = ' + lines.replace("\r\n", "\\\r\n")
        except:
            #raise FGCPDesignError('INVALID_FORMAT', 'File %s seems to have some syntax errors' % self.filePath)
            raise
        return vsystem

    def to_code(self, what):
        # FGCPElement().pformat() writes objects initialized with the right values
        return self.pformat(what)

    def from_yaml(self, lines):
        # TODO: import from yaml :-)
        from fgcp.resource import FGCPVSystem
        return FGCPVSystem(vsysName='TODO: import from yaml', description='This library does not support importing from yaml files yet')

    def to_yaml(self, what, depth=0, suffix=''):
        if isinstance(what, FGCPResource):
            # convert to dict recursively first
            what = self.to_var(what)
        L = []
        prefix = '  ' * depth
        # See http://yaml.org/spec/1.1/
        # Mapping of ...
        if isinstance(what, dict):
            keylist = what.keys()
            keylist.sort()
            for key in keylist:
                if key == '_class':
                    L.append('%s# %s%s' % (prefix, what[key], suffix))
                # ... mappings
                elif isinstance(what[key], dict):
                    L.append('%s%s: {' % (prefix, key))
                    # CHECKME: add , after each entry !
                    L.append(self.to_yaml(what[key], depth + 1, ','))
                    L.append('%s}%s' % (prefix, suffix))
                # ... sequences
                elif isinstance(what[key], list):
                    L.append('%s%s:' % (prefix, key))
                    L.append(self.to_yaml(what[key], depth + 1))
                    # CHECKME: no suffix here ???
                # ... scalars
                else:
                    L.append('%s%s: %s%s' % (prefix, key, what[key], suffix))
        # Sequence of ...
        elif isinstance(what, list):
            if len(what) == 0:
                return
            # ... mappings
            elif isinstance(what[0], dict):
                for item in what:
                    if '_class' in item:
                        L.append('%s- # %s' % (prefix, item['_class']))
                        del item['_class']
                    else:
                        L.append('%s-' % prefix)
                    L.append(self.to_yaml(item, depth + 1))
            # ... sequences
            elif isinstance(what[0], list):
                for item in what:
                    L.append('%s- [' % prefix)
                    # CHECKME: add , after each entry
                    for entry in item:
                        L.append(self.to_yaml(entry, depth + 1) + ',')
                    L.append('%s]' % prefix)
            # ... scalars
            else:
                for item in what:
                    L.append('%s- %s' % (prefix, item))
        # Scalar
        else:
            L.append('%s%s' % (prefix, what))
        return '\r\n'.join(L)

    def to_var(self, what):
        if isinstance(what, FGCPElement):
            # convert to dict and add _class
            new_what = {'_class': type(what).__name__}
            keylist = what.__dict__.keys()
            for key in keylist:
                # skip internal attributes
                if key.startswith('_') and key != '_status':
                    continue
                new_what[key] = self.to_var(what.__dict__[key])
            return new_what
        elif isinstance(what, dict):
            new_what = {}
            keylist = what.keys()
            for key in keylist:
                # skip internal keys
                #if key.startswith('_'):
                #    continue
                new_what[key] = self.to_var(what[key])
            return new_what
        elif isinstance(what, list):
            new_what = []
            for item in what:
                new_what.append(self.to_var(item))
            return new_what
        else:
            # str, int, float etc. are returned as is
            return what

    def load_file(self, filePath):
        """
        Load VSystem Design from file
        """
        self.filePath = filePath
        self.show_output('Loading VSystem Design from file %s' % self.filePath)
        import os.path
        if self.filePath is None or not os.path.exists(self.filePath):
            raise FGCPDesignError('INVALID_PATH', 'File %s does not seem to exist' % self.filePath)
        f = open(self.filePath, 'r')
        lines = f.read()
        f.close()
        # check if we have something we need, i.e. a FGCPSys() instance or # FGCPVSystem comment line
        if lines.startswith('FGCPVSystem('):
            format = 'txt'
            vsystem = self.from_code(lines)
        elif lines.startswith('#'):
            format = 'yaml'
            # TODO :-)
            vsystem = self.from_yaml(lines)
        else:
            raise FGCPDesignError('INVALID_FORMAT', 'File %s does not seem to start with FGCPSystem(' % self.filePath)
        self.show_output('Loaded VSystem Design for %s from file %s' % (vsystem.vsysName, self.filePath))
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
        self.vsysName = self.vsystem.vsysName
        return self.vsystem

    def load_vsystem(self, vsystem):
        """
        Load VSystem Design from vsystem
        """
        # let VDataCenter find the right vsystem
        self.vsystem = self._parent.get_vsystem(vsystem)
        self.show_output('Loading VSystem Design from vsystem %s' % self.vsystem.vsysName)
        # update vsystem inventory if necessary
        self.vsystem.get_inventory()
        self.vsysName = self.vsystem.vsysName
        return self.vsystem

    def build_vsystem(self, vsysName=None, filePath=None):
        """
        Build new VSystem based on loaded VSystem Design
        """
        if filePath is not None:
            self.load_file(filePath)
        # check that we have a vsystem design in memory
        if self.vsystem is None:
            raise FGCPDesignError('INVALID_VSYSTEM', 'No VSystem Design has been loaded')
        if vsysName is None:
            self.vsysName = 'New %s' % self.vsystem.vsysName
        else:
            self.vsysName = vsysName
        self.show_output('Building VSystem %s based on %s' % (self.vsysName, self.vsystem.vsysName))
        # 1. check that the base descriptor exists
        vsysdescriptor = self._parent.get_vsysdescriptor(self.vsystem.baseDescriptor)
        # 2. check if the new vsystem already exists
        try:
            new_vsystem = self._parent.get_vsystem(self.vsysName)
        except FGCPResourceError:
            # 3. create it if necessary
            vsysId = vsysdescriptor.create_vsystem(self.vsysName, wait=True)
            # retrieve the newly created vsystem
            new_vsystem = self._parent.get_vsystem(self.vsysName)
        # 4. boot vsystem if necessary
        new_vsystem.boot(wait=True)
        # 5. allocate more publicips as needed
        self.show_output('Checking PublicIPs')
        new_ips = len(new_vsystem.publicips)
        orig_ips = len(self.vsystem.publicips)
        if new_ips < orig_ips:
            while new_ips < orig_ips:
                new_vsystem.allocate_publicip(wait=True)
                new_ips = len(new_vsystem.publicips)
            # 6. attach publicips if necessary
            for publicip in new_vsystem.publicips:
                publicip.attach(wait=True)
        # 7. find missing vservers based on vserverName
        self.show_output('Checking VServers')
        new_vservers = {}
        for vserver in new_vsystem.vservers:
            new_vservers[vserver.vserverName] = vserver
        orig_vservers = {}
        for vserver in self.vsystem.vservers:
            orig_vservers[vserver.vserverName] = vserver
        for vserverName in orig_vservers:
            if vserverName in new_vservers:
                continue
            self.show_output('Creating VServer %s: %s' % (vserverName, orig_vservers[vserverName]))
            servertype = orig_vservers[vserverName].vserverType
            # note: use the diskimage name here, rather than the diskimage id
            diskimage = orig_vservers[vserverName].diskimageName
            # get the last part of the newtworkId as vnet (= DMZ, SECURE1, SECURE2 etc.)
            vnet = orig_vservers[vserverName].vnics[0].getid().split('-').pop()
            self.show_output('with parameters: %s, %s, %s, %s' % (vserverName, servertype, diskimage, vnet))
            # 8. let the new vsystem create the vserver - it will convert the parameters correctly
            new_vsystem.create_vserver(vserverName, servertype, diskimage, vnet, wait=True)
        # 9. find missing vdisks based on vdiskName
        self.show_output('Checking VDisks')
        new_vdisks = {}
        for vdisk in new_vsystem.vdisks:
            new_vdisks[vdisk.vdiskName] = vdisk
        orig_vdisks = {}
        for vdisk in self.vsystem.vdisks:
            orig_vdisks[vdisk.vdiskName] = vdisk
        for vdiskName in orig_vdisks:
            if vdiskName in new_vdisks:
                continue
            self.show_output('Creating VDisk %s: %s' % (vdiskName, orig_vdisks[vdiskName]))
            size = orig_vdisks[vdiskName].size
            self.show_output('with parameters: %s, %s' % (vdiskName, size))
            # 10. let the new vsystem create the vdisk - it will convert the parameters correctly
            new_vsystem.create_vdisk(vdiskName, size, wait=True)
        # 11. find missing loadbalancers based on efmName
        self.show_output('Checking LoadBalancers')
        new_loadbalancers = {}
        for loadbalancer in new_vsystem.loadbalancers:
            new_loadbalancers[loadbalancer.efmName] = loadbalancer
        orig_loadbalancers = {}
        for loadbalancer in self.vsystem.loadbalancers:
            orig_loadbalancers[loadbalancer.efmName] = loadbalancer
        for efmName in orig_loadbalancers:
            if efmName in new_loadbalancers:
                continue
            self.show_output('Creating LoadBalancer %s: %s' % (efmName, orig_loadbalancers[efmName]))
            orig_loadbalancers[efmName].pprint()
            slbVip = orig_loadbalancers[efmName].slbVip
            self.show_output('with parameters: %s, %s' % (efmName, slbVip))
            # 12. let the new vsystem create the loadbalancer - it will convert the parameters correctly
            # CHECKME: the only way to know in which vnet this SLB is located, is via the slbVip (which is translated to the efmName in design files) ???
            # FIXME; assume they're all in the DMZ at the moment !?
            new_vsystem.create_loadbalancer(efmName, 'DMZ', wait=True)
        # 13. refresh vserver and vdisk list
        new_vsystem.get_inventory(refresh=True)
        # TODO: attach the new vdisk to the right vserver !?
        # TODO: remap FW and SLB rules and update them !?
        self.show_output('Configured VSystem %s' % self.vsysName)

    def save_file(self, filePath, format='txt'):
        """
        Save VSystem Design to file
        """
        self.filePath = filePath
        import os.path
        if self.filePath is None or os.path.isdir(self.filePath):
            raise FGCPDesignError('INVALID_PATH', 'File %s is invalid for output' % self.filePath)
        # check that we have a vsystem design in memory
        if self.vsystem is None:
            raise FGCPDesignError('INVALID_VSYSTEM', 'No VSystem Design has been loaded')
        # update vsystem inventory if necessary
        self.vsystem.get_inventory()
        self.show_output('Saving VSystem Design for %s to file %s' % (self.vsystem.vsysName, self.filePath))
        # CHECKME: is description always the name correspoding to baseDescriptor ?
        seenip = {}
        # replace addresses and other variable information
        idx = 1
        #new_publicips = []
        for publicip in self.vsystem.publicips:
            seenip[publicip.address] = 'publicip.%s' % idx
            idx += 1
            #publicip.address = 'xxx.xxx.xxx.xxx'
            #new_publicips.append(publicip)
        #self.vsystem.publicips = new_publicips
        from fgcp.resource import FGCPFirewall
        new_firewalls = []
        for firewall in self.vsystem.firewalls:
            # in case we didn't load this from file
            if getattr(firewall, 'nat', None) is None:
                firewall.get_nat_rules()
            if getattr(firewall, 'dns', None) is None:
                firewall.get_dns()
            if getattr(firewall, 'directions', None) is None:
                firewall.get_policies(from_zone=None, to_zone=None)
            new_firewalls.append(firewall)
        self.vsystem.firewalls = new_firewalls
        #from fgcp.resource import FGCPLoadBalancer
        new_loadbalancers = []
        for loadbalancer in self.vsystem.loadbalancers:
            seenip[loadbalancer.slbVip] = loadbalancer.efmName
            #loadbalancer.slbVip = 'xxx.xxx.xxx.xxx'
            # in case we didn't load this from file
            if getattr(loadbalancer, 'groups', None) is None:
                loadbalancer.get_rules()
            new_loadbalancers.append(loadbalancer)
        self.vsystem.loadbalancers = new_loadbalancers
        # get mapping of diskimage id to name
        diskimages = self._parent.list_diskimages()
        imageid2name = {}
        for diskimage in diskimages:
            imageid2name[diskimage.diskimageId] = diskimage.diskimageName
        new_vservers = []
        for vserver in self.vsystem.vservers:
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
        self.vsystem.vservers = new_vservers
        #new_vdisks = []
        #for vdisk in self.vsystem.vdisks:
        #    new_vdisks.append(vdisk)
        #self.vsystem.vdisks = new_vdisks
        # Prepare for output - FGCPElement().pformat() writes objects initialized with the right values
        if format == 'txt':
            lines = self.to_code(self.vsystem)
        else:
            lines = self.to_yaml(self.vsystem)
        # Replace vsysId and creator everywhere (including Id's)
        lines = lines.replace(self.vsystem.vsysId, 'DEMO-VSYSTEM')
        lines = lines.replace(self.vsystem.creator, 'DEMO')
        # CHECKME: replace ip addresses with names everywhere, including firewall policies and loadbalancer rules
        for ip in seenip.keys():
            lines = lines.replace(ip, seenip[ip])
        # CHECKME: fix from=... issue for firewall policies
        if format == 'txt':
            lines = lines.replace('from=', 'from_zone=')
            lines = lines.replace('to=', 'to_zone=')
        # Write configuration to file
        f = open(self.filePath, 'wb')
        f.write(lines)
        f.close()
        self.show_output('Saved VSystem Design for %s to file %s' % (self.vsystem.vsysName, self.filePath))
