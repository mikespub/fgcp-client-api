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

import sys, time

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

    def from_json(self, lines, parent=None):
        try:
            import simplejson as json
        except:
            import json
        var = json.loads(lines)
        return self.from_var(var, parent)

    def to_json(self, what, indent=None):
        try:
            import simplejson as json
        except:
            import json
        var = self.to_var(what)
        return json.dumps(var, indent=indent, encoding='utf-8')

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

    def from_var(self, what, parent=None):
        if isinstance(what, dict):
            # convert to class based on _class
            if '_class' not in what:
                raise FGCPDesignError('INVALID_FORMAT', 'The dictionary does not contain a _class key:\n%s' % repr(what), self)
            #new_what = what['_class']()
            if not hasattr(sys.modules['fgcp.resource'], what['_class']):
                raise FGCPDesignError('INVALID_FORMAT', 'The dictionary contains invalid _class key %s:\n%s' % (what['_class'], repr(what)), self)
            klass = getattr(sys.modules['fgcp.resource'], what['_class'])
            new_what = klass()
            # CHECKME: add parent and proxy to the FGCP Resource
            new_what.setparent(parent)
            keylist = what.keys()
            for key in keylist:
                if key == '_class':
                    continue
                setattr(new_what, key, self.from_var(what[key], new_what))
            return new_what
        elif isinstance(what, list):
            new_what = []
            for item in what:
                new_what.append(self.from_var(item, parent))
            return new_what
        else:
            # str, int, float etc. are returned as is
            return what

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
        elif lines.startswith('{'):
            format = 'json'
            #vsystem = self.from_json(lines, self._parent)
            vsystem = self.from_json(lines)
        elif lines.startswith('#'):
            format = 'yaml'
            # TODO :-)
            vsystem = self.from_yaml(lines)
        else:
            raise FGCPDesignError('INVALID_FORMAT', 'File %s does not seem to start with FGCPSystem(' % self.filePath)
        self.show_output('Loaded VSystem Design for %s from file %s' % (vsystem.vsysName, self.filePath))
        try:
            # check if VDataCenter already has a vsystem with the same name - TODO: deal with offline case, cfr. vdc.json
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

    def save_file(self, filePath, format='txt', replaceIps=True):
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
                firewall.list_nat_rules()
                firewall.get_dns()
                firewall.list_policies()
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
            if vserver.diskimageId in imageid2name:
                setattr(vserver, 'diskimageName', imageid2name[vserver.diskimageId])
            else:
                setattr(vserver, 'diskimageName', vserver.diskimageId)
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
        elif format == 'json':
            lines = self.to_json(self.vsystem, indent=2)
        else:
            lines = self.to_yaml(self.vsystem)
        # Replace vsysId and creator everywhere (including Id's)
        lines = lines.replace(self.vsystem.vsysId, 'DEMO-VSYSTEM')
        lines = lines.replace(self.vsystem.creator, 'DEMO')
        # CHECKME: replace ip addresses with names everywhere, including firewall policies and loadbalancer rules
        if replaceIps:
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

    def load_vdc(self, filePath='vdc.json'):
        f = open(filePath, 'r')
        lines = f.read()
        f.close()
        self._parent = self.from_json(lines)
        return self._parent

    def save_vdc(self, filePath='vdc.json'):
        self._parent.list_vsystems()
        self._parent.list_vsysdescriptors()
        self._parent.list_diskimages()
        self._parent.list_servertypes()
        self._parent.list_publicips()
        self._parent.list_addressranges()
        #self._parent.list_users()
        lines = self.to_json(self._parent, indent=2)
        contractor = self._parent.get_contractor()
        lines = lines.replace(contractor.contract, 'DEMO')
        f = open(filePath, 'wb')
        f.write(lines)
        f.close()


class FGCPVisual(FGCPDesign):
    """
    FGCP Visual for use with vis.js and other visualisation tools
    """
    header = []
    table = []
    nodes = []
    edges = []
    layout = None
    direction = None
    node_idx = 0
    target_idx = {}

    def start(self, vsystem=None):
        if vsystem:
            self.load_vsystem(vsystem)
        self.header = []
        self.table = []
        self.nodes = []
        self.edges = []
        self.layout = None
        self.direction = None
        self.node_idx = 0
        self.target_idx = {}

    def link_nodes(self, from_idx, to_idx, arrows=False, label=None):
        edge = {'from': from_idx, 'to': to_idx} 
        if arrows:
            edge['arrows'] = 'middle'
            #self.edges.append({'from': from_idx, 'to': to_idx, 'arrows': 'middle'})
        if label and label != 'any':
            edge['label'] = label
        #self.edges.append({'from': from_idx, 'to': to_idx})
        self.edges.append(edge)

    def get_node_idx(self, label):
        if label in self.target_idx:
            return self.target_idx[label]
        # TODO: map class name to attribute to search for
        return

    def add_node(self, label, color=None, shape=None, group=None, descr=None, unique=True):
        if unique and label in self.target_idx:
            return self.target_idx[label]
        self.node_idx += 1
        if descr:
            node = {'id': self.node_idx, 'label': label + '\n' + descr}
        else:
            node = {'id': self.node_idx, 'label': label}
        if color:
            node['color'] = color
        if shape:
            node['shape'] = shape
        if group:
            node['group'] = group
        self.nodes.append(node)
        if unique:
            self.target_idx[label] = self.node_idx
        return self.node_idx

    def add_vnet(self, vnet):
        label = vnet.split('-')[-1]
        # CHECKME: use networkId as group for vservers!?
        group = label
        return self.add_node(label, group=group)

    def add_zone(self, zone):
        return self.add_node(zone)

    def add_publicip(self, publicip):
        label = publicip.address
        group = 'INTERNET'
        return self.add_node(label, group=group)

    def add_firewall(self, firewall):
        label = firewall.efmName
        group = 'INTERNET'
        #return self.add_node(label, color='red')
        return self.add_node(label, group=group)

    def add_loadbalancer(self, loadbalancer):
        label = loadbalancer.slbVip
        # CHECKME: assume SLB is in DMZ for now!?
        group = 'DMZ'
        descr = loadbalancer.efmName
        return self.add_node(label, shape='box', color='lightblue', group=group, descr=descr)

    def add_vserver(self, vserver):
        #if not isinstance(vserver, FGCPResource):
        #    return self.add_node(vserver, shape='box')
        label = vserver.vnics[0].privateIp
        # CHECKME: use networkId as group for vservers!?
        group = vserver.vnics[0].getid().split('-')[-1]
        descr = vserver.vserverName
        return self.add_node(label, shape='box', group=group, descr=descr)

    def add_fw_rule(self, fw_rule):
        label = str(fw_rule.dstPort)
        label += '\n' + fw_rule.protocol
        group = 'FW_RULE'
        if fw_rule.action != 'Accept':
            descr = fw_rule.action
            return self.add_node(label, color='red', group=group, descr=descr, unique=False)
        return self.add_node(label, group=group, unique=False)

    def add_ports(self, port1, port2=None):
        label = str(port1)
        if port2:
            label += '\n' + str(port2)
        group = 'SLB_RULE'
        return self.add_node(label, group=group, unique=False)

    def add_port(self, port):
        label = str(port)
        group = 'PORT'
        return self.add_node(label, group=group, unique=False)

    def add_unknown(self, unknown):
        descr = '<UNKNOWN>'
        return self.add_node(unknown, color='yellow', descr=descr)

    def save_zones(self, vsystem=None):
        self.get_zones(vsystem)
        self.write_vis(layout='directed')

    def get_zones(self, vsystem=None):
        self.start(vsystem)

        self.header = ['zone', 'vnet', 'type', 'name', 'ip']
        target_idx = {}
        target_idx['INTERNET'] = self.add_vnet('INTERNET')

        networks = {}
        vnets = self.vsystem.list_vnets()
        if isinstance(vnets, str):
            vnets = [vnets]
        for vnet in vnets:
            zone = vnet.split('-')[-1]
            networks[zone] = vnet
            target_idx[zone] = self.add_vnet(vnet)

        firewalls = self.vsystem.list_firewalls()
        for firewall in firewalls:
            target_idx[firewall.efmName] = self.add_firewall(firewall)
            self.link_nodes(target_idx['INTERNET'], target_idx[firewall.efmName])
            self.table.append(['INTERNET', 'INTERNET', 'Firewall', firewall.efmName, 'publicips TODO'])
            for zone in networks:
                self.link_nodes(target_idx[firewall.efmName], target_idx[zone])

        loadbalancers = self.vsystem.list_loadbalancers()
        for loadbalancer in loadbalancers:
            target_idx[loadbalancer.slbVip] = self.add_loadbalancer(loadbalancer)
            # CHECKME: assume SLB is in DMZ for now!?
            self.link_nodes(target_idx['DMZ'], target_idx[loadbalancer.slbVip])
            self.table.append(['DMZ', networks['DMZ'], 'Loadbalancer', loadbalancer.efmName, loadbalancer.slbVip])

        vservers = self.vsystem.list_vservers()
        for vserver in vservers:
            vnic = vserver.vnics[0]
            zone = vnic.networkId.split('-')[-1]
            target_idx[vnic.privateIp] = self.add_vserver(vserver)
            self.link_nodes(target_idx[zone], target_idx[vnic.privateIp])
            self.table.append([zone, networks[zone], 'VServer', vserver.vserverName, vnic.privateIp])

    def save_fw_rules(self, vsystem=None):
        self.get_fw_rules(vsystem)
        self.write_vis()
        #self.write_vis(layout='directed')
        #self.write_vis(layout='hubsize')

    def get_fw_rules(self, vsystem=None):
        self.start(vsystem)

        fw_rules = {}
        firewalls = self.vsystem.list_firewalls()
        for firewall in firewalls:
            directions = firewall.list_policies()
            for direction in directions:
                from_zone = getattr(direction, 'from_zone', '')
                if not from_zone:
                    from_zone = getattr(direction, 'from', '')
                from_zone = from_zone.split('-').pop()
                to_zone = getattr(direction, 'to_zone', '')
                if not to_zone:
                    to_zone = getattr(direction, 'to', '')
                to_zone = to_zone.split('-').pop()
                if from_zone not in fw_rules:
                    fw_rules[from_zone] = {}
                fw_rules[from_zone][to_zone] = direction.policies
        #return fw_rules

        # TODO: provide mapping from header to attrib?
        """
        {'dstService': u'NONE', 'src': u'any', 'dstPort': u'80', 'to_zone': u'DMZ', 'pro
        tocol': u'tcp', 'log': u'Off', 'dstType': u'IP', 'srcPort': u'any', 'dst': u'80.
        70.164.71', 'from_zone': u'INTERNET', 'srcType': u'IP', 'action': u'Accept', '_c
        lass': 'FGCPFWPolicy', 'id': u'35080'}
        """
        self.header = ['id', 'from_zone', 'srcType', 'src', 'srcPort', 'protocol', 'to_zone', 'dstType', 'dst', 'dstPort', 'dstService', 'action', 'log']
        target_idx = {}
        add_zones = True
        for from_zone in fw_rules:
            #if add_zones and from_zone not in target_idx:
            #    target_idx[from_zone] = self.add_vnet(from_zone)
            if add_zones:
                label_from = from_zone
            else:
                label_from = 'FROM_' + from_zone
            if label_from not in target_idx:
                target_idx[label_from] = self.add_node(label_from, shape='database', group=from_zone)
                #if add_zones:
                #    self.link_nodes(target_idx[from_zone], target_idx[label_from], arrows=True)
            for to_zone in fw_rules[from_zone]:
                #if add_zones and to_zone not in target_idx:
                #    target_idx[to_zone] = self.add_vnet(to_zone)
                if add_zones:
                    label_to = to_zone
                else:
                    label_to = to_zone + '_TO'
                if label_to not in target_idx:
                    target_idx[label_to] = self.add_node(label_to, shape='database', group=to_zone)
                    #if add_zones:
                    #    self.link_nodes(target_idx[label_to], target_idx[to_zone], arrows=True)
                for fw_rule in fw_rules[from_zone][to_zone]:
                    #from_label = from_zone + ':' + fw_rule.src
                    if add_zones:
                        if fw_rule.src != 'any':
                            from_label = label_from + ':FROM:' + fw_rule.src
                        else:
                            from_label = label_from
                    else:
                        from_label = label_from + ':' + fw_rule.src
                    if from_label not in target_idx:
                         target_idx[from_label] = self.add_node(from_label, shape='box', group=from_zone)
                         self.link_nodes(target_idx[label_from], target_idx[from_label], arrows=True)
                    #to_label = to_zone + ':' + fw_rule.dst
                    if add_zones:
                        if fw_rule.dst != 'any':
                            to_label = label_to + ':TO:' + fw_rule.dst
                        else:
                            to_label = label_to
                    else:
                        to_label = label_to + ':' + fw_rule.dst
                    if to_label not in target_idx:
                         target_idx[to_label] = self.add_node(to_label, shape='box', group=to_zone)
                         self.link_nodes(target_idx[to_label], target_idx[label_to], arrows=True)
                    if fw_rule.action != 'Accept':
                        rule_idx = self.add_node('%s:%s\n%s' % (fw_rule.srcPort, fw_rule.dstPort, fw_rule.protocol), group='FW_RULE', color='red', descr=fw_rule.action, unique=False)
                    else:
                        #rule_idx = self.add_node(fw_rule.srcPort+':'+fw_rule.dstPort+'\n'+fw_rule.protocol, group='FW_RULE', unique=False)
                        rule_idx = self.add_node('%s:%s\n%s' % (fw_rule.srcPort, fw_rule.dstPort, fw_rule.protocol), group=from_zone, unique=False)
                    if add_zones:
                        self.link_nodes(target_idx[from_label], rule_idx, arrows=True, label=fw_rule.src)
                        self.link_nodes(rule_idx, target_idx[to_label], arrows=True, label=fw_rule.dst)
                    else:
                        self.link_nodes(target_idx[from_label], rule_idx, arrows=True)
                        self.link_nodes(rule_idx, target_idx[to_label], arrows=True)
                    # CHECKME: add from and to zone here?
                    fw_rule.from_zone = from_zone
                    fw_rule.to_zone = to_zone
                    # TODO: do something with header & table
                    #self.table.append(self.to_var(fw_rule))
                    row = []
                    for attr in self.header:
                        row.append(getattr(fw_rule, attr, None))
                    self.table.append(row)
        #return fw_rules

    def save_fw_slb_match(self, vsystem=None):
        self.get_fw_slb_match(vsystem)
        self.write_vis()

    def get_fw_slb_match(self, vsystem=None):
        self.start(vsystem)

        target_idx = {}
        target_idx['INTERNET'] = self.add_vnet('INTERNET')

        natting = {}
        publicips = self.vsystem.list_publicips()
        for publicip in publicips:
            natting[publicip.address] = {}
            target_idx[publicip.address] = self.add_publicip(publicip)
            self.link_nodes(target_idx['INTERNET'], target_idx[publicip.address])

        mapto = {}
        fw_rules = {}
        firewalls = self.vsystem.list_firewalls()
        for firewall in firewalls:
            nat_rules = firewall.list_nat_rules()
            for nat_rule in nat_rules:
                #nat_rule.pprint()
                if nat_rule.publicIp not in natting:
                    print "Invalid NAT rule FROM"
                    nat_rule.pprint()
                    #return
                #if nat_rule.privateIp not in networks['DMZ']:
                #    print "Invalid NAT rule TO"
                #    nat_rule.pprint()
                #    #return
                natting[nat_rule.publicIp][nat_rule.privateIp] = {}
                #if nat_rule.privateIp not in targets:
                #     targets[nat_rule.privateIp] = {}
                #target_idx[nat_rule.privateIp] = self.add_publicip(nat_rule.privateIp)
                if nat_rule.publicIp not in target_idx:
                    target_idx[nat_rule.publicIp] = self.add_unknown(nat_rule.publicIp)
                mapto[nat_rule.privateIp] = target_idx[nat_rule.publicIp]
                #if nat_rule.privateIp not in target_idx:
                #    target_idx[nat_rule.privateIp] = visual.add_unknown(nat_rule.privateIp)
                #visual.link_nodes(target_idx[nat_rule.publicIp], target_idx[nat_rule.privateIp])
            directions = firewall.list_policies()
            #directions = firewall.get_policies(from_zone=None, to_zone=None)
            #result = firewall.set_policies(log='Off', policies=directions)
            for direction in directions:
                #direction.pprint()
                #_from = getattr(direction, 'from')
                #if _from not in fw_rules:
                #    fw_rules[_from] = {}
                #fw_rules[_from][direction.to] = direction.policies
                # get the last part of the direction, i.e. DMZ, SECURE1, SECURE2 etc.
                from_zone = getattr(direction, 'from_zone', '')
                if not from_zone:
                    from_zone = getattr(direction, 'from', '')
                from_zone = from_zone.split('-').pop()
                to_zone = getattr(direction, 'to_zone', '')
                if not to_zone:
                    to_zone = getattr(direction, 'to', '')
                to_zone = to_zone.split('-').pop()
                if from_zone not in fw_rules:
                    fw_rules[from_zone] = {}
                fw_rules[from_zone][to_zone] = direction.policies

        loadbalancers = self.vsystem.list_loadbalancers()
        for loadbalancer in loadbalancers:
            pass
            # CHECKME: assume SLB is in DMZ for now!?
            target_idx[loadbalancer.slbVip] = self.add_loadbalancer(loadbalancer)
            # CHECKME: always include SLB even if it's not natted
            if loadbalancer.slbVip in mapto:
                self.link_nodes(mapto[loadbalancer.slbVip], target_idx[loadbalancer.slbVip])

        mapip = {}
        vservers = self.vsystem.list_vservers()
        for vserver in vservers:
            vnic = vserver.vnics[0]
            #zone = vnic.networkId.split('-')[-1]
            if vnic.privateIp in mapto:
                target_idx[vnic.privateIp] = self.add_vserver(vserver)
            #    self.link_nodes(mapto[vnic.privateIp], target_idx[vnic.privateIp])
            mapip[vnic.privateIp] = vserver

        if 'INTERNET' not in fw_rules:
            print fw_rules
            fw_rules['INTERNET'] = {}
        if 'DMZ' not in fw_rules['INTERNET']:
            fw_rules['INTERNET']['DMZ'] = {}
        #sources = {}
        fw_port_idx = {}
        for fw_rule in fw_rules['INTERNET']['DMZ']:
            if fw_rule.dst == 'any':
                dstPort_idx = self.add_fw_rule(fw_rule)
                if fw_rule.dst not in target_idx:
                    target_idx[fw_rule.dst] = self.add_unknown(fw_rule.dst)
                    self.link_nodes(target_idx['INTERNET'], target_idx[fw_rule.dst])
                self.link_nodes(target_idx[fw_rule.dst], dstPort_idx)
            elif fw_rule.dst in natting:
                natted = natting[fw_rule.dst].keys()[0]
                # CHECKME: we're dealing with a vserver here
                if natted in mapip:
                    dstPort_idx = self.add_fw_rule(fw_rule)
                    self.link_nodes(target_idx[fw_rule.dst], dstPort_idx)
                    if natted not in target_idx:
                        target_idx[natted] = self.add_vserver(mapip[natted])
                    self.link_nodes(dstPort_idx, target_idx[natted])
                    continue
                # CHECKME: save FW port idx for mapping with SLB rules later, instead of linking to SLB here?
                #dstPort_idx = self.add_fw_rule(fw_rule)
                #self.link_nodes(target_idx[fw_rule.dst], dstPort_idx)
                #self.link_nodes(dstPort_idx, target_idx[natted])
                if natted not in fw_port_idx:
                    fw_port_idx[natted] = {}
                #fw_port_idx[natted][fw_rule.dstPort] = dstPort_idx
                if fw_rule.action != 'Accept':
                    dstPort_idx = self.add_fw_rule(fw_rule)
                    self.link_nodes(target_idx[fw_rule.dst], dstPort_idx)
                    fw_port_idx[natted][fw_rule.dstPort] = dstPort_idx
                else:
                    #fw_port_idx[natted][fw_rule.dstPort] = target_idx[fw_rule.dst]
                    if natted not in target_idx:
                        target_idx[natted] = self.add_unknown(natted)
                    fw_port_idx[natted][fw_rule.dstPort] = target_idx[natted]
            else:
                print "Unknown destination for FW_RULE"
                fw_rule.pprint()
                sys.exit()

        slb_rules = {}
        for loadbalancer in loadbalancers:
            try:
                groups = loadbalancer.list_groups()
            except:
                groups = []
            if loadbalancer.slbVip not in fw_port_idx:
                print "No port mapping for SLB in FW_RULE?"
                print fw_port_idx
                fw_port_idx[loadbalancer.slbVip] = {}
                if loadbalancer.slbVip not in target_idx:
                    target_idx[loadbalancer.slbVip] = self.add_loadbalancer(loadbalancer)
                #sys.exit()
            slb_rules[loadbalancer.slbVip] = {}
            for group in groups:
                #group.pprint()
                slb_rules[loadbalancer.slbVip][group.port1] = group
                # CHECKME: save FW port idx for mapping with SLB rules later, instead of linking to SLB here?
                if group.port1 not in fw_port_idx[loadbalancer.slbVip]:
                    print "No port mapping for SLB in FW_RULE?"
                    print fw_port_idx
                    group.pprint()
                    #sys.exit()
                    # CHECKME: add red Deny port instead?
                    if loadbalancer.slbVip not in target_idx:
                        #target_idx[loadbalancer.slbVip] = self.add_loadbalancer(loadbalancer)
                        target_idx[loadbalancer.slbVip] = self.add_node(loadbalancer.slbVip+'\n'+loadbalancer.efmName, color='red', group='FW_RULE', descr='FW_RULE ?')
                    else:
                        node_idx = self.add_node(group.port1, color='red', group='FW_RULE', descr='FW_RULE ?')
                        self.link_nodes(target_idx[loadbalancer.slbVip], node_idx)
                        fw_port_idx[loadbalancer.slbVip][group.port1] = node_idx
                # CHECKME: split port mapping when we have more than 1 target
                if len(group.targets) > 1:
                    parent_idx = self.add_ports(group.port1+'\n'+group.protocol)
                    self.link_nodes(fw_port_idx[loadbalancer.slbVip][group.port1], parent_idx)
                else:
                    parent_idx = fw_port_idx[loadbalancer.slbVip][group.port1]
                for target in group.targets:
                    if target.ipAddress not in target_idx:
                        target_idx[target.ipAddress] = self.add_vserver(mapip[target.ipAddress])
                    if len(group.targets) > 1:
                        port_idx = self.add_port(target.port1)
                    elif group.port1 == target.port1:
                        port_idx = self.add_ports(group.port1+'\n'+group.protocol)
                    else:
                        port_idx = self.add_ports(group.port1+'\n'+group.protocol, target.port1)
                    #self.link_nodes(target_idx[loadbalancer.slbVip], port_idx)
                    self.link_nodes(parent_idx, port_idx)
                    self.link_nodes(port_idx, target_idx[target.ipAddress])
                if getattr(group, 'port2', None) is None:
                    continue
                slb_rules[loadbalancer.slbVip][group.port2] = group
                # CHECKME: save FW port idx for mapping with SLB rules later, instead of linking to SLB here?
                if group.port2 not in fw_port_idx[loadbalancer.slbVip]:
                    print "No port mapping for SLB in FW_RULE?"
                    print fw_port_idx
                    group.pprint()
                    #sys.exit()
                    # CHECKME: add red Deny port instead?
                    if loadbalancer.slbVip not in target_idx:
                        #target_idx[loadbalancer.slbVip] = self.add_loadbalancer(loadbalancer)
                        target_idx[loadbalancer.slbVip] = self.add_node(loadbalancer.slbVip+'\n'+loadbalancer.efmName, color='red', group='FW_RULE', descr='FW_RULE ?')
                        fw_port_idx[loadbalancer.slbVip][group.port2] = target_idx[loadbalancer.slbVip]
                    else:
                        node_idx = self.add_node(group.port2, color='red', group='FW_RULE', descr='FW_RULE ?')
                        self.link_nodes(target_idx[loadbalancer.slbVip], node_idx)
                        fw_port_idx[loadbalancer.slbVip][group.port2] = node_idx
                # CHECKME: split port mapping when we have more than 1 target
                if len(group.targets) > 1:
                    parent_idx = self.add_ports(group.port2+'\n'+group.protocol)
                    self.link_nodes(fw_port_idx[loadbalancer.slbVip][group.port2], parent_idx)
                else:
                    parent_idx = fw_port_idx[loadbalancer.slbVip][group.port2]
                for target in group.targets:
                    if len(group.targets) > 1:
                        port_idx = self.add_port(target.port2)
                    elif group.port2 == target.port2:
                        port_idx = self.add_ports(group.port2+'\n'+group.protocol)
                    else:
                        port_idx = self.add_ports(group.port2+'\n'+group.protocol, target.port2)
                    #self.link_nodes(target_idx[loadbalancer.slbVip], port_idx)
                    self.link_nodes(parent_idx, port_idx)
                    self.link_nodes(port_idx, target_idx[target.ipAddress])

        for natted in fw_port_idx:
            if natted not in slb_rules:
                print "Natted not in SLB rules?"
                print natted
                print slb_rules
                print fw_port_idx
                if natted not in target_idx:
                    target_idx[natted] = self.add_unknown(natted)
                #sys.exit()
                slb_rules[natted] = {}
            for dstPort in fw_port_idx[natted]:
                if dstPort in slb_rules[natted]:
                    continue
                print "dstPort not in SLB rules?"
                print natted, dstPort
                #print slb_rules
                #print fw_port_idx
                #sys.exit()
                dstPort_idx = self.add_node(dstPort, color='red', group='FW_RULE', descr='SLB_RULE ?')
                #self.link_nodes(fw_port_idx[natted][dstPort], dstPort_idx)
                self.link_nodes(mapto[natted], dstPort_idx)
                self.link_nodes(dstPort_idx, target_idx[natted])

    def write_vis(self, filePath=None, layout=None, direction=None):
        if filePath:
            self.filePath = filePath
        if layout:
            self.layout = layout
        if direction:
            self.direction = direction
        self.write_vis_js()
        self.write_vis_json()
        return

    def write_vis_js(self):
        f = open(self.filePath, 'w')
        f.write("  // create an array with nodes\n");
        #f.write("  var nodes = new vis.DataSet([\n");
        f.write("  var nodes = [\n");
        for node in self.nodes:
            #print "    %s,\n" % node
            #if 'color' in node:
            #    f.write("    {id: %d, label: '%s', color: '%s'},\n" % (node['id'], node['label'], node['color']))
            #elif 'shape' in node:
            #    f.write("    {id: %d, label: '%s', shape: '%s'},\n" % (node['id'], node['label'], node['shape']))
            #else:
            #    f.write("    {id: %d, label: '%s'},\n" % (node['id'], node['label']))
            f.write("    %s,\n" % node)
        #f.write("  ]);\n");
        f.write("  ];\n");
        f.write("\n");
        f.write("  // create an array with edges\n");
        #f.write("  var edges = new vis.DataSet([\n");
        f.write("  var edges = [\n");
        for edge in self.edges:
            f.write("    %s,\n" % edge)
            #f.write("    {from: %d, to: %d},\n" % (edge['from'], edge['to']))
        #f.write("  ]);\n");
        f.write("  ];\n");
        f.write("\n");
        if not self.layout:
            f.write("  var options = {};\n");
        elif self.layout == 'directed' or self.layout == 'hubsize':
            f.write("  var options = {\n");
            f.write("    layout: {\n");
            f.write("      hierarchical: {\n");
            if self.direction:
                f.write("        direction: '%s',\n" % self.direction);
            else:
                f.write("        direction: 'UD',\n");
            f.write("        //sortMethod: 'hubsize'\n");
            f.write("        //sortMethod: 'directed'\n");
            f.write("        sortMethod: '%s'\n" % self.layout);
            f.write("      }\n");
            f.write("    }\n");
            f.write("  };\n");
        f.write("\n");
        f.close()
        return

    def write_vis_json(self):
        # CHECKME: save JSON version too for dynamic html
        import simplejson as json
        f = open(self.filePath + 'on', 'w')
        json.dump({'layout': self.layout, 'direction': self.direction, 'nodes': self.nodes, 'edges': self.edges, 'header': self.header, 'table': self.table}, f)
        f.close()
        return

    def get_vis_json(self, layout=None, direction=None):
        #if layout:
        #    self.layout = layout
        #if direction:
        #    self.direction = direction
        # CHECKME: save JSON version too for dynamic html
        import simplejson as json
        #return json.dumps({'layout': self.layout, 'direction': self.direction, 'nodes': self.nodes, 'edges': self.edges})
        return json.dumps({'layout': layout, 'direction': direction, 'nodes': self.nodes, 'edges': self.edges, 'header': self.header, 'table': self.table})
