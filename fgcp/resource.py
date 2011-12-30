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
Resource Actions on the Fujitsu Global Cloud Platform (FGCP)

Example: [see tests/test_resource.py for more examples]

# Connect with your client certificate to region 'uk'
from fgcp.resource import FGCPVDataCenter
vdc = FGCPVDataCenter('client.pem', 'uk')

# Do typical resource actions
vsystem = vdc.get_vsystem('Python API Demo System')
vsystem.show_status()
for vserver in vsystem.vservers:
    result = vserver.backup(wait=True)
...

TODO: review class inheritance vs. composition
"""

import time

from fgcp import FGCPError


class FGCPResourceError(FGCPError):
    """
    Exception class for FGCP Resource Errors
    """
    def __init__(self, status, message, resource=None):
        self.status = status
        self.message = message
        self.resource = resource

    def __str__(self):
        return '\nStatus: %s\nMessage: %s\nResource: %s' % (self.status, self.message, repr(self.resource))


class FGCPElement(object):
    def __init__(self, **kwargs):
        # initialize object attributes, cfr. FGCPDesigner().LoadSystemDesign
        for key in kwargs.keys():
            setattr(self, key, kwargs[key])

    def __repr__(self):
        return '<%s>' % type(self).__name__

    #=========================================================================

    def pformat(self, what, depth=0):
        if isinstance(what, str):
            return '  ' * depth + "'%s'" % what
        CRLF = '\r\n'
        L = []
        if isinstance(what, list):
            L.append('  ' * depth + '[')
            for val in what:
                L.append(self.pformat(val, depth + 1) + ',')
            L.append('  ' * depth + ']')
            return CRLF.join(L)
        # initialize object attributes, cfr. FGCPDesigner().SaveSystemDesign
        L.append('  ' * depth + '%s(' % type(what).__name__)
        depth += 1
        for key in what.__dict__:
            # TODO: skip _caller and _parent for output later ?
            if key == '_caller' or key == '_parent':
                if isinstance(what.__dict__[key], FGCPResource):
                    L.append('  ' * depth + "%s='%s'," % (key, repr(what.__dict__[key])))
                elif isinstance(what.__dict__[key], str):
                    L.append('  ' * depth + "%s='%s'," % (key, what.__dict__[key]))
                else:
                    L.append('  ' * depth + '%s=%s,' % (key, what.__dict__[key]))
            # TODO: skip _proxy for output later ?
            elif key == '_proxy':
                #if what.__dict__[key] is not None:
                #    L.append('  ' * depth + "%s='%s'," % (key, repr(what.__dict__[key])))
                #else:
                #    L.append('  ' * depth + '%s=None,' % key)
                pass
            elif isinstance(what.__dict__[key], FGCPElement):
                L.append('  ' * depth + '%s=' % key)
                L.append(self.pformat(what.__dict__[key], depth + 1) + ',')
            elif isinstance(what.__dict__[key], list):
                L.append('  ' * depth + '%s=[' % key)
                for val in what.__dict__[key]:
                    L.append(self.pformat(val, depth + 1) + ',')
                L.append('  ' * depth + '],')
            elif isinstance(what.__dict__[key], str):
                L.append('  ' * depth + "%s='%s'," % (key, what.__dict__[key]))
            elif isinstance(what.__dict__[key], int) or isinstance(what.__dict__[key], float):
                L.append('  ' * depth + "%s=%s," % (key, what.__dict__[key]))
            elif what.__dict__[key] is None:
                #L.append('  ' * depth + "%s=None," % key)
                pass
            else:
                L.append('  ' * depth + "%s='?%s?'," % (key, what.__dict__[key]))
        depth -= 1
        L.append('  ' * depth + ')')
        return CRLF.join(L)

    def pprint(self):
        """
        Show dump of the FGCP Element for development
        """
        print self.pformat(self)

    #=========================================================================

    def reset_attr(self, what):
        if hasattr(self, what):
            delattr(self, what)


class FGCPResponse(FGCPElement):
    """
    FGCP Response
    """
    _caller = None

    def __repr__(self):
        if self._caller is not None:
            return '<%s:%s>' % (type(self).__name__, repr(self._caller))
        else:
            return '<%s:%s>' % (type(self).__name__, '')


class FGCPResource(FGCPElement):
    """
    Generic FGCP Resource
    """
    _idname = None
    _parent = None
    _proxy = None
    #_actions = {}

    def __init__(self, **kwargs):
        # initialize object attributes, cfr. FGCPDesigner().LoadSystemDesign
        for key in kwargs.keys():
            setattr(self, key, kwargs[key])
        # CHECKME: special case for id=123 and/or parentid=12 ?
        if hasattr(self, 'id') and self._idname is not None and not hasattr(self, self._idname):
            setattr(self, self._idname, getattr(self, 'id'))

    def __repr__(self):
        return '<%s:%s>' % (type(self).__name__, self.getid())

    #=========================================================================

    """
    def create(self):
        return self.getid()

    def retrieve(self, refresh=None):
        return self

    def update(self):
        return
    """
    def replace(self):
        return
    """
    def destroy(self):
        return

    def status(self):
        return 'UNKNOWN'
    """
    #def action(self, who=None, what=None, where=None, when=None, why=None, how=None):
    #    pass

    #=========================================================================

    def check_status(self, in_state=[], out_state=[]):
        status = self.status()
        if status in out_state:
            # we're already in the expected outcome state for the action
            return status
        elif status in in_state:
            # we're still in the expected input state for the action
            return
        else:
            # we're in some unexpected state for the action
            raise FGCPResourceError('ILLEGAL_STATE', 'Invalid status %s' % status, self)

    def wait_for_status(self, in_state=[], out_state=[], timeout=900):
        start_time = time.time()
        stop_time = time.time()
        while stop_time < start_time + timeout:
            # wait 10 seconds before checking status again
            time.sleep(10)
            done = self.check_status(in_state, out_state)
            if done:
                # we're already in the expected outcome state for the action
                return done
            # we're still in the expected input state for the action
            stop_time = time.time()
        raise FGCPResourceError('TIMEOUT', 'Expected status %s not reached' % out_state, self)

    def show_output(self, text=''):
        # CHECKME: keep track of verbose ourselves - in all resource objects ???
        if self._proxy is not None:
            if self._proxy.verbose > 0:
                print text

    #=========================================================================

    def getid(self):
        if self._idname is not None and hasattr(self, self._idname):
            return getattr(self, self._idname)

    def getparentid(self):
        if self._parent is not None:
            if isinstance(self._parent, FGCPResource):
                return self._parent.getid()
            elif isinstance(self._parent, str):
                return self._parent

    def setparent(self, parent):
        self._parent = parent
        # CHECKME: set the proxy to the parent's proxy too
        self._proxy = self._parent._proxy

    def getproxy(self):
        if self._proxy is not None:
            # CHECKME: set the caller here for use in FGCPResponseParser !?
            self._proxy._caller = self
            return self._proxy

    #=========================================================================

    # convert *args and **kwargs from other method to dict
    def _args2dict(self, argslist=[], kwargsdict={}, allowed=None):
        print argslist
        print kwargsdict
        print allowed
        tododict = {}
        if len(argslist) == 2:
            # CHECKME: we assume a key, val pair - cfr. attributeName, attributeValue etc. !?
            tododict[argslist[0]] = argslist[1]
        elif len(argslist) == 1:
            # CHECKME: we got an object, use its __dict__
            if isinstance(argslist[0], FGCPResource):
                tododict = argslist[0].__dict__
            # CHECKME: we got key, val pairs
            elif isinstance(argslist[0], dict):
                tododict = argslist[0]
            elif isinstance(argslist[0], list):
                # now what ?
                return argslist[0]
            else:
                # now what ?
                return argslist[0]
        if len(kwargslist) > 0:
            tododict.update(kwargs)
        # TODO: sanitize dict by removing _* + the _idname, and diff the rest with current values ?
        if len(allowed) > 0 and len(tododict) > 0:
            newdict = {}
            for key in allowed:
                if key in tododict:
                    newdict[key] = tododict[key]
            tododict = newdict
        return tododict

    # CHECKME: no longer needed since we do it in FGCPResponseParser() based on conn._caller
    def _reparent(self, child=None, parent=None):
        if child is None:
            return child
        elif isinstance(child, str):
            return child
        elif isinstance(child, list):
            new_child = []
            for item in child:
                new_child.append(self._reparent(item, parent))
            return new_child
        elif isinstance(child, dict):
            new_child = {}
            for key, val in child:
                new_child[key] = self._reparent(val, parent)
            return new_child
        elif isinstance(child, FGCPResponse):
            child._caller = parent
            for key, val in child.__dict__:
                if key == '_caller':
                    continue
                # CHECKME: use caller as parent here
                setattr(child, key, self._reparent(val, parent))
            return child
        elif isinstance(child, FGCPResource):
            child._parent = parent
            for key, val in child.__dict__:
                if key == '_parent' or key == '_proxy':
                    continue
                # CHECKME: use child as parent here
                setattr(child, key, self._reparent(val, child))
            return child
        else:
            return child


class FGCPVDataCenter(FGCPResource):
    """
    FGCP VDataCenter
    """
    _idname = 'config'

    def __init__(self, key_file=None, region=None, verbose=0, debug=0):
        """
        Use the same PEM file for SSL client certificate and RSA key signature

        Note: to convert your .p12 or .pfx file to unencrypted PEM format, you can use
        the following 'openssl' command:

        openssl pkcs12 -in UserCert.p12 -out client.pem -nodes
        """
        # initialize proxy if necessary
        if key_file is not None and region is not None:
            self.config = '%s:%s' % (region, key_file)
            #from fgcp.client import FGCPClient
            #self._proxy = FGCPClient(key_file, region, verbose, debug)
            from fgcp.command import FGCPCommand
            self._proxy = FGCPCommand(key_file, region, verbose, debug)

    #=========================================================================

    def status(self):
        return 'Connection: %s\nResource: %s' % (repr(self._proxy), repr(self))

    #=========================================================================

    def list_vsystems(self):
        if not hasattr(self, 'vsystems'):
            setattr(self, 'vsystems', self.getproxy().ListVSYS())
        return getattr(self, 'vsystems')

    def get_vsystem(self, vsysName):
        # support resource, name or id
        if isinstance(vsysName, FGCPVSystem):
            return vsysName.retrieve()
        vsystems = self.list_vsystems()
        for vsystem in vsystems:
            if vsysName == vsystem.vsysName:
                # CHECKME: get detailed configuration now ?
                #vsystem.retrieve()
                return vsystem
            elif vsysName == vsystem.vsysId:
                # CHECKME: get detailed configuration now ?
                #vsystem.retrieve()
                return vsystem
        raise FGCPResourceError('ILLEGAL_VSYSTEM', 'Invalid vsysName %s' % vsysName, self)

    def create_vsystem(self, vsysName, vsysdescriptor, wait=None):
        vsysdescriptor = self.get_vsysdescriptor(vsysdescriptor)
        # let the vsysdescriptor handle it
        return vsysdescriptor.create_vsystem(vsysName, wait)

    def destroy_vsystem(self, vsysName, wait=None):
        vsystem = self.get_vsystem(vsysName)
        if wait:
            # make sure the vsystem is stopped first
            result = vsystem.stop(wait)
        # let the vsystem handle it
        return vsystem.destroy(wait)

    #=========================================================================

    def list_publicips(self):
        if not hasattr(self, 'publicips'):
            setattr(self, 'publicips', self.getproxy().ListPublicIP())
        return getattr(self, 'publicips')

    def get_publicip(self, publicipAddress):
        # support resource or address (=id)
        if isinstance(publicipAddress, FGCPPublicIP):
            return publicipAddress.retrieve()
        publicips = self.list_publicips()
        for publicip in publicips:
            if publicipAddress == publicip.address:
                return publicip
        raise FGCPResourceError('ILLEGAL_ADDRESS', 'Invalid publicipAddress %s' % publicipAddress, self)

    #=========================================================================

    def list_addressranges(self):
        if not hasattr(self, 'addressranges'):
            setattr(self, 'addressranges', self.getproxy().GetAddressRange())
        return getattr(self, 'addressranges')

    def create_addresspool(self, pipFrom=None, pipTo=None):
        return self.getproxy().CreateAddressPool(pipFrom, pipTo)

    def add_addressrange(self, pipFrom, pipTo):
        return self.getproxy().AddAddressRange(pipFrom, pipTo)

    def delete_addressrange(self, pipFrom, pipTo):
        return self.getproxy().DeleteAddressRange(pipFrom, pipTo)

    #=========================================================================

    def list_vsysdescriptors(self):
        if not hasattr(self, 'vsysdescriptors'):
            setattr(self, 'vsysdescriptors', self.getproxy().ListVSYSDescriptor())
        return getattr(self, 'vsysdescriptors')

    def get_vsysdescriptor(self, vsysdescriptorName):
        # support resource, name or id
        if isinstance(vsysdescriptorName, FGCPVSysDescriptor):
            return vsysdescriptorName.retrieve()
        vsysdescriptors = self.list_vsysdescriptors()
        for vsysdescriptor in vsysdescriptors:
            if vsysdescriptorName == vsysdescriptor.vsysdescriptorName:
                return vsysdescriptor
            elif vsysdescriptorName == vsysdescriptor.vsysdescriptorId:
                return vsysdescriptor
        raise FGCPResourceError('ILLEGAL_VSYSDESCRIPTOR', 'Invalid vsysdescriptorName %s' % vsysdescriptorName, self)

    #=========================================================================

    def list_diskimages(self, vsysdescriptor=None, category='GENERAL'):
        # CHECKME: reversed order of arguments here
        # get all diskimages
        if vsysdescriptor is None:
            if not hasattr(self, 'diskimages'):
                setattr(self, 'diskimages', self.getproxy().ListDiskImage())
            return getattr(self, 'diskimages')
        # get specific diskimages for this vsysdescriptor
        vsysdescriptor = self.get_vsysdescriptor(vsysdescriptor)
        # let the vsysdescriptor handle it
        return vsysdescriptor.list_diskimages(category)

    def get_diskimage(self, diskimageName):
        # support resource, name or id
        if isinstance(diskimageName, FGCPDiskImage):
            return diskimageName.retrieve()
        diskimages = self.list_diskimages()
        for diskimage in diskimages:
            if diskimageName == diskimage.diskimageName:
                return diskimage
            elif diskimageName == diskimage.diskimageId:
                return diskimage
        raise FGCPResourceError('ILLEGAL_DISKIMAGE', 'Invalid diskimageName %s' % diskimageName, self)

    #=========================================================================

    def list_servertypes(self, diskimage=None):
        # CHECKME: all diskimages support the same servertypes at the moment !?
        if hasattr(self, 'servertypes'):
            return getattr(self, 'servertypes')
        # pick the first diskimage that's available
        if diskimage is None:
            diskimage = self.list_diskimages()[0]
        else:
            diskimage = self.get_diskimage(diskimage)
        # let the diskimage handle it
        setattr(self, 'servertypes', diskimage.list_servertypes())
        return getattr(self, 'servertypes')

    def get_servertype(self, servertypeName):
        # support resource or name (=id)
        if isinstance(servertypeName, FGCPServerType):
            return servertypeName.retrieve()
        servertypes = self.list_servertypes()
        for servertype in servertypes:
            if servertypeName == servertype.name:
                return servertype
        raise FGCPResourceError('ILLEGAL_SERVERTYPE', 'Invalid servertypeName %s' % servertypeName, self)

    #=========================================================================

    def get_vsystem_usage(self, vsysIds=None):
        return self.getproxy().GetSystemUsage(vsysIds)

    #=========================================================================

    def get_vsystem_design(self, vsystem=None, filePath=None):
        from fgcp.design import FGCPDesign
        design = FGCPDesign(vsystem=vsystem, filePath=filePath)
        # set the parent of the design to this vdatacenter !
        design.setparent(self)
        return design


class FGCPVSystem(FGCPResource):
    _idname = 'vsysId'

    def create(self):
        # CHECKME: do we want this too ?
        pass

    def retrieve(self, refresh=None):
        # CHECKME: retrieve inventory here ?
        return self.get_inventory(refresh)

    def update(self):
        pass

    def destroy(self, wait=None):
        result = self.getproxy().DestroyVSYS(self.getid())
        # CHECKME: invalidate list of vsystems in VDataCenter
        if isinstance(self._parent, FGCPVDataCenter):
            self._parent.reset_attr('vsystems')
        return result

    def status(self):
        status = self.getproxy().GetVSYSStatus(self.getid())
        setattr(self, 'vsysStatus', status)
        return status

    def start(self, wait=None):
        self.show_output('Starting VSystem %s' % self.vsysName)
        # check if the vsystem is ready
        todo = self.check_status(['NORMAL'], ['DEPLOYING', 'RECONFIG_ING'])
        if todo:
            if wait:
                # wait for the vsystem to be ready
                result = self.wait_for_status(['DEPLOYING', 'RECONFIG_ING'], ['NORMAL'])
            else:
                # we're not ready and won't wait
                return todo
        # get system inventory if necessary
        self.get_inventory()
        # CHECKME: don't attach publicip and start firewalls here ?
        if wait:
            # start all firewalls
            for firewall in self.firewalls:
                firewall.start(wait)
            # attach publicip - cfr. sequence3 in java sdk
            for publicip in self.publicips:
                publicip.attach(wait)
        # start all servers
        for vserver in self.vservers:
            vserver.start(wait)
        # start all loadbalancers
        for loadbalancer in self.loadbalancers:
            loadbalancer.start(wait)
        if wait:
            self.show_output('Started VSystem %s' % self.vsysName)
        return

    def stop(self, wait=None):
        self.show_output('Stopping VSystem %s' % self.vsysName)
        # check if the vsystem is ready
        todo = self.check_status(['NORMAL'], ['DEPLOYING', 'RECONFIG_ING'])
        if todo:
            if wait:
                # wait for the vsystem to be ready
                result = self.wait_for_status(['DEPLOYING', 'RECONFIG_ING'], ['NORMAL'])
            else:
                # we're not ready and won't wait
                return todo
        # get system inventory if necessary
        self.get_inventory()
        # stop all loadbalancers
        for loadbalancer in self.loadbalancers:
            loadbalancer.stop(wait)
        # stop all servers
        for vserver in self.vservers:
            vserver.stop(wait)
        # CHECKME: don't detach publicip and stop firewalls here ?
        if wait:
            # detach publicip - cfr. sequence3 in java sdk
            for publicip in self.publicips:
                publicip.detach(wait)
            # stop all firewalls
            for firewall in self.firewalls:
                firewall.stop(wait)
            self.show_output('Stopped VSystem %s' % self.vsysName)
        return

    #=========================================================================

    def list_vservers(self):
        if not hasattr(self, 'vservers'):
            # FIXME: remove firewalls and loadbalancers here too !?
            setattr(self, 'vservers', self.getproxy().ListVServer(self.getid()))
        return getattr(self, 'vservers')

    def get_vserver(self, vserverName):
        # support resource, name or id
        if isinstance(vserverName, FGCPVServer):
            return vserverName.retrieve()
        vservers = self.list_vservers()
        for vserver in vservers:
            if vserverName == vserver.vserverName:
                return vserver
            elif vserverName == vserver.vserverId:
                return vserver
        raise FGCPResourceError('ILLEGAL_VSERVER', 'Invalid vserverName %s' % vserverName, self)

    def create_vserver(self, vserverName, servertype, diskimage, vnet, wait=None):
        # ask the parent VDataCenter to get the right servertype and diskimage
        servertype = self._parent.get_servertype(servertype)
        diskimage = self._parent.get_diskimage(diskimage)
        # get the right vnet ourselves
        vnet = self.get_vnet(vnet)
        # make a new vserver with the right attributes - vnet returns a string, so no vnet.getid() needed (for now ?)
        vserver = FGCPVServer(vserverName=vserverName, vserverType=servertype.getid(), diskimageId=diskimage.getid(), networkId=vnet)
        # set the parent of the vserver to this vsystem !
        vserver.setparent(self)
        # and now create it :-)
        return vserver.create(wait)

    def destroy_vserver(self, vserver, wait=None):
        vserver = self.get_vserver(vserver)
        return vserver.destroy(wait)

    def start_vserver(self, vserver, wait=None):
        vserver = self.get_vserver(vserver)
        return vserver.start(wait)

    def stop_vserver(self, vserver, wait=None, force=None):
        vserver = self.get_vserver(vserver)
        return vserver.stop(wait)

    def reboot_vserver(self, vserver, wait=None, force=None):
        vserver = self.get_vserver(vserver)
        return vserver.reboot(wait)

    #=========================================================================

    def list_vdisks(self):
        if not hasattr(self, 'vdisks'):
            setattr(self, 'vdisks', self.getproxy().ListVDisk(self.getid()))
        return getattr(self, 'vdisks')

    def get_vdisk(self, vdiskName):
        # support resource, name or id
        if isinstance(vdiskName, FGCPVDisk):
            return vdiskName.retrieve()
        vdisks = self.list_vdisks()
        for vdisk in vdisks:
            if vdiskName == vdisk.vdiskName:
                return vdisk
            elif vdiskName == vdisk.vdiskId:
                return vdisk
        raise FGCPResourceError('ILLEGAL_VDISK', 'Invalid vdiskName %s' % vdiskName, self)

    def create_vdisk(self, vdiskName, size, wait=None):
        # make a new vdisk with the right attributes - note: size is in GB
        vdisk = FGCPVDisk(vdiskName=vdiskName, size=size)
        # set the parent of the vdisk to this vsystem !
        vdisk.setparent(self)
        # and now create it :-)
        return vdisk.create(wait)

    def destroy_vdisk(self, vdisk, wait=None):
        vdisk = self.get_vdisk(vdisk)
        return vdisk.destroy(wait)

    def attach_vdisk(self, vdisk, vserver, wait=None):
        vdisk = self.get_vdisk(vdisk)
        vserver = self.get_vserver(vserver)
        return vdisk.attach(vserver, wait)

    def detach_vdisk(self, vdisk, vserver, wait=None):
        vdisk = self.get_vdisk(vdisk)
        vserver = self.get_vserver(vserver)
        return vdisk.detach(vserver, wait)

    #=========================================================================

    def list_firewalls(self):
        if not hasattr(self, 'firewalls'):
            setattr(self, 'firewalls', self.getproxy().ListEFM(self.getid(), "FW"))
        return getattr(self, 'firewalls')

    def get_firewall(self, efmName):
        # support resource, name or id
        if isinstance(efmName, FGCPFirewall):
            return efmName.retrieve()
        firewalls = self.list_firewalls()
        for firewall in firewalls:
            if efmName == firewall.efmName:
                return firewall
            elif efmName == firewall.efmId:
                return firewall
        raise FGCPResourceError('ILLEGAL_FIREWALL', 'Invalid efmName %s' % efmName, self)

    #=========================================================================

    def list_loadbalancers(self):
        if not hasattr(self, 'loadbalancers'):
            setattr(self, 'loadbalancers', self.getproxy().ListEFM(self.getid(), "SLB"))
        return getattr(self, 'loadbalancers')

    def get_loadbalancer(self, efmName):
        # support resource, name or id
        if isinstance(efmName, FGCPLoadBalancer):
            return efmName.retrieve()
        loadbalancers = self.list_loadbalancers()
        for loadbalancer in loadbalancers:
            if efmName == loadbalancer.efmName:
                return loadbalancer
            elif efmName == loadbalancer.efmId:
                return loadbalancer
        raise FGCPResourceError('ILLEGAL_LOADBALANCER', 'Invalid efmName %s' % efmName, self)

    #=========================================================================

    def list_vnets(self):
        if not hasattr(self, 'vnets'):
            self.retrieve()
        return getattr(self, 'vnets')

    def get_vnet(self, vnet):
        # support vnet
        vnets = self.list_vnets()
        # find exact match first
        if vnet in vnets:
            return vnet
        # find matching end if we used DMZ, SECURE1, SECURE2 here
        if len(vnet) < 8:
            for networkId in vnets:
                if networkId.endswith('-%s' % vnet):
                    return networkId
        raise FGCPResourceError('ILLEGAL_VNET', 'Invalid vnet %s' % vnet, self)

    def get_console_url(self, vnet):
        vnet = self.get_vnet(vnet)
        return self.getproxy().StandByConsole(self.getid(), vnet)

    #=========================================================================

    def list_publicips(self):
        if not hasattr(self, 'publicips'):
            setattr(self, 'publicips', self.getproxy().ListPublicIP(self.getid()))
        return getattr(self, 'publicips')

    def get_publicip(self, publicipAddress):
        # support resource or address (=id)
        if isinstance(publicipAddress, FGCPPublicIP):
            return publicipAddress.retrieve()
        publicips = self.list_publicips()
        for publicip in publicips:
            if publicipAddress == publicip.address:
                return publicip
        raise FGCPResourceError('ILLEGAL_ADDRESS', 'Invalid publicipAddress %s' % publicipAddress, self)

    def allocate_publicip(self, wait=None):
        self.show_output('Allocating PublicIP to VSystem %s' % self.vsysName)
        old_publicips = self.list_publicips()
        if len(old_publicips) < 1:
            old_publicips = []
        result = self.getproxy().AllocatePublicIP(self.getid())
        # CHECKME: invalidate list of publicips
        self.reset_attr('publicips')
        if wait:
            # CHECKME: we need to wait a bit before retrieving the new list !
            self.show_output('Please wait for allocation...')
            time.sleep(30)
            # update list of publicips
            new_publicips = self.list_publicips()
            if len(new_publicips) > len(old_publicips):
                # CHECKME: will this work on objects ?
                #diff_publicips = new_publicips.difference(old_publicips)
                old_ips = []
                for publicip in old_publicips:
                    old_ips.append(publicip.address)
                for publicip in new_publicips:
                    if publicip.address in old_ips:
                        continue
                    # wait until publicip deploying is done
                    result = publicip.wait_for_status(['DEPLOYING'], ['DETACHED', 'ATTACHED'])
                    self.show_output('Allocated PublicIP %s to VSystem %s' % (publicip.address, self.vsysName))
                    break
        return result

    #=========================================================================

    def get_inventory(self, refresh=None):
        # CHECKME: if we already have the firewall information, we already retrieved the configuration
        if not refresh and hasattr(self, 'firewalls'):
            return self
        # get configuration for this vsystem
        vsysconfig = self.getproxy().GetVSYSConfiguration(self.getid())
        # CHECKME: copy configuration to self
        for key in vsysconfig.__dict__:
            if key.startswith('_'):
                continue
            setattr(self, key, vsysconfig.__dict__[key])
        seenId = {}
        # get firewalls
        self.list_firewalls()
        for firewall in self.firewalls:
            seenId[firewall.efmId] = 1
        # get loadbalancers
        self.list_loadbalancers()
        for loadbalancer in self.loadbalancers:
            seenId[loadbalancer.efmId] = 1
        # CHECKME: remove firewalls and loadbalancers from vservers list
        todo = []
        for vserver in self.vservers:
            # skip servers we've already seen, i.e. firewalls and loadbalancers
            if vserver.vserverId in seenId:
                continue
            todo.append(vserver)
        setattr(self, 'vservers', todo)
        if not hasattr(self, 'vdisks'):
            setattr(self, 'vdisks', [])
        if not hasattr(self, 'publicips'):
            setattr(self, 'publicips', [])
        return self

    def get_status(self):
        self.show_output('Status Overview for VSystem %s' % self.vsysName)
        # get system inventory if necessary
        self.get_inventory()
        status = self.status()
        self.show_output('VSystem:%s:%s' % (self.vsysName, status))
        # get status of public ips
        for publicip in self.publicips:
            status = publicip.status()
            self.show_output('PublicIP:%s:%s' % (publicip.address, status))
        # get status of firewalls
        for firewall in self.firewalls:
            status = firewall.status()
            self.show_output('EFM FW:%s:%s' % (firewall.efmName, status))
        # get status of loadbalancers
        for loadbalancer in self.loadbalancers:
            status = loadbalancer.status()
            self.show_output('EFM SLB:%s:%s:%s' % (loadbalancer.efmName, loadbalancer.slbVip, status))
        # get status of vservers (excl. firewalls and loadbalancers)
        seenId = {}
        for vserver in self.vservers:
            status = vserver.status()
            self.show_output('VServer:%s:%s:%s' % (vserver.vserverName, vserver.vnics[0].privateIp, status))
            # get status of attached disks
            for vdisk in vserver.vdisks:
                status = vdisk.status()
                self.show_output(':VDisk:%s:%s' % (vdisk.vdiskName, status))
                seenId[vdisk.vdiskId] = 1
        # get status of unattached disks
        todo = []
        for vdisk in self.vdisks:
            # skip disks we've already seen, i.e. attached to a server
            if vdisk.vdiskId in seenId:
                continue
            todo.append(vdisk.vdiskId)
        if len(todo) > 0:
            self.show_output('Unattached Disks')
            for vdisk in self.vdisks:
                # skip disks we've already seen, i.e. attached to a server
                if vdisk.vdiskId in seenId:
                    continue
                status = vdisk.status()
                self.show_output(':VDisk:%s:%s' % (vdisk.vdiskName, status))
                seenId[vdisk.vdiskId] = 1
        self.show_output('.')

    def show_status(self):
        # set output to 1, i.e. don't show the status in the API command
        old_verbose = self._proxy.set_verbose(1)
        # get system status
        self.get_status()
        # reset output
        self._proxy.set_verbose(old_verbose)

    #=========================================================================

    def register_vsysdescriptor(self, name, description, keyword):
        return self.getproxy().RegisterPrivateVSYSDescriptor(self.getid(), name, description, keyword, self.vservers)

    def get_usage(self):
        return self.getproxy().GetSystemUsage(self.getid())


class FGCPVServer(FGCPResource):
    _idname = 'vserverId'

    def create(self, wait=None):
        # CHECKME: simplify vnics[0].getid() issue on create by allowing networkId
        if hasattr(self, 'vnics') and not hasattr(self, 'networkId'):
            setattr(self, 'networkId', self.vnics[0].getid())
        self.show_output('Creating VServer %s' % self.vserverName)
        vserverId = self.getproxy().CreateVServer(self.getparentid(), self.vserverName, self.vserverType, self.diskimageId, self.networkId)
        # set the vserverId here too
        setattr(self, 'vserverId', vserverId)
         # CHECKME: invalidate list of vservers in VSystem
        if isinstance(self._parent, FGCPVSystem):
            self._parent.reset_attr('vservers')
        if wait:
            # wait for the vserver to be ready
            self.wait_for_status(['DEPLOYING'], ['STOPPED'])
            self.show_output('Created VServer %s' % self.vserverName)
        return vserverId

    def retrieve(self, refresh=None):
        # CHECKME: retrieve configuration here ?
        return self.get_configuration(refresh)

    def update(self, *args, **kwargs):
        # CHECKME: do we actually want to allow arguments here ?
        allowed = ['vserverName', 'vserverType']
        # convert arguments to dict
        tododict = self._args2dict(args, kwargs, allowed)
        # CHECKME: what if we updated the object attributes directly ?
        result = None
        for key in tododict:
            result = self.getproxy().UpdateVServerAttribute(self.getparentid(), self.getid(), key, tododict[key])
        return result

    def destroy(self, wait=None):
        self.show_output('Destroying VServer %s' % self.vserverName)
        # make sure the server is stopped first
        result = self.stop(wait)
        # now destroy the server
        result = self.getproxy().DestroyVServer(self.getparentid(), self.getid())
        # CHECKME: invalidate list of vservers in VSystem
        if isinstance(self._parent, FGCPVSystem):
            self._parent.reset_attr('vservers')
        if wait:
            # CHECKME: we won't wait for it to be gone here
            self.show_output('Destroyed VServer %s' % self.vserverName)
        return result

    def status(self):
        status = self.getproxy().GetVServerStatus(self.getparentid(), self.getid())
        setattr(self, 'vserverStatus', status)
        return status

    def start(self, wait=None):
        self.show_output('Starting VServer %s' % self.vserverName)
        done = self.check_status(['STOPPED', 'UNEXPECTED_STOP'], ['RUNNING'])
        if done:
            return done
        result = self.getproxy().StartVServer(self.getparentid(), self.getid())
        if wait:
            result = self.wait_for_status(['STARTING'], ['RUNNING'])
            self.show_output('Started VServer %s' % self.vserverName)
        return result

    def stop(self, wait=None, force=None):
        self.show_output('Stopping VServer %s' % self.vserverName)
        done = self.check_status(['RUNNING'], ['STOPPED', 'UNEXPECTED_STOP'])
        if done:
            return done
        result = self.getproxy().StopVServer(self.getparentid(), self.getid(), force)
        if wait:
            result = self.wait_for_status(['STOPPING'], ['STOPPED', 'UNEXPECTED_STOP'])
            self.show_output('Stopped VServer %s' % self.vserverName)
        return result

    def reboot(self, wait=None, force=None):
        result = self.stop(wait, force)
        result = self.start(wait)
        return result

    #=========================================================================

    def get_configuration(self, refresh=None):
        # CHECKME: if we already have the vnics information, we already retrieved the configuration
        if not refresh and hasattr(self, 'vnics'):
            return self
        # get configuration for this vserver
        config = self.getproxy().GetVServerConfiguration(self.getparentid(), self.getid())
        # CHECKME: copy configuration to self
        for key in config.__dict__:
            if key.startswith('_'):
                continue
            setattr(self, key, config.__dict__[key])
        return self

    def get_password(self):
        return self.getproxy().GetVServerInitialPassword(self.getparentid(), self.getid())

    #=========================================================================

    def list_vdisks(self):
        if not hasattr(self, 'vdisks'):
            self.retrieve()
        return getattr(self, 'vdisks')

    def get_vdisk(self, vdisk):
        # let the VSystem get the right disk here, since it might not be attached to this VServer
        return self._parent.get_vdisk(vdisk)

    def attach_vdisk(self, vdisk, wait=None):
        vdisk = self.get_vdisk(vdisk)
        return vdisk.attach(self, wait)

    def detach_vdisk(self, vdisk, wait=None):
        # let the VSystem get the right disk here
        vdisk = self.get_vdisk(vdisk)
        return vdisk.detach(self, wait)

    #=========================================================================

    def list_backups(self, timeZone=None, countryCode=None):
        if timeZone or countryCode:
            # Note: the system disk has the same id as the vserver
            return self.getproxy().ListVDiskBackup(self.getparentid(), self.getid(), timeZone, countryCode)
        if not hasattr(self, 'backups'):
            # Note: the system disk has the same id as the vserver
            setattr(self, 'backups', self.getproxy().ListVDiskBackup(self.getparentid(), self.getid(), timeZone, countryCode))
        return getattr(self, 'backups')

    def backup(self, wait=None):
        self.show_output('Start Backup VServer %s' % self.vserverName)
        if wait:
            result = self.stop(wait)
        # get vserver configuration
        self.get_configuration()
        # the system disk has the same id as the vserver
        vdisk = self.getproxy().GetVDiskAttributes(self.getparentid(), self.getid())
        # backup the system disk
        result = vdisk.backup(wait)
        # CHECKME: add other disks if necessary ?
        #for vdisk in self.vdisks:
        #    result = vdisk.backup(wait)
        if wait:
            # CHECKME: start vserver again ?
            #result = self.start(wait)
            self.show_output('Stop Backup VServer %s' % self.vserverName)
        return result

    def restore(self, backup, wait=None):
        self.show_output('Start Restore %s for VServer %s' % (backup, self.vserverName))
        if wait:
            result = self.stop(wait)
        # get vserver configuration
        self.get_configuration()
        # the system disk has the same id as the vserver
        vdisk = self.getproxy().GetVDiskAttributes(self.getparentid(), self.getid())
        # backup the system disk
        result = vdisk.restore(backup, wait)
        # CHECKME: add other disks if necessary ?
        #for vdisk in self.vdisks:
        #    result = vdisk.backup(wait)
        if wait:
            # CHECKME: start vserver again ?
            #result = self.start(wait)
            self.show_output('Stop Restore VServer %s' % self.vserverName)
        return result

    def cleanup_backups(self, max_num=100, max_age=None):
        # get vserver configuration
        self.get_configuration()
        # the system disk has the same id as the vserver
        vdisk = self.getproxy().GetVDiskAttributes(self.getparentid(), self.getid())
        # let the system disk handle the cleanup
        return vdisk.cleanup_backups(max_num, max_age)

    #=========================================================================

    def list_vnics(self):
        if not hasattr(self, 'vnics'):
            self.retrieve()
        return getattr(self, 'vnics')

    #=========================================================================

    def register_diskimage(self, name, description):
        return self.getproxy().RegisterPrivateDiskImage(self.getid(), name, description)


class FGCPVDisk(FGCPResource):
    _idname = 'vdiskId'

    def getparentid(self):
        # CHECKME: the parent of a vdisk may be a vserver or a vsystem, so we need to override this
        if self._parent is not None:
            if isinstance(self._parent, FGCPVServer):
                # we get the vserver's parent's id here, i.e. the vsystem id
                return self._parent.getparentid()
            elif isinstance(self._parent, FGCPResource):
                # we get the parent's id as usual
                return self._parent.getid()
            elif isinstance(self._parent, str):
                return self._parent

    def create(self, wait=None):
        self.show_output('Creating VDisk %s' % self.vdiskName)
        vdiskId = self.getproxy().CreateVDisk(self.parentid(), self.vdiskName, self.size)
        # set the vdiskId here too
        setattr(self, 'vdiskId', vserverId)
         # CHECKME: invalidate list of vdisks in VSystem
        if isinstance(self._parent, FGCPVSystem):
            self._parent.reset_attr('vdisks')
        if wait:
            # wait for the vdisk to be ready
            self.wait_for_status(['DEPLOYING'], ['NORMAL'])
            self.show_output('Created VDisk %s' % self.vdiskName)
        return vdiskId

    def retrieve(self):
        pass

    def update(self):
        pass

    def destroy(self):
        pass

    def status(self):
        status = self.getproxy().GetVDiskStatus(self.getparentid(), self.getid())
        setattr(self, 'vdiskStatus', status)
        return status

    def attach(self, vserver, wait=None):
        self.show_output('Attaching VDisk %s' % self.vdiskName)
        done = self.check_status(['NORMAL'])
        result = self.getproxy().AttachVDisk(self.getparentid(), vserver.getid(), self.getid())
        if wait:
            result = self.wait_for_status(['ATTACHING'], ['NORMAL'])
            self.show_output('Attached VDisk %s' % self.vdiskName)
        return result

    def detach(self, vserver, wait=None):
        self.show_output('Detaching VDisk %s' % self.vdiskName)
        done = self.check_status(['NORMAL'])
        result = self.getproxy().DetachVDisk(self.getparentid(), vserver.getid(), self.getid())
        if wait:
            result = self.wait_for_status(['DETACHING'], ['NORMAL'])
            self.show_output('Detached VDisk %s' % self.vdiskName)
        return result

    #=========================================================================

    def list_backups(self, timeZone=None, countryCode=None):
        if timeZone or countryCode:
            return self.getproxy().ListVDiskBackup(self.getparentid(), self.getid(), timeZone, countryCode)
        if not hasattr(self, 'backups'):
            setattr(self, 'backups', self.getproxy().ListVDiskBackup(self.getparentid(), self.getid(), timeZone, countryCode))
        return getattr(self, 'backups')

    def get_backup(self, backup):
        # support resource or id
        if isinstance(backup, FGCPBackup):
            return backup.retrieve()
        backups = self.list_backups()
        for entry in backups:
            if backup == entry.backupId:
                return entry
        raise FGCPResourceError('ILLEGAL_BACKUP', 'Invalid backup %s' % backup, self)

    def backup(self, wait=None):
        self.show_output('Start Backup VDisk %s' % self.vdiskName)
        # check current status
        done = self.check_status(['NORMAL', 'STOPPED', 'UNEXPECTED_STOP'], ['BACKUP_ING'])
        if not done:
            # backup vdisk now
            result = self.getproxy().BackupVDisk(self.getparentid(), self.getid())
        else:
            result = done
        if wait:
            # wait for the backup to be done
            result = self.wait_for_status(['BACKUP_ING'], ['STOPPED', 'NORMAL'])
            self.show_output('End Backup VDisk %s' % self.vdiskName)
        return result

    def restore(self, backup, wait=None):
        backup = self.get_backup(backup)
        self.show_output('Start Restore %s for VDisk %s' % (backup, self.vdiskName))
        # check current status
        done = self.check_status(['NORMAL', 'STOPPED', 'UNEXPECTED_STOP'], ['RESTORING'])
        if not done:
            # restore vdisk now - note that we don't need to specify the vdiskId here
            if isinstance(backup, FGCPResource):
                result = self.getproxy().RestoreVDisk(self.getparentid(), backup.getid())
            else:
                result = self.getproxy().RestoreVDisk(self.getparentid(), backup)
        else:
            result = done
        if wait:
            # wait for the backup to be done
            result = self.wait_for_status(['RESTORING'], ['STOPPED', 'NORMAL'])
            self.show_output('End Restore VDisk %s' % self.vdiskName)
        return result

    def cleanup_backups(self, max_num=100, max_age=None):
        self.show_output('Start cleaning backups for VDisk %s' % self.vdiskName)
        self.list_backups()
        if len(self.backups) < 1:
            return
        # Sort list of objects: http://stackoverflow.com/questions/2338531/python-sorting-a-list-of-objects
        from operator import attrgetter
        self.backups.sort(key=attrgetter('timeval'), reverse=True)
        # show last backup
        oldest = float(self.backups[-1].timeval)
        # ...
        # TODO: find matching backups
        # TODO: destroy matching backups
        #for backup in todo:
        #    backup.pprint()
        #    backup.destroy()
        self.show_output('Stop cleaning backups for VDisk %s' % self.vdiskName)


class FGCPBackup(FGCPResource):
    _idname = 'backupId'

    def getparentid(self):
        # CHECKME: the parent of a backup is a vdisk, and we need to get the vsystem
        if self._parent is not None:
            if isinstance(self._parent, FGCPVDisk):
                # we get the vdisk's parent's id here, i.e. the vsystem id (see also above)
                return self._parent.getparentid()
            elif isinstance(self._parent, FGCPResource):
                # we get the parent's id as usual
                return self._parent.getid()
            elif isinstance(self._parent, str):
                return self._parent

    def get_timeval(self):
        # convert weird time format to time value
        timeval = time.mktime(time.strptime(self.backupTime, "%b %d, %Y %I:%M:%S %p"))
        # CHECKME: store as string again ?
        setattr(self, 'timeval', str(timeval))
        return timeval

    def restore(self, wait=None):
        result = self.getproxy().RestoreVDisk(self.getparentid(), self.getid())
        # CHECKME: we can't really wait here, because we're not on the vdisk level ?
        return result

    def destroy(self):
        result = self.getproxy().DestroyVDiskBackup(self.getparentid(), self.getid())
        return result


class FGCPVNic(FGCPResource):
    _idname = 'networkId'
    # CHECKME: or use privateIp ?


class FGCPEfm(FGCPResource):
    _idname = 'efmId'

    def create(self):
        pass

    def retrieve(self):
        pass

    def update(self):
        pass

    def destroy(self):
        pass

    def status(self):
        status = self.getproxy().GetEFMStatus(self.getparentid(), self.getid())
        setattr(self, 'efmStatus', status)
        return status

    def start(self, wait=None):
        self.show_output('Starting EFM %s %s' % (self.efmType, self.efmName))
        done = self.check_status(['STOPPED', 'UNEXPECTED_STOP'], ['RUNNING'])
        if done:
            return done
        result = self.getproxy().StartEFM(self.getparentid(), self.getid())
        if wait:
            result = self.wait_for_status(['STARTING'], ['RUNNING'])
            self.show_output('Started EFM %s %s' % (self.efmType, self.efmName))
        return result

    def stop(self, wait=None):
        self.show_output('Stopping EFM %s %s' % (self.efmType, self.efmName))
        done = self.check_status(['RUNNING'], ['STOPPED', 'UNEXPECTED_STOP'])
        if done:
            return done
        result = self.getproxy().StopEFM(self.getparentid(), self.getid())
        if wait:
            result = self.wait_for_status(['STOPPING'], ['STOPPED', 'UNEXPECTED_STOP'])
            self.show_output('Stopped EFM %s %s' % (self.efmType, self.efmName))
        return result

    #=========================================================================

    def list_backups(self):
        pass

    def get_backup(self):
        pass

    def backup(self):
        pass

    def restore(self):
        pass


class FGCPFirewall(FGCPResource):
    # CHECKME: this returns an attribute 'status' which is in conflict with the default status() method !
    pass


class FGCPFWNATRule(FGCPFirewall):
    pass


class FGCPFWDns(FGCPFirewall):
    pass


class FGCPFWDirection(FGCPFirewall):
    _idname = None

    def getid(self):
        from_zone = getattr(self, 'from', '').split('-').pop()
        to_zone = getattr(self, 'to', '').split('-').pop()
        return '%s-%s' % (from_zone, to_zone)


class FGCPFWPolicy(FGCPFWDirection):
    _idname = 'id'


class FGCPFWLogOrder(FGCPFirewall):
    def __init__(self, **kwargs):
        for key in kwargs:
            # CHECKME: replace from_zone and to_zone, because from=... is restricted
            setattr(self, key.replace('_zone', ''), kwargs[key])


class FGCPLoadBalancer(FGCPResource):
    # CHECKME: this returns an attribute 'status' which is in conflict with the default status() method !
    _idname = 'ipAddress'


class FGCPSLBGroup(FGCPLoadBalancer):
    _idname = 'id'


class FGCPSLBTarget(FGCPSLBGroup):
    pass


class FGCPSLBErrorStats(FGCPLoadBalancer):
    pass


class FGCPSLBErrorCause(FGCPSLBErrorStats):
    pass


class FGCPSLBErrorPeriod(FGCPSLBErrorStats):
    pass


class FGCPSLBServerCert(FGCPLoadBalancer):
    _idname = 'certNum'


class FGCPSLBCCACert(FGCPLoadBalancer):
    _idname = 'ccacertNum'


class FGCPPublicIP(FGCPResource):
    _idname = 'address'

    def allocate(self):
        # see VSystem allocate_publicip
        pass

    def retrieve(self, refresh=None):
        return self.get_attributes(refresh)

    def status(self):
        status = self.getproxy().GetPublicIPStatus(self.getid())
        setattr(self, 'publicipStatus', status)
        return status

    def attach(self, wait=None):
        self.show_output('Attaching PublicIP %s' % self.address)
        done = self.check_status(['DETACHED'], ['ATTACHED'])
        if done:
            return done
        result = self.getproxy().AttachPublicIP(self.getparentid(), self.getid())
        if wait:
            result = self.wait_for_status(['ATTACHING'], ['ATTACHED'])
            self.show_output('Attached PublicIP %s' % self.address)
        return result

    def detach(self, wait=None):
        self.show_output('Detaching PublicIP %s' % self.address)
        done = self.check_status(['ATTACHED'], ['DETACHED'])
        if done:
            return done
        result = self.getproxy().DetachPublicIP(self.getparentid(), self.getid())
        if wait:
            result = self.wait_for_status(['DETACHING'], ['DETACHED'])
            self.show_output('Detached PublicIP %s' % self.address)
        return result

    def free(self, wait=None):
        self.show_output('Freeing PublicIP %s' % self.address)
        # CHECKME: this actually won't work if the publicip has already been freed
        try:
            done = self.check_status(['DETACHED'], ['UNDEPLOYING', 'UNDEPLOY'])
        except:
            done = 'GONE'
        if done:
            return done
        result = self.getproxy().FreePublicIP(self.getparentid(), self.getid())
        if wait:
            # CHECKME: we won't wait for it to be gone here
            self.show_output('Free PublicIP %s' % self.address)
        return result

    def get_attributes(self, refresh=None):
        # CHECKME: if we already have the v4v6Flag information, we already retrieved the attributes
        if not refresh and hasattr(self, 'v4v6Flag'):
            return self
        # get attributes for this publicip
        publicipattr = self.getproxy().GetPublicIPAttributes(self.getid())
        # CHECKME: copy configuration to self
        for key in publicipattr.__dict__:
            if key.startswith('_'):
                continue
            setattr(self, key, publicipattr.__dict__[key])
        return self


class FGCPAddressRange(FGCPResource):
    _idname = None

    def create_pool():
        # see VDataCenter create_addresspool
        pass

    def add():
        # see VDataCenter add_addressrange
        pass

    def delete():
        # see VDataCenter delete_addressrange
        pass


class FGCPVSysDescriptor(FGCPResource):
    _idname = 'vsysdescriptorId'

    def register(self):
        # see VSystem register_vsysdescriptor()
        pass

    def retrieve(self, refresh=None):
        # CHECKME: retrieve configuration here ?
        return self.get_configuration(refresh)

    def update(self):
        #self.getproxy().UpdateVSYSDescriptorAttribute(self.getid(), updateLcId, attributeName, attributeValue)
        return

    def unregister(self):
        #return self.getproxy().UnregisterVSYSDescriptor(self.getid())
        # CHECKME: only private vsysdescriptors can be unregistered by end-users
        return self.getproxy().UnregisterPrivateVSYSDescriptor(self.getid())

    #=========================================================================

    def list_diskimages(self, category='GENERAL'):
        if not hasattr(self, 'diskimages'):
            # CHECKME: reversed order of arguments here
            setattr(self, 'diskimages', self.getproxy().ListDiskImage(category, self.getid()))
        return getattr(self, 'diskimages')

    def get_diskimage(self, diskimageName):
        # support resource, name or id
        if isinstance(diskimageName, FGCPDiskImage):
            return diskimageName.retrieve()
        diskimages = self.list_diskimages()
        for diskimage in diskimages:
            if diskimageName == diskimage.diskimageName:
                return diskimage
            elif diskimageName == diskimage.diskimageId:
                return diskimage
        raise FGCPResourceError('ILLEGAL_DISKIMAGE', 'Invalid diskimageName %s' % diskimageName, self)

    #=========================================================================

    def get_configuration(self, refresh=None):
        # CHECKME: if we already have the registrant information etc., we already retrieved the attributes
        # CHECKME: if we already also have the vservers information, we already retrieved the configuration
        if not refresh and hasattr(self, 'registrant'):
            return self
        # get configuration for this vsysdescriptor
        config = self.getproxy().GetVSYSDescriptorConfiguration(self.getid())
        # CHECKME: copy configuration to self
        for key in config.__dict__:
            if key.startswith('_'):
                continue
            setattr(self, key, config.__dict__[key])
        return self

    #=========================================================================

    def create_vsystem(self, vsysName, wait=None):
        self.show_output('Creating VSystem %s' % vsysName)
        vsysId = self.getproxy().CreateVSYS(self.getid(), vsysName)
        # CHECKME: invalidate list of vsystems in VDataCenter
        if isinstance(self._parent, FGCPVDataCenter):
            self._parent.reset_attr('vsystems')
            if wait:
                # get the newly created vsystem
                vsystem = self._parent.get_vsystem(vsysName)
                # wait for the vsystem to be ready
                vsystem.wait_for_status(['DEPLOYING', 'RECONFIG_ING'], ['NORMAL'])
                self.show_output('Created VSystem %s' % vsysName)
        return vsysId


class FGCPDiskImage(FGCPResource):
    _idname = 'diskimageId'

    def register(self):
        # see VServer register_diskimage
        pass

    def update(self):
        pass

    def unregister(self):
        return self.getproxy().UnregisterDiskImage(self.getid())

    def list_softwares(self):
        if not hasattr(self, 'softwares'):
            # CHECKME: initialize to None or list here ?
            setattr(self, 'softwares', None)
        return getattr(self, 'softwares')

    def list_servertypes(self):
        if not hasattr(self, 'servertypes'):
            setattr(self, 'servertypes', self.getproxy().ListServerType(self.getid()))
        return getattr(self, 'servertypes')


class FGCPDiskImageSoftware(FGCPResource):
    _idname = 'name'


class FGCPServerType(FGCPResource):
    # this is what we actually pass to CreateVServer
    _idname = 'name'


class FGCPServerTypeCPU(FGCPResource):
    # CHECKME: this is used as internal response element for ListServerType
    pass


class FGCPUsageInfo(FGCPResource):
    _idname = 'vsysId'


class FGCPUsageInfoProduct(FGCPResource):
    _idname = 'productName'


class FGCPUnknown(FGCPResource):
    pass
