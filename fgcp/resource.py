#!/usr/bin/python
#
#  Copyright (C) 2012-2016 Michel Dalle
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

# Do typical actions on resources
vsystem = vdc.get_vsystem('Python API Demo System')
vsystem.show_status()
for vserver in vsystem.vservers:
    result = vserver.backup(wait=True)
...
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
        # initialize object attributes, cfr. FGCPDesign().load()
        for key in kwargs.keys():
            setattr(self, key, kwargs[key])

    def __repr__(self):
        return '<%s>' % type(self).__name__

    #=========================================================================

    def pformat(self, what, depth=0):
        prefix = '  ' * depth
        #if what is None:
        #    return '%sNone' % prefix
        if isinstance(what, str):
            return "%s'%s'" % (prefix, what)
        CRLF = '\r\n'
        L = []
        if isinstance(what, list):
            L.append('%s[' % prefix)
            for val in what:
                L.append(self.pformat(val, depth + 1) + ',')
            L.append('%s]' % prefix)
            return CRLF.join(L)
        # initialize object attributes, cfr. FGCPDesign().save()
        L.append('%s%s(' % (prefix, type(what).__name__))
        depth += 1
        prefix = '  ' * depth
        for key in what.__dict__:
            # TODO: skip _caller and _parent for output later ?
            if key == '_caller' or key == '_parent' or key == '_status':
                if isinstance(what.__dict__[key], FGCPResource):
                    L.append("%s%s='%s'," % (prefix, key, repr(what.__dict__[key])))
                elif isinstance(what.__dict__[key], str):
                    L.append("%s%s='%s'," % (prefix, key, what.__dict__[key]))
                else:
                    L.append('%s%s=%s,' % (prefix, key, what.__dict__[key]))
            # TODO: skip _proxy for output later ?
            elif key == '_proxy':
                #if what.__dict__[key] is not None:
                #    L.append("%s%s='%s'," % (prefix, key, repr(what.__dict__[key])))
                #else:
                #    L.append('%s%s=None,' % (prefix, key))
                pass
            # CHECKME: skip all the others, e.g. _get_handler from FW and SLB
            elif key.startswith('_'):
                pass
            elif isinstance(what.__dict__[key], FGCPElement):
                L.append('%s%s=' % (prefix, key))
                L.append(self.pformat(what.__dict__[key], depth + 1) + ',')
            elif isinstance(what.__dict__[key], list):
                L.append('%s%s=[' % (prefix, key))
                for val in what.__dict__[key]:
                    L.append(self.pformat(val, depth + 1) + ',')
                L.append('%s],' % prefix)
            elif isinstance(what.__dict__[key], str):
                L.append("%s%s='%s'," % (prefix, key, what.__dict__[key]))
            elif isinstance(what.__dict__[key], int) or isinstance(what.__dict__[key], float):
                L.append("%s%s=%s," % (prefix, key, what.__dict__[key]))
            elif what.__dict__[key] is None:
                #L.append("%s%s=None," % (prefix, key))
                pass
            else:
                L.append("%s%s='?%s?'," % (prefix, key, what.__dict__[key]))
        depth -= 1
        prefix = '  ' * depth
        L.append('%s)' % prefix)
        return CRLF.join(L)

    def pprint(self):
        """
        Show dump of the FGCP Element for development
        """
        print self.pformat(self)

    #=========================================================================

    def reset_attr(self, what):
        if hasattr(self, what):
            setattr(self, what, None)


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
        # initialize object attributes, cfr. FGCPDesign().load()
        for key in kwargs.keys():
            setattr(self, key, kwargs[key])
        # CHECKME: special case for id=123 and/or parentid=12 ?
        if hasattr(self, 'id') and self._idname is not None:
            # CHECKME: set the _idname to the 'id' value
            if self._idname != 'id' and getattr(self, self._idname, None) is None:
                setattr(self, self._idname, getattr(self, 'id'))

    def __repr__(self):
        return '<%s:%s>' % (type(self).__name__, self.getid())

    #=========================================================================

    def create(self, wait=None):
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
    """
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
        if self._idname is not None and getattr(self, self._idname, None) is not None:
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
        if parent is not None and hasattr(parent, '_proxy'):
            self._proxy = parent._proxy

    def getproxy(self):
        if self._proxy is not None:
            # CHECKME: set the caller here for use in FGCPResponseParser !?
            self._proxy._caller = self
            return self._proxy

    def merge_attr(self, partial):
        # set missing parts of self with information from partial - do not overwrite
        for key in partial.__dict__:
            if key.startswith('_') and key != '_status':
                continue
            if getattr(self, key, None) is None:
                setattr(self, key, partial.__dict__[key])

    #=========================================================================

    # convert *args and **kwargs from other method to dict
    def _args2dict(self, argslist=[], kwargsdict={}, allowed=None):
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
        if len(kwargsdict) > 0:
            tododict.update(kwargsdict)
        # TODO: sanitize dict by removing _* + the _idname, and diff the rest with current values ?
        if len(allowed) > 0 and len(tododict) > 0:
            newdict = {}
            for key in allowed:
                if key in tododict:
                    newdict[key] = tododict[key]
            tododict = newdict
        return tododict

    """
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
    """


class FGCPVDataCenter(FGCPResource):
    """
    FGCP VDataCenter
    """
    _idname = 'config'
    config = None
    vsystems = None
    publicips = None
    addressranges = None
    vsysdescriptors = None
    diskimages = None
    servertypes = None

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
        if getattr(self, 'vsystems', None) is None:
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
            # make sure the vsystem is shutdown first
            result = vsystem.shutdown(wait)
        # let the vsystem handle it
        return vsystem.destroy()

    #=========================================================================

    def list_publicips(self):
        if getattr(self, 'publicips', None) is None:
            setattr(self, 'publicips', self.getproxy().ListPublicIP())
        return getattr(self, 'publicips')

    def get_publicip(self, publicipAddress):
        # support resource or address (=id)
        if isinstance(publicipAddress, FGCPPublicIP):
            return publicipAddress.retrieve()
        publicips = self.list_publicips()
        for publicip in publicips:
            if publicipAddress == publicip.address:
                return publicip.retrieve()
        raise FGCPResourceError('ILLEGAL_ADDRESS', 'Invalid publicipAddress %s' % publicipAddress, self)

    #=========================================================================

    def list_addressranges(self):
        if getattr(self, 'addressranges', None) is None:
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
        if getattr(self, 'vsysdescriptors', None) is None:
            setattr(self, 'vsysdescriptors', self.getproxy().ListVSYSDescriptor())
        return getattr(self, 'vsysdescriptors')

    def get_vsysdescriptor(self, vsysdescriptorName):
        # support resource, name or id
        if isinstance(vsysdescriptorName, FGCPVSysDescriptor):
            return vsysdescriptorName.retrieve()
        vsysdescriptors = self.list_vsysdescriptors()
        for vsysdescriptor in vsysdescriptors:
            if vsysdescriptorName == vsysdescriptor.vsysdescriptorName:
                return vsysdescriptor.retrieve()
            elif vsysdescriptorName == vsysdescriptor.vsysdescriptorId:
                return vsysdescriptor.retrieve()
        raise FGCPResourceError('ILLEGAL_VSYSDESCRIPTOR', 'Invalid vsysdescriptorName %s' % vsysdescriptorName, self)

    #=========================================================================

    def list_diskimages(self, vsysdescriptor=None, category='GENERAL'):
        # CHECKME: reversed order of arguments here
        # get all diskimages
        if vsysdescriptor is None:
            if getattr(self, 'diskimages', None) is None:
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
                return diskimage.retrieve()
            elif diskimageName == diskimage.diskimageId:
                return diskimage.retrieve()
        raise FGCPResourceError('ILLEGAL_DISKIMAGE', 'Invalid diskimageName %s' % diskimageName, self)

    #=========================================================================

    def list_servertypes(self, diskimage=None):
        # CHECKME: all diskimages support the same servertypes at the moment !?
        if getattr(self, 'servertypes', None) is not None:
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
                return servertype.retrieve()
        raise FGCPResourceError('ILLEGAL_SERVERTYPE', 'Invalid servertypeName %s' % servertypeName, self)

    #=========================================================================

    def get_vsystem_usage(self, vsysNames=None):
        if vsysNames is None:
            return self.getproxy().GetSystemUsage()
        vsysIds = []
        if isinstance(vsysNames, str):
            vsysNames = [vsysNames]
        for vsysName in vsysNames:
            vsystem = self.get_vsystem(vsysName)
            vsysIds.append(vsystem.vsysId)
        if len(vsysIds) > 0:
            vsysIds = ' '.join(vsysIds)
        else:
            vsysIds = None
        return self.getproxy().GetSystemUsage(vsysIds)

    def show_vsystem_usage(self, vsysNames=None):
        date, usagelist = self.get_vsystem_usage(vsysNames)
        print 'Usage Report on %s' % date
        for usageinfo in usagelist:
            #entry.pprint()
            print
            print 'VSystem: %s [%s]' % (usageinfo.vsysName, usageinfo.vsysId)
            for product in usageinfo.products:
                print '  %s:\t%s %s' % (product.productName, product.usedPoints, product.unitName)

    def show_vsystem_status(self, sep='\t'):
        for vsystem in self.list_vsystems():
            vsystem.show_status(sep)

    #=========================================================================

    def get_information(self, all=None, timeZone=None, countryCode=None):
        return self.getproxy().GetInformation(all, timeZone, countryCode)

    def get_eventlog(self, all=None, timeZone=None, countryCode=None):
        return self.getproxy().GetEventLog(all, timeZone, countryCode)

    #=========================================================================

    def get_vsystem_design(self, vsystem=None):
        # get design from existing vsystem if specified
        if vsystem is not None:
            vsystem = self.get_vsystem(vsystem)
        from fgcp.design import FGCPDesign
        design = FGCPDesign(vsystem=vsystem)
        # set the parent of the design to this vdatacenter !
        design.setparent(self)
        return design


class FGCPVSystem(FGCPResource):
    _idname = 'vsysId'
    vsysId = None
    vsysName = None
    description = None
    baseDescriptor = None
    creator = None
    cloudCategory = None
    vservers = None
    vdisks = None
    vnets = None
    publicips = None
    firewalls = None
    loadbalancers = None

    def create(self):
        # CHECKME: do we want this too ?
        pass

    def retrieve(self, refresh=None):
        # CHECKME: retrieve inventory here ?
        return self.get_inventory(refresh)

    def update(self, *args, **kwargs):
        self.show_output('Updating VSystem %s' % self.vsysName)
        allowed = ['vsysName', 'cloudCategory']
        # convert arguments to dict
        tododict = self._args2dict(args, kwargs, allowed)
        # CHECKME: what if we updated the object attributes directly ?
        result = None
        # CHECKME: different methods for different fields
        if 'vsysName' in tododict and tododict['vsysName'] != self.vsysName:
            result = self.getproxy().UpdateVSYSAttribute(self.getid(), 'vsysName', tododict['vsysName'])
        if 'cloudCategory' in tododict and tododict['cloudCategory'] != self.cloudCategory:
            result = self.getproxy().UpdateVSYSConfiguration(self.getid(), 'CLOUD_CATEGORY', tododict['cloudCategory'])
        self.show_output('Updated VSystem %s' % self.vsysName)
        return result

    def destroy(self):
        self.show_output('Destroying VSystem %s' % self.vsysName)
        result = self.getproxy().DestroyVSYS(self.getid())
        # CHECKME: invalidate list of vsystems in VDataCenter
        if isinstance(self._parent, FGCPVDataCenter):
            self._parent.reset_attr('vsystems')
        self.show_output('Destroyed VSystem %s' % self.vsysName)
        return result

    def status(self):
        status = self.getproxy().GetVSYSStatus(self.getid())
        setattr(self, 'vsysStatus', status)
        return status

    def boot(self, wait=None):
        self.show_output('Booting VSystem %s' % self.vsysName)
        # check if the vsystem is ready
        todo = self.check_status(['NORMAL'], ['DEPLOYING', 'RECONFIG_ING'])
        if todo and wait:
            # wait for the vsystem to be ready
            result = self.wait_for_status(['DEPLOYING', 'RECONFIG_ING'], ['NORMAL'])
        elif todo:
            # we're not ready and won't wait
            return todo
        # get system inventory if necessary
        self.get_inventory()
        # start all firewalls
        for firewall in self.firewalls:
            firewall.start(wait)
        # attach publicip - cfr. sequence3 in java sdk
        for publicip in self.publicips:
            publicip.attach(wait)
        self.show_output('Booted VSystem %s' % self.vsysName)
        return

    def start(self, wait=None):
        self.show_output('Starting VSystem %s' % self.vsysName)
        # check if the vsystem is ready
        self.boot(wait)
        # start all vservers
        for vserver in self.vservers:
            vserver.start(wait)
        # start all loadbalancers
        for loadbalancer in self.loadbalancers:
            loadbalancer.start(wait)
        self.show_output('Started VSystem %s' % self.vsysName)
        return

    def stop(self, wait=None):
        self.show_output('Stopping VSystem %s' % self.vsysName)
        # check if the vsystem is ready
        todo = self.check_status(['NORMAL'], ['DEPLOYING', 'RECONFIG_ING'])
        if todo and wait:
            # wait for the vsystem to be ready
            result = self.wait_for_status(['DEPLOYING', 'RECONFIG_ING'], ['NORMAL'])
        elif todo:
            # we're not ready and won't wait
            return todo
        # get system inventory if necessary
        self.get_inventory()
        # stop all loadbalancers
        for loadbalancer in self.loadbalancers:
            loadbalancer.stop(wait)
        # stop all vservers
        for vserver in self.vservers:
            vserver.stop(wait)
        self.show_output('Stopped VSystem %s' % self.vsysName)
        return

    def shutdown(self, wait=None):
        self.show_output('Shutting down VSystem %s' % self.vsysName)
        # detach publicip - cfr. sequence3 in java sdk
        for publicip in self.publicips:
            publicip.detach(wait)
        # stop all firewalls
        for firewall in self.firewalls:
            firewall.stop(wait)
        self.show_output('Shut down VSystem %s' % self.vsysName)
        return

    #=========================================================================

    def list_vservers(self):
        if getattr(self, 'vservers', None) is None:
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
                return vserver.retrieve()
            elif vserverName == vserver.vserverId:
                return vserver.retrieve()
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
        if getattr(self, 'vdisks', None) is None:
            setattr(self, 'vdisks', self.getproxy().ListVDisk(self.getid()))
        return getattr(self, 'vdisks')

    def get_vdisk(self, vdiskName):
        # support resource, name or id
        if isinstance(vdiskName, FGCPVDisk):
            return vdiskName.retrieve()
        vdisks = self.list_vdisks()
        for vdisk in vdisks:
            if vdiskName == vdisk.vdiskName:
                return vdisk.retrieve()
            elif vdiskName == vdisk.vdiskId:
                return vdisk.retrieve()
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
        if getattr(self, 'firewalls', None) is None:
            setattr(self, 'firewalls', self.getproxy().ListEFM(self.getid(), "FW"))
        return getattr(self, 'firewalls')

    def get_firewall(self, efmName):
        # support resource, name or id
        if isinstance(efmName, FGCPFirewall):
            return efmName.retrieve()
        firewalls = self.list_firewalls()
        for firewall in firewalls:
            if efmName == firewall.efmName:
                return firewall.retrieve()
            elif efmName == firewall.efmId:
                return firewall.retrieve()
        raise FGCPResourceError('ILLEGAL_FIREWALL', 'Invalid efmName %s' % efmName, self)

    #=========================================================================

    def list_loadbalancers(self):
        if getattr(self, 'loadbalancers', None) is None:
            setattr(self, 'loadbalancers', self.getproxy().ListEFM(self.getid(), "SLB"))
        return getattr(self, 'loadbalancers')

    def get_loadbalancer(self, efmName):
        # support resource, name or id
        if isinstance(efmName, FGCPLoadBalancer):
            return efmName.retrieve()
        loadbalancers = self.list_loadbalancers()
        for loadbalancer in loadbalancers:
            if efmName == loadbalancer.efmName:
                return loadbalancer.retrieve()
            elif efmName == loadbalancer.efmId:
                return loadbalancer.retrieve()
        raise FGCPResourceError('ILLEGAL_LOADBALANCER', 'Invalid efmName %s' % efmName, self)

    def create_loadbalancer(self, efmName, vnet, wait=None):
        # get the right vnet ourselves
        vnet = self.get_vnet(vnet)
        # make a new loadbalancer with the right attributes - vnet returns a string, so no vnet.getid() needed (for now ?)
        loadbalancer = FGCPLoadBalancer(efmName=efmName, networkId=vnet)
        # set the parent of the loadbalancer to this vsystem !
        loadbalancer.setparent(self)
        # and now create it :-)
        return loadbalancer.create(wait)

    #=========================================================================

    def list_vnets(self):
        if getattr(self, 'vnets', None) is None:
            self.retrieve()
        return getattr(self, 'vnets')

    def get_vnet(self, vnet):
        # support vnet
        vnets = self.list_vnets()
        # find exact match first - this is a string
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
        if getattr(self, 'publicips', None) is None:
            setattr(self, 'publicips', self.getproxy().ListPublicIP(self.getid()))
        return getattr(self, 'publicips')

    def get_publicip(self, publicipAddress):
        # support resource or address (=id)
        if isinstance(publicipAddress, FGCPPublicIP):
            return publicipAddress.retrieve()
        publicips = self.list_publicips()
        for publicip in publicips:
            if publicipAddress == publicip.address:
                return publicip.retrieve()
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
                    return result
            raise FGCPResourceError('TIMEOUT', 'Unable to retrieve PublicIP for VSystem %s' % self.vsysName, self)
        return result

    #=========================================================================

    def get_inventory(self, refresh=None):
        # CHECKME: if we already have the firewall information, we already retrieved the configuration
        if not refresh and getattr(self, 'firewalls', None) is not None:
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
        if getattr(self, 'vdisks', None) is None:
            setattr(self, 'vdisks', [])
        if getattr(self, 'publicips', None) is None:
            setattr(self, 'publicips', [])
        return self

    def get_status(self, sep='\t'):
        self.show_output('Status Overview for VSystem %s' % self.vsysName)
        # get system inventory if necessary
        self.get_inventory()
        status = self.status()
        self.show_output(sep.join(['VSystem', self.vsysName, status]))
        # get status of public ips
        for publicip in self.publicips:
            status = publicip.status()
            self.show_output(sep.join(['PublicIP', publicip.address, status]))
        # get status of firewalls
        for firewall in self.firewalls:
            status = firewall.status()
            self.show_output(sep.join(['Firewall', firewall.efmName, status]))
        # get status of loadbalancers
        for loadbalancer in self.loadbalancers:
            status = loadbalancer.status()
            self.show_output(sep.join(['LoadBalancer', loadbalancer.efmName, loadbalancer.slbVip, status]))
        # get status of vservers (excl. firewalls and loadbalancers)
        seenId = {}
        for vserver in self.vservers:
            status = vserver.status()
            self.show_output(sep.join(['VServer', vserver.vserverName, vserver.vnics[0].privateIp, status]))
            # get status of attached disks
            for vdisk in vserver.vdisks:
                status = vdisk.status()
                self.show_output(sep.join(['', 'VDisk', vdisk.vdiskName, status]))
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
                self.show_output(sep.join(['', 'VDisk', vdisk.vdiskName, status]))
                seenId[vdisk.vdiskId] = 1
        self.show_output('.')
        return self

    def show_status(self, sep='\t'):
        # set output to 1, i.e. don't show the status in the API command
        old_verbose = self._proxy.set_verbose(1)
        # get system status
        self.get_status(sep)
        # reset output
        self._proxy.set_verbose(old_verbose)

    #=========================================================================

    def register_vsysdescriptor(self, name, description, keyword):
        return self.getproxy().RegisterPrivateVSYSDescriptor(self.getid(), name, description, keyword, self.vservers)

    def get_usage(self):
        return self.getproxy().GetSystemUsage(self.getid())


class FGCPVServer(FGCPResource):
    _idname = 'vserverId'
    vserverId = None
    vserverName = None
    vserverType = None
    diskimageId = None
    creator = None
    vdisks = None
    vnics = None
    image = None
    backups = None

    def create(self, wait=None):
        # CHECKME: simplify vnics[0].getid() issue on create by allowing networkId
        if getattr(self, 'networkId') is None and getattr(self, 'vnics', None) is not None:
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
        self.show_output('Updating VServer %s' % self.vserverName)
        allowed = ['vserverName', 'vserverType']
        # convert arguments to dict
        tododict = self._args2dict(args, kwargs, allowed)
        # CHECKME: what if we updated the object attributes directly ?
        result = None
        for key in tododict:
            if tododict[key] != getattr(self, key, None):
                result = self.getproxy().UpdateVServerAttribute(self.getparentid(), self.getid(), key, tododict[key])
        self.show_output('Updated VServer %s' % self.vserverName)
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
        done = self.check_status(['STOPPED', 'UNEXPECTED_STOP'], ['RUNNING', 'STARTING'])
        if done:
            return done
        result = self.getproxy().StartVServer(self.getparentid(), self.getid())
        if wait:
            result = self.wait_for_status(['STARTING'], ['RUNNING'])
            self.show_output('Started VServer %s' % self.vserverName)
        return result

    def stop(self, wait=None, force=None):
        self.show_output('Stopping VServer %s' % self.vserverName)
        done = self.check_status(['RUNNING'], ['STOPPED', 'UNEXPECTED_STOP', 'STOPPING'])
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
        if not refresh and getattr(self, 'vnics', None) is not None:
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
        if getattr(self, 'vdisks', None) is None:
            self.retrieve()
        return getattr(self, 'vdisks')

    def get_vdisk(self, vdisk):
        # let the VSystem get the right disk here, since it might not be attached to this VServer
        return self._parent.get_vdisk(vdisk)

    def attach_vdisk(self, vdisk, wait=None):
        vdisk = self.get_vdisk(vdisk)
        return vdisk.attach(self, wait)

    def detach_vdisk(self, vdisk, wait=None):
        vdisk = self.get_vdisk(vdisk)
        return vdisk.detach(self, wait)

    #=========================================================================

    def list_backups(self, timeZone=None, countryCode=None):
        if timeZone or countryCode:
            # Note: the system disk has the same id as the vserver
            return self.getproxy().ListVDiskBackup(self.getparentid(), self.getid(), timeZone, countryCode)
        if getattr(self, 'backups', None) is None:
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
            self.show_output('Finish Backup VServer %s' % self.vserverName)
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
            self.show_output('Finish Restore VServer %s' % self.vserverName)
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
        if getattr(self, 'vnics', None) is None:
            self.retrieve()
        return getattr(self, 'vnics')

    #=========================================================================

    def register_diskimage(self, name, description):
        return self.getproxy().RegisterPrivateDiskImage(self.getid(), name, description)

    #=========================================================================

    def get_performance(self, interval='hour', dataType=None):
        return self.getproxy().GetPerformanceInformation(self.getparentid(), self.getid(), interval, dataType)


class FGCPVServerImage(FGCPResource):
    _idname = 'id'
    id = None
    cpuBit = None
    numOfMaxDisk = None
    numOfMaxNic = None
    serverApplication = None
    serverCategory = None
    softwares = None
    sysvolSize = None

    def list_softwares(self):
        if getattr(self, 'softwares', None) is None:
            # CHECKME: initialize to None or list here ?
            setattr(self, 'softwares', [])
        return getattr(self, 'softwares')


class FGCPVDisk(FGCPResource):
    _idname = 'vdiskId'
    vdiskId = None
    vdiskName = None
    size = None
    attachedTo = None
    creator = None
    backups = None

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
        self.show_output('Creating VDisk %s (%s GB)' % (self.vdiskName, self.size))
        vdiskId = self.getproxy().CreateVDisk(self.getparentid(), self.vdiskName, self.size)
        # set the vdiskId here too
        setattr(self, 'vdiskId', vdiskId)
        # CHECKME: invalidate list of vdisks in VSystem
        if isinstance(self._parent, FGCPVSystem):
            self._parent.reset_attr('vdisks')
        if wait:
            # wait for the vdisk to be ready
            self.wait_for_status(['DEPLOYING'], ['NORMAL'])
            self.show_output('Created VDisk %s' % self.vdiskName)
        return vdiskId

    def retrieve(self, refresh=None):
        return self

    def update(self, *args, **kwargs):
        self.show_output('Updating VDisk %s' % self.vdiskName)
        allowed = ['vdiskName']
        # convert arguments to dict
        tododict = self._args2dict(args, kwargs, allowed)
        # CHECKME: what if we updated the object attributes directly ?
        result = None
        for key in tododict:
            if tododict[key] != getattr(self, key, None):
                result = self.getproxy().UpdateVDiskAttribute(self.getparentid(), self.getid(), key, tododict[key])
        self.show_output('Updated VDisk %s' % self.vdiskName)
        return result

    def destroy(self):
        self.show_output('Destroying VDisk %s (%s GB)' % (self.vdiskName, self.size))
        vdiskId = self.getproxy().DestroyVDisk(self.getparentid(), self.vdiskId)
        # CHECKME: invalidate list of vdisks in VSystem
        if isinstance(self._parent, FGCPVSystem):
            self._parent.reset_attr('vdisks')
        self.show_output('Destroyed VDisk %s' % self.vdiskName)
        return

    def status(self):
        status = self.getproxy().GetVDiskStatus(self.getparentid(), self.getid())
        setattr(self, 'vdiskStatus', status)
        return status

    def attach(self, vserver, wait=None):
        self.show_output('Attaching VDisk %s to VServer %s' % (self.vdiskName, vserver.vserverName))
        done = self.check_status(['NORMAL'])
        result = self.getproxy().AttachVDisk(self.getparentid(), vserver.getid(), self.getid())
        if wait:
            result = self.wait_for_status(['ATTACHING'], ['NORMAL'])
            self.show_output('Attached VDisk %s to VServer %s' % (self.vdiskName, vserver.vserverName))
        return result

    def detach(self, vserver, wait=None):
        self.show_output('Detaching VDisk %s from VServer %s' % (self.vdiskName, vserver.vserverName))
        done = self.check_status(['NORMAL'])
        result = self.getproxy().DetachVDisk(self.getparentid(), vserver.getid(), self.getid())
        if wait:
            result = self.wait_for_status(['DETACHING'], ['NORMAL'])
            self.show_output('Detached VDisk %s from VServer %s' % (self.vdiskName, vserver.vserverName))
        return result

    #=========================================================================

    def list_backups(self, timeZone=None, countryCode=None):
        if timeZone or countryCode:
            return self.getproxy().ListVDiskBackup(self.getparentid(), self.getid(), timeZone, countryCode)
        if getattr(self, 'backups', None) is None:
            setattr(self, 'backups', self.getproxy().ListVDiskBackup(self.getparentid(), self.getid(), timeZone, countryCode))
        return getattr(self, 'backups')

    def get_backup(self, backup):
        # support resource or id
        if isinstance(backup, FGCPBackup):
            return backup.retrieve()
        backups = self.list_backups()
        for entry in backups:
            if backup == entry.backupId:
                return entry.retrieve()
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
            self.show_output('Finish Backup VDisk %s' % self.vdiskName)
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
            self.show_output('Finish Restore VDisk %s' % self.vdiskName)
        return result

    def cleanup_backups(self, max_num=100, max_age=None):
        self.show_output('TODO: Start cleaning backups for VDisk %s' % self.vdiskName)
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
        self.show_output('TODO: Stop cleaning backups for VDisk %s' % self.vdiskName)


class FGCPBackup(FGCPResource):
    _idname = 'backupId'
    backupId = None
    backupTime = None

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
        self.show_output('Restoring Backup %s' % self.getid())
        if isinstance(self._parent, FGCPVDisk):
            result = self.getproxy().RestoreVDisk(self.getparentid(), self.getid())
        elif isinstance(self._parent, FGCPEfm):
            # grand-parent, parent and current
            result = self.getproxy().RestoreEFM(self._parent.getparentid(), self.getparentid(), self.getid())
        else:
            result = 'UNKNOWN'
        # CHECKME: we can't really wait here, because we're not on the vdisk or efm level ?
        return result

    def destroy(self):
        self.show_output('Destroying Backup %s' % self.getid())
        if isinstance(self._parent, FGCPVDisk):
            result = self.getproxy().DestroyVDiskBackup(self.getparentid(), self.getid())
        elif isinstance(self._parent, FGCPEfm):
            # grand-parent, parent and current
            result = self.getproxy().DestroyEFMBackup(self._parent.getparentid(), self.getparentid(), self.getid())
        else:
            result = 'UNKNOWN'
        return result


class FGCPVNic(FGCPResource):
    _idname = 'networkId'
    # CHECKME: or use privateIp ?
    networkId = None
    privateIp = None
    nicNo = None


class FGCPEfm(FGCPResource):
    _idname = 'efmId'
    efmId = None
    efmName = None
    efmType = None
    creator = None
    firewall = None
    loadbalancer = None
    slbVip = None
    backups = None

    def create(self, wait=None):
        # CHECKME: we use networkId to identify the network here, although this isn't found in the normal object definition !?
        self.show_output('Creating EFM %s %s' % (self.efmType, self.efmName))
        efmId = self.getproxy().CreateEFM(self.getparentid(), self.efmType, self.efmName, self.networkId)
        # set the efmId here too
        setattr(self, 'efmId', efmId)
        # CHECKME: invalidate list of firewalls/loadbalancers in VSystem
        if isinstance(self._parent, FGCPVSystem):
            if self.efmType == 'FW':
                self._parent.reset_attr('firewalls')
            else:
                self._parent.reset_attr('loadbalancers')
        if wait:
            # wait for the EFM to be ready
            self.wait_for_status(['DEPLOYING'], ['STOPPED'])
            self.show_output('Created EFM %s %s' % (self.efmType, self.efmName))
        return efmId

    def retrieve(self):
        return self

    def update(self, *args, **kwargs):
        self.show_output('Updating EFM %s' % self.efmName)
        allowed = ['efmName']
        # convert arguments to dict
        tododict = self._args2dict(args, kwargs, allowed)
        # CHECKME: what if we updated the object attributes directly ?
        result = None
        for key in tododict:
            if tododict[key] != getattr(self, key, None):
                result = self.getproxy().UpdateEFMAttribute(self.getparentid(), self.getid(), key, tododict[key])
        self.show_output('Updated EFM %s' % self.efmName)
        return result

    def destroy(self):
        self.show_output('Destroying EFM %s %s' % (self.efmType, self.efmName))
        efmId = self.getproxy().DestroyEFM(self.getparentid(), self.efmType, self.efmId)
        # CHECKME: invalidate list of firewalls/loadbalancers in VSystem
        if isinstance(self._parent, FGCPVSystem):
            if self.efmType == 'FW':
                self._parent.reset_attr('firewalls')
            else:
                self._parent.reset_attr('loadbalancers')
        self.show_output('Destroyed EFM %s %s' % (self.efmType, self.efmName))
        return

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

    def list_backups(self, timeZone=None, countryCode=None):
        if timeZone or countryCode:
            return self.getproxy().ListEFMBackup(self.getparentid(), self.getid(), timeZone, countryCode)
        if getattr(self, 'backups', None) is None:
            setattr(self, 'backups', self.getproxy().ListEFMBackup(self.getparentid(), self.getid(), timeZone, countryCode))
        return getattr(self, 'backups')

    def get_backup(self, backup):
        # support resource or id
        if isinstance(backup, FGCPBackup):
            return backup.retrieve()
        backups = self.list_backups()
        for entry in backups:
            if backup == entry.backupId:
                return entry.retrieve()
        raise FGCPResourceError('ILLEGAL_BACKUP', 'Invalid backup %s' % backup, self)

    def backup(self, wait=None):
        self.show_output('Start Backup EFM %s' % self.efmName)
        # check current status
        done = self.check_status(['RUNNING'], ['BACKUP_ING'])
        if not done:
            # backup EFM now
            result = self.getproxy().BackupEFM(self.getparentid(), self.getid())
        else:
            result = done
        if wait:
            # wait for the backup to be done
            result = self.wait_for_status(['BACKUP_ING'], ['RUNNING'])
            self.show_output('Finish Backup EFM %s' % self.efmName)
        return result

    def restore(self, backup, wait=None):
        backup = self.get_backup(backup)
        self.show_output('Start Restore %s for EFM %s' % (backup, self.efmName))
        # check current status
        done = self.check_status(['RUNNING'], ['RESTORING'])
        if not done:
            if isinstance(backup, FGCPResource):
                result = self.getproxy().RestoreEFM(self.getparentid(), self.getid(), backup.getid())
            else:
                result = self.getproxy().RestoreEFM(self.getparentid(), self.getid(), backup)
        else:
            result = done
        if wait:
            # wait for the backup to be done
            result = self.wait_for_status(['RESTORING'], ['RUNNING'])
            self.show_output('Finish Restore EFM %s' % self.efmName)
        return result

    #=========================================================================

    def get_config_handler(self):
        if getattr(self, '_get_handler', None) is None:
            setattr(self, '_get_handler', self.getproxy().GetEFMConfigHandler(self.getparentid(), self.getid()))
        return getattr(self, '_get_handler')

    def update_config_handler(self):
        if getattr(self, '_update_handler', None) is None:
            setattr(self, '_update_handler', self.getproxy().UpdateEFMConfigHandler(self.getparentid(), self.getid()))
        return getattr(self, '_update_handler')

    #=========================================================================

    def get_update_info(self):
        update_info = self.get_config_handler().fw_update()
        # CHECKME: merge answer with current firewall/loadbalancer ?
        self.merge_attr(update_info)
        return update_info

    def apply_update(self):
        return self.update_config_handler().efm_update()

    def revert_update(self):
        return self.update_config_handler().efm_backout()

    #=========================================================================

    def get_child_object(self):
        # CHECKME: get child firewall or loadbalancer object and merge EFM attributes
        if isinstance(self, FGCPFirewall) or isinstance(self, FGCPLoadBalancer):
            # we're already a firewall or loadbalancer
            return self
        if self.efmType == 'FW':
            if getattr(self, 'firewall', None) is None:
                # create new firewall
                setattr(self, 'firewall', FGCPFirewall())
            # check if we have the right child object
            if not isinstance(self.firewall, FGCPFirewall):
                # return whatever this is, e.g. str for logs or list for limit_policies
                return self.firewall
            # set attributes of EFM in firewall
            for key in self.__dict__:
                if key == 'firewall':
                    continue
                setattr(self.firewall, key, self.__dict__[key])
            # move one step up in the hierarchy
            self.firewall.setparent(self._parent)
            # return firewall
            return self.firewall
        elif self.efmType == 'SLB':
            if getattr(self, 'loadbalancer', None) is None:
                # create new loadbalancer
                setattr(self, 'loadbalancer', FGCPLoadBalancer())
            if not isinstance(self.loadbalancer, FGCPLoadBalancer):
                # return whatever this is, e.g. ???
                return self.loadbalancer
            # set attributes of EFM in loadbalancer
            for key in self.__dict__:
                if key == 'loadbalancer':
                    continue
                setattr(self.loadbalancer, key, self.__dict__[key])
            # move one step up in the hierarchy
            self.loadbalancer.setparent(self._parent)
            # return loadbalancer
            return self.loadbalancer


class FGCPFirewall(FGCPEfm):
    efmType = 'FW'
    # CHECKME: this returns an attribute 'status' which is in conflict with the default status() method !
    _status = None
    nat = None
    dns = None
    directions = None
    log = None
    category = None
    latestVersion = None
    comment = None
    firmUpdateExist = None
    configUpdateExist = None
    updateDate = None
    backout = None
    currentVersion = None

    def list_nat_rules(self):
        if self.nat is None:
            self.get_nat_rules()
        return self.nat

    def get_nat_rules(self):
        # CHECKME: merge answer with current firewall ?
        self.nat = self.get_config_handler().fw_nat_rule()
        if self.nat is None:
            self.nat = []
        return self.nat

    def set_nat_rules(self, rules=None):
        result = self.update_config_handler().fw_nat_rule(rules)
        return result

    def _add_nat_rule(self, **kwargs):
        if getattr(self, 'nat', None) is None:
            self.get_nat_rules()
        #nat_rule = FGCPNATRule(publicIp='80.70.163.172', snapt='true', privateIp='192.168.0.211')
        nat_rule = FGCPNATRule(**kwargs)
        # set the parent of the nat_rule to this firewall
        #nat_rule.setparent(self)
        self.nat.append(nat_rule)
        # TODO: send update to proxy

    def get_dns(self):
        # CHECKME: merge answer with current firewall ?
        self.dns = self.get_config_handler().fw_dns()
        return self.dns

    def set_dns(self, dnstype='AUTO', primary=None, secondary=None):
        result = self.update_config_handler().fw_dns(dnstype, primary, secondary)
        self.dns = None
        return result

    def list_policies(self):
        if self.directions is None:
            self.get_policies()
        return self.directions

    def get_policies(self, from_zone=None, to_zone=None):
        if from_zone or to_zone:
            return self.get_config_handler().fw_policy(from_zone, to_zone)
        # CHECKME: merge answer with current firewall ?
        self.directions = self.get_config_handler().fw_policy()
        return self.directions

    def set_policies(self, log='On', policies=None):
        result = self.update_config_handler().fw_policy(log, policies)
        self.directions = None
        return result

    def _add_direction(self, **kwargs):
        if self.directions is None:
            self.directions = []
        #direction = FGCPFWDirection(from_zone='INTERNET', to_zone='DMZ', policies=[])
        direction = FGCPFWDirection(**kwargs)
        # set the parent of the direction to this firewall
        #direction.setparent(self)
        self.directions.append(direction)
        # TODO: send update to proxy

    def get_log(self, num=100, orders=None):
        # FIXME: make log order builder !?
        return self.get_config_handler().fw_log(num, orders)

    def get_limit_policies(self, from_zone=None, to_zone=None):
        return self.get_config_handler().fw_limit_policy(from_zone, to_zone)


class FGCPFWNATRule(FGCPResource):
    _idname = 'publicIp'
    publicIp = None
    privateIp = None
    snapt = None


class FGCPFWDns(FGCPResource):
    _idname = 'type'
    type = None
    primary = None
    secondary = None


class FGCPFWDirection(FGCPResource):
    # CHECKME: this has an attribute 'from' which causes problems for Python !
    _idname = None
    from_zone = None
    to_zone = None
    policies = None
    acceptable = None
    maxPolicyNum = None
    prefix = None

    def getid(self):
        # get the last part of the direction, i.e. DMZ, SECURE1, SECURE2 etc.
        from_zone = getattr(self, 'from', '').split('-').pop()
        to_zone = getattr(self, 'to', '').split('-').pop()
        return '%s-%s' % (from_zone, to_zone)

    def _list_policies(self):
        return getattr(self, 'policies', [])

    def _add_policy(self, **kwargs):
        if self.policies is None:
            self.policies = []
        #policy = FGCPFWPolicy(id=123, action='Accept', ...)
        policy = FGCPFWPolicy(**kwargs)
        # set the parent of the policy to this direction
        #direction.setparent(self)
        self.policies.append(policy)


class FGCPFWPolicy(FGCPResource):
    _idname = 'id'
    id = None
    action = None
    dst = None
    dstPort = None
    dstService = None
    dstType = None
    log = None
    protocol = None
    src = None
    srcPort = None
    srcType = None


class FGCPFWLogOrder(FGCPResource):
    _idname = 'prefix'
    # CHECKME: this has an attribute 'from' which causes problems for Python !
    prefix = None
    value = None
    from_zone = None
    to_zone = None

    def __init__(self, **kwargs):
        for key in kwargs:
            # CHECKME: replace from_zone and to_zone, because from=... is restricted
            setattr(self, key.replace('_zone', ''), kwargs[key])


class FGCPLoadBalancer(FGCPEfm):
    efmType = 'SLB'
    ipAddress = None
    # CHECKME: this returns an attribute 'status' which is in conflict with the default status() method !
    _status = None
    webAccelerator = None
    groups = None
    loadStatistics = None
    errorStatistics = None
    servercerts = None
    ccacerts = None
    srcPort = None
    srcType = None
    category = None
    latestVersion = None
    comment = None
    firmUpdateExist = None
    configUpdateExist = None
    updateDate = None
    backout = None
    currentVersion = None

    def get_rules(self):
        # CHECKME: get loadbalancer directly from config_handler ?
        rules = self.get_config_handler().slb_rule()
        # CHECKME: merge answer with current loadbalancer ?
        self.merge_attr(rules)
        if self.groups is None:
            self.groups = []
        return rules

    def set_rules(self, groups=None, force=None, webAccelerator=None):
        """Usage:
        loadbalancer = vsystem.get_loadbalancer('SLB1')
        # get all rules
        rules = loadbalancer.get_rules()
        # adapt the group list
        new_groups = []
        for group in rules.groups:
            ...
            new_groups.append(group)
        # update all rules
        result = loadbalancer.set_rules(groups=new_groups, force=None, webAccelerator=None)
        """
        result = self.update_config_handler().slb_rule(groups, force, webAccelerator)
        # CHECKME: invalidate list of groups to be sure
        self.groups = None
        return result

    def list_groups(self):
        if self.groups is None:
            self.get_rules()
        return self.groups

    def get_group(self, groupId):
        # support resource or id
        if isinstance(groupId, FGCPSLBGroup):
            return groupId.retrieve()
        if not isinstance(groupId, str):
            groupId = str(groupId)
        groups = self.list_groups()
        for group in groups:
            if groupId == group.id:
                return group.retrieve()
        raise FGCPResourceError('ILLEGAL_SLB_GROUP', 'Invalid groupId %s' % groupId, self)

    def add_group(self, **kwargs):
        """Usage:
        loadbalancer = vsystem.get_loadbalancer('SLB1')
        vserver1 = vsystem.get_vserver('WebApp1')
        vserver2 = vsystem.get_vserver('WebApp2')
        # add single group
        loadbalancer.add_group(id=10, protocol='http', targets=[vserver1, vserver2])
        """
        if self.groups is None:
            self.get_rules()
        #group = FGCPSLBGroup(id=10, protocol='http', port1=80, targets=[], ...)
        group = FGCPSLBGroup(**kwargs)
        # set the parent of the group to this loadbalancer
        #group.setparent(self)
        # CHECKME: set default values depending on protocol
        group.set_defaults()
        if len(group.targets) < 1:
            raise FGCPResourceError('ILLEGAL_SLB_GROUP', 'You need to specify at least one target vserver for this group', self)
        self.groups.append(group)
        if len(self.groups) > 0:
            result = self.set_rules(groups=self.groups, webAccelerator=self.webAccelerator)
            # CHECKME: invalidate list of groups to be sure
            self.groups = None
            return result

    def _add_group_target(self, groupId, serverId):
        pass

    def _delete_group_target(self, groupId, serverId):
        pass

    def delete_group(self, groupId):
        """Usage:
        loadbalancer = vsystem.get_loadbalancer('SLB1')
        # list all groups
        groups = loadbalancer.list_groups()
        for group in groups:
            if group.protocol != 'http':
                continue
            # delete single group
            loadbalancer.delete_group(group.id)
            break
        """
        groupId = self.get_group(groupId).id
        new_groups = []
        for group in self.list_groups():
            if groupId != group.id:
                new_groups.append(group)
        self.groups = new_groups
        result = self.set_rules(groups=self.groups, webAccelerator=self.webAccelerator)
        # CHECKME: invalidate list of groups to be sure
        self.groups = None
        return result

    def get_load_stats(self):
        load_stats = self.get_config_handler().slb_load()
        return load_stats

    def clear_load_stats(self):
        return self.update_config_handler().slb_load_clear()

    def get_error_stats(self):
        error_stats = self.get_config_handler().slb_error()
        return error_stats

    def clear_error_stats(self):
        return self.update_config_handler().slb_error_clear()

    def list_servercerts(self, detail=None):
        if detail:
            return self.get_config_handler().slb_cert_list('server', detail)
        if self.servercerts is None:
            self.get_cert_list()
        return self.servercerts

    def get_cert_list(self, certCategory=None, detail=None):
        if certCategory or detail:
            return self.get_config_handler().slb_cert_list(certCategory, detail)
        cert_list = self.get_config_handler().slb_cert_list()
        # CHECKME: merge answer with current loadbalancer ?
        self.merge_attr(cert_list)
        if self.servercerts is None:
            self.servercerts = []
        if self.ccacerts is None:
            self.ccacerts = []
        return cert_list

    def add_cert(self, certNum, filePath, passphrase):
        result = self.update_config_handler().slb_cert_add(certNum, filePath, passphrase)
        # CHECKME: invalidate list of servercerts to be sure
        self.servercerts = None
        return result

    def set_cert(self, certNum, groupId):
        return self.update_config_handler().slb_cert_set(certNum, groupId)

    def release_cert(self, certNum):
        return self.update_config_handler().slb_cert_release(certNum)

    def delete_cert(self, certNum, force=None):
        result = self.update_config_handler().slb_cert_delete(certNum, force)
        # CHECKME: invalidate list of servercerts to be sure
        self.servercerts = None
        return result

    def list_ccacerts(self, detail=None):
        if detail:
            return self.get_config_handler().slb_cert_list('cca', detail)
        if self.ccacerts is None:
            self.get_cert_list()
        return self.ccacerts

    def add_cca(self, ccacertNum, filePath):
        result = self.update_config_handler().slb_cca_add(ccacertNum, filePath)
        # CHECKME: invalidate list of ccacerts to be sure
        self.ccacerts = None
        return result

    def delete_cca(self, ccacertNum):
        result = self.update_config_handler().slb_cca_delete(ccacertNum)
        # CHECKME: invalidate list of ccacerts to be sure
        self.ccacerts = None
        return result

    def start_maintenance(self, groupId, ipAddress, time=None, unit=None):
        return self.update_config_handler().slb_start_maint(groupId, ipAddress, time, unit)

    def stop_maintenance(self, groupId, ipAddress):
        return self.update_config_handler().slb_stop_maint(groupId, ipAddress)


class FGCPSLBGroup(FGCPResource):
    _idname = 'id'
    id = None
    protocol = None
    port1 = None
    port2 = None
    certNum = None
    balanceType = None
    monitorType = None
    maxConnection = None
    uniqueType = None
    uniqueRetention = None
    interval = None
    timeout = None
    retryCount = None
    recoveryAction = None
    targets = None
    causes = None

    def set_defaults(self):
        # CHECKME: set default values depending on protocol
        if self.protocol is None:
            self.protocol = 'http'
        defaults = {'port2': None, 'targets': [], 'interval': 60, 'timeout': 10, 'retryCount': 3, 'monitorType': 'ping', 'balanceType': 'round-robin', 'recoveryAction': 'switch-back'}
        if self.protocol == 'http+https':
            defaults['uniqueType'] = 'By IP address'
            defaults['uniqueRetention'] = 90
            defaults['maxConnection'] = 10000
            defaults['port1'] = 80
            defaults['port2'] = 443
        elif self.protocol == 'https':
            defaults['uniqueType'] = 'By connection'
            defaults['maxConnection'] = 10000
            defaults['port1'] = 443
        elif self.protocol == 'http':
            defaults['uniqueType'] = 'By connection'
            defaults['maxConnection'] = 58000
            defaults['port1'] = 80
        else:
            defaults['uniqueType'] = 'By connection'
            defaults['maxConnection'] = 58000
        for key in defaults:
            if getattr(self, key, None) is None:
                setattr(self, key, defaults[key])
        new_targets = []
        for target in self.targets:
            if isinstance(target, str):
                # TODO: find the right serverId
                target = FGCPSLBTarget(serverId=target)
                # set the parent of the target to this group
                #target.setparent(self)
            elif isinstance(target, FGCPVServer):
                target = FGCPSLBTarget(serverId=target.vserverId)
                # set the parent of the target to this group
                #target.setparent(self)
            if getattr(target, 'port1', None) is None:
                setattr(target, 'port1', self.port1)
            if getattr(target, 'port2', None) is None:
                setattr(target, 'port2', self.port2)
            new_targets.append(target)
        self.id = str(self.id)
        self.targets = new_targets

    def _list_targets(self):
        return getattr(self, 'targets', [])

    def _get_target(self, serverId):
        for target in self._list_targets():
            if target.serverId == serverId:
                return target

    def _add_target(self, **kwargs):
        if self.targets is None:
            self.targets = []
        #target = FGCPSLBTarget(serverId=serverId, port1=port1, port2=port2)
        target = FGCPSLBTarget(**kwargs)
        # set the parent of the target to this group
        #target.setparent(self)
        self.targets.append(target)

    def _delete_target(self, serverId):
        serverId = self._get_target(serverId).serverId
        targets = self._list_targets()
        new_targets = []
        for target in targets:
            if serverId != target.serverId:
                new_targets.append(target)
        self.targets = new_targets

    def _list_causes(self):
        return getattr(self, 'causes', [])


class FGCPSLBTarget(FGCPResource):
    _idname = 'serverId'
    serverId = None
    ipAddress = None
    serverName = None
    port1 = None
    port2 = None
    # CHECKME: this returns an attribute 'status' which may be in conflict with the default status() method !
    status = None
    peak = None
    now = None


class FGCPSLBCause(FGCPResource):
    _idname = 'cat'
    cat = None
    # CHECKME: this returns an attribute 'status' which may be in conflict with the default status() method !
    status = None
    before = None
    current = None
    today = None
    total = None
    yesterday = None
    #filePath = None


class FGCPSLBErrorStats(FGCPResource):
    _idname = None
    period = None
    groups = None

    def list_groups(self):
        return getattr(self, 'groups', [])


class FGCPSLBErrorPeriod(FGCPResource):
    _idname = None
    before = None
    current = None
    today = None
    yesterday = None


class FGCPSLBServerCert(FGCPResource):
    _idname = 'certNum'
    certNum = None
    subject = None
    issuer = None
    validity = None
    groupId = None
    detail = None


class FGCPSLBCCACert(FGCPResource):
    _idname = 'ccacertNum'
    ccacertNum = None
    subject = None
    description = None
    issuer = None
    validity = None
    detail = None


class FGCPPublicIP(FGCPResource):
    _idname = 'address'
    address = None
    v4v6Flag = None
    vsysId = None

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
        if not refresh and getattr(self, 'v4v6Flag', None) is not None:
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
    # CHECKME: this has an attribute 'from' which causes problems for Python !
    _idname = None
    from_ip = None
    to_ip = None
    range = None

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
    vsysdescriptorId = None
    vsysdescriptorName = None
    description = None
    keyword = None
    creatorName = None
    registrant = None
    vservers = None
    diskimages = None

    def register(self):
        # see VSystem register_vsysdescriptor()
        pass

    def retrieve(self, refresh=None):
        # CHECKME: retrieve configuration here ?
        return self.get_configuration(refresh)

    def update(self, *args, **kwargs):
        self.show_output('Updating VSYSDescriptor %s' % self.vsysdescriptorName)
        allowed = ['vsysdescriptorName', 'description', 'keyword']
        updatename = {'vsysdescriptorName': 'updateName', 'description': 'updateDescription', 'keyword': 'updateKeyword'}
        # convert arguments to dict
        tododict = self._args2dict(args, kwargs, allowed)
        # CHECKME: what if we updated the object attributes directly ?
        result = None
        for key in tododict:
            if tododict[key] != getattr(self, key, None):
                # CHECKME: updateLcId = 'en' here
                result = self.getproxy().UpdateVSYSDescriptorAttribute(self.getid(), 'en', updatename[key], tododict[key])
        self.show_output('Updated VSYSDescriptor %s' % self.vsysdescriptorName)
        return result

    def unregister(self):
        #return self.getproxy().UnregisterVSYSDescriptor(self.getid())
        # CHECKME: only private vsysdescriptors can be unregistered by end-users
        return self.getproxy().UnregisterPrivateVSYSDescriptor(self.getid())

    #=========================================================================

    def list_diskimages(self, category='GENERAL'):
        if getattr(self, 'diskimages', None) is None:
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
                return diskimage.retrieve()
            elif diskimageName == diskimage.diskimageId:
                return diskimage.retrieve()
        raise FGCPResourceError('ILLEGAL_DISKIMAGE', 'Invalid diskimageName %s' % diskimageName, self)

    #=========================================================================

    def list_vservers(self):
        if getattr(self, 'vservers', None) is None:
            self.retrieve()
        return getattr(self, 'vservers')

    #=========================================================================

    def get_configuration(self, refresh=None):
        # CHECKME: if we already have the registrant information etc., we already retrieved the attributes
        # CHECKME: if we already also have the vservers information, we already retrieved the configuration
        if not refresh and getattr(self, 'registrant', None) is not None:
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
    diskimageId = None
    diskimageName = None
    description = None
    creatorName = None
    licenseInfo = None
    osName = None
    osType = None
    registrant = None
    size = None
    softwares = None
    servertypes = None

    def register(self):
        # see VServer register_diskimage
        pass

    def update(self, *args, **kwargs):
        self.show_output('Updating DiskImage %s' % self.diskimageName)
        allowed = ['diskimageName', 'description']
        updatename = {'diskimageName': 'updateName', 'description': 'updateDescription'}
        # convert arguments to dict
        tododict = self._args2dict(args, kwargs, allowed)
        # CHECKME: what if we updated the object attributes directly ?
        result = None
        for key in tododict:
            if tododict[key] != getattr(self, key, None):
                # CHECKME: updateLcId = 'en' here
                result = self.getproxy().UpdateDiskImageAttribute(self.getid(), 'en', updatename[key], tododict[key])
        self.show_output('Updated DiskImage %s' % self.diskimageName)
        return result

    def unregister(self):
        return self.getproxy().UnregisterDiskImage(self.getid())

    def list_softwares(self):
        if getattr(self, 'softwares', None) is None:
            # CHECKME: initialize to None or list here ?
            setattr(self, 'softwares', [])
        return getattr(self, 'softwares')

    def list_servertypes(self):
        if getattr(self, 'servertypes', None) is None:
            setattr(self, 'servertypes', self.getproxy().ListServerType(self.getid()))
        return getattr(self, 'servertypes')


class FGCPImageSoftware(FGCPResource):
    _idname = 'name'
    name = None
    license = None
    category = None
    id = None
    officialVersion = None
    patch = None
    support = None
    version = None


class FGCPServerType(FGCPResource):
    # this is what we actually pass to CreateVServer
    _idname = 'name'
    name = None
    chargeType = None
    comment = None
    cpu = None
    expectedUsage = None
    id = None
    label = None
    memory = None
    price = None
    productId = None
    productName = None
    disks = None

    def list_disks(self):
        # CHEKCME: currently unused ?
        if getattr(self, 'disks', None) is None:
            setattr(self, 'disks', [])
        return getattr(self, 'disks')


class FGCPServerTypeCPU(FGCPResource):
    _idname = None
    cpuArch = None
    cpuPerf = None
    numOfCpu = None


class FGCPServerTypeDisk(FGCPResource):
    # CHEKCME: currently unused ?
    _idname = None
    diskSize = None
    diskType = None
    diskUsage = None


class FGCPUsageInfo(FGCPResource):
    _idname = 'vsysId'
    vsysId = None
    vsysName = None
    products = None

    def list_products(self):
        if getattr(self, 'products', None) is None:
            setattr(self, 'products', [])
        return getattr(self, 'products')


class FGCPUsageInfoProduct(FGCPResource):
    _idname = 'productName'
    productName = None
    unitName = None
    usedPoints = None


class FGCPInformation(FGCPResource):
    _idname = 'seqno'
    entryDate = None
    expiry = None
    message = None
    seqno = None
    startDate = None
    title = None


class FGCPEventLog(FGCPResource):
    _idname = None
    entryDate = None
    expiry = None
    message = None
    startDate = None
    title = None


class FGCPPerformanceInfo(FGCPResource):
    _idname = None
    cpuUtilization = None
    diskReadRequestCount = None
    diskReadSector = None
    diskWriteRequestCount = None
    diskWriteSector = None
    nicInputByte = None
    nicInputPacket = None
    nicOutputByte = None
    nicOutputPacket = None
    recordTime = None


class FGCPUnknown(FGCPResource):
    pass
