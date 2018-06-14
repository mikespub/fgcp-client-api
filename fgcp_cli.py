#!/usr/bin/python2.7
from __future__ import print_function
import os
import sys
from fgcp.resource import FGCPVDataCenter
import json


class FGCP_CLI(object):

    def __init__(self, key_file='client.pem', region='uk'):
        self.key_file = key_file
        self.region = region
        self.verbose = False
        #self.debug = False
        #self.wait = True
        self.wait = False
        if self.wait:
            self.verbose = True
        self.vdc = None
        self.design = None
        self.vsystem = None
        self.vsysName = None

    def show_usage(self, argv):
        print(argv[0], '<vsysName> <vserverName> status|start|stop|restart')

    def run(self, argv):
        print(argv)
        if len(argv) < 2:
            self.show_usage(argv)
            return self.list_vsystems()
        #if os.path.isfile(argv[1]):
        #   return self.load(argv[1])
        if len(argv) < 3:
            return self.list_vservers(argv[1])
        vserver = self.get_vserver(argv[1], argv[2])
        status = vserver.status()
        if len(argv) < 4:
            print(status)
            result = vserver
        elif argv[3] == 'status':
            result = status
        elif argv[3] == 'start':
            result = vserver.start(self.wait)
        elif argv[3] == 'stop':
            result = vserver.stop(self.wait)
        elif argv[3] == 'restart':
            result = vserver.reboot(self.wait)
        elif argv[3] == 'halt':
            result = vserver.stop(self.wait, force=True)
        else:
            print('Invalid option %s' % argv[3])
            result = vserver
        return result

    def dump(self, var):
        design = self.get_design()
        return json.dumps(var, default=lambda o: design.to_var(o), indent=4)

    def get_design(self):
        if not self.design:
            self.design = self.get_vdc().get_vsystem_design()
        return self.design

    def get_vdc(self):
        if not self.vdc:
            self.vdc = FGCPVDataCenter(self.key_file, self.region, self.verbose)
        return self.vdc

    def list_vsystems(self):
        return self.get_vdc().list_vsystems()

    def get_vsystem(self, vsysName):
        if not self.vsystem or vsysName != self.vsysName:
            self.vsystem = self.get_vdc().get_vsystem(vsysName)
            self.vsysName = vsysName
        return self.vsystem

    def list_vservers(self, vsysName=None):
        return self.get_vsystem(vsysName).list_vservers()

    def get_vserver(self, vsysName=None, vserverName=None):
        return self.get_vsystem(vsysName).get_vserver(vserverName)


class FGCP_Menu(FGCP_CLI):

    def loop(self, obj=None, depth=0):
        if not obj:
            obj = self.get_vdc()
        print(self.dump(obj))
        while True:
            print(depth, type(obj).__name__)
            method = self.select_method(obj)
            if not method:
                break
            result = self.run_method(obj, method)
            print(self.dump(result))
            item = self.select_result(obj, method, result)
            if not item:
                continue
            #print self.dump(item)
            self.loop(item, depth + 1)

    def select_method(self, obj, default='1'):
        if not type(obj).__name__.startswith('FGCP'):
            return
        idx = 1
        selected = {}
        #methodlist = sorted(self.get_methods(obj, 'list_'))
        methodlist = sorted(self.get_methods(obj))
        for method in methodlist:
            selected[str(idx)] = method
            print('%s. %s' % (idx, method))
            idx += 1
        print('%s. %s' % (0, 'Return'))
        if len(methodlist) < 1:
            default = '0'
        idx = raw_input('Please select %s method [%s] ' % (type(obj).__name__, default))
        if not idx:
            idx = default
        if idx in selected:
            return selected[idx]
        return

    def run_method(self, obj, method):
        params = self.get_method_params(obj, method)
        if not params:
            return getattr(obj, method)()
        print(params)
        return getattr(obj, method)(*params)

    def get_method_params(self, obj, method):
        func = getattr(obj, method)
        argcount = func.__code__.co_argcount
        if argcount < 2:
            return
        args = list(func.__code__.co_varnames[:argcount])
        defaults = func.__defaults__ or ()
        values = dict(zip(reversed(args), reversed(defaults)))
        args.pop(0)
        params = []
        for arg in args:
            if arg in values:
                val = raw_input('%s [%s] ' % (arg, values[arg]))
                if val:
                    params.append(val)
                #if not val:
                #   val = values[arg]
            else:
                val = raw_input('%s ' % arg)
                params.append(val)
            #params.append({arg: val})
        return params

    def select_result(self, obj, method, result):
        if not isinstance(result, list):
            if type(result).__name__.startswith('FGCP'):
                return result
            return
        if len(result) < 1:
            return
        if not method.startswith('list_'):
            return
        get_method = method.replace('list_', 'get_')[:-1]
        if not hasattr(obj, get_method):
            return
        print(get_method)
        idx = 1
        selected = {}
        for item in result:
            if hasattr(item, 'getid'):
                id = item.getid()
            else:
                id = item
            selected[str(idx)] = id
            print('%s. %s' % (idx, id))
            idx += 1
        default = '1'
        print('%s. %s' % (0, 'Return'))
        idx = raw_input('Please select %s item [%s] ' % (type(result[0]).__name__, default))
        if not idx:
            idx = default
        if idx in selected:
            return getattr(obj, get_method)(selected[idx])
        return

    def get_methods(self, obj, prefix=None):
        # check for local class methods here, not any inherited ones
        #attrlist = dir(obj)
        attrlist = type(obj).__dict__.keys()
        if not prefix:
            return [attr for attr in attrlist if not attr.startswith('_') and callable(getattr(obj, attr))]
        return [attr for attr in attrlist if attr.startswith(prefix) and callable(getattr(obj, attr))]

if __name__ == "__main__":
    key_file = 'client.pem'
    region = 'de'
    if len(sys.argv) < 2:
        menu = FGCP_Menu(key_file, region)
        menu.loop()
        sys.exit()
    cli = FGCP_CLI(key_file, region)
    result = cli.run(sys.argv)
    print(cli.dump(result))
