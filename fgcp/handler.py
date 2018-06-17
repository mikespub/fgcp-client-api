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
Resource Object Handler for the Fujitsu Global Cloud Platform (FGCP)
"""
from __future__ import print_function
from builtins import zip
from builtins import object
from fgcp.resource import FGCPResource


class FGCP_Handler(object):
    debug = False

    def _is_resource(self, obj):
        return isinstance(obj, FGCPResource)

    def _has_method(self, obj, attr):
        if hasattr(obj, attr) and callable(getattr(obj, attr)):
            return True
        return False

    def _has_property(self, obj, attr):
        if hasattr(obj, attr) and not callable(getattr(obj, attr)):
            return True
        return False

    def _get_methods(self, obj, prefix=None):
        # check for local class methods here, not any inherited ones
        # attrlist = dir(obj)
        attrlist = list(type(obj).__dict__.keys())
        if not prefix:
            return [attr for attr in attrlist if not attr.startswith('_') and callable(getattr(obj, attr))]
        return [attr for attr in attrlist if attr.startswith(prefix) and callable(getattr(obj, attr))]

    def _get_properties(self, obj, prefix=None):
        # check for local class properties here, not any inherited ones
        # attrlist = dir(obj)
        attrlist = list(type(obj).__dict__.keys())
        if not prefix:
            return [attr for attr in attrlist if not attr.startswith('_') and not callable(getattr(obj, attr))]
        return [attr for attr in attrlist if attr.startswith(prefix) and not callable(getattr(obj, attr))]

    def _run_method(self, obj, method, *args, **kwargs):
        if not callable(getattr(obj, method)):
            return getattr(obj, method)
        params = self._get_method_params(obj, method)
        if self.debug:
            print('_run_method:', repr(obj), method, repr(params), repr(args), repr(kwargs))
        if not params or len(params) < 1:
            return getattr(obj, method)()
        # TODO: fill in values from kwargs
        return getattr(obj, method)(*args)

    def _get_method_params(self, obj, method):
        func = getattr(obj, method)
        argcount = func.__code__.co_argcount
        if argcount < 2:
            return []
        args = list(func.__code__.co_varnames[:argcount])
        defaults = func.__defaults__ or ()
        values = dict(list(zip(reversed(args), reversed(defaults))))
        args.pop(0)
        # CHECKME: return list instead of dict here (or use OrderedDict?)
        params = []
        for arg in args:
            if arg in values:
                params.append((arg, values[arg]))
            else:
                params.append(arg)
        return params

    def _get_property(self, obj, attr, *args, **kwargs):
        if self.debug:
            print('_get_property:', repr(obj), attr, repr(args), repr(kwargs))
        result = getattr(obj, attr)
        if len(args) > 0:
            if not isinstance(result, list):
                print('Result is not a list')
                return
            for item in result:
                if not self._is_resource(item):
                    print('Item is not a resource' + repr(item))
                    return
                if item.getid() == args[0]:
                    return item.retrieve()
            print('Item %s not found' % args[0])
            return
        return result
