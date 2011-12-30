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
Client API library for the Fujitsu Global Cloud Platform (FGCP)
using XML-RPC API Version 2011-01-31

Requirements: this module uses gdata.tlslite.utils to create the key signature,
see http://code.google.com/p/gdata-python-client/ for download and installation

Caution: this is a development work in progress - please do not use
for productive systems without adequate testing...
"""

__version__ = '0.9.5'


class FGCPError(Exception):
    """
    Exception class for FGCP Errors
    """
    def __init__(self, status, message):
        self.status = status
        self.message = message

    def __str__(self):
        return '\nStatus: %s\nMessage: %s' % (self.status, self.message)
