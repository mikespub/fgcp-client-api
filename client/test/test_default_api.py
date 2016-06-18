# coding: utf-8

"""
Copyright 2016 SmartBear Software

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   ref: https://github.com/swagger-api/swagger-codegen
"""

from __future__ import absolute_import

import os
import sys
import unittest

import swagger_client
from swagger_client.rest import ApiException
from swagger_client.apis.default_api import DefaultApi


class TestDefaultApi(unittest.TestCase):
    """ DefaultApi unit test stubs """

    def setUp(self):
        self.api = swagger_client.apis.default_api.DefaultApi()

    def tearDown(self):
        pass

    def test_fgcp_diskimages_get(self):
        """
        Test case for fgcp_diskimages_get

        
        """
        pass

    def test_fgcp_diskimages_options(self):
        """
        Test case for fgcp_diskimages_options

        
        """
        pass

    def test_fgcp_get(self):
        """
        Test case for fgcp_get

        
        """
        pass

    def test_fgcp_options(self):
        """
        Test case for fgcp_options

        
        """
        pass

    def test_fgcp_servertypes_get(self):
        """
        Test case for fgcp_servertypes_get

        
        """
        pass

    def test_fgcp_servertypes_options(self):
        """
        Test case for fgcp_servertypes_options

        
        """
        pass

    def test_fgcp_vsysdescriptors_get(self):
        """
        Test case for fgcp_vsysdescriptors_get

        
        """
        pass

    def test_fgcp_vsysdescriptors_options(self):
        """
        Test case for fgcp_vsysdescriptors_options

        
        """
        pass

    def test_fgcp_vsystems_get(self):
        """
        Test case for fgcp_vsystems_get

        
        """
        pass

    def test_fgcp_vsystems_options(self):
        """
        Test case for fgcp_vsystems_options

        
        """
        pass

    def test_fgcp_vsystems_vsys_id_get(self):
        """
        Test case for fgcp_vsystems_vsys_id_get

        
        """
        pass

    def test_fgcp_vsystems_vsys_id_options(self):
        """
        Test case for fgcp_vsystems_vsys_id_options

        
        """
        pass


if __name__ == '__main__':
    unittest.main()