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

    Ref: https://github.com/swagger-api/swagger-codegen
"""

from pprint import pformat
from six import iteritems
import re


class VSystem(object):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """
    def __init__(self):
        """
        VSystem - a model defined in Swagger

        :param dict swaggerTypes: The key is attribute name
                                  and the value is attribute type.
        :param dict attributeMap: The key is attribute name
                                  and the value is json key in definition.
        """
        self.swagger_types = {
            'creator': 'str',
            'vsys_name': 'str',
            'firewalls': 'list[Firewall]',
            'base_descriptor': 'str',
            'vdisks': 'list[VDisk]',
            'vservers': 'list[VServer]',
            'loadbalancers': 'list[LoadBalancer]',
            'vsys_id': 'str',
            'href': 'str',
            '_class': 'str',
            'id': 'str',
            'cloud_category': 'str',
            'publicips': 'list[PublicIP]',
            'vnets': 'list[str]'
        }

        self.attribute_map = {
            'creator': 'creator',
            'vsys_name': 'vsysName',
            'firewalls': 'firewalls',
            'base_descriptor': 'baseDescriptor',
            'vdisks': 'vdisks',
            'vservers': 'vservers',
            'loadbalancers': 'loadbalancers',
            'vsys_id': 'vsysId',
            'href': 'href',
            '_class': '_class',
            'id': 'id',
            'cloud_category': 'cloudCategory',
            'publicips': 'publicips',
            'vnets': 'vnets'
        }

        self._creator = None
        self._vsys_name = None
        self._firewalls = None
        self._base_descriptor = None
        self._vdisks = None
        self._vservers = None
        self._loadbalancers = None
        self._vsys_id = None
        self._href = None
        self.__class = None
        self._id = None
        self._cloud_category = None
        self._publicips = None
        self._vnets = None

    @property
    def creator(self):
        """
        Gets the creator of this VSystem.


        :return: The creator of this VSystem.
        :rtype: str
        """
        return self._creator

    @creator.setter
    def creator(self, creator):
        """
        Sets the creator of this VSystem.


        :param creator: The creator of this VSystem.
        :type: str
        """
        
        self._creator = creator

    @property
    def vsys_name(self):
        """
        Gets the vsys_name of this VSystem.


        :return: The vsys_name of this VSystem.
        :rtype: str
        """
        return self._vsys_name

    @vsys_name.setter
    def vsys_name(self, vsys_name):
        """
        Sets the vsys_name of this VSystem.


        :param vsys_name: The vsys_name of this VSystem.
        :type: str
        """
        
        self._vsys_name = vsys_name

    @property
    def firewalls(self):
        """
        Gets the firewalls of this VSystem.


        :return: The firewalls of this VSystem.
        :rtype: list[Firewall]
        """
        return self._firewalls

    @firewalls.setter
    def firewalls(self, firewalls):
        """
        Sets the firewalls of this VSystem.


        :param firewalls: The firewalls of this VSystem.
        :type: list[Firewall]
        """
        
        self._firewalls = firewalls

    @property
    def base_descriptor(self):
        """
        Gets the base_descriptor of this VSystem.


        :return: The base_descriptor of this VSystem.
        :rtype: str
        """
        return self._base_descriptor

    @base_descriptor.setter
    def base_descriptor(self, base_descriptor):
        """
        Sets the base_descriptor of this VSystem.


        :param base_descriptor: The base_descriptor of this VSystem.
        :type: str
        """
        
        self._base_descriptor = base_descriptor

    @property
    def vdisks(self):
        """
        Gets the vdisks of this VSystem.


        :return: The vdisks of this VSystem.
        :rtype: list[VDisk]
        """
        return self._vdisks

    @vdisks.setter
    def vdisks(self, vdisks):
        """
        Sets the vdisks of this VSystem.


        :param vdisks: The vdisks of this VSystem.
        :type: list[VDisk]
        """
        
        self._vdisks = vdisks

    @property
    def vservers(self):
        """
        Gets the vservers of this VSystem.


        :return: The vservers of this VSystem.
        :rtype: list[VServer]
        """
        return self._vservers

    @vservers.setter
    def vservers(self, vservers):
        """
        Sets the vservers of this VSystem.


        :param vservers: The vservers of this VSystem.
        :type: list[VServer]
        """
        
        self._vservers = vservers

    @property
    def loadbalancers(self):
        """
        Gets the loadbalancers of this VSystem.


        :return: The loadbalancers of this VSystem.
        :rtype: list[LoadBalancer]
        """
        return self._loadbalancers

    @loadbalancers.setter
    def loadbalancers(self, loadbalancers):
        """
        Sets the loadbalancers of this VSystem.


        :param loadbalancers: The loadbalancers of this VSystem.
        :type: list[LoadBalancer]
        """
        
        self._loadbalancers = loadbalancers

    @property
    def vsys_id(self):
        """
        Gets the vsys_id of this VSystem.


        :return: The vsys_id of this VSystem.
        :rtype: str
        """
        return self._vsys_id

    @vsys_id.setter
    def vsys_id(self, vsys_id):
        """
        Sets the vsys_id of this VSystem.


        :param vsys_id: The vsys_id of this VSystem.
        :type: str
        """
        
        self._vsys_id = vsys_id

    @property
    def href(self):
        """
        Gets the href of this VSystem.


        :return: The href of this VSystem.
        :rtype: str
        """
        return self._href

    @href.setter
    def href(self, href):
        """
        Sets the href of this VSystem.


        :param href: The href of this VSystem.
        :type: str
        """
        
        self._href = href

    @property
    def _class(self):
        """
        Gets the _class of this VSystem.


        :return: The _class of this VSystem.
        :rtype: str
        """
        return self.__class

    @_class.setter
    def _class(self, _class):
        """
        Sets the _class of this VSystem.


        :param _class: The _class of this VSystem.
        :type: str
        """
        
        self.__class = _class

    @property
    def id(self):
        """
        Gets the id of this VSystem.


        :return: The id of this VSystem.
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id):
        """
        Sets the id of this VSystem.


        :param id: The id of this VSystem.
        :type: str
        """
        
        self._id = id

    @property
    def cloud_category(self):
        """
        Gets the cloud_category of this VSystem.


        :return: The cloud_category of this VSystem.
        :rtype: str
        """
        return self._cloud_category

    @cloud_category.setter
    def cloud_category(self, cloud_category):
        """
        Sets the cloud_category of this VSystem.


        :param cloud_category: The cloud_category of this VSystem.
        :type: str
        """
        
        self._cloud_category = cloud_category

    @property
    def publicips(self):
        """
        Gets the publicips of this VSystem.


        :return: The publicips of this VSystem.
        :rtype: list[PublicIP]
        """
        return self._publicips

    @publicips.setter
    def publicips(self, publicips):
        """
        Sets the publicips of this VSystem.


        :param publicips: The publicips of this VSystem.
        :type: list[PublicIP]
        """
        
        self._publicips = publicips

    @property
    def vnets(self):
        """
        Gets the vnets of this VSystem.


        :return: The vnets of this VSystem.
        :rtype: list[str]
        """
        return self._vnets

    @vnets.setter
    def vnets(self, vnets):
        """
        Sets the vnets of this VSystem.


        :param vnets: The vnets of this VSystem.
        :type: list[str]
        """
        
        self._vnets = vnets

    def to_dict(self):
        """
        Returns the model properties as a dict
        """
        result = {}

        for attr, _ in iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

    def to_str(self):
        """
        Returns the string representation of the model
        """
        return pformat(self.to_dict())

    def __repr__(self):
        """
        For `print` and `pprint`
        """
        return self.to_str()

    def __eq__(self, other):
        """
        Returns true if both objects are equal
        """
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """
        Returns true if both objects are not equal
        """
        return not self == other

