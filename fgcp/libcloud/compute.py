#!/usr/bin/python
#
#  Copyright (C) 2016 Michel Dalle
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

from libcloud.common.base import ConnectionKey
from libcloud.compute.drivers.openstack import OpenStack_1_1_NodeDriver, OpenStack_1_1_FloatingIpPool, OpenStack_1_1_FloatingIpAddress, OpenStackNodeSize
from libcloud.compute.base import Node, NodeImage, NodeLocation, StorageVolume, VolumeSnapshot
from libcloud.common.types import LibcloudError


class FGCPException(LibcloudError):
    pass


class FGCPConnectionKey(ConnectionKey):
    def connect(self, host=None, port=None):
        pass


class FGCPNode(Node):
    pass


class FGCPNodeSize(OpenStackNodeSize):
    pass


class FGCPNodeImage(NodeImage):
    pass


class FGCPNodeLocation(NodeLocation):
    pass


class FGCPStorageVolume(StorageVolume):
    pass


class FGCPVolumeSnapshot(VolumeSnapshot):
    pass


class FGCPFloatingIpPool(OpenStack_1_1_FloatingIpPool):
    pass

    #def list_floating_ips(self):

    def _to_floating_ip(self, obj):
        return OpenStack_1_1_FloatingIpAddress(id=obj['id'],
                                               ip_address=obj['ip'],
                                               pool=self,
                                               node_id=obj['instance_id'],
                                               driver=self.connection.driver)


class FGCPFloatingIpAddress(OpenStack_1_1_FloatingIpAddress):
    pass


class FGCPNodeDriver(OpenStack_1_1_NodeDriver):
    """
    # Register FGCP as third party driver for libcloud
    from libcloud.compute.providers import set_driver
    from libcloud.compute.providers import get_driver
    set_driver('fgcp',
               'fgcp.libcloud.compute',
               'FGCPNodeDriver')
    cls = get_driver('fgcp')

    # Connect with your client certificate to region 'uk' and work in location 'Demo VSystem'
    driver = cls('client.pem', region='uk', location='Demo VSystem')

    #regions = driver.list_regions()
    #locations = driver.list_locations()
    #nodes = driver.list_nodes()
    #images = driver.list_images()
    #sizes = driver.list_sizes()
    #volumes = driver.list_volumes()
    #for volume in volumes:
    #    snapshots = driver.list_volume_snapshots(volume)
    #    snapshots_and_backups = driver.list_volume_snapshots(volume, ex_include_backups=True)
    #    backups = driver.ex_list_volume_backups(volume)


    Requirements: this module uses tlslite.utils or gdata.tlslite.utils to create
    the key signature, see https://pypi.python.org/pypi/tlslite-ng or
    https://pypi.python.org/pypi/tlslite for download and installation

    Note: to convert your .p12 or .pfx file to unencrypted PEM format, you can use
    the following 'openssl' command:

    openssl pkcs12 -in UserCert.p12 -out client.pem -nodes
    """
    connectionCls = FGCPConnectionKey
    name = 'FGCP'
    type = 'fgcp'

    def __init__(self, *args, **kwargs):
        super(FGCPNodeDriver, self).__init__(*args, **kwargs)

        # Connect with your client certificate to this region
        self._ex_init_fgcp(self.key, self.region)
        #print self.__dict__
        # CHECKME: use location or tenant (= project) for vsystem here!?
        if 'location' in kwargs:
            self.location = kwargs['location']
        elif 'ex_tenant_name' in kwargs:
            self.location = kwargs['ex_tenant_name']

    def list_regions(self):
        regions = []
        from fgcp.server import FGCP_REGIONS
        for region in FGCP_REGIONS:
            regions.append(region)
        return regions

    def _ex_init_fgcp(self, pem_file, region):
        from fgcp.resource import FGCPVDataCenter
        # Connect with your client certificate to this region
        self._ex_fgcp_vdc = FGCPVDataCenter(pem_file, region)
        # Set your private key for signatures if you use the relay server
        if self.region.startswith('relay') and hasattr(self, 'private_key'):
            self._ex_fgcp_vdc.getproxy().set_key(self.private_key)

    def _ex_get_vsystem(self, vsysName=None):
        # CHECKME: use location or tenant (= project) for vsystem here!?
        if not vsysName:
            vsysName = self.location
        if not vsysName:
            raise FGCPException(value='Missing location or ex_tenant_name (= project) for vsystem',
                                driver=self)
            return
        return self._ex_fgcp_vdc.get_vsystem(vsysName)

    def list_locations(self):
        locations = []
        for vsystem in self._ex_fgcp_vdc.list_vsystems():
            locations.append(self._to_location(vsystem))
        return locations

    def _to_location(self, vsystem):
        location = FGCPNodeLocation(
            id=vsystem.vsysId,
            name=vsystem.vsysName,
            country=self.region,
            driver=self
        )
        location.extra = vsystem.get_attr()
        return location

    def list_images(self, location=None, ex_only_active=True):
        #if location and location != self.location:
        #    self.location = location
        images = []
        for diskimage in self._ex_fgcp_vdc.list_diskimages():
            images.append(self._to_image(diskimage))
        return images

    def _to_image(self, diskimage):
        return FGCPNodeImage(
            id=diskimage.diskimageId,
            name=diskimage.diskimageName,
            driver=self,
            extra=diskimage.get_attr()
        )

    """
    def _to_image_openstack(self, api_image):
        server = api_image.get('server', {})
        return NodeImage(
            id=api_image['id'],
            name=api_image['name'],
            driver=self,
            extra=dict(
                updated=api_image['updated'],
                created=api_image['created'],
                status=api_image['status'],
                progress=api_image.get('progress'),
                metadata=api_image.get('metadata'),
                serverId=server.get('id'),
                minDisk=api_image.get('minDisk'),
                minRam=api_image.get('minRam'),
            )
        )
    """

    def list_sizes(self, location=None):
        #if location and location != self.location:
        #    self.location = location
        sizes = []
        for servertype in self._ex_fgcp_vdc.list_servertypes():
            sizes.append(self._to_size(servertype))
        return sizes

    def _to_size(self, servertype, price=None, bandwidth=None):
        if not price:
            price = servertype.price
        if not servertype.disks:
            disk = None
        else:
            disk = float(servertype.disks)
        extra = servertype.get_attr()
        extra['cpu'] = extra['cpu'].get_attr()
        return FGCPNodeSize(
            id=servertype.id,
            name=servertype.name,
            ram=int(float(servertype.memory) * 1024),
            disk=disk,
            # TODO: check cpuPerf too?
            vcpus=int(servertype.cpu.numOfCpu),
            ephemeral_disk=None,
            swap=None,
            extra=extra,
            bandwidth=bandwidth,
            price=float(price),
            driver=self,
        )

    """
    def _to_size_openstack(self, api_flavor, price=None, bandwidth=None):
        # if provider-specific subclasses can get better values for
        # price/bandwidth, then can pass them in when they super().
        if not price:
            price = self._get_size_price(str(api_flavor['id']))

        extra = api_flavor.get('OS-FLV-WITH-EXT-SPECS:extra_specs', {})
        return OpenStackNodeSize(
            id=api_flavor['id'],
            name=api_flavor['name'],
            ram=api_flavor['ram'],
            disk=api_flavor['disk'],
            vcpus=api_flavor['vcpus'],
            ephemeral_disk=api_flavor.get('OS-FLV-EXT-DATA:ephemeral', None),
            swap=api_flavor['swap'],
            extra=extra,
            bandwidth=bandwidth,
            price=price,
            driver=self,
        )
    """

    def list_nodes(self, ex_all_tenants=False):
        nodes = []
        if ex_all_tenants:
            return nodes
        vsystem = self._ex_get_vsystem()
        for vserver in vsystem.list_vservers():
            nodes.append(self._to_node(vserver))
        return nodes

    def _to_node(self, vserver):
        # CHECKME: retrieve configuration of this vserver
        vserver.retrieve()
        # TODO: map states
        state = vserver.status()
        #state = self.NODE_STATE_MAP.get(vserver.status(),
        #                                NodeState.UNKNOWN)
        private_ips = []
        for vnic in vserver.list_vnics():
            private_ips.append(vnic.privateIp)
        servertype = self._ex_fgcp_vdc.get_servertype(vserver.vserverType)
        # CHECKME: find system disk size
        if not servertype.disks:
            servertype.disks = vserver.image.sysvolSize
        size = self._to_size(servertype)
        # CHECKME: deal with outdated images
        try:
            diskimage = self._ex_fgcp_vdc.get_diskimage(vserver.diskimageId)
        except:
            diskimage = vserver.image
            diskimage.diskimageId = diskimage.id
            diskimage.diskimageName = 'Old Image'
            if len(vserver.image.softwares) > 0:
                diskimage.diskimageName += ' with ' + vserver.image.softwares[0].name
        image = self._to_image(diskimage)
        return FGCPNode(
            id=vserver.vserverId,
            name=vserver.vserverName,
            state=state,
            public_ips=[],
            private_ips=private_ips,
            driver=self,
            size=size,
            image=image,
            extra=vserver.get_attr()
        )

    """
    def _to_node_openstack(self, api_node):
        public_networks_labels = ['public', 'internet']

        public_ips, private_ips = [], []

        for label, values in api_node['addresses'].items():
            for value in values:
                ip = value['addr']

                is_public_ip = False

                try:
                    public_subnet = is_public_subnet(ip)
                except:
                    # IPv6
                    public_subnet = False

                # Openstack Icehouse sets 'OS-EXT-IPS:type' to 'floating' for
                # public and 'fixed' for private
                explicit_ip_type = value.get('OS-EXT-IPS:type', None)

                if explicit_ip_type == 'floating':
                    is_public_ip = True
                elif explicit_ip_type == 'fixed':
                    is_public_ip = False
                elif label in public_networks_labels:
                    # Try label next
                    is_public_ip = True
                elif public_subnet:
                    # Check for public subnet
                    is_public_ip = True

                if is_public_ip:
                    public_ips.append(ip)
                else:
                    private_ips.append(ip)

        # Sometimes 'image' attribute is not present if the node is in an error
        # state
        image = api_node.get('image', None)
        image_id = image.get('id', None) if image else None
        config_drive = api_node.get("config_drive", False)
        volumes_attached = api_node.get('os-extended-volumes:volumes_attached')

        return Node(
            id=api_node['id'],
            name=api_node['name'],
            state=self.NODE_STATE_MAP.get(api_node['status'],
                                          NodeState.UNKNOWN),
            public_ips=public_ips,
            private_ips=private_ips,
            driver=self,
            extra=dict(
                hostId=api_node['hostId'],
                access_ip=api_node.get('accessIPv4'),
                access_ipv6=api_node.get('accessIPv6', None),
                # Docs says "tenantId", but actual is "tenant_id". *sigh*
                # Best handle both.
                tenantId=api_node.get('tenant_id') or api_node['tenantId'],
                userId=api_node.get('user_id', None),
                imageId=image_id,
                flavorId=api_node['flavor']['id'],
                uri=next(link['href'] for link in api_node['links'] if
                         link['rel'] == 'self'),
                service_name=self.connection.get_service_name(),
                metadata=api_node['metadata'],
                password=api_node.get('adminPass', None),
                created=api_node['created'],
                updated=api_node['updated'],
                key_name=api_node.get('key_name', None),
                disk_config=api_node.get('OS-DCF:diskConfig', None),
                config_drive=config_drive,
                availability_zone=api_node.get('OS-EXT-AZ:availability_zone'),
                volumes_attached=volumes_attached,
                task_state=api_node.get("OS-EXT-STS:task_state", None),
                vm_state=api_node.get("OS-EXT-STS:vm_state", None),
                power_state=api_node.get("OS-EXT-STS:power_state", None),
                progress=api_node.get("progress", None),
                fault=api_node.get('fault')
            ),
        )
    """

    def list_volumes(self):
        volumes = []
        vsystem = self._ex_get_vsystem()
        for vdisk in vsystem.list_vdisks():
            volumes.append(self._to_volume(vdisk))
        return volumes

    def _to_volume(self, vdisk):
        # TODO: map states
        state = vdisk.status()
        #state = self.VOLUME_STATE_MAP.get(vdisk.status(),
        #                                  StorageVolumeState.UNKNOWN)
        return FGCPStorageVolume(
            id=vdisk.vdiskId,
            name=vdisk.vdiskName,
            size=float(vdisk.size),
            state=state,
            driver=self,
            extra=vdisk.get_attr()
        )

    """
    def _to_volume_openstack(self, api_node):
        if 'volume' in api_node:
            api_node = api_node['volume']

        state = self.VOLUME_STATE_MAP.get(api_node['status'],
                                          StorageVolumeState.UNKNOWN)

        return StorageVolume(
            id=api_node['id'],
            name=api_node['displayName'],
            size=api_node['size'],
            state=state,
            driver=self,
            extra={
                'description': api_node['displayDescription'],
                'attachments': [att for att in api_node['attachments'] if att],
                # TODO: remove in 1.18.0
                'state': api_node.get('status', None),
                'snapshot_id': api_node.get('snapshotId', None),
                'location': api_node.get('availabilityZone', None),
                'volume_type': api_node.get('volumeType', None),
                'metadata': api_node.get('metadata', None),
                'created_at': api_node.get('createdAt', None)
            }
        )
    """

    #def ex_list_snapshots(self):

    def list_volume_snapshots(self, volume, ex_include_backups=False):
        snapshots = []
        vsystem = self._ex_get_vsystem()
        vdisk = vsystem.get_vdisk(volume.id)
        for snapshot in vdisk.list_snapshots():
            snapshot.id = snapshot.snapshotId
            # CHECKME: get status and size from volume?
            snapshot.size = float(vdisk.size)
            disk_status = vdisk.status()
            # TODO: map states
            if disk_status == 'RUNNING':
                snapshot.state = 'AVAILABLE'
            else:
                snapshot.state = disk_status
            snapshots.append(self._to_snapshot(snapshot))
        # CHECKME: also include backups here, or refer to backup API?
        if ex_include_backups:
            snapshots.extend(self.ex_list_volume_backups(volume))
        return snapshots

    def _to_snapshot(self, snapshot):
        return VolumeSnapshot(
            id=snapshot.id,
            driver=self,
            size=snapshot.size,
            extra=snapshot.get_attr(),
            created=float(snapshot.timeval),
            state=snapshot.state
        )

    def ex_list_volume_backups(self, volume):
        backups = []
        vsystem = self._ex_get_vsystem()
        vdisk = vsystem.get_vdisk(volume.id)
        for backup in vdisk.list_backups():
            backup.id = backup.backupId
            # CHECKME: get status and size from volume?
            backup.size = float(vdisk.size)
            disk_status = vdisk.status()
            # TODO: map states
            if disk_status == 'RUNNING':
                backup.state = 'AVAILABLE'
            else:
                backup.state = disk_status
            backups.append(self._to_snapshot(backup))
        return backups

    """
    def _to_snapshot_openstack(self, data):
        if 'snapshot' in data:
            data = data['snapshot']

        volume_id = data.get('volume_id', data.get('volumeId', None))
        display_name = data.get('display_name', data.get('displayName', None))
        created_at = data.get('created_at', data.get('createdAt', None))
        description = data.get('display_description',
                               data.get('displayDescription', None))
        status = data.get('status', None)

        extra = {'volume_id': volume_id,
                 'name': display_name,
                 'created': created_at,
                 'description': description,
                 'status': status}

        state = self.SNAPSHOT_STATE_MAP.get(
            status,
            VolumeSnapshotState.UNKNOWN
        )

        try:
            created_dt = parse_date(created_at)
        except ValueError:
            created_dt = None

        snapshot = VolumeSnapshot(id=data['id'], driver=self,
                                  size=data['size'], extra=extra,
                                  created=created_dt, state=state)
        return snapshot

    """

    #def list_key_pairs(self):

    """
    def _to_key_pair(self, obj):
        key_pair = KeyPair(name=obj['name'],
                           fingerprint=obj['fingerprint'],
                           public_key=obj['public_key'],
                           private_key=obj.get('private_key', None),
                           driver=self)
        return key_pair
    """

    #def ex_list_networks(self):

    """
    def _to_network(self, obj):
        return OpenStackNetwork(id=obj['id'],
                                name=obj['label'],
                                cidr=obj.get('cidr', None),
                                driver=self)
    """

    #def ex_list_security_groups(self):

    """
    def _to_security_group(self, obj):
        rules = self._to_security_group_rules(obj.get('rules', []))
        return OpenStackSecurityGroup(id=obj['id'],
                                      tenant_id=obj['tenant_id'],
                                      name=obj['name'],
                                      description=obj.get('description', ''),
                                      rules=rules,
                                      driver=self)
    """

    """
    def _to_security_group_rule(self, obj):
        ip_range = group = tenant_id = None
        if obj['group'] == {}:
            ip_range = obj['ip_range'].get('cidr', None)
        else:
            group = obj['group'].get('name', None)
            tenant_id = obj['group'].get('tenant_id', None)

        return OpenStackSecurityGroupRule(
            id=obj['id'], parent_group_id=obj['parent_group_id'],
            ip_protocol=obj['ip_protocol'], from_port=obj['from_port'],
            to_port=obj['to_port'], driver=self, ip_range=ip_range,
            group=group, tenant_id=tenant_id)
    """

    #def ex_list_floating_ip_pools(self):

    """
    def _to_floating_ip_pool(self, obj):
        return OpenStack_1_1_FloatingIpPool(obj['name'], self.connection)
    """

    #def ex_list_floating_ips(self):

    """
    def _to_floating_ip(self, obj):
        return OpenStack_1_1_FloatingIpAddress(id=obj['id'],
                                               ip_address=obj['ip'],
                                               pool=None,
                                               node_id=obj['instance_id'],
                                               driver=self)
    """
