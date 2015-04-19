# Copyright 2014 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc
import collections
import os
import re
import shutil
import socket
import sys
import uuid

import netaddr
from oslo.config import cfg
import six

from neutron.agent.linux import dhcp
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import constants
from neutron.common import exceptions
from neutron.openstack.common import importutils
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils

LOG = logging.getLogger(__name__)


class MlnxDnsmasq(dhcp.Dnsmasq):

    def spawn_process(self):
        """Spawns a Dnsmasq process for the network."""
        env = {
            self.NEUTRON_NETWORK_ID_KEY: self.network.id,
        }

        cmd = [
            'dnsmasq',
            '--no-hosts',
            '--no-resolv',
            '--strict-order',
            '--bind-interfaces',
            '--interface=%s' % self.interface_name,
            '--except-interface=lo',
            '--pid-file=%s' % self.get_conf_file_name(
                'pid', ensure_conf_dir=True),
            '--dhcp-hostsfile=%s' % self._output_hosts_file(),
            '--addn-hosts=%s' % self._output_addn_hosts_file(),
            '--dhcp-optsfile=%s' % self._output_opts_file(),
            '--leasefile-ro',
            '--dhcp-authoritative',
        ]

        possible_leases = 0
        for i, subnet in enumerate(self.network.subnets):
            # if a subnet is specified to have dhcp disabled
            if not subnet.enable_dhcp:
                continue
            if subnet.ip_version == 4:
                mode = 'static'
            else:
                # TODO(mark): how do we indicate other options
                # ra-only, slaac, ra-nameservers, and ra-stateless.
                mode = 'static'
            if self.version >= self.MINIMUM_VERSION:
                set_tag = 'set:'
            else:
                set_tag = ''

            cidr = netaddr.IPNetwork(subnet.cidr)

            cmd.append('--dhcp-range=%s%s,%s,%s,%ss' %
                       (set_tag, self._TAG_PREFIX % i,
                        cidr.network,
                        mode,
                        self.conf.dhcp_lease_duration))
            possible_leases += cidr.size

        # Cap the limit because creating lots of subnets can inflate
        # this possible lease cap.
        cmd.append('--dhcp-lease-max=%d' %
                   min(possible_leases, self.conf.dnsmasq_lease_max))

        cmd.append('--conf-file=%s' % self.conf.dnsmasq_config_file)
        if self.conf.dnsmasq_dns_servers:
            cmd.extend(
                '--server=%s' % server
                for server in self.conf.dnsmasq_dns_servers)

        if self.conf.dhcp_domain:
            cmd.append('--domain=%s' % self.conf.dhcp_domain)

        cmd.append('--dhcp-broadcast')

        ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                      self.network.namespace)
        ip_wrapper.netns.execute(cmd, addl_env=env)

    def _output_hosts_file(self):
        prefix = 'ff:00:00:00:00:00:02:00:00:02:c9:00:'
        buf = six.StringIO()
        filename = self.get_conf_file_name('host')

        LOG.debug(_('Building host file: %s'), filename)
        for (port, alloc, hostname, name) in self._iter_hosts():
            set_tag = ''
            # (dzyu) Check if it is legal ipv6 address, if so, need wrap
            # it with '[]' to let dnsmasq to distinguish MAC address from
            # IPv6 address.
            ip_address = alloc.ip_address
            if netaddr.valid_ipv6(ip_address):
                ip_address = '[%s]' % ip_address

            LOG.debug(_('Adding %(mac)s : %(name)s : %(ip)s'),
                      {"mac": port.mac_address, "name": name,
                       "ip": ip_address})
            mac_first = port.mac_address[:8]
            middle = ':00:00:'
            mac_last = port.mac_address[9:]
            client_id = ''.join([prefix, mac_first, middle, mac_last])

            if getattr(port, 'extra_dhcp_opts', False):
                if self.version >= self.MINIMUM_VERSION:
                    set_tag = 'set:'

                buf.write('%s,id:%s,%s,%s,%s%s\n' %
                          (port.mac_address, client_id, name, ip_address,
                           set_tag, port.id))
            else:
                buf.write('%s,id:%s,%s,%s\n' %
                          (port.mac_address, client_id, name, ip_address))

        utils.replace_file(filename, buf.getvalue())
        LOG.debug(_('Done building host file %s'), filename)
        return filename
