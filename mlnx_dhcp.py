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

import os

import netaddr
from oslo_log import log as logging
import six

from neutron.agent.linux import dhcp
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils

LOG = logging.getLogger(__name__)


class MlnxDnsmasq(dhcp.Dnsmasq):

    def _output_hosts_file(self):
        """Writes a dnsmasq compatible dhcp hosts file.

        The generated file is sent to the --dhcp-hostsfile option of dnsmasq,
        and lists the hosts on the network which should receive a dhcp lease.
        Each line in this file is in the form::

            'mac_address,FQDN,ip_address'

        IMPORTANT NOTE: a dnsmasq instance does not resolve hosts defined in
        this file if it did not give a lease to a host listed in it (e.g.:
        multiple dnsmasq instances on the same network if this network is on
        multiple network nodes). This file is only defining hosts which
        should receive a dhcp lease, the hosts resolution in itself is
        defined by the `_output_addn_hosts_file` method.
        """
        prefix = 'ff:00:00:00:00:00:02:00:00:02:c9:00:'
        buf = six.StringIO()
        filename = self.get_conf_file_name('host')

        LOG.debug('Building host file: %s', filename)
        dhcp_enabled_subnet_ids = [s.id for s in self.network.subnets
                                   if s.enable_dhcp]
        for (port, alloc, hostname, name) in self._iter_hosts():
            if not alloc:
                if getattr(port, 'extra_dhcp_opts', False):
                    buf.write('%s,%s%s\n' %
                              (port.mac_address, 'set:', port.id))
                continue

            # don't write ip address which belongs to a dhcp disabled subnet.
            if alloc.subnet_id not in dhcp_enabled_subnet_ids:
                continue

            # (dzyu) Check if it is legal ipv6 address, if so, need wrap
            # it with '[]' to let dnsmasq to distinguish MAC address from
            # IPv6 address.
            ip_address = alloc.ip_address
            if netaddr.valid_ipv6(ip_address):
                ip_address = '[%s]' % ip_address

            mac_first = port.mac_address[:8]
            middle = ':00:00:'
            mac_last = port.mac_address[9:]
            client_id = ''.join([prefix, mac_first, middle, mac_last])

            if getattr(port, 'extra_dhcp_opts', False):
                buf.write('%s,id:%s,%s,%s,%s%s\n' %
                          (port.mac_address, client_id, name, ip_address,
                           'set:', port.id))
            else:
                buf.write('%s,id:%s,%s,%s\n' %
                          (port.mac_address, client_id, name, ip_address))

        utils.replace_file(filename, buf.getvalue())
        LOG.debug('Done building host file %s with contents:\n%s', filename,
                  buf.getvalue())
        return filename

    def _release_lease(self, mac_address, ip, client_id):
        """Release a DHCP lease."""
        cmd = ['dhcp_release', self.interface_name, ip, mac_address, client_id]
        ip_wrapper = ip_lib.IPWrapper(namespace=self.network.namespace)
        ip_wrapper.netns.execute(cmd, run_as_root=True)

    def _read_hosts_file_leases(self, filename):
        leases = set()
        if os.path.exists(filename):
            with open(filename) as f:
                for l in f.readlines():
                    host = l.strip().split(',')
                    leases.add((host[3].strip('[]'), host[0], host[1][3:]))
        return leases

    def _release_unused_leases(self):
        filename = self.get_conf_file_name('host')
        old_leases = self._read_hosts_file_leases(filename)

        new_leases = set()
        for port in self.network.ports:
            for alloc in port.fixed_ips:
                new_leases.add((alloc.ip_address, port.mac_address))

        for ip, mac, client_id in old_leases - new_leases:
            self._release_lease(mac, ip, client_id)
