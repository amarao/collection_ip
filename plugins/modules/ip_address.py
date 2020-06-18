#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019-2020, George Shuklin <george.shuklin@gmail.com>

# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: ip_address
version_added: "2.10"
author: "George Shuklin (@amarao)"
short_description: Create or delete IP addresses on interfaces
requirements: [iproute2]
description: >
    Allows to add or remove IP addresses using ip utility (iproute2).

options:
    name:
        type: str
        aliases: [device]
        required: true
        description:
            - Name of a new network device.
            - Required for I(state)=present

    namespace:
        type: str
        description:
            - Name of namespace where interface is.
            - Namespace should exist

    address:
        type: str
        description:
            - Address to assign
            - Can be a stand-alone address or CIDR.
            - If no CIDR is given, it's assumed to be /32.
            - Required for both I(state)=C(present) and I(state)=C(absent).
            - Should not be used for I(state)=C(flush)

    state:
        type: str
        choices: [present, absent, flush]
        default: present
        description:
            - Should address be addedd or removed.
            - C(flush) removes all addresses from the interface.

    peer:
        type: str
        description:
            - Address of remote endpoint for point-to-point links.

    broadcast:
        type: str
        description:
            - Broadcast address for the interface.

    label:
        type: str
        description:
            - Label, assosicated with address.
            - Maximum length is 15 characters.
            - In order to compatibility with Linux-2.0 net aliases, this string
              must coincide with the name of the device or must be prefixed
              with the device name followed by colon.

    scope:
        type: str
        description:
            - Scope where address is valid.
            - The available scopes are listed in file /etc/iproute2/rt_scopes.
            - Predefined values are C(global), C(site), C(link), C(host).

    metric:
        type: int
        description:
            - Priority of prefix route associated with address.

    valid_lft:
        type: str
        description:
            - Valid lifetime for the address.
            - Address stop been used after expiration.
            - Set to a number or C(forever).
            - Default value in kernel is 'forver'.

    preferred_lft:
        type: str
        description:
            - Preferred lifetime for the address.
            - Address stop been used after expiration.
            - Set to a number or C(forever).
            - Default value in kernel is 'forver'.

    home:
        type: bool
        description:
            - Designates this address the "home address".
            - IPv6 only.

    dad:
        type: bool
        description:
            - Enable or disable Duplicate Address Discovery for this address.
            - Kernel default is 'enabled'.

    prefixroute:
        type: bool
        description:
            - Enable or disable automatic creation/deletion of a route for the
              network prefix of the address.
            - Kernel default is 'eanbled'.

notes:
    - All changes made by this module are not permanent and are
      lost after reboot.
    - Address parameters are not checked and not changed for existing
      addresses.
    - Autojoin and mngtmpaddr options are not supported.
"""

EXAMPLES = """
- name: Assign an IP address to the interface
  ip_address:
    device: veth0
    namepace: foo
    address: 192.168.0.1/24

- name: Remove address from the interface
  ip_address:
    name: eth3
    address: 2a00:1450:4017:807::200e
    state: absent

- name: Remove all addresses from interface
  ip_link_address:
    device: tun0
    state: flush
"""

RETURN = r''' # '''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text


__metaclass__ = type


BOOLS = ['off', 'on']


class Address(object):
    """Main class for the module."""

    def __init__(self, module):
        self.module = module
        self.check_mode = module.check_mode
        for param_name, param_value in self.module.params.items():
            setattr(self, param_name, param_value)
        if self.state != 'flush' and not self.address:
            self.module.fail_json(
                msg=to_text(
                    'State=present/absent require address.'
                )
            )
        if self.address:
            if '/' not in self.address:
                if ':' in self.address:  # IPv6
                    self.address += '/128'
                elif '.' in self.address:  # IPv4
                    self.address += '/32'
        prefix_length = self.address.split('/')[1]
        if '.' in prefix_length:
            self.module.fail_json(
                'Dot found in prefix length. '
                'Network masks are not supported, '
                'use CIDR notation (a.b.c.d/z)'
            )

    def _exec(self, namespace, cmd, not_found_is_ok=False):
        if namespace:
            return self._exec(
                None,
                ['ip', 'netns', 'exec', namespace] + cmd,
                not_found_is_ok
            )
        # if self.type=='gre' and 'add' in cmd:
        #     self.module.fail_json(msg=to_text(cmd))
        rc, out, err = self.module.run_command(cmd)
        if rc != 0:
            self.module.fail_json(
                msg=to_text(err),
                failed_command=' '.join(cmd)
            )
        return out

    def _get_addresses(self):
        cmd = ['ip', '-o', 'address', 'show', 'dev', self.name]
        stdout = self._exec(self.namespace, cmd)
        for line in stdout.split('\n'):
            pieces = line.split()
            if len(pieces) < 4:
                continue
            address = pieces[3]
            yield address

    def _addr_part(self):
        snippet = [self.address]
        if self.peer:
            snippet += ['peer', str(self.peer)]
        if self.broadcast:
            snippet += ['broadcast', str(self.broadcast)]
        if self.label:
            snippet += ['label', str(self.label)]
        if self.scope:
            snippet += ['scope', str(self.scope)]
        if self.metric:  # contradiction in man!
            snippet += ['metric', str(self.metric)]
        return snippet

    def _lifetime_part(self):
        snippet = []
        if self.valid_lft:
            snippet += ['valid_lft', str(self.valid_lft)]
        if self.preferred_lft:
            snippet += ['preferred_lft', str(self.preferred_lft)]
        return snippet

    def _confflag_part(self):
        snippet = []
        if self.home is True:
            snippet += ['home']
        if self.dad is False:
            snippet += ['nodad']
        if self.prefixroute is False:
            snippet += ['noprefixroute']
        return snippet

    def _add(self):
        cmd = ['ip', 'address', 'add']
        cmd += self._addr_part()
        cmd += ['dev', self.name]
        cmd += self._lifetime_part()
        cmd += self._confflag_part()
        self._exec(self.namespace, cmd)

    def _delete(self):
        cmd = ['ip', 'address', 'delete', self.address, 'dev', self.name]
        self._exec(self.namespace, cmd)

    def flush(self):
        addresses = list(self._get_addresses())
        if addresses:
            if self.check_mode:
                self.module.exit_json(changed=True)
            cmd = ['ip', '-statistics', 'address', 'flush', 'dev', self.name]
            res = self._exec(self.namespace, cmd)
            changed = not ('Nothing to flush' in res)
            self.module.exit_json(changed=changed)
        self.module.exit_json(changed=False)

    def present(self):
        addresses = self._get_addresses()
        if self.address not in addresses:
            if not self.check_mode:
                self._add()
            self.module.exit_json(changed=True)
        self.module.exit_json(changed=False)

    def absent(self):
        addresses = self._get_addresses()
        if self.address in addresses:
            if not self.check_mode:
                self._delete()
            self.module.exit_json(changed=True)
        self.module.exit_json(changed=False)

    def run(self):
        if self.state == 'flush':
            self.flush()
        elif self.state == 'present':
            self.present()
        elif self.state == 'absent':
            self.absent()
        else:
            self.module.fail_json(
                msg=to_text("Unknown state: %s" % repr(self.state)),
            )


def main():
    """Entry point."""
    module = AnsibleModule(
        argument_spec={
            'name': {'aliases': ['device'], 'required': True},
            'namespace': {},
            'state': {
                'choices': ['present', 'absent', 'flush'],
                'default': 'present'
            },
            'address': {},
            'peer': {},
            'broadcast': {},
            'label': {},
            'scope': {},
            'metric': {'type': 'int'},
            'valid_lft': {},
            'preferred_lft': {},
            'home': {'type': 'bool'},
            'dad': {'type': 'bool'},
            'prefixroute': {'type': 'bool'},
        },
        supports_check_mode=True,
    )

    link_dev = Address(module)
    link_dev.run()


if __name__ == '__main__':
    main()
