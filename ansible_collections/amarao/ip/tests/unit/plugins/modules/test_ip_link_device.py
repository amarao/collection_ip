# Copyright (c) 2020 George Shuklin
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import pytest
import mock
from ansible_collections.amarao.ip.plugins.modules import ip_link_device  # noqa
from collections import defaultdict


@pytest.fixture(scope='function')
def Module():
    class Module:
        def __init__(self, d):
            self.params = defaultdict(
                lambda: None,
                d
            )
        check_mode = False
        fail_res = {}
        exit_res = {}
        exit_changed = None

        def fail_json(self, **kwargs):
            self.fail_res = kwargs

        def exit_json(self, **kwargs):
            self.exit_res = kwargs

    return Module


@pytest.fixture(scope='function')
def LinkDevice():
    with mock.patch.object(
        ip_link_device.LinkDevice, "is_exists", return_value=False
    ):
        with mock.patch.object(
            ip_link_device.LinkDevice, "_exec", return_value=(0, "", "")
        ):
            yield ip_link_device.LinkDevice


def test_veth_create(Module, LinkDevice):
    mod = Module({
            'name': 'veth0',
            'state': 'present',
            'type': 'veth'
    })
    link = LinkDevice(mod)
    link.run()
    expected = ['ip', 'link', 'add', 'name', 'veth0', 'type', 'veth']
    assert link._exec.call_args[0][1] == expected


def test_bond_create_no_params(Module, LinkDevice):
    mod = Module({
            'name': 'bond0',
            'state': 'present',
            'type': 'bond'
    })
    link = LinkDevice(mod)
    link.run()
    expected = ['ip', 'link', 'add', 'name', 'bond0', 'type', 'bond']
    assert link._exec.call_args[0][1] == expected


def test_bond_create_params(Module, LinkDevice):
    mod = Module({
            'name': 'bond0',
            'state': 'present',
            'type': 'bond',
            'bond_options': {
                'mode': '802.3ad',
                'miimon': 42,
                'updelay': 10,
                'downdelay': 33,
                'xmit_hash_policy': 'layer3+4',
                'num_grat_arp': 13,
                'lacp_rate': 'fast',
            }
    })
    link = LinkDevice(mod)
    link.run()
    expected = [
        'ip', 'link', 'add', 'name', 'bond0',
        'type', 'bond', 'downdelay', '33',
        'lacp_rate', 'fast', 'miimon', '42',
        'mode', '802.3ad', 'num_grat_arp', '13',
        'updelay', '10', 'xmit_hash_policy',
        'layer3+4'
    ]

    assert link._exec.call_args[0][1] == expected
