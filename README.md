IP
==

Ansible collection with modules to manage network devices, routes and addresses.
It's a wrapper for ip utility, with idempotent handling of different aspects of iproute2
functionality.

This is work-in-progress which slowly covers different aspects of iprout with aim to
provide comprehensive coverage.

Currently there are:
* `ip_link_device_attribute` - module to change device attributes (up/down state, mtu, etc).
* `ip_link_device` - module to create and delete network devices (vxlan, vlan, gre, bridge, veth)
* `ip_address` - to manage IP addresses on the interface.

(`ip_route` is still missing).

You can get module inside amarao.ip collection from Ansible Galaxy:
https://galaxy.ansible.com/amarao/ip

Any bugreports/PRs are welcome.
