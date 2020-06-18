#  amarao.ip

Set of modules to wrap different aspects of Linux's iproute2 (/sbin/ip): network device management, route management, etc.
Modules:
* `ip_link_device` - create and deletion of network interfaces (analogous to `ip link add`, `ip link delete`)
* `ip_link_device_attribute` - set attributes for network interface (analogous to `ip link set up`, `ip link set mtu`, etc)
* `ip_address` - add or delete ip addresses on interface (analogous to `ip address replace`, `ip address delete`).

All operations are non-persistent (they are performed directly on network interface without involvement of netplan, ifupdown,
network-scripts, etc).

All modules support network namespaces.
