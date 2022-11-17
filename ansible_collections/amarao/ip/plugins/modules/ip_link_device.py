#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019-2020, George Shuklin <george.shuklin@gmail.com>
# this code is partially based on ip_netns.py code by
# (c) 2017, Arie Bregman <abregman@redhat.com>

# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: ip_link_device
version_added: "0.0.1"
author: "George Shuklin (@amarao)"
short_description: Create or delete network interfaces in Linux
requirements: [iproute2]
description: >
    Allows to create or delete network interfaces in Linux using ip utility
    from iproute2 package. It currently support a limited number of
    interface types (vlan, vxlan, veth, bridge) for creation but it can
    delete interfaces of any deletable type.

options:
    name:
        type: str
        aliases: [device]
        description:
            - Name of a new network device.
            - Required for I(state)=present
            - Either I(name), I(group_id) or I(type) is required for
              I(state)=absent

    group_id:
        type: str
        description:
            - Id of the group of interfaces to delete.
            - Can be used only for I(state)=absent.
            - The group 'default' contains all interfaces which aren't part
              of some other group (use with caution).

    namespace:
        type: str
        description:
            - Name of namespace where interface should be created/deleted.
            - Namespace should exist.
            - If interface with I(type)=veth is created in a namespace,
              peer interface is created in the same namespace

    search_namespaces:
        type: list
        elements: str
        description:
            - List of network namespaces to check if interface is already
              exist.
            - Used only for I(state)=C(present).
            - If interface exists in any of namespace from I(search_namespaces)
              it is not created.
            - If interface is not found in any of I(search_namespaces)
              namespace it's created in I(namespace) namespace (or in
              root namespace if no I(namespace) specified.
            - If namespace from the list does not exists, it's ignored.

    state:
        type: str
        choices: [present, absent]
        required: true
        description:
            - Declare the state of interface.
            - If state is present and interface is exists the interface
              is not checked for type (for both present and absent modes)

    type:
        type: str
        choices: [bridge, dummy, gre, gretap, veth, vlan, vxlan, bond, vrf]
        description:
            - Type of a new interface to add or delete.
            - Can be specified instead of I(name) or I(group_id)
              for I(state)=absent, in this case all interfaces of that
              type are removed.
            - Module may fail if corresponding kernel module is not available
            - Each type (except C(dummy)) has own set of additional options
              (f.e. I(vlan_options), I(veth_options), I(bridge_options)).

    link:
        type: str
        description:
            - Name of parent interface for vlan type device
            - Required for I(type)=vlan
            - Parent device should exist
            - Is ignored if had no sense

    txqueuelen:
        type: int
        description:
            - Transmit queue length of a new interface
            - The kernel uses default value for the interface type if omitted

    address:
        type: str
        description:
            - MAC address (L2 address) for a new interface
            - Some interface types can not have L2 address. Module will fail
              if address is specified for interface without L2 address
              support (f.e. 'type vcan')
            - The kenel generates address automatically if needed

    broadcast:
        type: str
        description:
            - broadcast (L2) address for a new interface
            - The default value is 'ff:ff:ff:ff:ff:ff'
            - Some addresses have no broadcast support. Module will fail
              if broadcast is specified for interface without broadcast
              support (f.e. 'type vcan')

    mtu:
        type: int
        description:
            - Set MTU value for a new interface.
            - The kernel uses appropriate default value if omitted
            - This is L3 mtu (limit on size of IP packets)

    index:
        type: int
        description:
            - Number of a new interface in the kernel's interface table
            - Assigned automatically if omitted

    numtxqueues:
        type: int
        description:
            - Number of transmit queues for a new interface.
            - Default value is used by the kernel if omitted.

    numrxqueues:
        type: int
        description:
            - Number of recieve queues for a new interface.
            - Default value is used by the kernel if omitted.

    gso_max_size:
        type: int
        description:
            - Number of bytes for GSO (Generic Segment Offload)
            - Poorly tested
            - Requires new version of the kernel and iproute2 package.
            - Default value is used by the kernel if omitted.

    gso_max_segs:
        type: int
        description:
            - Number of segments for GSO (Generic Segment Offload)
            - Poorly tested
            - Requires new version of the kernel and iproute2 package.
            - Default value is used by the kernel if omitted

    vlan_options:
        type: dict
        description:
            - Options, specific for I(type)=C(vlan)
            - Should not be used for any other type
        suboptions:
            protoocol:
                type: str
                choices: [802.1q, 802.1ad]
                default: 802.1q
                description:
                  - VLAN protocol to use. 802.1q is 'usual' VLANs and
                    802.1ad is QinQ (nested VLANs)
            id:
                type: int
                description:
                    - VLAN ID to use.
                    - Allowed range is [0-4095]
            reorder_hdr:
                type: bool
                description:
                    - Allow hardware to process VLANs
                    - Kernel default is 'on'
                    - To check if hardware supports VLAN offloading
                      use "ethtool -k <phy_dev> | grep tx-vlan-offload"
            gvrp:
                type: bool
                description:
                    - Register VLAN using GARP VLAN
            mvrp:
                type: bool
                description:
                    - Register VLAN using
                      Multiple VLAN Registration Protocol

            loose_binding:
                type: bool
                description:
                    - Should VLAN state to be bound to the underlaying
                      device state

            bridge_binding:
                type: bool
                description:
                    - Should VLAN device link state tracks the state of
                      bridge ports that are members of the VLAN.
                    - Poorly tested.
                    - Requires new version of the kernel and iproute2 package.


            ingress_qos_map:
                type: list
                elements: str
                description:
                    - Mapping of VLAN header prio field for incoming frames.
                    - Each mapping in a list has form "FROM:TO"

            egress_qos_map:
                type: list
                elements: str
                description:
                    - Mapping of VLAN header prio field for outgoing frames.
                    - Each mapping in a list has form "FROM:TO"

    vxlan_options:
        type: dict
        description:
            - Options, specific for I(type)=C(vxlan)
            - Should not be used for any other type
        suboptions:
            id:
                type: int
                description:
                    - VNI (VXLAN Segment Identifier) to use
                    - Some iproute2 versions reject to create vxlan device
                      without this option.
            dev:
                type: str
                description:
                    - Name of device to use for tunnel endpoint communication
                    - Do not confuse with I(device), which is alias for
                      I(name).

            group:
                type: str
                description:
                    - Multicast group to join
                    - Multicast IP adddress
                    - Should not be used together with "remote" parameter

            remote:
                type: str
                description:
                    - Unicast IP address for outgoing packets to use when
                       the destination link layer address is not known
                       in the VXLAN device forwarding database
                     - Should not be used together with 'group' paramter

            local:
                type: str
                description:
                    - Local IP address for outgoing packets

            ttl:
                type: int
                description:
                    - TTL (time to live) value for outgoing packets.

            tos:
                type: int
                description:
                    - TOS value for outgoing packets.

            df:
                type: str
                choices: [set, unset, inherit]
                description:
                    - Value for do not fragment flag.
                    - C(inherit) value copy it from original IP header.
                    - By default the kernel does not set it.

            flowlabel:
                type: str
                description:
                    - Flow label to use for outgoing packets.

            dstport:
                type: int
                description:
                    - Destination port to use for outgoing packets.

            srcport:
                type: list
                elements: int
                description:
                    - Range of source ports [min, max] to use for outgoing
                      packets.
                    - Can be the same number, restricting to a single port.

            learning:
                type: bool
                description:
                    - Learn unknown link-level and IP addresses.

            rsc:
                type: bool
                description:
                    - Enable route short circuit.

            proxy:
                type: bool
                description:
                    - Enable ARP proxy mode.

            l2miss:
                type: bool
                description:
                    - Send notifications for L2 address misses.

            l3miss:
                type: bool
                description:
                    - Send notifications for L3 address misses.

            udpcsum:
                type: bool
                description:
                    - Calculate UDP/IPv4 checksum for outgoing packets.

            udp6zerocsumtx:
                type: bool
                description:
                    - Replace UDP/IPv6 checksums with zeroes for outgoing
                      packets.

            udp6zerocsumrx:
                type: bool
                description:
                    - Allow zero checksums for incoming UDP/IPv6 packets.

            ageing:
                type: int
                description:
                    - Lifetime in seconds of FDB entries in the kernel.

            maxaddress:
                type: int
                description:
                    - Limit on number of FDB entries in the kernel.

            external:
                type: bool
                description:
                    - Enable external control plane instead of FDB.

            gbp:
                type: bool
                description:
                    - Include a transport group policy information mark
                      into outgoing packets and accept such information in
                      incoming packets.

            gpe:
                type: bool
                description:
                    - Enables Generic Protocol Extention (VXLAN-GPE).
                    - Supported only for external control plane.

    veth_options:
        type: dict
        description:
            - Options, specific for I(type)=C(veth).
            - Should not be used for any other type.
        suboptions:
            peer_name:
                type: str
                description:
                    - Name of the peer veth interface.
                    - Automatically assigned name is used if not specified.

    gre_options:
        type: dict
        description:
            - Options, specific for I(type)=C(gre).
            - Should not be used for any other type.
            - Secondary encapsulation options (fou/gue) are not supported.
        suboptions:
            remote:
                type: str
                required: true
                description:
                    - Remote address for the tunnel.
            local:
                type: str
                description:
                    - Local address for the tunnel.
            iseq:
                type: bool
                description:
                    - Required serial numbers for input packets.

            oseq:
                type: bool
                description:
                    - Add serial numbers for output packets.

            ikey:
                type: str
                description:
                    - Key for incoming traffic.
                    - Can be a number or ipv4-like quad of four numbers
                      separated by dots.
                    - Special value 'no' is used to indicate lack of ikey
                      (translated to noikey argument to ip utility).
                    - Should not be used together with key option.
            okey:
                type: str
                description:
                    - Key for outgoing traffic.
                    - Can be a number or ipv4-like quad of four numbers
                      separated by dots.
                    - Special value 'no' is used to indicate lack of ikey
                      (translated to noikey argument to ip utility).
                    - Should not be used together with key option.

            key:
                type: str
                description:
                    - Key for both incoming and outgoing traffic
                    - Can be a number or ipv4-like quad of four numbers
                      separated by dots.
                    - Special value 'no' is used to indicate lack of ikey
                      (translated to noikey argument to ip utility).
                    - Should not be used together with ikey/okey options.

            icsum:
                type: bool
                description:
                    - Requre correct checksums for incoming traffic.
                    - Should not be used together with I(csum).

            ocsum:
                type: bool
                description:
                    - Calculate and add correct checksums for outgoing traffic.
                    - Should not be used together with I(csum).

            csum:
                type: bool
                description:
                    - Calculate and add correct checksums for outgoing traffic
                      and require correct checksums on incoming traffic.
                    - Should not be used together with I(iscum), I(ocsum).

            ttl:
                type: int
                description:
                    - TTL (time to live) value for outgoing packets

            tos:
                type: int
                description:
                    - TOS value for outgoing packets.

            pmtudisc:
                type: bool
                description:
                    - Enable Path MTU discovery.
                    - Disabling PMTU discovery is incompatible with fixed ttl
                      value.
            ignore_df:
                type: bool
                description:
                    - Ignore DF (do not fragment) flag on tunneled packets.

            dev:
                type: str
                description:
                    - Name of the interface to use for endpoint communications.

            external:
                type: bool
                description:
                    - Use externally controlled tunnels.

    gretap_options:
        type: dict
        description:
            - Options, specific for I(type)=C(gretap).
            - Should not be used for any other type.
            - Secondary encapsulation options (fou/gue) are not supported.
        suboptions:
            remote:
                type: str
                required: true
                description:
                    - Remote address for the tunnel.
            local:
                type: str
                description:
                    - Local address for the tunnel.
            iseq:
                type: bool
                description:
                    - Required serial numbers for input packets.

            oseq:
                type: bool
                description:
                    - Add serial numbers for output packets.

            ikey:
                type: str
                description:
                    - Key for incoming traffic.
                    - Can be a number or ipv4-like quad of four numbers
                      separated by dots.
                    - Special value 'no' is used to indicate lack of ikey
                      (translated to noikey argument to ip utility).
                    - Should not be used together with key option.
            okey:
                type: str
                description:
                    - Key for outgoing traffic.
                    - Can be a number or ipv4-like quad of four numbers
                      separated by dots.
                    - Special value 'no' is used to indicate lack of ikey
                      (translated to noikey argument to ip utility).
                    - Should not be used together with key option.

            key:
                type: str
                description:
                    - Key for both incoming and outgoing traffic
                    - Can be a number or ipv4-like quad of four numbers
                      separated by dots.
                    - Special value 'no' is used to indicate lack of ikey
                      (translated to noikey argument to ip utility).
                    - Should not be used together with ikey/okey options.

            icsum:
                type: bool
                description:
                    - Requre correct checksums for incoming traffic.

            ocsum:
                type: bool
                description:
                    - Calculate and add correct checksums for outgoing traffic.

            ttl:
                type: int
                description:
                    - TTL (time to live) value for outgoing packets

            tos:
                type: int
                description:
                    - TOS value for outgoing packets.

            pmtudisc:
                type: bool
                description:
                    - Enable Path MTU discovery.
                    - Disabling PMTU discovery is incompatible with fixed ttl
                      value.
            ignore_df:
                type: bool
                description:
                    - Ignore DF (do not fragment) flag on tunneled packets.

            dev:
                type: str
                description:
                    - Name of the interface to use for endpoint communications.

            external:
                type: bool
                description:
                    - Use externally controlled tunnels.

    bridge_options:
        type: dict
        description:
            - Options, specific for I(type)=C(bridge).
            - Should not be used for any other type.
            - Option 'mcast_hash_elasticity' from man pages for ip link
              is deprecated in modern kernels and is not supported in
              this module (use I(mcast_hash_max) insdead).
        suboptions:
            ageing_time:
                type: int
                required: false
                description:
                    - Aging time for bridge FDB entries.
                    - Value in seconds.

            group_fwd_mask:
                type: int
                required: false
                description:
                    - Bitmask for link-local addresses to be forwared.
                    - Default value in the kernel is 0.
                    - Value 0 disables link-local address forwarding.

            group_address:
                type: str
                required: false
                description:
                    - MAC address of the multicast group for this bridge
                      to use for STP.
                    - Address must be link-local address in a standard form
                      (01:80:C2:00:00:0X, X in [0, 4..f]).

            forward_delay:
                type: int
                required: false
                description:
                    - Delay for transitioning from LISTENING to LEARNING
                      and from LEARNING to FORWARDING states for STP.
                    - Used only if STP is enabled.
                    - Valid values are from 2 to 30.

            hello_time:
                type: int
                required: false
                description:
                    - Delay between HELLO packets in STP when it's not root
                      or designated bridge.
                    - Used only if STP is enabled.
                    - Valid values are from 1 to 10 according to man page.
                    - Tests shows value should be over 100.

            max_age:
                type: int
                required: false
                description:
                    - HELLO packet timeout.
                    - Used only if STP is enabled.
                    - Valid values are from 6 to 40 according to man page.
                    - Tests shows value should be over 600.

            stp:
                type: bool
                required: false
                description:
                    - Enable STP
                    - Corresponds to stp_state paramter to ip link.

            priority:
                type: int
                required: false
                description:
                    - Set bridge priority for STP.
                    - Used only if STP is enabled.
                    - Valid values are from 0 to 65535.

            vlan_filtering:
                type: bool
                required: false
                description:
                    - Enable or disable VLAN filtering.
                    - If disabled, bridge will ignore VLAN tag on packets.

            vlan_protocol:
                type: str
                choices: [802.1Q, 802.1ad]
                required: false
                description:
                    - Protocol to use for vlan filtering.

            vlan_default_pvid:
                type: int
                required: false
                description:
                    - default PVID for the bridge.
                    - Value set VLAN ID for untagged/native traffic.

            vlan_stats:
                type: bool
                required: false
                description:
                    - Enable per-vlan stats accounting.
                    - Corresponds to vlan_stats_enabled option for ip link.

            vlan_stats_per_port:
                type: bool
                required: false
                description:
                    - Enable per-VLAN per-port accounting.
                    - Can be changed only when there are no port VLANs
                      configured.
                    - Poorly tested.
                    - Requiers new kernel.

            mcast_snooping:
                type: bool
                required: false
                description:
                    - Enable multicast snooping.

            mcast_router:
                type: int
                required: false
                choices: [0, 1, 2]
                description:
                    - Set routing mode for bidge for multicast routing
                      if IGMP snooping is enabled.
                    - 0 disables routing mode.
                    - 1 sets automatic mode.
                    - 2 permanently enable routing.

            mcast_query_use_ifaddr:
                type: bool
                required: false
                description:
                    - Enable use bridge own IP address for IGMP queries.
                    - Address 0.0.0.0 is used if disabled.

            mcast_querier:
                type: bool
                required: false
                description:
                    - Enable IGMP querier.
                    - Disabled by default.

            mcast_querier_interval:
                type: int
                required: false
                description:
                    - Interval between queries by IGMP querier.
                    - Used only if I(mcast_querier) is enabled.

            mcast_hash_max:
                type: int
                required: false
                description:
                    - Maximum size of the multicast hash table.
                    - Must be power of 2.
                    - Default value in the kernel is 512.

            mcast_last_member_count:
                type: int
                required: false
                description:
                    - Number of queries before stopping forwaring for
                      a multicast group after 'leave' message.
                    - Default value in the kernel is 2.

            mcast_last_member_interval:
                type: int
                required: false
                description:
                    - Interval between queries to find remaining members of
                      group after 'leave' message was recieved.
                    - Value in seconds.

            mcast_startup_query_count:
                type: int
                required: false
                description:
                    - Number of IGMP queries at startup phase.
                    - Default value in the kernel is 2.

            mcast_startup_query_interval:
                type: int
                required: false
                description:
                    - Interval between IGMP queries in startup phase.
                    - Value in seconds.

            mcast_query_interval:
                type: int
                required: false
                description:
                    - Inverval between IGMP queries after startup.
                    - Value in seconds.

            mcast_query_response_interval:
                type: int
                required: false
                description:
                    - Max response time for IGMP/MLD queries.
                    - Value in seconds.

            mcast_membership_interval:
                type: int
                required: false
                description:
                    - Delay before leaving a group if no membership reports
                      for this group was recieved.
                    - Value in seconds.

            mcast_stats:
                type: bool
                required: false
                description:
                    - Enable stats accounting for IGMP/MLD.
                    - Corresponds to mcast_stats_enabled option of ip link.

            mcast_igmp_version:
                type: str
                required: false
                description:
                    - Set version of IGMP.

            mcast_mld_version:
                type: str
                required: false
                description:
                    - Set version of MLD.

            nf_call_iptables:
                type: bool
                required: false
                description:
                    - Enable iptables hooks on the bridge.

            nf_call_ip6tables:
                type: bool
                required: false
                description:
                    - Enable ip6tables hooks on the bridge.

            nf_call_arptables:
                type: bool
                required: false
                description:
                    - Enable arptables hooks on the bridge.

    bond_options:
        type: dict
        description:
            - Options, specific for I(type)=C(bond)
            - Should not be used for any other type.
            - Most options are for rarely used bond types.
            - Physical devices can added to a bond by setting them
              as master for the bond using M(ip_link_device_atrribute).
              (see examples).
            - Extensive documentation for linux boding is provided
              in the Kernel docs at https://www.kernel.org/doc/Documentation/networking/bonding.txt

        suboptions:
            mode:
                type: str
                choices:
                    - balance-rr
                    - active-backup
                    - balance-xor
                    - broadcast
                    - 802.3ad
                    - balance-tlb
                    - balance-alb
                description:
                    - Mode to use for bond management.
                    - Default (kernel-specific) mode is used if omitted.
                    - Must be supported by underlaying device type.
                    - Use of C(802.3ad) is recommended for most cases.

            active_slave:
                type: str
                description:
                    - Active slave device name.
                    - Device should exists and prior to call.
                    - Device must be in UP state to be selected as active slave.
                    - Supported for I(mode)=C(active-backup), C(balance-alb),
                      C(balance-tlb) modes.

            clear_active_slave:
                type: bool
                description:
                    - Set 'clear_active_slave' option when creating bond interface.
                    - Value C(false) should not be used.

            miimon:
                type: int
                description:
                    - MII (link) monitoring frequiency in milliseconds.
                    - Value zero disables monitoring.
                    - Default (kernel) value is C(0).

            updelay:
                type: int
                description:
                    - Time before enabling slave after link recovery.
                    - Value is in milliseconds.
                    - Valid only if miimon active.
                    - Must be a multiple of miimon value.
                    - Default (kernel) value is C(0).

            downdelay:
                type: int
                description:
                    - Time before disabling slave after link failure.
                    - Value is in milliseconds.
                    - Valid only if miimon active.
                    - Must be a multiple of miimon value.
                    - Default (kernel) value is C(0).

            use_carrier:
                type: bool
                description:
                    - Value C(True) uses netif_carrier_ok()
                    - Value C(False) uses ethtool ioctls.
                    - Defalut (kernel) value is C(True)

            arp_interval:
                type: int
                description:
                    - ARP link monitor frequency.
                    - Value is in milliseconds.
                    - Value C(0) disables ARP monitoring.
                    - Default (kernel) value is C(0).

            arp_validate:
                type: str
                choices:
                    - "none"
                    - "0"
                    - active
                    - "1"
                    - all
                    - "3"
                    - filter
                    - "4"
                    - filter_active
                    - "5"
                    - filter_bacup
                    - "6"
                description:
                    - Control if ARP replies should be validated/filtered or not.
                    - C("none") or C("0") disable validation
                    - C(active) or C("1") validates only for active slave.
                    - C(backup) or C("2") validates only for backup slaves.
                    - C(all) or C("3") validates for all slaves.
                    - C(filter) or C("4") filters on all slaves.
                    - C(filter_active) or C("5") filters on active slaves.
                    - C(filter_backup) or C("6") filters only on backup slaves.

            arp_all_targets:
                type: str
                choices: [any, "0", all, "1"]
                description:
                    - Specifies the quantity of arp_ip_targets that must be reachable
                      in order for the ARP monitor to consider a slave as being up.
                    - C(any) or C("0") consider the slave up only when any of
                      the arp_ip_targets is reachable.
                    - C(all) or C("1") consider the slave up only when all of
                      the arp_ip_targets are reachable.

            arp_ip_target:
                type: list
                elements: str
                description:
                    - IP addresses to use as ARP monitoring peers when
                      I(arp_interval) is > 0.
                    - Specify these values in ddd.ddd.ddd.ddd format.
                    - At least one IP address must be given for ARP monitoring
                      to function.
                    - The maximum number of targets that can be specified is 16.

            primary:
                type: str
                description:
                    - Name of primary device for I(mode) C(active-backup),
                      C(balance-tlb), C(balance-alb).
                    - Device should exists prior to call.
                    - The specified device will always be the
                      active slave while it is available.
                    - Only when the primary is offline

            primary_reselect:
                type: str
                choices:
                    - always
                    - "0"
                    - better
                    - "1"
                    - failure
                    - "2"
                description:
                  - Reselection policy for the primary slave.
                  - C(always) or C("0") makes primary slave to become
                    the active slave whenever it comes back up.
                  - C(better) or C("1") makes primary slave to become
                    the active slave when it comes back up, if the speed
                    and duplex of the primary slave is better than
                    the speed and duplex of the current active slave.
                  - C(failure) or C("2") makes  slave to become
                    the active slave only if the current active slave
                    fails and the primary slave is up.
                  - Default (kernel) value is C(always).
            fail_over_mac:
                type: str
                choices:
                    - "none"
                    - "0"
                    - "active"
                    - "1"
                    - "follow"
                    - "2"
                description:
                    - Specifies whether active-backup mode should set all slaves to
                      the same MAC address at enslavement (the traditional
                      behavior), or, when enabled, perform special handling of the
                      bond's MAC address in accordance with the selected policy.
                    - C("none") or C("0") disables fail_over_mac, and causes
                      bonding to set all slaves of an active-backup bond to
                      the same MAC address at enslavement time.
                    - C("active") or C("1") makes the MAC address of the bond
                      to always  be the MAC address of the currently active slave.
                      The MAC address of the slaves is not changed; instead, the MAC
                      address of the bond changes during a failover.
            xmit_hash_policy:
                type: str
                choices: [layer2, layer2+3, layer3+4, encap2+3, encap3+4]
                description:
                    - Selects the transmit hash policy to use for slave selection in
                      I(mode) C(balance-xor), C(802.3ad), and C(active-tlb).
                    - C(layer2) uses XOR of hardware MAC addresses and packet type ID
                      field to generate the hash. This algorithm is 802.3ad compliant.
                    - C(layer2+3) uses a combination of layer2 and layer3 protocol
                      information to generate the hash. This algorithm is 802.3ad compliant.
                    - C(layer3+4) uses upper layer protocol information,
                      when available, to generate the hash. This algorithm is not
                      fully 802.3ad compliant.  It may causes packets
                      striped across two interfaces.  This may result in out
                      of order delivery.
                    - C(encap2+3) uses the same formula as layer2+3 but it
                      relies on skb_flow_dissect to obtain the header fields
                      which might result in the use of inner headers if an
                      encapsulation protocol is used.
                    - C(encap3+4) uses the same formula as layer3+4 but it
                      relies on skb_flow_dissect to obtain the header fields
                      which might result in the use of inner headers if an
                      encapsulation protocol is used.
            resend_igmp:
                type: int
                description:
                    - Number of IGMP membership reports to be issued after
                      a failover event.
                    - Value from C(0) to C(255).
                    - The kernel default is C(1).
                    - C(0) prevents the IGMP membership report from
                      being issued.
            num_grat_arp:
                type: int
                description:
                    - Specify the number of peer notifications (gratuitous ARPs and
                      unsolicited IPv6 Neighbor Advertisements) to be issued after a
                      failover event.
                    - I(num_grat_arp) can be used instead of num_unsol_na option
                      for IPv6 networks.
                    - Valid values are from C(0) to C(255).
                    - Default (kernel) value is C(1).
            all_slaves_active:
                type: bool
                description:
                    - Specifies that duplicate frames (received on inactive ports) should be
                      dropped C(false) or delivered C(true).
                    - Default (kernel) value is C(false).
            min_links:
                type: int
                description:
                    - Minimum number of member ports that must be up (link-up state) before
                      marking the bond device as up (carrier on).
                    - Default (kernel) value is 0.
                    - Value C(1) has same effect as C(0).
            lp_interval:
                type: int
                description:
                    - Specifies the number of seconds between instances where the bonding
                      driver sends learning packets to each slaves peer switch.
                    - Valid only for I(mode) C(balance-tlb) and C(balance-alb).
                    - Valid vaues are in range from C(1) to C(2147483647).
                    - Default (kernel) value is C(1).
            packets_per_slave:
                type: int
                description:
                    - Specify the number of packets to transmit through a slave before
                      moving to the next one.
                    - When value is C(0) then a slave is chosen at random.
                    - Valid values are from C(0) to C(65535).
                    - Default (kernel) value is C(1).
                    - Can be used only in I(mode)=C(balance-rr).
            tlb_dynamic_lb:
                type: bool
                description:
                    - Specifies if dynamic shuffling of flows is enabled.
                    - Can be used only for I(mode)=C(balance-tlb).
                    - Default (kernel) value is C(true).
            lacp_rate:
                type: str
                choices:
                    - slow
                    - "0"
                    - fast
                    - "1"
                description:
                    - the rate ito ask link partner to transmit LACPDU packets.
                    - Valid only for I(mode)=C(802.3ad).
                    - C(slow) is the same as C("0").
                    - C(fast) is the same as C("1").
                    - Default (kernel) value is C(slow).
            ad_select:
                type: str
                choices:
                    - stable
                    - "0"
                    - bandwidth
                    - "1"
                    - count
                    - "2"
                description:
                    - Specifies aggregation selection logic to use.
                    - Valid only for I(mode)=C(802.3ad).
                    - C(stable) or C("0") makes the active aggregator
                      to be chosen by largest aggregate bandwidth
                      only when all slaves of the active aggregator are
                      down or the active aggregator has no slaves.
                    - C(bandwidth) or C("1") makes active aggregator
                      to be chosen by largest aggregate bandwidth.
                      Reselection occurs on link change.
                    - C(count) or C("2") makes active aggregator to be
                      chosen by the largest number of ports (slaves)
                      on link change.
            ad_user_port_key:
                type: int
                description:
                    - Specify port key value.
                    - Valid only for I(mode)=C(802.3ad).
                    - Valid values are from C(0) to C(1023).
                    - Composite bit field, bit 0 is specify duplex,
                      bits 1-5 specify speed and bits 6-15 specify
                      user-defined values.
                    - Default (kernel) value is C(0).
            ad_actor_sys_prio:
                type: int
                description:
                    - System priority for 802.3ad protocol.
                    - Valid values are from C(0) to C(65535).
                    - Valid only for I(mode)=C(802.3ad).
                    - Default (kernel) value is C(65535).
            ad_actor_system:
                type: str
                description:
                    - mac-address for the actor in protocol
                      packet exchanges (LACPDUs) for 802.3ad protocol.
                    - If the value is not given then
                      system defaults to using the masters'
                      mac address as actors' system address.
                    - Valid only for I(mode)=C(802.3ad).

    vrf_options:
        type: dict
        description:
            - Options, specific for I(type)=C(vrf)
            - Should not be used for any other type.
            - VRF documentation is available at https://docs.kernel.org/networking/vrf.html

        suboptions:
            table:
                type: str
                description:
                    - ID of the routing table used for VRF.
notes:
    - The module does not check the interface type when checking
      if interface is present or not. I(type) and corresponding options are
      used only for the creation of a new interface and are used only if no
      interface with I(name) found and I(state)=C(present).
    - This module does not change parameters for existing interfaces,
      all type-specific options are used only for new interfaces.
    - See M(ip_link_device_attribute) module for updating attributes of
      an existing interface.
    - Some type-specific options may have additional restrictions which are not
      described in the module documentation. Check "man ip-link" for details.
    - Some interfaces types may require kernel modules available (vxlan, gre).
    - Some options may require new version of iproute2 and the kernel.
    - Virtual interfaces (gre, vxlan) creates 'fake' interfaces when activated.
      They can be removed only by unloading corresponding modules
      (f.e. rmmod ip_gre).
"""

EXAMPLES = """
- name: Create veth pair in namespace foo
  ip_link_device:
    name: veth3
    namepace: foo
    type: veth
    mtu: 8974
    txqueuelen: 1
    veth_options:
        peer_name: veth4

- name: Add vlan interface for eth4
  ip_link_device:
    name: eth3.3
    link: eth3
    type: vlan
    vlan_options:
        id: 3
        loose_binding: false

- name: Create GRE tunnel
  ip_link_device:
    name: gre42
    type: gre
    gre_options:
        local: 192.168.0.1
        remote: 192.168.0.2
        dev: eth0
        key: 42

- name: Create dummy interface
  ip_link_device:
    name: dummy3
    type: dummy
    state: present

- name: Create bridge
  ip_link_device:
    device: br0
    type: bridge
    bridge_options:
        ageing_time: 42
    state: present

- name: Create bond
  ip_link_device:
    device: bond0
    type: bond
    state: present
    bond_options:
        mode: 802.3ad
        lacp_rate: fast

- name: Add device to bond
  ip_link_device_attribute:  # it's a different module!
    name: eth3
    master: bond

- name: Create vrf
  ip_link_device:
    device: blue
    type: vrf
    state: present
    vrf_options:
        table: 42

- name: Enslave vxlan
  ip_link_device_attribute:  # it's a different module!
    device: vxlan.42
    master: blue
"""

RETURN = """
failed_command:
    description: Failed command to ip utility.
    returned: failure
    type: str
msg:
    description: Error message.
    returned: failure
    type: str
"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text


__metaclass__ = type


BOOLS = ["off", "on"]


TYPE_COMMANDS = {
    "vlan": {
        "protocol": lambda proto: ["protocol", proto],
        "id": lambda id: ["id", str(id)],
        "reorder_hdr": lambda flag: ["reorder_hdr", BOOLS[flag]],
        "gvrp": lambda flag: ["gvrp", BOOLS[flag]],
        "mvrp": lambda flag: ["mvrp", BOOLS[flag]],
        "loose_binding": lambda flag: ["loose_binding", BOOLS[flag]],
        "bridge_binding": lambda flag: ["bridge_binding", BOOLS[flag]],
        # man ip says that 'The format is FROM:TO with muliple mappings
        # separated by spaces.
        # experiments shows that each mapping should be a separate
        # argument
        "ingress_qos_map": lambda map: ["ingress-qos-map"] + map,
        "egress_qos_map": lambda map: ["egress-qos-map"] + map,
    },
    "vxlan": {
        "id": lambda id: ["id", str(id)],
        "dev": lambda dev: ["dev", dev],
        "group": lambda group: ["group", group],
        "remote": lambda ip: ["remote", ip],
        "local": lambda ip: ["local", ip],
        "ttl": lambda ttl: ["ttl", str(ttl)],
        "tos": lambda tos: ["tos", str(tos)],
        "df": lambda df: ["df", str(df)],
        "flowlabel": lambda label: ["flowlabel", label],
        "dstport": lambda port: ["dstport", str(port)],
        "srcport": lambda port: ["srcport", " ".join(map(str, port))],
        "learning": lambda flag: [["nolearning", "learning"][flag]],
        "rsc": lambda flag: [["norsc", "rsc"][flag]],
        "proxy": lambda flag: [["noproxy", "proxy"][flag]],
        "l2miss": lambda flag: [["nol2miss", "l2miss"][flag]],
        "l3miss": lambda flag: [["nol3miss", "l3miss"][flag]],
        "udpcsum": lambda flag: [["noudpcsum", "udpcsum"][flag]],
        "udp6zerocsumtx": lambda flag: [["noudp6zerocsumtx", "udp6zerocsumtx"][flag]],
        "udp6zerocsumrx": lambda flag: [["noudp6zerocsumrx", "udp6zerocsumrx"][flag]],
        "ageing": lambda age: ["ageing", str(age)],
        "maxaddress": lambda age: ["maxaddress", str(age)],
        "external": lambda flag: [["noexternal", "external"][flag]],
        "gbp": lambda flag: [None, "gbp"][flag],
        "gpe": lambda flag: [None, "gpe"][flag],
    },
    "veth": {
        "peer_name": lambda arg: ["peer", "name", arg],
    },
    "gre": {
        "remote": lambda ip: ["remote", ip],
        "local": lambda ip: ["local", ip],
        "iseq": lambda flag: [["noiseq", "iseq"][flag]],
        "oseq": lambda flag: [["nooseq", "oseq"][flag]],
        "ikey": lambda key: ["noikey"] if key == "no" else ["ikey", str(key)],
        "okey": lambda key: ["nookey"] if key == "no" else ["okey", str(key)],
        "key": lambda key: ["nokey"] if key == "no" else ["key", str(key)],
        "icsum": lambda flag: [["noicsum", "icsum"][flag]],
        "ocsum": lambda flag: [["noocsum", "ocsum"][flag]],
        "csum": lambda flag: [["nocsum", "csum"][flag]],
        "ttl": lambda ttl: ["ttl", str(ttl)],
        "tos": lambda tos: ["tos", str(tos)],
        "pmtudisc": lambda flag: [["nopmtudisc", "nopmtudisc"][flag]],
        "ignore_df": lambda flag: [["noignore-df", "ignore-df"][flag]],
        "dev": lambda dev: ["dev", dev],
        "external": lambda flag: [["external"] if flag else []],
    },
    "gretap": {
        "remote": lambda ip: ["remote", ip],
        "local": lambda ip: ["local", ip],
        "iseq": lambda flag: [["noiseq", "iseq"][flag]],
        "oseq": lambda flag: [["nooseq", "oseq"][flag]],
        "ikey": lambda key: ["noikey"] if key == "no" else ["ikey", str(key)],
        "okey": lambda key: ["nookey"] if key == "no" else ["okey", str(key)],
        "key": lambda key: ["nokey"] if key == "no" else ["key", str(key)],
        "icsum": lambda flag: [["noicsum", "icsum"][flag]],
        "ocsum": lambda flag: [["noocsum", "ocsum"][flag]],
        "csum": lambda flag: [["nocsum", "csum"][flag]],
        "ttl": lambda ttl: ["ttl", str(ttl)],
        "tos": lambda tos: ["tos", str(tos)],
        "pmtudisc": lambda flag: [["nopmtudisc", "nopmtudisc"][flag]],
        "ignore_df": lambda flag: [["noignore-df", "ignore-df"][flag]],
        "dev": lambda dev: ["dev", dev],
        "external": lambda flag: [["external"] if flag else []],
    },
    "dummy": {},
    "bridge": {
        "ageing_time": lambda time: ["ageing_time", str(time)],
        "group_fwd_mask": lambda mask: ["group_fwd_mask", str(mask)],
        "group_address": lambda addr: ["group_address", str(addr)],
        "forward_delay": lambda delay: ["forward_delay", str(delay)],
        "hello_time": lambda time: ["hello_time", str(time)],
        "max_age": lambda age: ["max_age", str(age)],
        "stp": lambda state: ["stp_state", str(int(state))],
        "priority": lambda pri: ["priority", str(pri)],
        "vlan_filtering": lambda flag: ["vlan_filtering", str(int(flag))],
        "vlan_protocol": lambda proto: ["vlan_protocol", str(proto)],
        "vlan_default_pvid": lambda pvid: ["vlan_default_pvid", str(pvid)],
        "vlan_stats": lambda flag: ["vlan_stats_enabled", str(int(flag))],
        "vlan_stats_per_port": lambda flag: ["vlan_stats_per_port", str(int(flag))],
        "mcast_snooping": lambda flag: ["mcast_snooping", str(int(flag))],
        "mcast_router": lambda mode: ["mcast_router", str(mode)],
        "mcast_query_use_ifaddr": lambda flag: [
            "mcast_query_use_ifaddr",
            str(int(flag)),
        ],
        "mcast_querier": lambda flag: ["mcast_querier", str(int(flag))],
        "mcast_querier_interval": lambda interval: [
            "mcast_querier_interval",
            str(interval),
        ],
        "mcast_hash_max": lambda max_hash: ["mcast_hash_max", str(max_hash)],
        "mcast_last_member_count": lambda cnt: ["mcast_last_member_count", str(cnt)],
        "mcast_last_member_interval": lambda interval: [
            "mcast_last_member_interval",
            str(interval),
        ],
        "mcast_startup_query_count": lambda cnt: [
            "mcast_startup_query_count",
            str(cnt),
        ],
        "mcast_startup_query_interval": lambda interval: [
            "mcast_startup_query_interval",
            str(interval),
        ],
        "mcast_query_interval": lambda interval: [
            "mcast_query_interval",
            str(interval),
        ],
        "mcast_query_response_interval": lambda interval: [
            "mcast_query_response_interval",
            str(interval),
        ],
        "mcast_membership_interval": lambda interval: [
            "mcast_membership_interval",
            str(interval),
        ],
        "mcast_stats": lambda flg: ["mcast_stats_enabled", str(int(flg))],
        "mcast_igmp_version": lambda ver: ["mcast_igmp_version", str(ver)],
        "mcast_mld_version": lambda ver: ["mcast_mld_version", str(ver)],
        "nf_call_iptables": lambda flag: ["nf_call_iptables", str(int(flag))],
        "nf_call_ip6tables": lambda flag: ["nf_call_iptables", str(int(flag))],
        "nf_call_arptables": lambda flag: ["nf_call_arptables", str(int(flag))],
    },
    "bond": {
        "mode": lambda mode: ["mode", mode],
        "active_slave": lambda dev: ["active_slave", dev],
        "clear_active_slave": lambda flag: ([], ["clear_active_slave"])[int(flag)],
        "miimon": lambda msec: ["miimon", str(msec)],
        "updelay": lambda msec: ["updelay", str(msec)],
        "downdelay": lambda msec: ["downdelay", str(msec)],
        "use_carrier": lambda flag: ["use_carrier", ("0", "1")[int(flag)]],
        "arp_interval": lambda msec: ["arp_interval", str(msec)],
        "arp_validate": lambda val: ["arp_validate", str(val)],
        "arp_all_targets": lambda val: ["arp_all_targets", str(val)],
        "arp_ip_target": lambda tgts: ["arp_ip_target", ",".join(tgts)],
        "primary": lambda dev: ["primary", dev],
        "primary_reselect": lambda param: ["primary_reselect", param],
        "fail_over_mac": lambda param: ["fail_over_mac", param],
        "xmit_hash_policy": lambda param: ["xmit_hash_policy", param],
        "resend_igmp": lambda cnt: ["resend_igmp", str(cnt)],
        "num_grat_arp": lambda cnt: ["num_grat_arp", str(cnt)],
        "all_slaves_active": lambda flag: ["all_slaves_active", ("0", "1")[int(flag)]],
        "min_links": lambda cnt: ["min_links", str(cnt)],
        "lp_interval": lambda msec: ["lp_interval", str(msec)],
        "packets_per_slave": lambda cnt: ["packets_per_slave", int(cnt)],
        "tlb_dynamic_lb": lambda flag: ["tlb_dynamic_lb", ("0", "1")[int(flag)]],
        "lacp_rate": lambda param: ["lacp_rate", str(param)],
        "ad_select": lambda param: ["ad_select", str(param)],
        "ad_user_port_key": lambda val: ["ad_user_port_key", str(val)],
        "ad_actor_sys_prio": lambda val: ["ad_actor_sys_prio", str(val)],
        "ad_actor_system": lambda addr: ["ad_actor_system", str(addr)],
    },
    "vrf": {
        "table": lambda table_id: ["table", str(table_id)],
    },
}


class LinkDevice(object):
    """Main class for the module."""

    params_list = [  # module paramters which aren't passed to ip or special
        "name",
        "namespace",
        "group_id",
        "state",
        "type",
        "link",
        "search_namespaces",
    ]
    knob_cmds = {  # module paramtes which are directly translates to ip args
        "txqueuelen": lambda len: ["txqueuelen", str(len)],
        "address": lambda addr: ["address", addr],
        "broadcast": lambda addr: ["broadcast", addr],
        "mtu": lambda mtu: ["mtu", str(mtu)],
        "index": lambda idx: ["index", str(idx)],
        "numtxqueues": lambda num: ["numtxqueues", str(num)],
        "numrxqueues": lambda num: ["numrxqueues", str(num)],
        "gso_max_size": lambda size: ["gso_max_size", str(size)],
        "gso_max_segs": lambda size: ["gso_max_segs", str(size)],
    }

    def __init__(self, module):
        self.module = module
        self.check_mode = module.check_mode
        self.knobs = {}
        self.type_options = {}

        for knob in self.knob_cmds.keys():
            self.knobs[knob] = module.params[knob]
        for param in self.params_list:
            setattr(self, param, module.params[param])
        if self.state == "present" and self.group_id:
            self.module.fail_json(
                msg=to_text("State=present can not be used with group_id.")
            )
        if self.name:
            self.id_postfix = ["dev", self.name]
        if self.group_id:
            self.id_postfix = ["group", self.group_id]

        if self.state == "present" and not self.type:
            self.module.fail_json(msg=to_text("State=present requires type"))
        if self.state == "present":
            self.type_options = module.params.get(self.type + "_options") or {}
            self._validate_type_options()

    def _validate_type_options(self):
        possible_type_options = set(TYPE_COMMANDS[self.type].keys())
        type_options = set(self.type_options.keys())
        unknown_type_options = type_options - possible_type_options
        if unknown_type_options:
            self.module.fail_json(
                msg=to_text(
                    "Unknown option(s) for type %s: %s"
                    % (self.type, ", ".join(unknown_type_options))
                )
            )

    def _exec(self, namespace, cmd, not_found_is_ok=False):
        if namespace:
            return self._exec(
                None, ["ip", "netns", "exec", namespace] + cmd, not_found_is_ok
            )
        # if self.type=='gre' and 'add' in cmd:
        #     self.module.fail_json(msg=to_text(cmd))
        rc, out, err = self.module.run_command(cmd)
        if rc != 0:
            if not_found_is_ok:
                # show for non-existing group  return empty output
                # show for non-existing device yield a specific error
                if self.name:
                    not_found_msg = 'Device "%s" does not exist' % self.name
                    if not_found_msg in err:
                        return ""
            self.module.fail_json(msg=to_text(err), failed_command=" ".join(cmd))
        return out

    def is_exists(self, namespaces=None):
        """Check if interface is exists in namespaces."""
        cmd = ["ip", "-o", "link", "show"] + self.id_postfix
        raw_output = self._exec(self.namespace, cmd, not_found_is_ok=True)
        res = bool(raw_output.strip())
        if res:
            return True
        if namespaces:
            for ns in namespaces:
                raw_output = self._exec(ns, cmd, not_found_is_ok=True)
                res = bool(raw_output.strip())
                if res:
                    return True
        return res

    def _link_name(self):
        if self.link:
            return ["link", self.link]
        return []

    def _common_args(self):
        args = []
        order = [
            "txqueuelen",
            "address",
            "broadcast",
            "mtu",
            "index",
            "numtxqueues",
            "numrxqueues",
            "gso_max_size",
            "gso_max_segs",
        ]
        for knob_name in order:
            knob_value = self.knobs[knob_name]
            if knob_value:
                args.extend(self.knob_cmds[knob_name](knob_value))
        return args

    def _type_args(self):
        args = ["type", self.type]
        typecmd = TYPE_COMMANDS[self.type]
        for opt_name, opt_value in sorted(self.type_options.items()):
            if opt_value:
                args.extend(typecmd[opt_name](opt_value))
        return args

    def _create(self):
        # order of snippets is according to 'man ip link':
        #        ip link add [ link DEVICE ] [ name ] NAME
        #           [ txqueuelen PACKETS ]
        #           [ address LLADDR ] [ broadcast LLADDR ]
        #           [ mtu MTU ] [ index IDX ]
        #           [ numtxqueues QUEUE_COUNT ] [ numrxqueues QUEUE_COUNT ]
        #           [ gso_max_size BYTES ] [ gso_max_segs SEGMENTS ]
        #           type TYPE [ ARGS ]

        cmd = ["ip", "link", "add"]
        cmd += self._link_name()
        cmd += ["name", self.name]
        cmd += self._common_args()
        cmd += self._type_args()
        self._exec(self.namespace, cmd)

    def _delete(self):
        cmd = ["ip", "link", "delete"] + self.id_postfix
        self._exec(self.namespace, cmd)

    def run(self):
        changed = False
        if self.state == "absent":
            exists = self.is_exists()
            if exists:
                if not self.check_mode:
                    self._delete()
                changed = True
        if self.state == "present":
            exists = self.is_exists(namespaces=self.search_namespaces)
            if not exists:
                if not self.check_mode:
                    self._create()
                changed = True
        self.module.exit_json(changed=changed)


def main():
    """Entry point."""
    module = AnsibleModule(
        argument_spec={
            "name": {"aliases": ["device"]},
            "group_id": {},
            "namespace": {},
            "search_namespaces": {"type": "list"},
            "state": {"choices": ["present", "absent"], "required": True},
            "type": {
                "choices": [
                    "veth",
                    "vlan",
                    "vxlan",
                    "gre",
                    "gretap",
                    "dummy",
                    "bridge",
                    "bond",
                    "vrf",
                ]
            },
            "link": {},
            "txqueuelen": {"type": "int"},
            "address": {},
            "broadcast": {},
            "mtu": {"type": "int"},
            "index": {"type": "int"},
            "numtxqueues": {"type": "int"},
            "numrxqueues": {"type": "int"},
            "gso_max_size": {"type": "int"},
            "gso_max_segs": {"type": "int"},
            "veth_options": {"type": "dict"},
            "vlan_options": {"type": "dict"},
            "vxlan_options": {"type": "dict"},
            "gre_options": {"type": "dict"},
            "gretap_options": {"type": "dict"},
            "bridge_options": {"type": "dict"},
            "bond_options": {"type": "dict"},
            "vrf_options": {"type": "dict"},
        },
        supports_check_mode=True,
        mutually_exclusive=[
            ["group_id", "group"],
            ["name", "group_id"],
            [
                "vlan_options",
                "vxlan_options",
                "gre_options",
                "gretap_options",
                "veth_options",
                "bridge_options",
                "bond_options",
                "vrf_options",
            ],
        ],
        required_one_of=[["name", "group_id"]],
    )

    link_dev = LinkDevice(module)
    link_dev.run()


if __name__ == "__main__":
    main()
