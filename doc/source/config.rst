===============================
Network configuration reference
===============================

This section describes the supported ``/etc/os-net-config/config.yaml`` YAML
format and how they map to networking backend providers. The root element is
a ``network_config`` attribute, and the value is an array of dicts entries
describing the physical and virtual interfaces to configure. Each interface
entry has a mandatory ``type`` attribute, and the value determines what other
attributes are supported for that type.

.. _common-attributes:

Common attributes
-----------------

The following attributes are used in many types. See :ref:`multiple-nics` for
examples.

addresses
=========

A list of ``ip_netmask`` entries to specify the network addresses for this
interface. For example:

  .. code-block:: yaml

    addresses:
      - ip_netmask: 192.0.2.2/24
      - ip_netmask: 192.0.3.2/32

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Sets ``BOOTPROTO=static`` and populates ``IPADDR`` and ``NETMASK, followed by
``IPADDR<i>``, ``NETMASK<i>`` for subsequent addresses with ``<i>`` incrementing
from ``1``.

defroute
========

A boolean which defaults to ``true``. When ``false`` the default route given by an
IPV4 DHCP server will be ignored.

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Sets ``DEFROUTE=no`` when set to ``false``.

dhclient_args
=============

Arguments to append to the call to the dhclient command, as a single string.

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Sets ``DHCLIENTARGS`` to the supplied value

dns_servers
===========

A list of DNS servers (maximum of 2) to use for name resolution.

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Sets ``DNS1``, ``DNS2`` to support up to 2 DNS resolvers.

domain
======

A string or a list of strings containing DNS search domains

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Sets ``DOMAIN`` containing all values as a space-separated list.

mtu
===

Maximum transmission unit for this interface.

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Sets ``MTU`` to the specified value. If unspecified the default is ``1500``.

name
====

This is the name for the interface which is one of:

- the name of existing physical interface (NIC)
- the identifier from the mapping file which maps to a NIC
- the desired name of a bridge or bond
- a numbered identifier ``nic<i>`` starting with ``1`` for each active NIC:
  ``nic1``, ``nic2`` etc


ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

When the name is an identifier in the mapping file or a ``nic<i>``
identifier, the actual name used will be the mapping value, not the
identifier.

The name format of a physical interfaces depends on ``biosdevname`` or
``net.ifnames`` sysctl settings or udev rules for persistent names. Names
will begin with ``eth`` if both sysctl settings are disabled and there are no
udev rules. The sort order used to allocate ``nic<i>`` identifiers are:

- Embedded interfaces first (``em<j>``, ``eth<j>``, ``eno<j>``) ordered
  alphanumerically
- Then, other active NICs ordered alphanumerically

Each interface definition is written to
``/etc/sysconfig/network-scripts/ifcfg-<name>`` and the first value in the
file is ``DEVICE=<name>``.

nm_controlled
=============

Boolean whether this interface is managed by `NetworkManager`_, defaults to
``false``.

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Sets ``NM_CONTROLLED=yes`` or ``NM_CONTROLLED=no``

onboot
======

Boolean which determines whether to enable the interface on machine boot,
defaults to ``true``.

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Sets ``ONBOOT=yes`` or ``ONBOOT=no``.

primary
=======

In the ``members`` entries for a bond or bridge this may be set to ``true``
for the primary interface. This results in the bond or bridge inheriting the MAC
address of the primary interface.

routes
======

A list of route entries for this interface containing attributes:

- ``default`` Boolean whether this is the default route for this interface
- ``ip_netmask`` or ``destination`` Destination network address when ``default``
  is ``false``
- ``next_hop`` or ``nexthop`` Gateway address for route destination

Other supported attributes include:

- ``route_table`` The table ID or name to add this route to
- ``route_options`` String of extra options to append to the end of the route

For example:

  .. code-block:: yaml

    routes:
      - default: true
        next_hop: 198.51.100.1
      - ip_netmask: 192.0.2.2/24
        next_hop: 203.0.113.254
        route_table: 2
        route_options: metric 100

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

A routes file for each interface definition is written to
``/etc/sysconfig/network-scripts/route-<name>``.

rules
=====

A list of commented route rules, for example:

  .. code-block:: yaml

    rules:
      - rule: "iif em1 table 200"
        comment: "Route incoming traffic to em1 with table 200"
      - rule: "from 192.0.2.0/24 table 200"
        comment: "Route all traffic from 192.0.2.0/24 with table 200"
      - rule: "add blackhole from 172.19.40.0/24 table 200"
      - rule: "add unreachable iif em1 from 192.168.1.0/24"

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Each interface is iterated in order and its rules are compared to existing
rules then converged by running ``ip rule del <rule>`` and ``ip rule add
<rule>``.

use_dhcp
========

Boolean for whether to use DHCP for the IPv4 boot protocol.

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Sets ``PEERDNS=no`` when ``false``.

use_dhcpv6
==========

Boolean for whether to use DHCP for the IPv6 boot protocol.

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Sets ``DHCPV6C=yes`` when ``true``.

.. 
    Undocumented:
    rules
    nic_mapping
    persist_mapping
    

.. _ovs-attributes:

Open vSwitch attributes
-----------------------

The `Open vSwitch`_ types support some or all of these attributes:

.. _ovs-options:

ovs_options
===========

String of other options to pass to Open vSwitch for this bond or bridge.

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Sets the ``OVS_OPTIONS`` value.

.. _ovs-extra:

ovs_extra
=========

A list of extra options to pass to Open vSwitch.

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Will set the ``OVS_EXTRA`` value with all the provided values.

ovs_fail_mode
=============

Failure mode for a bridge, defaults to ``standard``, can also be set to ``secure``

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Will be appended to the ``OVS_OPTIONS`` value and the concatenated list of
``OVS_EXTRA`` values.

type: interface
---------------

Configures a physical NIC. See :ref:`multiple-nics` for examples. All of the
:ref:`common-attributes` can be used with this type along with the following
attributes:

ethtool_opts
============

Device-specific options supported by `ethtool`_.

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Sets ``ETHTOOL_OPTS`` to the value.

hotplug
=======

A boolean for whether to activate the device when it is plugged in.

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Sets ``HOTPLUG=yes`` or ``HOTPLUG=no``

linkdelay
=========

Integer number of seconds to wait for link negotiation before configuring
the device.

ifcfg implementation
^^^^^^^^^^^^^^^^^^^^

Sets ``LINKDELAY`` to the delay value.

type: ovs_bridge
----------------

Configures an `Open vSwitch`_ bridge. See :ref:`control-plane-bridge` for an
example. All of the :ref:`common-attributes` and :ref:`ovs-attributes` can be
used with this type. The ``members`` attribute contains a list of entries for
interfaces to bridge typically of ``type``:

- ``interface``
- ``linux_bond``
- ``ovs_bond``
- ``vlan``
- other Open vSwitch internal interfaces


ifcfg implementation
====================

Values ``DEVICETYPE=ovs`` and ``TYPE=OVSBridge`` are set. When ``use_dhcp``
or ``use_dhcpv6`` is ``true``, ``OVSBOOTPROTO=dhcp`` is set and
``OVSDHCPINTERFACES`` is populated.

type: ovs_bond
--------------

Configures an `Open vSwitch`_ bond. See :ref:`ovs-bond` for an example. All
of the :ref:`common-attributes` and :ref:`ovs-attributes` can be used with
this type. The ``members`` attribute contains a list of entries for
interfaces to be bonded.

ifcfg implementation
====================

Values ``DEVICETYPE=ovs`` and ``TYPE=OVSBridge`` are set. When ``use_dhcp``
or ``use_dhcpv6`` is ``true``, ``OVSBOOTPROTO=dhcp`` is set and
``OVSDHCPINTERFACES`` is populated.

type: vlan
----------

Configures VLAN tagging for one VLAN. See :ref:`bonds-with-vlans` for an
example. :ref:`common-attributes` are supported but generally only ``mtu``,
``addresses`` or ``routes`` are used.

Other attributes for ``vlan`` are:

device
======

The ``name`` of an existing interface entry, which will typically be of
``type: interface``, ``type: ovs_bond``, or ``type: linux_bond``. Usually
``device`` is only used when the VLAN is not part of an ``ovs_bridge``. A
VLAN on an ``ovs_bridge`` is part of the ``members`` list for the bridge,
where a Linux VLAN is associated with an ``interface`` or ``linux_bond``
using the ``device`` parameter.

vlan_id
=======

The VLAN ID to tag when passing through the ``device`` interface.

ifcfg implementation
====================

Sets ``VLAN=yes`` and ``PHYSDEV`` to the ``device`` value.

type: linux_bridge
------------------

Configures a `Linux bridge`_. See :ref:`linux-bridge` for an example. All of
the :ref:`common-attributes` can be used with this type. The ``members``
attribute contains a list of entries for interfaces to bridge.

ifcfg implementation
====================

Sets ``TYPE=Bridge`` and ``DELAY=0``. The MAC address of the ``members``
interface which has ``primary: true`` will be used for the ``MACADDR`` value.

type: linux_bond
----------------

Configures a `Linux bond`_. See :ref:`bonds-vlans-dpdk` for an example. All
of the :ref:`common-attributes` can be used with this type. The ``members``
attribute contains a list of entries for interfaces to be bonded.

Extra bonding options are specified in the ``bonding_options`` string.

ifcfg implementation
====================

The MAC address of the ``members`` interface which has ``primary: true`` will
be used for the ``MACADDR`` value. ``BONDING_OPTS`` will contain the value of the
``bonding_options`` attribute.

type: ovs_user_bridge
---------------------

Configures an `Open vSwitch`_ bridge where the members are user ports. This
is generally used to set up `DPDK vHost User Ports`_. See
:ref:`bonds-vlans-dpdk` for an example. All of the :ref:`common-attributes`
and :ref:`ovs-attributes` can be used with this type. The ``members``
attribute usually contains a single ``type: ovs_dpdk_bond`` entry.

ifcfg implementation
====================

Values ``DEVICETYPE=ovs`` and ``TYPE=OVSUserBridge`` are set. When ``use_dhcp``
or ``use_dhcpv6`` is ``true``, ``OVSBOOTPROTO=dhcp`` is set and
``OVSDHCPINTERFACES`` is populated.

Each ``members`` interface also has ``OVS_BRIDGE`` set, as well as other
values depending on the type of the member.

type: ovs_dpdk_bond
-------------------

Configures an `Open vSwitch`_ bond for binding DPDK ports. See
:ref:`bonds-vlans-dpdk` for an example. All of the :ref:`common-attributes`
and :ref:`ovs-attributes` can be used with this type. The ``members``
attribute contains a list of ``type: ovs_dpdk_port`` ports to be bonded. The
value for attribute ``rx_queue`` will determine the RX queue length.

ifcfg implementation
====================

Values ``DEVICETYPE=ovs``, ``TYPE=OVSDPDKBond``, and ``RX_QUEUE`` are set.
``BOND_IFACES`` is populated with the ``name`` of all members. ``OVS_EXTRA``
is extended with a ``set Interface...`` directive for each member.

type: ovs_dpdk_port
-------------------

Creates an Open vSwitch DPDK port, usually in the ``members`` of a ``type:
ovs_dpdk_bond`` bond interface. See :ref:`bonds-vlans-dpdk` for an example.
All of the :ref:`common-attributes` and :ref:`ovs-attributes` can be used
with this type. Each port must have a ``members`` list with a single
interface entry. A port can have its own ``rx_queue`` specifed. The
``driver`` attribute can override the default kernel driver module of
``vfio-pci``.

ifcfg implementation
====================

Values ``DEVICETYPE=ovs`` and ``TYPE=OVSDPDKPort``, and ``RX_QUEUE`` are set.
``OVS_EXTRA`` is extended with a ``set Interface...`` directive for the one
``members`` interface.

.. 
    Undocumented types:
    route_table
    route_rule
    team
    ivs_bridge
    ivs_interface
    nfvswitch_bridge
    nfvswitch_internal
    ovs_tunnel
    ovs_patch_port
    ib_interface
    ib_child_interface
    vpp_interface
    vpp_bond
    contrail_vrouter
    contrail_vrouter_dpdk
    sriov_pf
    sriov_vf
    linux_tap

.. _NetworkManager: https://en.wikipedia.org/wiki/NetworkManager
.. _ethtool: https://en.wikipedia.org/wiki/Ethtool
.. _Open vSwitch: https://www.openvswitch.org/
.. _Linux bridge: https://wiki.linuxfoundation.org/networking/bridge
.. _Linux bond: https://wiki.linuxfoundation.org/networking/bonding
.. _DPDK vHost User Ports: https://docs.openvswitch.org/en/latest/topics/dpdk/vhost-user/
