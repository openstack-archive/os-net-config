======================
Example configurations
======================

.. _multiple-nics:

Multiple NICs
-------------

  .. code-block:: yaml
  
    network_config:
    - type: interface
      name: nic1
      mtu: 1500
      dns_servers: 8.8.8.8
      domain: example.com
      routes:
      - default: true
        next_hop: 198.51.100.1
      - ip_netmask: 192.0.2.2/24
        next_hop: 203.0.113.254
      use_dhcp: false
      addresses:
      - ip_netmask: 198.18.100.0/15
    - type: interface
      name: nic2
      use_dhcp: true
    - type: interface
      name: nic3
      use_dhcp: false # do not configure this interface

.. _control-plane-bridge:

Control plane bridge
--------------------

  .. code-block:: yaml

    network_config:
    - type: ovs_bridge
      name: br-ctlplane
      use_dhcp: false
      ovs_extra:
      - br-set-external-id br-ctlplane bridge-id br-ctlplane
      addresses:
      - ip_netmask: 192.0.2.2/24
      - ip_netmask: 198.51.100.2/24
      - ip_netmask: 203.0.113.2/24
      dns_servers: 8.8.8.8
      domain: example.com
      members:
        - type: interface
          name: nic1
          primary: true
          mtu: 1450

.. _ovs-bond:

OVS bond
--------

  .. code-block:: yaml

    network_config:
    - type: ovs_bridge
      name: br-ex
      use_dhcp: true
      dns_servers: 8.8.8.8
      domain: example.com
      members:
      - type: ovs_bond
        name: bond1
        use_dhcp: true
        ovs_options: bond_mode=balance-slb
        members:
        - type: interface
          name: nic1
        - type: interface
          name: nic2

.. _bonds-with-vlans:

Bonds with VLANs and jumbo frames
---------------------------------

  .. code-block:: yaml

    network_config:
    - type: interface
      name: nic1
    - type: ovs_bridge
      name: br-bond
      dns_servers: 8.8.8.8
      domain: example.com
      members:
      - type: ovs_bond
        name: bond1
        mtu: 9000
        ovs_options: bond_mode=balance-tcp lacp=active other-config:lacp-fallback-ab=true
        members:
        - type: interface
          name: nic2
          mtu: 9000
          primary: true
        - type: interface
          name: nic3
          mtu: 9000
      - type: vlan
        device: bond1
        mtu: 9000
        vlan_id: 10
        addresses:
        - ip_netmask: 198.51.200.2/24
      - type: vlan
        device: bond1
        mtu: 9000
        vlan_id: 20
        addresses:
        - ip_netmask: 198.51.100.2/24

.. _linux-bridge:

Linux bridge
------------

  .. code-block:: yaml

    network_config:
    - type: linux_bridge
      name: br-ex
      addresses:
      - ip_netmask: 192.0.2.2/24
      dns_servers: 8.8.8.8
      domain: example.com
      members:
      - type: interface
        name: nic1
        # force the MAC address of the bridge to this interface
        primary: true
      routes:
      - ip_netmask: 0.0.0.0/0
        next_hop: 10.0.0.1
        default: true

.. _bonds-vlans-dpdk:

Linux bonds, VLANs, and DPDK
----------------------------

  .. code-block:: yaml
  
    network_config:
    - type: interface
      name: nic1
      mtu: 1500
      use_dhcp: false
      addresses:
      - ip_netmask: 192.0.2.2/24
      routes:
      - ip_netmask: 0.0.0.0/0
        next_hop: 10.0.0.1
        default: true
    - type: linux_bond
      name: bond_api
      mtu: 1500
      use_dhcp: false
      dns_servers: 8.8.8.8
      members:
      - type: interface
        name: nic2
        mtu: 1500
        primary: true
      - type: interface
        name: nic3
        mtu: 1500
    - type: vlan
      device: bond_api
      mtu: 1500
      vlan_id: 10
      addresses:
      - ip_netmask: 198.51.200.2/24
    - type: vlan
      device: bond_api
      mtu: 1500
      vlan_id: 20
      addresses:
      - ip_netmask: 198.51.100.2/24
    # Used as a provider network with external DHCP #
    - type: ovs_user_bridge
      name: br-dpdk0
      members:
      - type: ovs_dpdk_bond
        name: dpdkbond0
        rx_queue: 1
        members:
        - type: ovs_dpdk_port
          name: dpdk0
          members:
          - type: interface
            name: nic4
        - type: ovs_dpdk_port
          name: dpdk1
          members:
          - type: interface
            name: nic5