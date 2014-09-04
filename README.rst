===============================
os-net-config
===============================

host network configuration tool

An implementation of the 'network configuration' spec @
https://review.openstack.org/#/c/97859/.
The intention is for this code to be moved under the tripleo project in due course.

* Free software: Apache license
* Documentation: http://docs.openstack.org/developer/os-net-config
* Source: http://git.openstack.org/cgit/openstack/os-net-config
* Bugs: http://bugs.launchpad.net/os-net-config

Features
--------

The core aim of this project is to allow fine grained (but extendable)
configuration of the networking parameters for a network host. The
project consists of:

 * A CLI (os-net-config) which provides configuration via a YAML or JSON
   file formats.  By default os-net-config uses a YAML config file located
   at /etc/os-net-config/config.yaml. This can be customized via the
   --config-file CLI option.

 * A python library which provides configuration via an object model.

YAML Config Examples
--------------------
 * Configure an OVS bridge with a single attached interface (port)

.. code-block:: yaml

  network_config:
    - 
      type: ovs_bridge
      name: br-ctlplane
      use_dhcp: true
      ovs_extra:
        - br-set-external-id br-ctlplane bridge-id br-ctlplane
      members:
        - 
          type: interface
          name: em1

..


 * Configure an OVS bridge on top of an OVS bond

.. code-block:: yaml

  network_config:
    - 
       type: ovs_bridge
       name: br-ctlplane
       use_dhcp: true
       members:
         - 
           type: ovs_bond
           name: bond1
           members:
             - 
               type: interface
               name: em1
             - 
               type: interface
               name: em2

..

 * Configure a tagged VLAN interface on top of an OVS bridge

.. code-block:: yaml

  network_config:
    - 
      type: ovs_bridge
      name: br-ctlplane
      use_dhcp: true
      members:
        - 
          type: interface
          name: em1
        - 
          type: vlan
          vlan_id: 16
          addresses:
            - 
              ip_netmask: 192.0.2.1/24

..

Provider Configuration
----------------------
Providers are use to apply (implement) the desired configuration on the
host system. By default 3 providers are implemented:

 * Ifcfg: persistent network config format stored in
   /etc/sysconfig/network-scripts

 * ENI: persistent network config format stored in /etc/network/interfaces

 * iproute2: non-persistent provider which implements the config using
   iproute2, vconfig, etc... (implementation in progress)

When using bin/os-net-config the provider is automatically selected based on
the host systems perferred persistent network type (ifcfg or ENI). This can
be customized via the --provider CLI option.
