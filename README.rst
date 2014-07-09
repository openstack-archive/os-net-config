===============================
os-net-config
===============================

host network configuration tool

This is an initial implementation towards the 'network configuration' spec @
https://review.openstack.org/#/c/97859/ The intention is for this code to be
moved under the tripleo project in due course.

* Free software: Apache license
* Documentation: http://docs.openstack.org/developer/os-net-config
* Source: http://git.openstack.org/cgit/openstack/os-net-config
* Bugs: http://bugs.launchpad.net/os-net-config

Features
--------

The core aim of this project is to allow fine grained (but extendable)
configuration of the networking parameters for a network host. The
project consists of:

 * A python library which provides configuration via an object model.

 * A CLI (os-net-config) which provides configuration via a JSON file format.
   By default os-net-config uses a JSON config file located at
   /etc/os-net-config/config.json. This can be customized via the
   --config-file CLI option.

JSON Config Examples
--------------------
 * Configure an OVS bridge with a single attached interface (port)

.. code-block:: json

 { "network_config": [
         {
             "type": "ovs_bridge",
             "name": "br-ctlplane",
             "use_dhcp": "true",
             "members": [
                 {
                     "type": "interface",
                     "name": "em1"
                 }
             ]
         }
     ]
 }

..


 * Configure an OVS bridge on top of an OVS bond

.. code-block:: json

 { "network_config": [
         {
             "type": "ovs_bridge",
             "name": "br-ctlplane",
             "use_dhcp": "true",
             "members": [
                 {
                     "type": "ovs_bond",
                     "name": "bond1",
                     "use_dhcp": "true",
                     "members": [
                         { "type": "interface", "name": "em1" },
                         { "type": "interface", "name": "em2" }
                     ]
                 }
             ]
         }
     ]
 }

..

 * Configure a tagged VLAN interface on top of an OVS bridge

.. code-block:: json

 { "network_config": [
         {
             "type": "ovs_bridge",
             "name": "br-ctlplane",
             "members": [
                 {
                     "type": "vlan",
                     "device": "em1",
                     "vlan_id": "16",
                     "addresses": [{
                         "ip_netmask": "192.0.2.1/24"
                     }],
                     "routes": [{
                         "next_hop": "192.0.2.1",
                         "ip_netmask": "192.0.2.1/24"
                     }]
                 }
             ]
         }
     ]
 }

..

Provider Configuration
----------------------
Providers are use to apply (implement) the desired configuration on the
host system. By default 3 providers are implemented:

 * Ifcfg: persistent network config format stored in
   /etc/sysconfig/network-scripts

 * ENI: persistent network config format stored in /etc/network/interfaces

 * iproute2: non-persistent provider which implements the config using
   iproute2, vconfig, etc...

When using bin/os-net-config the provider is automatically selected based on
the host systems perferred persistent network type (ifcfg or ENI). This can
be customized via the --provider CLI option.
