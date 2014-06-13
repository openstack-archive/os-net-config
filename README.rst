===============================
os-net-config
===============================

OpenStack network configuration

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
configuration of the networking parameters for a network host. At present
this host configuration is performed by the ensure-bridge and init-neutron-ovs
tripleo element scripts. More details are available in the specification
linked to above.
