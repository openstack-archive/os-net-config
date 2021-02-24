=============
os-net-config
=============

Team and repository tags
------------------------

.. image:: https://governance.openstack.org/tc/badges/os-net-config.svg
    :target: https://governance.openstack.org/tc/reference/tags/index.html

Overview
--------

``os-net-config`` is a host network configuration tool which supports multiple
backend configuration providers.

* Documentation: https://docs.openstack.org/os-net-config/latest
* Source: https://opendev.org/openstack/os-net-config
* Bugs: https://bugs.launchpad.net/os-net-config
* Release Notes: https://docs.openstack.org/releasenotes/os-net-config
* Free software: Apache License (2.0)


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