# IPA platform abstraction

The ``ipaplatform`` package provides an abstraction layer for
supported Linux distributions and flavors. The package contains
constants, paths to commands and config files, services, and tasks.

* **base** abstract base platform
* **debian** Debian- and Ubuntu-like
* **redhat** abstract base for Red Hat platforms
* **fedora** Fedora
* **fedora_container** freeipa-container on Fedora
* **rhel** RHEL and CentOS
* **rhel_container** freeipa-container on RHEL and CentOS
* **suse** OpenSUSE and SLES

```
[base]
  ├─ debian
  ├─[redhat]
  │   ├─ fedora
  │   │   └─ fedora_container
  │   └─ rhel
  │       └─ rhel_container
  └─ suse
```
(Note: Debian and SUSE use some definitions from Red Hat namespace.)


## freeipa-container platform

The **fedora_container** and **rhel_container** platforms are flavors
of the **fedora** and **rhel** platforms. These platform definitions
are specifically designed for
[freeipa-container](https://github.com/freeipa/freeipa-container).
The FreeIPA server container implements a read-only container. Paths
like ``/etc``, ``/usr``, and ``/var`` are mounted read-only and cannot
be modified. The image uses symlinks to store all variable data like
config files and LDAP database in ``/data``.

* Some commands don't write through dangling symlinks. The IPA
  platforms for containers prefix some paths with ``/data``.
* ``ipa-server-upgrade`` verifies that the platform does not change
  between versions. To allow upgrades of old containers, sysupgrade
  maps ``$distro_container`` to ``$distro`` platform.
* The container images come with authselect pre-configured with
  ``sssd with-sudo`` option. The tasks ``modify_nsswitch_pam_stack``
  and ``migrate_auth_configuration`` are no-ops. ``ipa-restore``
  does not restore authselect settings. ``ipa-backup`` still stores
  authselect settings in backup data.
* The ``--mkhomedir`` option is not supported.
