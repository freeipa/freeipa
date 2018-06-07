..
  Copyright 2015, 2016  Red Hat, Inc.

  This work is licensed under the Creative Commons Attribution 4.0
  International License. To view a copy of this license, visit
  http://creativecommons.org/licenses/by/4.0/.


Introduction
============

FreeIPA_ is a centralised identity management system.  In this
workshop you will learn how to deploy FreeIPA servers and enrol
client machines, define and manage user and service identities, set
up access policies, configure network services to take advantage of
FreeIPA's authentication and authorisation facilities and issue
X.509 certificates for services.

.. _FreeIPA: http://www.freeipa.org/page/Main_Page


Curriculum overview
-------------------

- `Unit 1: Installing the FreeIPA server`_
- `Unit 2: Enrolling client machines`_
- `Unit 3: User management and Kerberos authentication`_
- `Unit 4: Host-based access control (HBAC)`_
- `Unit 5: Web application authentication and authorisation`_
- `Unit 6: Certificate management`_
- `Unit 7: Replica installation`_
- `Unit 8: Sudo rule management`_
- `Unit 9: SELinux User Maps`_
- `Unit 10: SSH user and host key management`_

.. _Unit 1\: Installing the FreeIPA server: 1-server-install.rst
.. _Unit 2\: Enrolling client machines: 2-client-install.rst
.. _Unit 3\: User management and Kerberos authentication: 3-user-management.rst
.. _Unit 4\: Host-based access control (HBAC): 4-hbac.rst
.. _Unit 5\: Web application authentication and authorisation: 5-web-app-authnz.rst
.. _Unit 6\: Certificate management: 6-cert-management.rst
.. _Unit 7\: Replica installation: 7-replica-install.rst
.. _Unit 8\: Sudo rule management: 8-sudorule.rst
.. _Unit 9\: SELinux User Maps: 9-selinux-user-map.rst
.. _Unit 10\: SSH user and host key management: 10-ssh-key-management.rst


Editing files on VMs
--------------------

Parts of the workshop involve editing files on virtual
machines.  The ``vi`` and GNU ``nano`` editors are available on the
VMs.  If you are not familiar with ``vi`` or you are unsure of what to use, you
should choose ``nano``.


Example commands
----------------

This guide contains many examples of commands.  Some of the commands
should be executed on your host, others on a particular guest VM.
For clarity, commands are annotated with the host on which they are
meant to be executed, as in these examples::

  $ echo "Run it on virtualisation host (no annotation)"

  [server]$ echo "Run it on FreeIPA server"

  [client]$ echo "Run it on IPA-enrolled client"

  ...


Preparation
===========

Some preparation is needed prior to the workshop.  The workshop is
designed to be carried out in a Vagrant_ environment that configures
three virtual machines with all software network configuration ready
for the workshop.

several VMs.  **The goal of the preparation** is to be able to
successfully ``vagrant up`` the VMs as the first step of the
workshop.

.. _Vagrant: https://www.vagrantup.com/


Requirements
------------

For the FreeIPA workshop you will need to:

- Install **Vagrant** and **VirtualBox**. (On Fedora, you can use **libvirt**
  instead of VirtualBox).

- Use Git to clone the repository containing the ``Vagrantfile``

- Fetch the Vagrant *box* for the workshop

- Add entries for the guest VMs to your hosts file (so you can
  access them by their hostname)

Please set up these items **prior to the workshop**.  More detailed
instructions follow.


Install Vagrant and VirtualBox
------------------------------

Fedora
^^^^^^

If you intend to use the ``libvirt`` provider (recommended), install
``vagrant-libvirt`` and ``vagrant-libvirt-doc``::

  $ sudo dnf install -y vagrant-libvirt vagrant-libvirt-doc

Also ensure you have the latest versions of ``selinux-policy`` and
``selinux-policy-targeted``.

Allow your regular user ID to start and stop Vagrant boxes using ``libvirt``.
Add your user to ``libvirt`` group so you don't need to enter your administrator
password everytime::

  $ sudo gpasswd -a ${USER} libvirt
  $ newgrp libvirt

On **Fedoda 28** you need to enable ``virtlogd``::

  $ systemctl enable virtlogd.socket
  $ systemctl start virtlogd.socket

Finally restart the services::

  $ systemctl restart libvirtd
  $ systemctl restart polkit

Otherwise, you will use VirtualBox and the ``virtualbox`` provider.
VirtualBox needs to build kernel modules, and that means that you must
first install kernel headers and Dynamic Kernel Module Support::

  $ sudo dnf install -y vagrant kernel-devel dkms

Next, install VirtualBox from the official VirtualBox package repository.
Before using the repo, check that its contents match what appears
in the transcript below (to make sure it wasn't tampered with)::

  $ sudo curl -o /etc/yum.repos.d/virtualbox.repo \
    http://download.virtualbox.org/virtualbox/rpm/fedora/virtualbox.repo

  $ cat /etc/yum.repos.d/virtualbox.repo
  [virtualbox]
  name=Fedora $releasever - $basearch - VirtualBox
  baseurl=http://download.virtualbox.org/virtualbox/rpm/fedora/$releasever/$basearch
  enabled=1
  gpgcheck=1
  repo_gpgcheck=1
  gpgkey=https://www.virtualbox.org/download/oracle_vbox.asc

  $ sudo dnf install -y VirtualBox-5.2

Finally, load the kernel modules (you may need to restart your system for this to work)::

  $ sudo modprobe vboxdrv vboxnetadp


Mac OS X
^^^^^^^^

Install Vagrant for Mac OS X from
https://www.vagrantup.com/downloads.html.

Install VirtualBox 5.2 for **OS X hosts** from
https://www.virtualbox.org/wiki/Downloads.

Install Git from https://git-scm.com/download/mac or via your
preferred package manager.


Debian / Ubuntu
^^^^^^^^^^^^^^^

Install Vagrant and Git::

  $ sudo apt-get install -y vagrant git

**Virtualbox 5.2** may be available from the system package manager,
depending your your release.  Find out which version of VirtualBox is
available::

  $ apt list virtualbox
  Listing... done
  virtualbox/bionic 5.2.10-dfsg-6 amd64

If version 5.2 is available, install it via ``apt-get``::

  $ sudo apt-get install -y virtualbox

If VirtualBox 5.2 was not available in the official packages for
your release, follow the instructions at
https://www.virtualbox.org/wiki/Linux_Downloads to install it.


Windows
^^^^^^^

Install Vagrant via the ``.msi`` available from
https://www.vagrantup.com/downloads.html.

Install VirtualBox 5.2 for **Windows hosts** from
https://www.virtualbox.org/wiki/Downloads.

You will also need to install an SSH client, and Git.  Git for
Windows also comes with an SSH client so just install Git from
https://git-scm.com/download/win.


Clone this repository
---------------------

This repository contains the ``Vagrantfile`` that is used for the
workshop, which you will need locally.

::

  $ git clone https://github.com/freeipa/freeipa-workshop.git


Fetch Vagrant box
-----------------

Please fetch the Vagrant box prior to the workshop.  It is > 600MB
so it may not be feasible to download it during the workshop.

::

  $ vagrant box add netoarmando/freeipa-workshop


Add hosts file entries
----------------------

*This step is necessary if you want to access the FreeIPA Web UI in
the VM from a browser on your host, but otherwise this step is optional. All
workshop units can be completed using the CLI.*

Add the following entries to your hosts file::

  192.168.33.10   server.ipademo.local
  192.168.33.11   replica.ipademo.local
  192.168.33.20   client.ipademo.local

On Unix systems (including Mac OS X), the hosts file is ``/etc/hosts``
(you need elevated permissions to edit it.)

On Windows, edit ``C:\Windows\System32\system\drivers\etc\hosts`` as
*Administrator*.
