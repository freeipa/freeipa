Unit 2: Enrolling client machines
===================================

**Prerequisites**:

- `Unit 1: Installing the FreeIPA server <1-server-install.rst>`_

In this unit, you will enrol a *host* as a client of your FreeIPA
domain.  This means that *users* in your FreeIPA realm (or Active
Directory realms for which there is a trust with FreeIPA) can log
into the client machine (subject to access policies) and that *services*
on the client can leverage FreeIPA's authentication and
authorisation services.

From the directory that contains the ``Vagrantfile``, SSH into the
``client`` machine::

  $ vagrant ssh client


On ``client``, start the FreeIPA client enrolment program::

  [client]$ sudo ipa-client-install --mkhomedir

The FreeIPA server should be detected through DNS autodiscovery.
(If DNS discovery fails, e.g. due to client machine having incorrect
``/etc/resolv.conf`` configuration, you would be prompted to
manually enter the domain and server hostname instead).

The autodetected server settings will be displayed; confirm to
proceed::

  [client]$ sudo ipa-client-install --mkhomedir
  Discovery was successful!
  Client hostname: client.ipademo.local
  Realm: IPADEMO.LOCAL
  DNS Domain: ipademo.local
  IPA Server: server.ipademo.local
  BaseDN: dc=ipademo,dc=local

  Continue to configure the system with these values? [no]: yes

Next, the client's time will be synchronised with the server, then
the installer will prompt you to enter the credentials of a user
authorised to enrol hosts (``admin``)::

  User authorized to enroll computers: admin
  Password for admin@IPADEMO.LOCAL:

The enrolment now proceeds; no further input is required.  You will
see output detailing the operations being completed.  Client
enrolment only takes a few seconds.

Users in your FreeIPA domain can now log into FreeIPA-enrolled
hosts, subject to *Host-based access control* (HBAC) rules.  Users
logged onto the host can also acquire Kerberos tickets for accessing
*services* in your domain.

You can now move on to
`Unit 3: User management and Kerberos authentication <3-user-management.rst>`_.
