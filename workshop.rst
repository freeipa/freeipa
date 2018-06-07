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


Unit 1: Installing the FreeIPA server
=======================================

In this unit you will install a FreeIPA server.  All tasks in
subsequent units require the services and data provided by the
server.

First, in the directory containing the ``Vagrantfile`` (the clone of
this repository), execute ``vagrant up`` to bring up the Vagrant
environment.  (If you are using the VirtualBox provider on a platform
where that is not the default, e.g. Fedora, you will also need the
``--provider virtualbox`` option).

::

  $ vagrant up --provider virtualbox

The Vagrant environment contains three hosts:

- ``server.ipademo.local``
- ``replica.ipademo.local``
- ``client.ipademo.local``

From the directory containing the ``Vagrantfile``, SSH into the
``server`` machine::

  $ vagrant ssh server


On ``server``, start the FreeIPA server installation program::

  [server]$ sudo ipa-server-install --no-host-dns --mkhomedir

The ``--no-host-dns`` argument is needed because there are no reverse
DNS records for the Vagrant environment.  For production deployment,
this important sanity check should not be skipped. The ``--mkhomedir``
flag configure PAM to create missing home directories when users log
into the host for the first time. FreeIPA supports automount so
consider using that for production deployments.

You will be asked a series of questions. Accept the defaults for most
of the questions, except as outlined below.

Configure FreeIPA's DNS server::

  Do you want to configure integrated DNS (BIND)? [no]: yes


Accept default values for the server hostname, domain name and realm::

  Enter the fully qualified domain name of the computer
  on which you're setting up server software. Using the form
  <hostname>.<domainname>
  Example: master.example.com.


  Server host name [server.ipademo.local]:

  Warning: skipping DNS resolution of host server.ipademo.local
  The domain name has been determined based on the host name.

  Please confirm the domain name [ipademo.local]:

  The kerberos protocol requires a Realm name to be defined.
  This is typically the domain name converted to uppercase.

  Please provide a realm name [IPADEMO.LOCAL]:


Enter passwords for *Directory Manager* (used to manage the
directory server) and *admin* (the main account used for FreeIPA
administration).  Use something simple that you're not going to
forget during the workshop!

::

  Certain directory server operations require an administrative user.
  This user is referred to as the Directory Manager and has full access
  to the Directory for system management tasks and will be added to the
  instance of directory server created for IPA.
  The password must be at least 8 characters long.

  Directory Manager password:
  Password (confirm):

  The IPA server requires an administrative user, named 'admin'.
  This user is a regular system account used for IPA server administration.

  IPA admin password:
  Password (confirm):


Do not configure a DNS forwarder (you will want to configure a DNS
forwarder for a real-world deployment but it is not needed for this
workshop) and accept the defaults for configuring the reverse zone::

  Checking DNS domain ipademo.local., please wait ...
  Do you want to configure DNS forwarders? [yes]: no
  No DNS forwarders configured
  Do you want to search for missing reverse zones? [yes]:


Next, you will be presented with a summary of the server
configuration and asked for final confirmation.  Give confirmation to begin the
server installation::

  The IPA Master Server will be configured with:
  Hostname:       server.ipademo.local
  IP address(es): 192.168.33.10
  Domain name:    ipademo.local
  Realm name:     IPADEMO.LOCAL

  BIND DNS server will be configured to serve IPA domain with:
  Forwarders:       No forwarders
  Forward policy:   only
  Reverse zone(s):  No reverse zone

  Continue to configure the system with these values? [no]: yes

The installation takes a few minutes; you will see output indicating
the progress.

When it completes, run ``kinit admin`` and enter your *admin*
password to obtain a Kerberos ticket granting ticket (TGT) for the
``admin`` user::

  [server]$ kinit admin
  Password for admin@IPADEMO.LOCAL:  <enter password>

Run ``klist`` to view your current Kerberos tickets::

  [server]$ klist
  Ticket cache: KEYRING:persistent:1000:1000
  Default principal: admin@IPADEMO.LOCAL

  Valid starting     Expires            Service principal
  10/15/15 01:48:59  10/16/15 01:48:57  krbtgt/IPADEMO.LOCAL@IPADEMO.LOCAL

The FreeIPA server is now set up and you are ready to begin
enrolling client machines, creating users, managing services, and
more!

To prepare for the next unit, exit the ``server`` SSH session (but
do not shut the VM down).


Unit 2: Enrolling client machines
===================================

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

You might see a warning about time synchronisation, which for this
workshop can be ignored.  Next you will be be prompted to enter
credentials of a user authorised to enrol hosts (``admin``)::

  User authorized to enroll computers: admin
  Password for admin@IPADEMO.LOCAL:

The enrolment now proceeds; no further input is required.  You will
see output detailing the operations being completed.  Unlike
``ipa-server-install``, client enrolment only takes a few seconds.

Users in your FreeIPA domain can now log into FreeIPA-enrolled
hosts, subject to *Host-based access control* (HBAC) rules.  Users
logged onto the host can also acquire Kerberos tickets for accessing
*services* in your domain.


Unit 3: User management and Kerberos authentication
=====================================================

This unit introduces the ``ipa`` CLI program and the web
interface.  We will perform some simple administrative tasks: adding
groups and users and managing group membership.

Web UI
------

Visit ``https://server.ipademo.local/``.  You'll get a TLS
*untrusted issuer* warning which you can dismiss (by adding a temporary
exception).  Log in as ``admin``.

Welcome to the FreeIPA Web UI.  Most management activities can be
performed here, or via the ``ipa`` CLI program.  Use the Web UI to
perform the following actions:

1. Add a *User* with the username ``alice``.
2. Add a *User Group* for system administrators named ``sysadmin``.
3. Add ``alice`` to the ``sysadmin`` group.


CLI
---

Make sure you have a Kerberos ticket for ``admin`` (reminder:
``kinit admin``).

Most FreeIPA adminstrative actions can be carried out using the
``ipa`` CLI program.  Let's see what commands are available::

  [server]% ipa help commands
  automember-add                    Add an automember rule.
  automember-add-condition          Add conditions to an automember rule.
  automember-default-group-remove   Remove default (fallback) group for all unmatched entries.
  automember-default-group-set      Set default (fallback) group for all unmatched entries.
  automember-default-group-show     Display information about the default (fallback) automember groups.
  ...

Whoa!  There are nearly 400 commands!  We'll be using only a handful
of these today.  Note that command completion is enabled in the
shell, so you can type a partial command and press ``<TAB>`` a
couple of times to see what commands are available, e.g. all the
commands starting with ``cert-``::

  [server]$ ipa cert-<TAB>
  cert-find         cert-request      cert-show
  cert-remove-hold  cert-revoke       cert-status


You'll notice that commands are grouped by *plugin*.  You can read a
general overview of a plugin by running ``ipa help <plugin>``, and
specific information on a particular command by running ``ipa help
<command>``.

Add a user named ``bob`` from the CLI.  See if you can work out how
to do this using the CLI help commands.  (**hint**: the ``user``
plugin provides the command).


User authentication
-------------------

We have seen how to authenticate as ``admin``.  The process is the
same for regular users - just ``kinit <username>``!

Try to authenticate as ``bob``::

  [server]$ kinit bob
  kinit: Pre-authentication failed: Invalid argument while getting initial credentials

If you did *not* encounter this error, congratulations - you must be
a disciplined reader of documentation!  To set an initial password
when creating a user via the ``ipa user-add`` command you must
supply the ``--password`` flag (the command will prompt for the
password).

Use the ``ipa passwd`` command to (re)set a user's password::

  [server]$ ipa passwd bob
  New Password:
  Enter New Password again to verify:
  ----------------------------------------
  Changed password for "bob@IPADEMO.LOCAL"
  ----------------------------------------

Whenever a user has their password reset (including the first time
it is set), the next ``kinit`` will prompt them to enter a new
password::

  [server]$ kinit bob
  Password for bob@IPADEMO.LOCAL:
  Password expired.  You must change it now.
  Enter new password:
  Enter it again:


Now ``bob`` has a TGT (run ``klist`` to confirm) which he can use to
authenticate himself to other hosts and services.  Try logging into
``client.ipademo.local``::

  [server]$ ssh bob@client.ipademo.local
  Creating home directory for bob.
  [bob@client]$

You are now logged into the client as ``bob``.  Type ``^D`` or
``exit`` to log out and return to the ``server`` shell.  If you run
``klist`` again, you will see not only the TGT but a *service ticket*
that was automatically acquired to log in to
``client.ipademo.local`` without prompting for a password.  Kerberos
is a true *single sign-on* protocol!

::

  [server]$ klist
  Ticket cache: KEYRING:persistent:1000:1000
  Default principal: admin@IPADEMO.LOCAL

  Valid starting       Expires              Service principal
  06/04/2018 21:45:50  06/05/2018 21:38:24  host/client.ipademo.local@IPADEMO.LOCAL
  06/04/2018 21:38:41  06/05/2018 21:38:24  krbtgt/IPADEMO.LOCAL@IPADEMO.LOCAL


Unit 4: Host-based access control (HBAC)
==========================================

FreeIPA's *host-based access control* (HBAC) feature allows you to
define policies that restrict access to hosts or services based on
the user attempting to log in and that user's groups, the host that
they are trying to access (or its *Host Groups*), and (optionally)
the service being accessed.

In this unit, we will define an HBAC policy that restricts
access to ``client.ipademo.local`` to members of the
``sysadmin`` user group.


Adding a host group
-------------------

Instead of defining the HBAC rule to directly talk about
``client.ipademo.local``, create a *Host Group* named ``webservers``
and add ``client.ipademo.local`` to it.  You can do this via the Web
UI or the ``ipa`` CLI program (don't forget to ``kinit admin``; see
if you can work out what plugin provides the host group
functionality).

**Hint:** if you use the CLI will need to run two commands - one to
create the host group, and one to add ``client.ipademo.local`` as a
member of the host group.


Disabling the ``allow_all`` HBAC rule
-------------------------------------

HBAC rules are managed via the ``hbacrule`` plugin.  You can
complete the following actions via the Web UI as well, but we will
cover the CLI commands.

List the existing HBAC rules::

  [server]$ ipa hbacrule-find
  -------------------
  1 HBAC rule matched
  -------------------
    Rule name: allow_all
    User category: all
    Host category: all
    Service category: all
    Description: Allow all users to access any host from any host
    Enabled: TRUE
  ----------------------------
  Number of entries returned 1
  ----------------------------

The FreeIPA server is installed with a single default ``allow_all``
rule.  This rule must be disabled for other HBAC rules to take
effect.  Look for a command that can do this, and run it.


Creating HBAC rules
-------------------

HBAC rules are built up incrementally.  The rule is created, then
users or groups, hosts or hostsgroups and HBAC services are added to
the rule.  The following transcript details the process::

  [server]$ ipa hbacrule-add sysadmin_webservers
  -------------------------------------
  Added HBAC rule "sysadmin_webservers"
  -------------------------------------
    Rule name: sysadmin_webservers
    Enabled: TRUE

  [server]$ ipa hbacrule-add-host sysadmin_webservers --hostgroup webservers
    Rule name: sysadmin_webservers
    Enabled: TRUE
    Host Groups: webservers
  -------------------------
  Number of members added 1
  -------------------------

  [server]$ ipa hbacrule-add-user sysadmin_webservers --group sysadmin
    Rule name: sysadmin_webservers
    Enabled: TRUE
    User Groups: sysadmin
    Host Groups: webservers
  -------------------------
  Number of members added 1
  -------------------------

  [server]$ ipa hbacrule-mod sysadmin_webservers --servicecat=all
  ----------------------------------------
  Modified HBAC rule "sysadmin_webservers"
  ----------------------------------------
    Rule name: sysadmin_webservers
    Service category: all
    Enabled: TRUE
    User Groups: sysadmin
    Host Groups: webservers

The ``--servicecat=all`` option applies this rule for all services on
matching hosts.  It could have been set during the ``hbacrule-add``
command instead.


Testing HBAC rules
------------------

You can test HBAC rule evaluation using the ``ipa hbactest``
command::

  [server]$ ipa hbactest --host client.ipademo.local --service sshd --user bob
  ---------------------
  Access granted: False
  ---------------------
    Not matched rules: sysadmin_webservers

Poor ``bob``.  He won't be allowed in because he is not a member of
the ``sysadmin`` group.  What about ``alice``?

``kinit`` as ``bob`` and try to log in to the client::

  [server]$ kinit bob
  Password for bob@IPADEMO.LOCAL:
  [server]$ ssh bob@client.ipademo.local
  Connection closed by UNKNOWN port 65535

Then try ``alice``::

  [server]$ kinit alice
  Password for alice@IPADEMO.LOCAL:
  [server]$ ssh alice@client.ipademo.local
  Creating home directory for alice.
  [alice@client]$


Unit 5: Web application authentication and authorisation
==========================================================

You can configure many kinds of applications to rely on FreeIPA's
centralised authentication, including web applications.  In this
unit you will configure the Apache web server to use Kerberos
authentication to authenticate users, PAM to enforce HBAC rules, and
``mod_lookup_identity`` to populate the request environment with
user attributes.

All activities in this unit take place on ``client`` unless
otherwise specified.

The demo web application is trivial.  It just reads its request
environment and responds in plain text with a list of variables
starting with the string ``"REMOTE_"``.  It should be up and running
already::

  [client]$ curl http://client.ipademo.local
  NOT LOGGED IN

  REMOTE_* REQUEST VARIABLES:

    REMOTE_ADDR: 192.168.33.20
    REMOTE_PORT: 34356


Create a service
----------------

Create a *service* representing the web application on
``client.ipademo.local``.  A service principal name has the service
type as its first part, separated from the host name by a slash,
e.g.  ``HTTP/www.example.com``.  The host part must correspond to an
existing host in the directory.

You must be getting the hang of FreeIPA by now, so I'll leave the
rest of this step up to you.  (It's OK to ask for help!)


Retrieve Kerberos keytab
------------------------

The service needs access to its Kerberos key in order to
authenticate users.  Retrieve the key from the FreeIPA server and
store it in a *keytab* file (you will need a TGT for ``admin``)::

  [client]$ ipa-getkeytab -s server.ipademo.local \
            -p HTTP/client.ipademo.local -k app.keytab
  Keytab successfully retrieved and stored in: app.keytab

We also have to move the file, change its ownership and apply the
proper SELinux labels to the keytab file so that the Apache process
which runs under the confined ``apache`` user may read it::

  [client]$ sudo mv app.keytab /etc/httpd
  [client]$ sudo chown apache:apache /etc/httpd/app.keytab
  [client]$ sudo restorecon /etc/httpd/app.keytab


Enable Kerberos authentication
------------------------------

In this section we will use mod_auth_gssapi_ to enable Kerberos
Negotiate / SPNEGO authentication for a web application.

.. _mod_auth_gssapi: https://github.com/modauthgssapi/mod_auth_gssapi

The Apache configuration for the demo application lives in the file
``/etc/httpd/conf.d/app.conf``.  Update the configuration (use
``sudo vi`` or ``sudo nano``) to enable Kerberos authentication::

  <VirtualHost *:80>
    ServerName client.ipademo.local
    WSGIScriptAlias / /usr/share/httpd/app.py

    <Location />
      AuthType GSSAPI
      AuthName "Kerberos Login"
      GssapiCredStore keytab:/etc/httpd/app.keytab
      Require valid-user
    </Location>

    <Directory /usr/share/httpd>
      <Files "app.py">
        Require all granted
      </Files>
    </Directory>
  </VirtualHost>


When the configuration is in place, restart Apache::

  [client]$ sudo systemctl restart httpd


To test that Kerberos Negotiate authentication is working, ``kinit``
and make a request using ``curl``::

  [client]$ kinit bob
  Password for bob@IPADEMO.LOCAL:

  [client]$ curl -u : --negotiate http://client.ipademo.local/
  LOGGED IN AS: bob@IPADEMO.LOCAL

  REMOTE_* REQUEST VARIABLES:

    REMOTE_ADDR: 192.168.33.20
    REMOTE_USER: bob@IPADEMO.LOCAL
    REMOTE_PORT: 42499

The ``REMOTE_USER`` variable in the request environment indicates
that there is a logged-in user and identifies that user.


Populating request environment with user attributes
----------------------------------------------------

Applications need to know more than just the username of a logged-in
user.  They want to know the user's name, to send mail to their email
address and perhaps to know their group memberships or other
attributes.  In this section, we will use mod_lookup_identity_ to
populate the HTTP request environment with variables providing
information about the authenticated user.

.. _mod_lookup_identity: http://www.adelton.com/apache/mod_lookup_identity/


``mod_lookup_identity`` retrieves user attributes from SSSD (via D-Bus).
Edit ``/etc/sssd/sssd.conf``; enable the SSSD ``ifp`` *InfoPipe*
responder, permit the ``apache`` user to query it, and configure the
attributes that you want to expose.  Add the following configuration to
``sssd.conf``::

  [domain/ipademo.local]
  ...
  ldap_user_extra_attrs = mail, givenname, sn

  [sssd]
  services = nss, sudo, pam, ssh, ifp
  ...

  [ifp]
  allowed_uids = apache, root
  user_attributes = +mail, +givenname, +sn


Restart SSSD::

  [client]$ sudo systemctl restart sssd

If you had not added an email address to your users when you created them, you will need to empty the SSSD cache::

  [client]$ sudo sss_cache -E


You can test the SSSD InfoPipe directly via the ``dbus-send``
utility::

  [client]$ sudo dbus-send --print-reply --system \
      --dest=org.freedesktop.sssd.infopipe /org/freedesktop/sssd/infopipe \
      org.freedesktop.sssd.infopipe.GetUserAttr string:alice array:string:mail
  method return time=1528050430.867333 sender=:1.147 -> destination=:1.150 serial=5 reply_serial=2
     array [
        dict entry(
           string "mail"
           variant             array [
                 string "alice@ipademo.local"
              ]
        )
     ]


Now update the Apache configuration to populate the request
environment.  The ``LookupUserXXX`` directives define the mapping of
user attributes to request environment variables.  Multi-valued
attributes can be expanded into multiple variables, as in the
``LookupUserGroupsIter`` directive.  Do not forget the
``LoadModule`` directive!

::

  LoadModule lookup_identity_module modules/mod_lookup_identity.so

  <VirtualHost *:80>
    ServerName client.ipademo.local
    WSGIScriptAlias / /usr/share/httpd/app.py

    <Location />
      AuthType GSSAPI
      AuthName "Kerberos Login"
      GssapiCredStore keytab:/etc/httpd/app.keytab
      Require valid-user

      LookupUserAttr mail REMOTE_USER_MAIL
      LookupUserAttr givenname REMOTE_USER_FIRSTNAME
      LookupUserAttr sn REMOTE_USER_LASTNAME
      LookupUserGroupsIter REMOTE_USER_GROUP
    </Location>

    ...
  </VirtualHost>

Default SELinux policy prevents Apache from communicating with SSSD
over D-Bus.  Flip ``httpd_dbus_sssd`` to ``1``::

  [client]$ sudo setsebool -P httpd_dbus_sssd 1

Restart Apache::

  [client]$ sudo systemctl restart httpd

Now make another request to the application and observe that user
information that was injected into the request environment by
``mod_lookup_identity`` is reflected in the response::

  [client]$ curl -u : --negotiate http://client.ipademo.local/
  LOGGED IN AS: alice@IPADEMO.LOCAL

  REMOTE_* REQUEST VARIABLES:

    REMOTE_USER_GROUP_N: 2
    REMOTE_ADDR: 192.168.33.20
    REMOTE_USER_FIRSTNAME: Alice
    REMOTE_USER_LASTNAME: Able
    REMOTE_USER: alice@IPADEMO.LOCAL
    REMOTE_USER_GROUP_2: ipausers
    REMOTE_USER_GROUP_1: sysadmin
    REMOTE_PORT: 42586
    REMOTE_USER_EMAIL: alice@ipademo.local


HBAC for web services
---------------------

The final task for this unit is to configure Apache to use FreeIPA's HBAC
rules for access control.  We will use mod_authnz_pam_ in
conjunction with SSSD's PAM responder to achieve this.

.. _mod_authnz_pam: http://www.adelton.com/apache/mod_authnz_pam/

First add an *HBAC service* named ``app`` for the web application.
You can do this as ``admin`` via the Web UI or CLI.  **Hint:** the
``hbacsvc`` plugin provides this functionality.

Next, add an HBAC rule allowing members of the ``sysadmin`` user
group access to ``app`` (on any host)::

  [client]$ ipa hbacrule-add --hostcat=all sysadmin_app
  ------------------------------
  Added HBAC rule "sysadmin_app"
  ------------------------------
    Rule name: sysadmin_app
    Host category: all
    Enabled: TRUE

  [client]$ ipa hbacrule-add-user sysadmin_app --group sysadmin
    Rule name: sysadmin_app
    Host category: all
    Enabled: TRUE
    User Groups: sysadmin
  -------------------------
  Number of members added 1
  -------------------------

  [client]$ ipa hbacrule-add-service sysadmin_app --hbacsvcs app
    Rule name: sysadmin_app
    Host category: all
    Enabled: TRUE
    User Groups: sysadmin
    Services: app
  -------------------------
  Number of members added 1
  -------------------------

Next, define the PAM service on ``client``.  The name must match the
``hbacsvc`` name (in our case: ``app``), and the name is indicated
by the *name of the file* that configures the PAM stack.  Create
``/etc/pam.d/app`` with the following contents::

  account required   pam_sss.so

Finally, update the Apache configuration.  Find the line::

  Require valid-user

Replace with::

  Require pam-account app

Also add the ``LoadModule`` directive to the top of the file::

  LoadModule authnz_pam_module modules/mod_authnz_pam.so

Once again, we must set a special SELinux boolean to allow
``mod_authnz_pam`` to work::

  [client]$ sudo setsebool -P allow_httpd_mod_auth_pam 1

Restart Apache and try and perform the same ``curl`` request again
as ``alice``.  Everything should work as before because ``alice`` is
a member of the ``sysadmin`` group.  What happens when you are
authenticated as ``bob`` instead?


Unit 6: Certificate management
================================

You probably noticed that the web service was not hosted over HTTPS,
so there is no TLS-based authentication or confidentiality.  In this
unit, we will issue an X.509 certificate for the web service via
the *certmonger* program.

Certmonger supports multiple CAs including FreeIPA's CA, and can
generate keys, issue certifiate requests, track certificates, and
renew tracked certificates when the expiration time approaches.
Will also use ``mod_ssl`` with Apache.

Let's start by confirming that the HTTP service does not yet have a
certificate::

  [client]$ ipa service-show HTTP/client.ipademo.local
    Principal: HTTP/client.ipademo.local@IPADEMO.LOCAL
    Keytab: True
    Managed by: client.ipademo.local

Enable and start certmonger::

  [client]$ sudo systemctl enable certmonger
  Created symlink from /etc/systemd/system/multi-user.target.wants/certmonger.service to /usr/lib/systemd/system/certmonger.service.
  [client]$ sudo systemctl start certmonger

Now let's request a certificate.  We will generate keys and store
certificates in the NSS database at ``/etc/httpd/alias``::

  [client]$ sudo ipa-getcert request -f /etc/pki/tls/certs/app.crt -k /etc/pki/tls/private/app.key \
            -K HTTP/client.ipademo.local \
            -D client.ipademo.local
  New signing request "20180603185400" added.

Let's break down some of those command arguments.

``-k <path>``
  Path to private key
``-f <path>``
  Path to certificate
``-K <principal>``
  Kerberos service principal; because different kinds of services may
  be accessed at one hostname, this argument is needed to tell
  certmonger which service principal is the subject
``-D <dnsname>``
  Requests the given domain name to appear in the *Subject
  Alternative Name (SAN)* extension.  The hostname will appear in
  the *Common Name (CN)* field but this practice is deprecated, so
  it is important to also include it in the SAN extension.

Another important argument is ``-N <subject-name>`` but this
defaults to the system hostname, which in our case
(``client.ipademo.local``) is appropriate.

Let's check the status of our certificate request using the tracking
identifier given in the ``ipa-getcert request`` output::

  [client]$ sudo getcert list -i 20180603185400
  Number of certificates and requests being tracked: 1.
  Request ID '20180603185400':
    status: MONITORING
    stuck: no
    key pair storage: type=FILE,location='/etc/pki/tls/private/app.key'
    certificate: type=FILE,location='/etc/pki/tls/certs/app.crt'
    CA: IPA
    issuer: CN=Certificate Authority,O=IPADEMO.LOCAL
    subject: CN=client.ipademo.local,O=IPADEMO.LOCAL
    expires: 2020-06-03 18:54:00 UTC
    dns: client.ipademo.local
    principal name: HTTP/client.ipademo.local@IPADEMO.LOCAL
    key usage: digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment
    eku: id-kp-serverAuth,id-kp-clientAuth
    pre-save command:
    post-save command:
    track: yes
    auto-renew: yes


Confirm that the certificate was issued and that certmonger is now
``MONITORING`` the certificate and will ``auto-renew`` it when it is
close to expiration.  Now if you run ``ipa service-show``, you will
see a number of attributes related to the certificate, including the
certificate itself.  Can you work out how to save the PEM-encoded
certificate to a file?

Now we can reconfigure Apache to serve our app over TLS.  Update
``app.conf`` to listen on port 443 and add the SSL directives::

  ...
  Listen 443

  <VirtualHost *:443>
      SSLEngine on
      SSLCertificateFile "/etc/pki/tls/certs/app.crt"
      SSLCertificateKeyFile "/etc/pki/tls/private/app.key"

      ServerName client.ipademo.local
      ...


Restart Apache and make a request to the app over HTTPS::

  [client]$ sudo systemctl restart httpd
  [client]$ curl -u : --negotiate https://client.ipademo.local
  LOGGED IN AS: alice@IPADEMO.LOCAL

  REMOTE_* REQUEST VARIABLES:

    REMOTE_USER: alice@IPADEMO.LOCAL
    REMOTE_USER_GROUP_1: ipausers
    REMOTE_USER_GROUP_2: sysadmin
    REMOTE_USER_GROUP_N: 2
    REMOTE_USER_FIRSTNAME: Alice
    REMOTE_USER_LASTNAME: Alice
    REMOTE_USER_MAIL: alice@ipademo.local
    REMOTE_ADDR: 192.168.33.20
    REMOTE_PORT: 51876


Unit 7: Replica installation
==============================

FreeIPA is designed to be run in a replicated multi-master
environment.  In this unit, we will deploy a single FreeIPA
replica.  For recommended production topologies, see
http://www.freeipa.org/page/Deployment_Recommendations#Replicas.

If you have disabled the ``allow_all`` HBAC rule, add a new rule
that will **allow ``admin`` to access the ``sshd`` service on any
host**.

[To be confirmed] As of FreeIPA 4.3, replica installation is accomplished by
*promoting* an enrolled client machine to a server.

SSH to the ``replica`` VM and enrol it per `Unit 2: Enrolling
client machines`_.

Now promote the client to server.  We will set up the replica
*without* CA or DNS, but in a production deployment there should be
at least one instance of these services in each datacentre.  These
components can be added later via ``ipa-ca-install(1)`` and
``ipa-dns-install(1)``.

::

  [replica]$ sudo ipa-replica-install
  Password for admin@IPADEMO.LOCAL:
  ipaserver.install.server.replicainstall: ERROR    Reverse DNS resolution of address 192.168.33.10 (server.ipademo.local) failed. Clients may not function properly. Please check your DNS setup. (Note that this check queries IPA DNS directly and ignores /etc/hosts.)
  Continue? [no]: yes
  Run connection check to master
  Connection check OK
  Configuring directory server (dirsrv). Estimated time: 30 seconds
    [1/41]: creating directory server instance
    [2/41]: enabling ldapi
  ...

The rest of the replica installation process is almost identical to
server installation.  One important difference is the initial
replication of data to the new Directory Server instance::

  [28/41]: setting up initial replication
  Starting replication, please wait until this has completed.
  Update in progress, 4 seconds elapsed
  Update succeeded

After ``ipa-replica-install`` finishes, the replica is operational.


Unit 8: Sudo rule management
============================

Sudo is a program that allows users to run programs as another user
with different privileges (possibly ``root``).  Sudo rules provide
fine-grained control over who can execute which processes, as which
users.  FreeIPA allows centralised management of Sudo rules.  To
simplify management, Sudo rules can refer to User Groups, Host
Groups and *Command Groups* as well as individual users, hosts and
commands.

The goal of this unit is to allow ``alice`` (being a ``sysadmin``)
to run any command on any FreeIPA-enrolled machine, and to allow
``bob`` (who is merely a web server administrator) to control
``httpd`` on hosts that are ``webservers``.

As of FreeIPA 4.6.90.pre2, you should enable SSSD's sudo responder by running::

  [client]$ sudo authselect enable-feature with-sudo

Restart SSSD::

  [client]$ sudo systemctl restart sssd

Permitting ``alice`` to run all commmands
-----------------------------------------

Let's deal with ``alice`` first.  Before we do anything else, log in
as ``alice`` and attempt to run the ``id`` command as ``root``.
Observe that the action is denied::

  [client]$ su -l alice
  Password:
  [alice@client]$ sudo id
  [sudo] password for alice:
  alice is not allowed to run sudo on client.  This incident will be reported.
  [alice@client]$ exit
  logout

Now define the ``sysadmin_sudo`` rule, which allows members of the
``sysadmin`` User Group to to run any command on any host::

  [client]$ ipa sudorule-add sysadmin_sudo \
      --hostcat=all --runasusercat=all --runasgroupcat=all --cmdcat=all
  -------------------------------
  Added Sudo Rule "sysadmin_sudo"
  -------------------------------
    Rule name: sysadmin_sudo
    Enabled: TRUE
    Host category: all
    Command category: all
    RunAs User category: all
    RunAs Group category: all

Next add the ``sysadmin`` User Group to the Sudo rule::

  [client]$ ipa sudorule-add-user sysadmin_sudo --group sysadmin
    Rule name: sysadmin_sudo
    Enabled: TRUE
    Host category: all
    Command category: all
    RunAs User category: all
    RunAs Group category: all
    User Groups: sysadmin
  -------------------------
  Number of members added 1
  -------------------------

Now attempt to ``sudo id`` as ``alice`` again::

  [client]$ su -l alice
  Password:
  [alice@client]$ sudo id
  [sudo] password for alice:
  uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

This time the action was allowed, and we can see from the output
that ``alice`` indeed executed the ``id`` command as ``root``.


Permitting ``bob`` to run web administration commands
-----------------------------------------------------

Now let us turn our attention to ``bob``.  The goal is to allow
``bob`` and other web servers administrators to run commands related
to web server administration (and only such commands).  First, let's
observe that ``bob`` currently cannot restart Apache::

  [client]$ su -l bob
  Password:
  [bob@client]$ sudo systemctl restart httpd
  [sudo] password for bob:
  Sorry, user bob is not allowed to execute '/bin/systemctl restart httpd' as root on client.ipademo.local.

Make a new User Group named ``webadmin`` and add ``bob`` as a
member.  Add an ``hbacrule`` that allows ``bob`` to log into hosts
that are members of the ``webservers`` Host Group.

Now define the ``webadmin_sudo`` rule.  Note that we *do not* use
``--hostcat=all`` or ``cmdcat=all`` this time.

::

  [client]$ ipa sudorule-add webadmin_sudo \
      --runasusercat=all --runasgroupcat=all
  -------------------------------
  Added Sudo Rule "webadmin_sudo"
  -------------------------------
    Rule name: webadmin_sudo
    Enabled: TRUE
    RunAs User category: all
    RunAs Group category: all
  [client]$

Add the ``webadmin`` User Group and ``webservers`` Host Group to the rule::

  [client]$ ipa sudorule-add-user webadmin_sudo --group webadmin
    Rule name: webadmin_sudo
    Enabled: TRUE
    RunAs User category: all
    RunAs Group category: all
    User Groups: webadmin
  -------------------------
  Number of members added 1
  -------------------------
  [client]$ ipa sudorule-add-host webadmin_sudo --hostgroup webservers
    Rule name: webadmin_sudo
    Enabled: TRUE
    RunAs User category: all
    RunAs Group category: all
    User Groups: webadmin
    Host Groups: webservers
  -------------------------
  Number of members added 1
  -------------------------

Next, define *Sudo Commands* and a *Sudo Command Group* for
web server administration::

  [client]$ ipa sudocmd-add "/usr/bin/systemctl start httpd"
  ---------------------------------------------------
  Added Sudo Command "/usr/bin/systemctl start httpd"
  ---------------------------------------------------
    Sudo Command: /usr/bin/systemctl start httpd
  [client]$ ipa sudocmd-add "/usr/bin/systemctl restart httpd"
  -----------------------------------------------------
  Added Sudo Command "/usr/bin/systemctl restart httpd"
  -----------------------------------------------------
    Sudo Command: /usr/bin/systemctl restart httpd
  [client]$ ipa sudocmdgroup-add webadmin_cmds
  ----------------------------------------
  Added Sudo Command Group "webadmin_cmds"
  ----------------------------------------
    Sudo Command Group: webadmin_cmds
  [client]$ ipa sudocmdgroup-add-member webadmin_cmds \
      --sudocmds "/usr/bin/systemctl start httpd" \
      --sudocmds "/usr/bin/systemctl restart httpd"
    Sudo Command Group: webadmin_cmds
    Member Sudo commands: /usr/bin/systemctl start httpd, /usr/bin/systemctl restart httpd
  -------------------------
  Number of members added 2
  -------------------------

Finally, add this new command group to the Sudo rule::

  [client]$ ipa sudorule-add-allow-command webadmin_sudo \
      --sudocmdgroups webadmin_cmds
    Rule name: webadmin_sudo
    Enabled: TRUE
    RunAs User category: all
    RunAs Group category: all
    User Groups: webadmin
    Host Groups: webservers
    Sudo Allow Command Groups: webadmin_cmds
  -------------------------
  Number of members added 1
  -------------------------

Now log in again as ``bob`` and observe that we have reached our goal: he can
restart (or start) Apache, but not run other commands via ``sudo``::

  [client]$ su -l bob
  Password:
  [bob@client]$ sudo systemctl restart httpd
  [sudo] password for bob:
  [bob@client]$ sudo id
  Sorry, user bob is not allowed to execute '/bin/id' as root on client.ipademo.local.


Unit 9: SELinux User Maps
=========================

SELinux is a *mandatory access controls* mechanism for Linux,
providing more powerful and flexible access control than traditional
Unix permissions.  Users have an SELinux *context* consisting of a
*user*, *role* and *type*.  The goal of this unit is to cause users
to be *confined* by an SELinux *role-based access control (RBAC)*
policy when the log into hosts that are members of the
``webservers`` Host Group.

..
  - users can have different selinux policy on diff hosts

**Note:** SELinux contexts are applied during PAM-based login, so
when testing our changes in this unit ``su -l <user>`` will not
suffice: it is necessary to log in via SSH.  You can do this from
any of the VMs (even ``client`` itself).

Log in as ``alice`` and run ``id -Z`` to see her current SELinux
context::

  [alice@client]$ id -Z
  unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

``alice`` is currently *unconfined*.  We want her to be confined to
the ``staff_u`` context when she logs in, to limit the impact of an
account compromise.

SELinux User Maps can refer to users and hosts directly, or they can
inherit the users and hosts of an existing HBAC rule.  Because
access control is defined by HBAC, it is a good administration
practice to link SELinux User Maps to HBAC rules, so that when users
or hosts are added to the HBAC rule, the correct SELinux context
will automatically be used.

Recall that members of the ``sysadmin`` User Group already have
access to ``webservers`` via the ``sysadmin_webservers`` rule that
was created in `Unit 4: Host-based access control (HBAC)`_.  Create
the SELinux User Map::

  [client]$ ipa selinuxusermap-add sysadmin_staff_t \
      --hbacrule sysadmin_webservers --selinuxuser staff_u:s0-s0:c0.c1023
  -----------------------------------------
  Added SELinux User Map "sysadmin_staff_t"
  -----------------------------------------
    Rule name: sysadmin_staff_t
    SELinux User: staff_u:s0-s0:c0.c1023
    HBAC Rule: sysadmin_webservers
    Enabled: TRUE


Now login in as ``alice`` over SSH and observe that she is confined
by the ``staff_u`` policy::

  [server]$ ssh alice@client.ipademo.local
  alice@client.ipademo.local's password:
  Last login: Fri Sep  2 05:47:03 2016
  [alice@client]$ id -Z
  staff_u:staff_r:staff_t:s0-s0:c0.c1023


**Note:** in production use you should ensure that only one HBAC
rule allows access for a given user/host/SELinux User Map
combination.  Only one SELinux policy will be applied, and if
multiple policies match, the winning policy may be chosen
inconsistently.


Unconfined ``sudo``
-------------------

``alice`` is now confined by the ``staff_u`` policy, but being a
``sysadmin`` she needs to be unconfined when running commands via
``sudo``.  With the current configuration, commands run via ``sudo``
inherit a user's context, as the following commands demonstrate::

  [alice@client]$ sudo -s
  [sudo] password for alice:
  sh-4.3# id -Z
  staff_u:staff_r:staff_t:s0-s0:c0.c1023
  sh-4.3# systemctl restart httpd
  Failed to restart httpd.service: Access denied
  See system logs and 'systemctl status httpd.service' for details.
  sh-4.3#

Now let's make it so that ``alice`` can do her job.  We need to
update the Sudo rule to change the SELinux context::

  [alice@client]$ ipa sudorule-add-option sysadmin_sudo --sudooption type=unconfined_t
  -------------------------------------------------------------
  Added option "type=unconfined_t" to Sudo Rule "sysadmin_sudo"
  -------------------------------------------------------------
    Rule name: sysadmin_sudo
    Enabled: TRUE
    Host category: all
    Command category: all
    RunAs User category: all
    RunAs Group category: all
    Sudo Option: type=unconfined_t
  [alice@client]$ ipa sudorule-add-option sysadmin_sudo --sudooption role=unconfined_r
  -------------------------------------------------------------
  Added option "role=unconfined_r" to Sudo Rule "sysadmin_sudo"
  -------------------------------------------------------------
    Rule name: sysadmin_sudo
    Enabled: TRUE
    Host category: all
    Command category: all
    RunAs User category: all
    RunAs Group category: all
    Sudo Option: type=unconfined_t, role=unconfined_r

Now when ``alice`` runs ``sudo`` it changes the SELinux context of
the program being run::

  [alice@client]$ sudo -s
  sh-4.3# id -Z
  staff_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
  sh-4.3# systemctl restart httpd
  sh-4.3#


Unit 10: SSH user and host key management
=========================================

In this module you will explore how to use FreeIPA as a backend
provider for SSH keys.  Instead of distributing ``authorized_keys``
and ``known_hosts`` files, SSH keys are uploaded to their
corresponding user and host entries in FreeIPA.

Using FreeIPA as a backend store for SSH user keys
--------------------------------------------------

OpenSSH can use *public-private key pairs* to authenticate users.  A
user wanting to access a host can get her *public key* added to an
``authorized_keys`` file on the target host.  When the user attempts
to log in, she presents her public key and the host grants access if
her key is in an ``authorized_keys`` file.  There are system-wide
and per-user ``authorized_keys`` files, but if the target systems do
not mount a network-backed home directory (e.g. NFS), then the user
must copy her public key to every system she intends to log in to.

On FreeIPA-enrolled systems, SSSD can be configured to cache and
retrieve user SSH keys so that applications and services only have
to look in one location for user public keys.  FreeIPA provides the
centralized repository of keys, which users can manage themselves.
Administrators do not need to worry about distributing, updating or
verifying user SSH keys.

Generate a user keypair on the client system::

  [client]$ sudo -i -u alice
  [alice@client]$
  [alice@client]$ ssh-keygen -C alice@ipademo.local
  Generating public/private rsa key pair.
  Enter file in which to save the key (/home/alice/.ssh/id_rsa):
  Created directory '/home/alice/.ssh'.
  Enter passphrase (empty for no passphrase):
  Enter same passphrase again:
  Your identification has been saved in /home/alice/.ssh/id_rsa.
  Your public key has been saved in /home/alice/.ssh/id_rsa.pub.
  The key fingerprint is:
  SHA256:TbuWICAdqkdXwG3uQoXxh03DuJdRC6Vh3ntOcacdfHM alice@ipademo.local
  The key's randomart image is:
  +---[RSA 2048]----+
  |   .+=.o*oo      |
  |   oo+=*o* .  .  |
  |  + ++o.=o+ . .+E|
  | o o..o.oo o o +=|
  |. .. ...S + o . .|
  | .  . .. . *     |
  |     .    + .    |
  |         .       |
  |                 |
  +----[SHA256]-----+

The public key is stored in ``/home/alice/.ssh/id_rsa.pub`` in an
OpenSSH-specific format.  ``alice`` can now upload it to her user
entry in FreeIPA::

  [alice@client]$ kinit alice
  Password for alice@IPADEMO.LOCAL:
  [alice@client]$ ipa user-mod alice \
      --sshpubkey="$(cat /home/alice/.ssh/id_rsa.pub)"
  ---------------------
  Modified user "alice"
  ---------------------
    User login: alice
    First name: Alice
    Last name: Able
    Home directory: /home/alice
    Login shell: /bin/sh
    Email address: alice@ipademo.local
    UID: 1278000001
    GID: 1278000001
    SSH public key: ssh-rsa
                    AAAAB3NzaC1yc2EAAAADAQABAAABAQDH8pLi61DjkEPqNZnfOgGLLZfLdu9EqVL9UrZeXD3M/j3ig+xeDCCO80YjzuND0UZE4CHgA+uGrtoinQMYkt/FRkm/ie8wcinP/8BxSoOeYSHDNG+cG3iSNJrDiHoqPeQ/+nzBS5n6HWy18N5IMNoqC+f9f2VDuHWZCKqPHMLD29MAX6vOgawdHWFcAk416O+EgS43w3ub89+VPz3Egz4z9K+gjpoboFHk94n7n09B+qyzzImVMsz9vMFSr0rcaVRd9Tb0Q6HlUXkU7aH1Vjkl/DJdQalCpPYJXujkRYAZIs1ouU5IBuuq6k54fk1vBmwjv2tK2NkpvfWfhaxQVwdn
                    alice@ipademo.local
    Account disabled: False
    Password: True
    Member of groups: ipausers, sysadmin
    Indirect Member of Sudo rule: sysadmin_sudo
    Indirect Member of HBAC rule: sysadmin_all
    Kerberos keys available: True
    SSH public key fingerprint: C4:62:89:7A:65:F9:82:12:EF:08:96:D1:C9:7D:51:A5 alice@ipademo.local
                                (ssh-rsa)

During enrolment of the systems, SSSD has been configured to use
FreeIPA as one of its identity domains and OpenSSH has been
configured to use SSSD for managing user keys.

If you have disabled the ``allow_all`` HBAC rule, add a new rule
that will **allow ``alice`` to access the ``sshd`` service on any
host**.

Logging in to the server using SSH public key authentication should
now work::

  [alice@client]$ ssh -o GSSAPIAuthentication=no server.ipademo.local
  Last login: Tue Feb  2 15:10:13 2016
  [alice@server]$

To verify the SSH public key was used for authentication, you can
check the ``sshd`` service journal on the server, which should have
an entry like::

  server.ipademo.local sshd[19729]: \
    Accepted publickey for alice from 192.168.33.20 port 37244 \
    ssh2: RSA SHA256:rgVSyPM/yn/b5bsZQIsAXWF+16zkP59VS9GS+k+bbOg


Using FreeIPA as a backend store for SSH host keys
--------------------------------------------------

OpenSSH uses public keys to authenticate hosts.  When a client
attempts to log in over SSH, the target host presents its public
key.  The first time the host authenticates, the user may have to
examine the target host's public key and manually authenticate it.
The client then stores the host's public key in a ``known_hosts``
file.  On subsequent attempts to log in, the client checks its
``known_hosts`` files and automatically grants access to recognised
hosts.

Based on the last exercise, try to figure out how to upload SSH host
keys to the FreeIPA server.

**Note:** OpenSSH has already been configured to look up known hosts
on the FreeIPA server, so no manual configuration is required for
this section.
