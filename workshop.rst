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

- Module 1: Installing the FreeIPA server
- Module 2: Enrolling a client machine in the FreeIPA domain
- Module 3: User creation and administration, Kerberos authentication
- Module 4: Host-Based Access Control (HBAC)
- Module 5: Authorisation and authentication for web applications
- Module 6: Certificate management


Editing files on VMs
--------------------

Parts of the workshop involve editing files on virtual
machines.  The ``vi`` and GNU ``nano`` editors are available on the
VMs.  If you are not familiar with ``vi`` or you are unsure of what to use, you
should choose ``nano``.


Example commands
----------------

This guide contains many examples of commands.  Some of the commands
should be executed on your host, others on either the ``server`` or the
``client`` guest VM.  For clarity, commands are annotated with the
host on which they are meant to be executed, as in these examples::

  $ echo "Run it on virtualisation host (no annotation)"

  [server]$ echo "Run it on FreeIPA server"

  [client]$ echo "Run it on IPA-enrolled client"


Workshop feedback
-----------------

After you have completed the workshop, consider leaving feedback at
https://goo.gl/forms/P11DtfJiNq.


Preparation
===========

Some preparation is needed prior to the workshop.  The workshop is
designed to be carried out in a Vagrant_ environment that consists of
several VMs.  **The goal of the preparation** is to be able to
successfully ``vagrant up`` the VMs as the first step of the
workshop.

.. _Vagrant: https://www.vagrantup.com/


Requirements
------------

For the FreeIPA workshop you will need to:

- Install **Vagrant** and **VirtualBox 4.3** (VirtualBox 5 is not
  supported by Vagrant).  (On Fedora, you can use **libvirt**
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
``vagrant-libvirt``::

  $ sudo dnf install -y vagrant-libvirt


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

  $ sudo dnf install -y VirtualBox-4.3

Finally, load the kernel modules::

  $ sudo modprobe vboxdrv vboxnetadp


Mac OS X
^^^^^^^^

Install Vagrant for Mac OS X from
https://www.vagrantup.com/downloads.html.

Install VirtualBox 4.3 for **OS X hosts** from
https://www.virtualbox.org/wiki/Download_Old_Builds_4_3.

Install Git from https://git-scm.com/download/mac or via your
preferred package manager.


Debian / Ubuntu
^^^^^^^^^^^^^^^

Install Vagrant and Git::

  $ sudo apt-get install -y vagrant git

**Virtualbox 4.3** may be available from the system package manager,
depending your your release.  Find out which version of VirtualBox is
available::

  $ apt list virtualbox
  Listing... done
  virtualbox/trusty-updates,trusty-security 4.3.10-dfsg-1ubuntu5 amd64

If version 4.3 is available, install it via ``apt-get``::

  $ sudo apt-get install -y virtualbox

If VirtualBox 4.3 was not available in the official packages for
your release, follow the instructions at
https://www.virtualbox.org/wiki/Linux_Downloads to install it.


Windows
^^^^^^^

Install Vagrant via the ``.msi`` available from
https://www.vagrantup.com/downloads.html.

Install VirtualBox 4.3 for **Windows hosts** from
https://www.virtualbox.org/wiki/Download_Old_Builds_4_3.

You will also need to install an SSH client, and Git.  Git for
Windows also comes with an SSH client so just install Git from
https://git-scm.com/download/win.


Clone Vagrantfile repository
----------------------------

Clone the repository containing the Vagrantfile for the workshop::

  $ git clone https://github.com/frasertweedale/freeipa-workshop-vagrantfile.git


Fetch Vagrant box
-----------------

Please fetch the Vagrant box prior to the workshop.  It is > 500MB
so it may not be feasible to download it during the workshop.

::

  $ vagrant box add ftweedal/freeipa-workshop


If you are running an older version of Vagrant that does not know
about the *Atlas* service where the box is hosted, you can add it
by URL instead::

  $ vagrant box add ftweedal/freeipa-workshop \
      https://atlas.hashicorp.com/ftweedal/boxes/freeipa-workshop/versions/0.0.4/providers/virtualbox.box


Add hosts file entries
----------------------

*This step is necessary if you want to access the FreeIPA Web UI in
the VM from a browser on your host, but otherwise this step is optional. All
workshop modules can be completed using the CLI.*

Add the following entries to your hosts file::

  192.168.33.10   server.ipademo.local
  192.168.33.20   client.ipademo.local

On Unix systems (including Mac OS X), the hosts file is ``/etc/hosts``
(you need elevated permissions to edit it.)

On Windows, edit ``C:\system32\system\drivers\etc\hosts`` as
*Administrator*.


Module 1: FreeIPA server installation
=====================================

In this module you will install the FreeIPA server, which you will
use for the rest of the workshop.

First ``cd`` into the directory where the ``Vagrantfile`` was
checked out, then bring up the Vagrant environment::

  $ cd freeipa-workshop-vagrantfile
  $ vagrant up --provider virtualbox

The Vagrant environment contains two hosts: ``server.ipademo.local``
and ``client.ipademo.local``.  From the directory containing the
``Vagrantfile``, SSH into the ``server`` machine::

  $ vagrant ssh server


On ``server``, start the FreeIPA server installation program::

  [server]$ sudo ipa-server-install --no-host-dns

The ``--no-host-dns`` argument is needed because there is no DNS PTR
resolution for the Vagrant environment.  For production deployment,
this important sanity check should not be skipped.

You will be asked a series of questions.
Accept the defaults for most of the questions, except as outlined
below.

Configure FreeIPA's DNS server::

  Do you want to configure integrated DNS (BIND)? [no]: yes

  Existing BIND configuration detected, overwrite? [no]: yes

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
  This user is referred to as the Directory Manager and has full
  access
  to the Directory for system management tasks and will be added to
  the
  instance of directory server created for IPA.
  The password must be at least 8 characters long.

  Directory Manager password: 
  Password (confirm): 

  The IPA server requires an administrative user, named 'admin'.
  This user is a regular system account used for IPA server
  administration.

  IPA admin password: 
  Password (confirm): 


Do not configure a DNS forwarder (it is likely that you will want to configure
a DNS forwarder for a real-world deployment but it is not needed today) and
accept the defaults for configuring the reverse zone::

  Do you want to configure DNS forwarders? [yes]: no
  Do you want to configure the reverse zone? [yes]: 
  Please specify the reverse zone name [33.168.192.in-addr.arpa.]: 
  Using reverse zone(s) 33.168.192.in-addr.arpa.


Next, you will be presented with a summary of the server
configuration and asked for final confirmation.  Give confirmation to begin the
server installation::

  The IPA Master Server will be configured with:
  Hostname:       server.ipademo.local
  IP address(es): 192.168.33.10
  Domain name:    ipademo.local
  Realm name:     IPADEMO.LOCAL

  BIND DNS server will be configured to serve IPA domain with:
  Forwarders:    10.0.2.3
  Reverse zone(s):  33.168.192.in-addr.arpa.

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


Module 2: Client enrolment
==========================

In this module, you will enrol a *host* as a client of your FreeIPA
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

The ``--mkhomedir`` flag configure PAM to create missing home
directories when users log into the host for the first time.
FreeIPA supports automount so consider using that for production
deployments.

The FreeIPA server should be detected through DNS autodiscovery.
(If DNS discovery fails, e.g. due to client machine having incorrect
``/etc/resolv.conf`` configuration, you would be prompted to
manually enter the domain and server hostname instead).

The autodetected server settings will be displayed; confirm to
proceed::

  [client]$ sudo ipa-client-install
  Discovery was successful!
  Hostname: client.ipademo.local
  Realm: IPADEMO.LOCAL
  DNS Domain: ipademo.local
  IPA Server: server.ipademo.local
  BaseDN: dc=ipademo,dc=local

  Continue to configure the system with these values? [no]: yes


The client machine's clock will be synchronised to the server's (the
Kerberos protocol requires this).  You will then be prompted to
enter credentials of a user authorised to enrol hosts (``admin``)::

  Synchronizing time with KDC...
  Attempting to sync time using ntpd.  Will timeout after 15 seconds
  User authorized to enroll computers: admin
  Password for admin@IPADEMO.LOCAL: 

The enrolment now proceeds; no further input is required.  You will
see output detailing the operations being completed.  Unlike
``ipa-server-install``, client enrolment only takes a few seconds.

Users in your FreeIPA domain can now log into FreeIPA-enrolled
hosts, subject to *Host-based access control* (HBAC) rules.  Users
logged onto the host can also acquire Kerberos tickets for accessing
*services* in your domain.


Module 3: User management
=========================

This module introduces the ``ipa`` CLI program and the web
interface.  We will perform some simple administrative tasks: adding
groups and users and managing group membership.

Web UI
------

Visit ``https://server.ipademo.local/``.  You'll get a TLS
*untrusted issuer* warning which you can dismiss (by adding a temporary
exception).  Log in as ``admin``.

Welcome to the FreeIPA web UI.  Most management activities can be
performed here, or via the ``ipa`` CLI program.  See if you can work
out how to add a *User Group* (let's call it ``sysadmin``) and a
*User* (give her the username ``alice``).  Make ``alice`` a member
of the ``sysadmin`` group.


CLI
---

On ``server``, make sure you have a Kerberos ticket for ``admin``
(reminder: ``kinit admin``).

Most FreeIPA adminstrative actions can be carried out using the
``ipa`` CLI program.  Let's see what commands are available::

  [server]% ipa help commands
  automember-add                    Add an automember rule.
  automember-add-condition          Add conditions to an automember rule.
  automember-default-group-remove   Remove default (fallback) group for all unmatched entries.
  automember-default-group-set      Set default (fallback) group for all unmatched entries.
  automember-default-group-show     Display information about the default (fallback) automember groups.
  ...

Whoa!  There's almost 300 of them!  We'll be using only a handful of
these today.

You'll notice that commands are grouped by *plugin*.  You can get a
general overview of a plugin by running ``ipa help <plugin>``, and
specific information on a particular command by running ``ipa help
<command>``.

Let's add the user *bob* from the CLI.  See if you can work out how
to do this using the CLI help commands.  (**hint**: the plugin name
is ``user``).


User authentication
-------------------

We have seen how to authenticate as ``admin``.  The process is the
same for regular users - just ``kinit <username>``!

Try to authenticate as ``bob``::

  [server]$ kinit bob
  kinit: Generic preauthentication failure while getting initial credentials

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

Whenever a user has their password reset (including the first time),
the next ``kinit`` will prompt them to enter a new password::

  [server]$ kinit bob
  Password for bob@IPADEMO.LOCAL: 
  Password expired.  You must change it now.
  Enter new password: 
  Enter it again: 


Now ``bob`` has a TGT (run ``klist`` to confirm) which can use to
log in to other hosts and services.  Try logging into
``client.ipademo.local``::

  [server]$ ssh bob@client.ipademo.local
  [bob@client]$ 

You are now logged into the client as ``bob``.  Type ``^D`` or
``exit`` to log out and return to the ``server`` shell.  If you run
``klist`` again, you will see not only the TGT but a *service ticket*
that was automatically acquired to log in to
``client.ipademo.local`` without prompting for a password.  Kerberos
is a true *single sign-on* protocol!

::

  [server]$ klist
  Ticket cache: KEYRING:persistent:1000:krb_ccache_dYtyLyU
  Default principal: bob@IPADEMO.LOCAL

  Valid starting     Expires            Service principal
  15/10/15 07:15:11  16/10/15 07:15:02  host/client.ipademo.local@IPADEMO.LOCAL
  15/10/15 07:15:03  16/10/15 07:15:02  krbtgt/IPADEMO.LOCAL@IPADEMO.LOCAL



Module 4: Host-based access control
===================================

FreeIPA's *host-based access control* (HBAC) feature allows you to
define policies that restrict access to hosts or services based on
the user attempting to log in and that user's groups, the host that
they are trying to access (or its *host groups*), and (optionally)
the service being accessed.

In this module, we will define an HBAC policy that restricts
access to ``client.ipademo.local`` to members of the
``sysadmin`` user group.


Adding a host group
-------------------

Instead of defining the HBAC rule to directly talk about
``client.ipademo.local``, create a *host group* called
``webservers`` and make ``client.ipademo.local`` a member.

Explore the Web UI to work out how to do this, or use the CLI (you
will need to ``kinit admin``; see if you can work out what plugin
provides the host group functionality).

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
    Description: Allow all users to access any host from any
    host
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

  [server]$ ipa hbactest --user bob --host client.ipademo.local --service sshd
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
  Connection closed by UNKNOWN

Then try ``alice``::

  [server]$ kinit alice
  Password for alice@IPADEMO.LOCAL: 
  [server]$ ssh alice@client.ipademo.local
  Last login: Fri Oct 16 01:09:10 2015 from 192.168.33.10
  -sh-4.3$ 


Module 5: Web App External Authentication
=========================================

You can configure many kinds of applications to rely on FreeIPA's
centralised authentication, including web applications.  In this
module you will configure the Apache web server to use Kerberos
authentication to authenticate users, PAM to enforce HBAC rules, and
``mod_lookup_identity`` to populate the request environment with
user attributes.

All activities in this module take place on ``client`` unless
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
store it in a *keytab* file (remember to ``kinit admin``)::

  [client]$ ipa-getkeytab -s server.ipademo.local -p HTTP/client.ipademo.local -k app.keytab
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


You can test the SSSD InfoPipe directly via the ``dbus-send``
utility::

  [client]$ sudo dbus-send --print-reply --system \
      --dest=org.freedesktop.sssd.infopipe /org/freedesktop/sssd/infopipe \
      org.freedesktop.sssd.infopipe.GetUserAttr string:alice array:string:mail
  method return sender=:1.117 -> dest=:1.119 reply_serial=2
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
``LookupUserGroupsIter`` directive.

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

    REMOTE_USER_GECOS: Alice Able
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

The final task for this module is to configure Apache to use FreeIPA's HBAC
rules for access control.  We will use ``mod_authnz_pam_`` in
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


Module 6: Certificate management
================================

You probably noticed that the web service was not hosted over HTTPS,
so there is no TLS-based authentication or confidentiality.  In this
module, we will issue an X.509 certificate for the web service via
the *certmonger* program.

Certmonger supports multiple CAs including FreeIPA's CA, and can
generate keys, issue certifiate requests, track certificates, and
renew tracked certificates when the expiration time approaches.
Certmonger works with NSS, so we will also use ``mod_nss`` with
Apache, rather than ``mod_ssl``.

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

Now let's request a certificate.  ``mod_nss`` is already configured
to use the certificate database at ``/etc/httpd/alias``, so we tell
certmonger to generate the key and add the certificate in that
database::

  [client]$ sudo ipa-getcert request -d /etc/httpd/alias -n app \
      -K HTTP/client.ipademo.local -U id-kp-serverAuth
  New signing request "20151026222558" added.

Let's break down some of those command arguments.

``-d <path>``
  Path to NSS database
``-n <nickname>``
  *Nickname* to use for key and certificate
``-K <principal>``
  Kerberos service principal; because different kinds of services may
  be accessed at one hostname, this argument is needed to tell
  certmonger which service principal is the subject
``-U id-kp-serverAuth``
  Add an *extended key usage* certificate extension request
  asserting that the certificate is for TLS WWW authentication.

Another important argument is ``-N <subject-name>`` but this
defaults to the system hostname, which in our case
(``client.ipademo.local``) was appropriate.

Let's check the status of our certificate request using the tracking
identifier given in the ``ipa-getcert request`` output::

  [client]$ sudo getcert list -i 20151026222558
  Number of certificates and requests being tracked: 1.
  Request ID '20151026222558':
          status: MONITORING
          stuck: no
          key pair storage: type=NSSDB,location='/etc/httpd/alias',nickname='app',token='NSS Certificate DB'
          certificate: type=NSSDB,location='/etc/httpd/alias',nickname='app',token='NSS Certificate DB'
          CA: IPA
          issuer: CN=Certificate Authority,O=IPADEMO.LOCAL
          subject: CN=client.ipademo.local,O=IPADEMO.LOCAL
          expires: 2017-10-26 22:26:00 UTC
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

You can also see that the certificate is present in the NSS
database, identified by the specified nickname::

  [client]# sudo certutil -d /etc/httpd/alias -L -n app
  Certificate:
      Data:
          Version: 3 (0x2)
          Serial Number: 11 (0xb)
          Signature Algorithm: PKCS #1 SHA-256 With RSA Encryption
          Issuer: "CN=Certificate Authority,O=IPADEMO.LOCAL"
          Validity:
              Not Before: Mon Oct 26 22:26:00 2015
              Not After : Thu Oct 26 22:26:00 2017
          Subject: "CN=client.ipademo.local,O=IPADEMO.LOCAL"
    ...


Now we can reconfigure Apache to serve our app over TLS.  Update
``app.conf`` to listen on port 443 and add the NSS directives::

  ...

  Listen 443

  <VirtualHost *:443>
      NSSEngine on
      NSSCertificateDatabase /etc/httpd/alias
      NSSNickname app
      NSSCipherSuite +rsa_rc4_128_md5,+rsa_rc4_128_sha,+rsa_3des_sha,-rsa_des_sha,-rsa_rc4_40_md5,-rsa_rc2_40_md5,-rsa_null_md5,-rsa_null_sha,+fips_3des_sha,-fips_des_sha,-fortezza,-fortezza_rc4_128_sha,-fortezza_null,-rsa_des_56_sha,-rsa_rc4_56_sha,+rsa_aes_128_sha,+rsa_aes_256_sha

      ServerName client.ipademo.local
      ...


Restart Apache and make a request to the app over HTTPS::

  [client]$ sudo systemctl restart httpd
  [client]$ curl -u : --negotiate https://client.ipademo.local
  LOGGED IN AS: alice@IPADEMO.LOCAL

  REMOTE_* REQUEST VARIABLES:

    REMOTE_USER_MAIL: alice@ipademo.local
    REMOTE_USER_GECOS: Alice Able
    REMOTE_USER: alice@IPADEMO.LOCAL
    REMOTE_USER_GROUP_N: 1
    REMOTE_ADDR: 192.168.33.20
    REMOTE_USER_FIRSTNAME: Alice
    REMOTE_USER_LASTNAME: Able
    REMOTE_USER_GROUP_1: ipausers
    REMOTE_PORT: 47894
