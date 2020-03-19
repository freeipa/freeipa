Unit 8: Sudo rule management
============================

**Prerequisites**:

- `Unit 3: User management and Kerberos authentication <3-user-management.rst>`_
- `Unit 4: Host-based access control (HBAC) <4-hbac.rst>`_

Sudo is a program that allows users to run programs as another user
with different privileges (possibly ``root``).  Sudo rules provide
fine-grained control over who can execute which processes, as which
users.  FreeIPA allows centralised management of Sudo rules.  To
simplify management, Sudo rules can refer to User Groups, Host
Groups and *Command Groups* as well as individual users, hosts and
commands.

Older versions of sudo did not require pam access for passwordless
rules (e.g. rules with the NOPASSWD keyword).
sudo-1.8.23 and newer require pam access for all rules.

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

**Note:** if the command is prevented there may be some stale cache
entries.  Move on with the workshop and try again in 5 minutes.


Permitting ``bob`` to run web administration commands
-----------------------------------------------------

Now let us turn our attention to ``bob``.  The goal is to allow
``bob`` and other web servers administrators to run commands related
to web server administration (and only such commands).

First, create a new User Group named ``webadmin`` and add ``bob`` as a
member.  Add an ``hbacrule`` that allows ``bob`` to log into hosts
that are members of the ``webservers`` Host Group using the ``sshd``
service.

Once this is done you should be able to login, but not use ``su -l``::

  [client]$ su -l bob
  Password:

  [bob@client]$ su -l bob
  Password:
  su: Permission denied

Then, let's observe that ``bob`` currently cannot restart Apache::

  [bob@client]$ sudo systemctl restart httpd
  [sudo] password for bob:
  sudo: PAM account management error: Permission denied

Take note that the error is different from the one alice got, which was::

  alice is not allowed to run sudo on client.  This incident will be reported.

While the HBAC rule alice uses (sysadmin_webservers) was created with
"--servicecat=all", the HBAC rule for bob was created with sshd in mind,
like this::

  [server]$ ipa hbacrule-add-service webadmin_webservers --hbacsvcs=sshd

As bob needs to run both ``su -l`` and ``sudo``, add both commands to
the list of allowed services in your access control rule, for instance::

  [server]$ ipa hbacrule-add-service webadmin_webservers \
      --hbacsvcs=sudo --hbacsvcs=su-l

Now login and logout as bob. Not only bob should now be able to use
``su -l``, but the error message from ``sudo`` should change::

  [bob@client]$ sudo systemctl restart httpd
  [sudo] password for bob:
  Sorry, user bob is not allowed to execute '/bin/systemctl restart httpd' as root on client.ipademo.local.

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


This concludes the unit.  Now that you have Sudo rules working,
proceed to `Unit 9: SELinux User Maps <9-selinux-user-map.rst>`_.
