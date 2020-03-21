Unit 9: SELinux User Maps
=========================

**Prerequisites**:

- `Unit 3: User management and Kerberos authentication <3-user-management.rst>`_
- `Unit 4: Host-based access control (HBAC) <4-hbac.rst>`_
- `Unit 8: Sudo rule management <8-sudorule.rst>`_

SELinux is a *mandatory access controls* mechanism for Linux,
providing more powerful and flexible access control than traditional
Unix permissions.  Users have an SELinux *context* consisting of a
*user*, *role* and *type*.  In this unit, you will cause users
to be *confined* by an SELinux *role-based access control (RBAC)*
policy when the log into hosts that are members of the
``webservers`` Host Group.  You will also learn how to change a
user's SELinux context when they execute commands via Sudo.

**Note:** SELinux contexts are applied during PAM-based login, so
when testing our changes in this unit ``su -l <user>`` will not
suffice: it is necessary to log in via SSH.  You can do this from
any of the VMs (even ``client`` itself).

Confining users
---------------

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

  sh-4.4# id
  uid=0(root) gid=0(root) groups=0(root) context=staff_u:staff_r:staff_t:s0-s0:c0.c1023

  sh-4.4# echo "Hello, world!" > /etc/motd
  sh: /etc/motd: Permission denied

As you can see, ``alice`` became ``root``, but the SELinux
confinement prevents her from writing ``/etc/motd`` (and many other
things).  Let's make it so that ``alice`` can do her job.  We need
to update the Sudo rule to change the SELinux context::

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

  sh-4.4# id -Z
  staff_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

  sh-4.4# echo "Hello, world!" > /etc/motd

  sh-4.4# cat /etc/motd
  Hello, world!

This concludes the unit.  You can now proceed to
`Unit 10: SSH user and host key management <10-ssh-key-management.rst>`_
or
`return to the curriculum overview <workshop.rst#curriculum-overview>`_
to see all the available topics.
