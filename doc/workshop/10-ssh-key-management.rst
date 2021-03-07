Unit 10: SSH user and host key management
=========================================

**Prerequisites:**

- `Unit 3: User management and Kerberos authentication <3-user-management.rst>`_

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
  SHA256:KZ1MQCvaGAGZxKaMxmWBexzH98NPBsTsuo1uf/42SB0 alice@ipademo.local
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
    SSH public key fingerprint: C4:62:89:7A:65:F9:82:12:EF:08:96:D1:C9:7D:51:A5 alice@ipademo.local
                                (ssh-rsa)
    Account disabled: False
    Password: True
    Member of groups: ipausers, sysadmin
    Indirect Member of Sudo rule: sysadmin_sudo
    Indirect Member of HBAC rule: sysadmin_all
    Kerberos keys available: True

During enrolment of the systems, SSSD has been configured to use
FreeIPA as one of its identity domains and OpenSSH has been
configured to use SSSD for managing user keys.

If you have disabled the ``allow_all`` HBAC rule, add a new rule
that will **allow ``alice`` to access the ``sshd`` service on any
host**.

Logging in to the server using SSH public key authentication should
now work::

  [alice@client]$ ssh -o GSSAPIAuthentication=no server.ipademo.local
  Enter passphrase for key '/home/alice/.ssh/id_rsa':
  Last login: Tue Feb  2 15:10:13 2016
  [alice@server]$

To verify that the SSH public key was used for authentication, you
can check the ``sshd`` log on the server::

  [server]$ sudo journalctl -u sshd -S "5 minutes ago" --no-pager
  -- Logs begin at Mon 2018-06-04 19:01:11 UTC, end at Mon 2018-06-11 04:55:19 UTC. --
  Jun 11 04:51:52 server.ipademo.local sshd[8570]: Accepted publickey for alice from 192.168.33.20 port 57596 ssh2: RSA SHA256:KZ1MQCvaGAGZxKaMxmWBexzH98NPBsTsuo1uf/42SB0


Using FreeIPA as a backend store for SSH host keys
--------------------------------------------------

OpenSSH uses public keys to authenticate hosts.  When a client
attempts to log in over SSH, the target host presents its public
key.  The first time the host authenticates, the user may have to
examine the target host's public key and manually authenticate it.
The client then stores the host's public key in a ``known_hosts``
file.  On subsequent attempts to log in, the client checks its
``known_hosts`` files.  If the presented host key does not match the
stored host key, the OpenSSH client refuses to continue.

Based on the last exercise, try to figure out how to upload SSH host
keys to the FreeIPA server.

**Note:** OpenSSH has already been configured to look up known hosts
on the FreeIPA server, so no manual configuration is required for
this section.
