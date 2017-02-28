# IPA Server

## Overview

FreeIPA allows Linux administrators to centrally manage identity,
authentication and access control aspects of Linux and UNIX systems
by providing simple to install and use command line and web based
managment tools.
FreeIPA is built on top of well known Open Source components and standard
protocols with a very strong focus on ease of management and automation
of installation and configuration tasks.
FreeIPA can seamlessly integrate into an Active Directory environment via
cross-realm Kerberos trust or user synchronization.

## Benefits

FreeIPA:
* Allows all your users to access all the machines with the same credentials
  and security settings
* Allows users to access personal files transparently from any machine in
  an authenticated and secure way
* Uses an advanced grouping mechanism to restrict network access to services
  and files only to specific users
* Allows central management of security mechanisms like passwords,
  SSH Public Keys, SUDO rules, Keytabs, Access Control Rules
* Enables delegation of selected administrative tasks to other power users
* Integrates into Active Directory environments

## Components

The FreeIPA project provides unified installation and management
tools for the following components:
* LDAP Server - based on the 389 project (LDAP)
  http://directory.fedoraproject.org/wiki/Main_Page
* KDC - based on MIT Kerberos implementation
  http://k5wiki.kerberos.org/wiki/Main_Page
* PKI based on Dogtag project
  http://pki.fedoraproject.org/wiki/PKI_Main_Page
* Samba libraries for Active Directory integration
  http://www.samba.org/
* DNS Server based on BIND and the Bind-DynDB-LDAP plugin
  https://www.isc.org/software/bind
  https://pagure.io/bind-dyndb-ldap

## Project Website

Releases, announcements and other information can be found on the IPA
server project page at http://www.freeipa.org/.

## Documentation

The most up-to-date documentation can be found at
http://freeipa.org/page/Documentation.

## Quick Start

To get started quickly, start here:
http://www.freeipa.org/page/Quick_Start_Guide

## Licensing

Please see the file called COPYING.

## Contacts

   * If you want to be informed about new code releases, bug fixes,
     security fixes, general news and information about the IPA server
     subscribe to the freeipa-announce mailing list at
     https://www.redhat.com/mailman/listinfo/freeipa-interest/.

   * If you have a bug report please submit it at:
     https://bugzilla.redhat.com

   * If you want to participate in actively developing IPA please
     subscribe to the freeipa-devel mailing list at
     https://www.redhat.com/mailman/listinfo/freeipa-devel/ or join
     us in IRC at irc://irc.freenode.net/freeipa
