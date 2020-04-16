.. AUTO-GENERATED FILE, DO NOT EDIT!

=========================================
ipactl(8) -- IPA Server Control Interface
=========================================

SYNOPSIS
========

ipactl *command*

DESCRIPTION
===========

A tool to help an administer control an IPA environment.

IPA glues several discrete services together to work in concert and the
order that these services are started and stopped is important. ipactl
ensures that they are started and stopped in the correct order.

IPA stores the available masters and the services configured on each
one. The first thing ipactl does is start (if it is not already running)
the IPA 389-ds instance to query what services it controls. The hostname
used in the query needs to match the hostname of the value stored in
LDAP. This can be controlled with the host option in
*/etc/ipa/default.conf*. This should be a fully-qualified hostname.

OPTIONS
=======

start
   Start all of the services that make up IPA

stop
   Stop all of the services that make up IPA

restart
   Stop then start all of the services that make up IPA

status
   Provides status of all the services that make up IPA

.. option:: -d, --debug

   Display debugging information

.. option:: --skip-version-check

   Skip version check

.. option:: --ignore-service-failures

   If any service start fails, do not rollback the services, continue
   with the operation

.. option:: -f, --force

   Force IPA to start. Combine options --skip-version-check and
   --ignore-service-failures
