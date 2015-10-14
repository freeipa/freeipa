..
  Copyright 2015  Red Hat, Inc.

  This work is licensed under the Creative Commons Attribution 4.0
  International License. To view a copy of this license, visit
  http://creativecommons.org/licenses/by/4.0/.


Title
=====

Identity Management with FreeIPA


Brief Description
=================

FreeIPA is a centralised identity management system.  In this
workshop, learn how to deploy FreeIPA servers and enrol client
machines, define and manage user, host and service identities, set
up access policies, issue digital certificates and configure network
services to take advantage of FreeIPA's authentication and
authorisation capabilities.


Abstract
========

FreeIPA is an integrated identity management solution providing
centralised user, host and service management, authentication and
authorisation in Linux/UNIX networked environments, with a focus on
ease of deployment and management.  It is built on top of well-known
Open Source technologies and standards including 389 Directory
Server, MIT Kerberos and Dogtag Certificate System.

This hand-on workshop will provide participants with a comprehensive
introduction to FreeIPA including server deployment and
administration, client machine enrolment, and configuring server
software to use FreeIPA's centralised identity and policy store.

Participants will:

- Install a FreeIPA server and replica
- Enrol client machines in the domain
- Create and administer users
- Manage host-based access control (HBAC) policies
- Issue X.509 certificates for network services
- Configure a web server to use FreeIPA for user authentication and
  access control

There will be a number of elective units which participants can
choose, based on their progress and particular use cases:

- OTP two-factor authentication
- Advanced certificate management: profiles, sub-CAs and user
  certificates
- OpenSSH key management
- Federated identity with Ipsilon
- User self-service secret management
- ...and more!

Project URL: http://www.freeipa.org/


Additional notes
================

The workshop will begin with a short presentation about FreeIPA,
concurrently with a demonstration of the install process (which
takes several minutes).  Participants will then install a FreeIPA
server themselves, and begin working through the curriculum.  At
intervals supporting material, topics for further exploration, and
abbreviated walkthroughs of the core curriculum modules will be
presented.

Participants will deploy the server and client machines either on a
public cloud (conditional on Internet access and finding a willing
sponsor) or on their own hypervisor.  The precise format is yet to
be determined.  Hardware/software requirements and expected
preparation will be communicated in advance of the conference.


Speaker Bio
===========

Fraser is an identity management engineer at Red Hat where he works
on FreeIPA and the Dogtag Certificate System.  He cares about
security and cryptography (and making it easier for humans to get
right!) and is deeply interested in functional programming, type
theory and theorem proving.
