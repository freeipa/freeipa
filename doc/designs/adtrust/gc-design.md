# Global Catalog service for FreeIPA

Global Catalog is a special service that exposes read-only information about
objects in FreeIPA domain in a way expected by the clients enrolled to Active
Directory environments. Active Directory domain controllers and other systems
use Global Catalog to search across the potentially multi-domain forest for the
information about users, groups, machines, and other types of objects.

A search in the Global Catalog service allows machines enrolled to an Active
Directory environment to efficiently maintain a relationship between internal
access control lists (ACLs) associated with the resources provided by the
machines, and the visual representation of the access controls for interaction
with users, locally and remotely.

The information stored in the Global Catalog represents a subset of the
information available at the specific domain controllers in Active Directory.

A detailed overview of Global Catalog structure and design in Active Directory
can be found at the following
[MSDN article](https://msdn.microsoft.com/en-us/library/how-global-catalog-servers-work(v=ws.10).aspx).

Since no native FreeIPA clients are expected to use Global Catalog for write
purposes, it is only accessible in read-only mode. Any change to the information
shall come through the domain controllers responsible for a domain in question.

## Prototype design

When original design for FreeIPA Global Catalog was planned in [the design page](https://www.freeipa.org/page/V4/Global_Catalog_Support),
an idea was to reuse slapi-nis plugin functionality to generate LDAP entries
using Active Directory schema on the fly. However, this approach never took off
due to a slower development of 389-ds plugins to reuse components of slapi-nis.

Instead, current design attempts to build on existing code base in both FreeIPA
and 389-ds that allows quick prototyping in Python. Both FreeIPA and 389-ds
provide classes to represent LDAP objects and create separate LDAP server
instances. FreeIPA also has already implemented syncrepl handler that would
allow to update the content of a new LDAP instance based on the syncrepl
protocol exchanges.

### Requirements

* Global Catalog instance has to run on the same server as an IPA master.
* Global Catalog instance is exposed over TCP ports 3268 and 3269 (SSL)
* Global Catalog instance represents details about users and groups from primary
  FreeIPA data store in an LDAP schema and DIT compatible with Active Directory
* Global Catalog instance accepts GSS-SPNEGO authentication and maps any
  authenticated principal to an LDAP object that has read-only access rights
  over the GC LDAP tree
* Global Catalog instance updates come from a dedicated application over LDAPI
  protocol to allow mapping the identity of the updater to an LDAP object that
  has write privileges

### Minimal Viable Product

* Provide a tool to configure GC instance, `ipa-gc-install`
* Provide a synchronization daemon to sync data from IPA LDAP to GC instance
* Support IPA user and group objects in the synchronization daemon
* Allow Windows machines to resolve users and groups from IPA in Security tab
  when assigning permissions to resources on Windows machines
* Allow IPA users to log into Windows machines enrolled into a trusted Active
  Directory forest over bi-directional trust to AD

### Integration with primary FreeIPA data store

Global Catalog instance is a separate 389-ds LDAP instance that has no direct
relationship to the primary FreeIPA data store. The content from the primary
FreeIPA data store will be pulled in, transformed, and added to the Global
Catalog instance by an external application.

Global Catalog instance is decoupled from the primary FreeIPA LDAP instance due
to the following facts:

* 389-ds does not have means to bind to multiple TCP ports to serve separate
  LDAP subtrees
* Active Directory LDAP schema is not compatible with the LDAP schema used by
  FreeIPA

### LDAP instance design

Global Catalog LDAP instance DIT follows Active Directory DIT requirements. For
a minimal prototype, only users, groups, and machines will be exposed with their
basic attributes mapped. Following details will not be mapped:

* External group membership for users/groups from trusted domains
* Any IPA-specific attributes

The concept is to provide a minimal set of attributes as requested by Windows
clients when performing a lookup over Global Catalog when assigning permissions
to resources on Windows side.

#### Supported naming contexts

There are three naming contexts which exist in Active Directory: Schema Naming
Context, Configuration Naming Context, and Domain Naming Context. The scope for
Global Catalog service in FreeIPA is limited to Domain Naming Context in the
initial implementation.

#### Supported ports and protocols

FreeIPA Global Catalog service is only available over TCP port 3268 in the first
implementation phase. Retrieval and update of universal group membership cache
over TCP port 135 is not planned to be supported. The latter is a feature of
Active Directory used by its domain controllers over DCE RPC protocol stack.

Samba implements corresponding functionality for user and group name lookups
with the help of the primary FreeIPA LDAP server instance.

#### Global Catalog provisioning

The data in Global Catalog is provisioned from the primary LDAP server instance
running on the same FreeIPA master. A SYNCREPL mechanism is used to retrieve the
changes and an external Python application daemon is used to transform FreeIPA
original data to a schema compatible with Global Catalog in Active Directory.

The data is stored in a proper LDAP backend so it is persistent across the
directory server restarts.

#### GC tree structure

In Active Directory Global Catalog contains directory data for all domains in a
forest. For an Active Directory forest with multiple forest roots this means
multiple domain suffixes exist in the Global Catalog tree. For FreeIPA there is
only a single domain that corresponds to the forest tree and thus only a single
domain suffix is hosted in the Global Catalog.

Since FreeIPA is built around a flat DIT, there are no organizational units
available. As result, object-specific containers are children of the forest
domain suffix: e.g. for users a subtree of '''cn=users,dc=example,dc=com''' is
used.

#### GC schema mapping

There are two separate mapping processes: first, a data from the primary FreeIPA
LDAP instance needs to be mapped to a schema expected by Active Directory
clients consuming Global Catalog service. However, the Global Catalog schema
itself requires transformation so that it could be used in 389-ds directory
server environment.

#### FreeIPA schema to GC schema mapping

To perform data transformation from the primary FreeIPA LDAP instance to GC
instance, an external application that consumes original LDAP objects from the
primary FreeIPA LDAP instance will be written. For the Python based prototype,
it is easier and more convenient to perform this transformation in Python code,
by reusing existing `python-ldap` API and `ipapython.ipaldap` classes.

#### Equality and attribute syntax rules mapping

Global Catalog instance schema is derived from a schema published by Microsoft
through WSPP program as MS-ADSC document,
http://msdn.microsoft.com/en-us/library/cc221630.aspx. Schema files are
available in LDIF format from http://go.microsoft.com/fwlink/?LinkId=212555 and
processed with the help of a converting script. The script to convert schema to
389-ds format is based on a similar script from Samba (ms_schema.py) which only
supports non-validating output for LDB database. FreeIPA's version has to
generate valid schema in 389-ds format and thus adds mapping between schema
attribute definitions existing in 389-ds and MS-ADSC. In particular, attribute
types, their ordering and matching functions mapped to those of 389-ds.

{| border="1"
|+ Equality rules mapping
|-
! Original syntax !! Mapped syntax
|-
| 2.5.5.8 || booleanMatch
|-
| 2.5.5.9 || integerMatch
|-
| 2.5.5.16 || integerMatch
|-
| 2.5.5.14 || distinguishedNameMatch
|-
| 1.3.12.2.1011.28.0.702 || octetStringMatch
|-
| 1.2.840.113556.1.1.1.12 || distinguishedNameMatch
|-
| 2.5.5.7 || octetStringMatch
|-
| 2.6.6.1.2.5.11.29 || octetStringMatch
|-
| 1.2.840.113556.1.1.1.11 || octetStringMatch
|-
| 2.5.5.13 || caseIgnoreMatch
|-
| 2.5.5.10 || octetStringMatch
|-
| 2.5.5.3 || caseIA5Match
|-
| 2.5.5.5 || caseIA5Match
|-
| 2.5.5.15 || octetStringMatch
|-
| 2.5.5.6 || numericStringMatch
|-
| 2.5.5.2 || objectIdentifierMatch
|-
| 2.5.5.10 || octetStringMatch
|-
| 2.5.5.17 || caseExactMatch
|-
| 2.5.5.4 || caseIgnoreMatch
|-
| 2.5.5.12 || caseIgnoreMatch
|-
| 2.5.5.11 || generalizedTimeMatch
|}

{| border="1"
|+ Attribute syntax mapping
|-
! Original syntax !! Mapped syntax
|-
| 2.5.5.8 || 1.3.6.1.4.1.1466.115.121.1.7 
|-
| 2.5.5.9 || 1.3.6.1.4.1.1466.115.121.1.27
|-
| 2.5.5.16 || 1.3.6.1.4.1.1466.115.121.1.27
|-
| 2.5.5.14 || 1.3.6.1.4.1.1466.115.121.1.12
|-
| 1.3.12.2.1011.28.0.702 || 1.3.6.1.4.1.1466.115.121.1.5
|-
| 1.2.840.113556.1.1.1.12 || 1.3.6.1.4.1.1466.115.121.1.12
|-
| 2.5.5.7 || 1.3.6.1.4.1.1466.115.121.1.12
|-
| 2.6.6.1.2.5.11.29 || 1.3.6.1.4.1.1466.115.121.1.12
|-
| 1.2.840.113556.1.1.1.11 || 1.3.6.1.4.1.1466.115.121.1.12
|-
| 2.5.5.13 || 1.3.6.1.4.1.1466.115.121.1.43
|-
| 1.3.12.2.1011.28.0.732 || 1.3.6.1.4.1.1466.115.121.1.43
|-
| 2.5.5.10 || 1.3.6.1.4.1.1466.115.121.1.5
|-
| 1.2.840.11.3556.1.1.1.6 || 1.3.6.1.4.1.1466.115.121.1.5
|}

#### Auxiliary classes

Active Directory schema supports multiple inheritance through use of
auxiliaryClass and systemAuxiliaryClass attributes. 389-ds does not support
mechanism to specify multiple superior classes in the schema. In result, we need
to explicitly add these classes to the objects of a specific objectClass type on
creation.

#### Tree structure correctness

Active Directory schema describes types of objects that may contain the object
of a type through systemPossSuperiors and possSuperiors attributes. 389-ds does
not support this type enforcement. In result, we need to explicitly check these
requirements on the object creation rather than by using those attributes.

### Synchronization service design

Synchronization service is an external application (daemon) that runs
independently on IPA masters. The daemon is connected to the primary FreeIPA
LDAP instance over LDAPI socket and listens for changes with SYNCREPL mechanism.
Upon an arrival of an update, it determines whether this update should be
translated into Global Catalog's change. If the change is required, a
transformation is performed by the daemon.

In order to write to Global Catalog instance, the daemon connects to it over
LDAPI socket and binds with SASL EXTERNAL. Global Catalog is configured to
auto-bind such connection from the daemon identity to a special LDAP object that
has permissions to write to Global Catalog trees. As result, only updates
performed by this identity are allowed in Global Catalog.
