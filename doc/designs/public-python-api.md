# Public Python API

## Overview

The public Python API provides a stable and high-level interface to
IPA's internal Python API with long-term support.


## ipalib.api shouldn't be used directly

While IPA's Python API is very powerful, it's not the design for end
users.

* Several lines of boiler plate code are required to initialize
  the API, before it can be consumed. The boiler plate differs for
  remote RPC connections and in-server LDAP connections.
* The API objects exposes internal implementation details and internal
  helpers, that are neither stable interfaces nor functions that
  should not be used directly. The API objects don't make it obvious
  which elements of the interface are public and stable.
* The Python API is not easily explorable and introspectable in an
  interactive console. The ``help()`` function does not return useful
  information. The output of ``dir()`` or ``APICommand`` methods
  is hard to understand without deep knowledge of the API.

### ipalib.api example

Initialize the API:
```
from ipalib import api
api.bootstrap()
api.finalize()
if api.env.in_server:
   # in-server LDAP connection
   api.backend.ldap2.connect()
else:
    # remote JSON RPC
    api.Backend.rcpclient.connect()
```

Introspect the API:
```
>>> def get_public(obj):
...     """Return public members"""
...     return sorted(k for k in dir(obj) if not k.startswith('_'))
...
>>> get_public(api)
['Backend', 'Command', 'Method', 'Object', 'Updater', 'add_module',
 'add_package', 'add_plugin', 'bases', 'bootstrap',
 'bootstrap_with_global_options', 'build_global_parser', 'env',
 'finalize', 'get_plugin_next', 'is_production_mode', 'isdone',
 'load_plugins', 'log', 'packages', 'parser']
>>> api.Command
<ipalib.plugable.APINameSpace object at 0x7f561426a7f0>
>>> get_public(api.Command)
['get', 'get_plugin', 'items', 'keys', 'values']
>>> api.Command.items()
ItemsView(<ipalib.plugable.APINameSpace object at 0x7f561426a7f0>)
>>> len(api.Command.items())
474
```

Introspect an API command:
```
>>> list(api.Command.items())[62]
(<class 'ipaclient.plugins.cert.cert_find'>, ipaclient.plugins.cert.cert_find())
>>> get_public(api.Command.cert_find)
['Backend', 'Command', 'NO_CLI', 'add_message', 'api', 'api_version',
 'args', 'args_options_2_entry', 'args_options_2_params', 'attr_name',
 'bases', 'callback_types', 'check_args', 'context', 'convert',
 'critical', 'debug', 'doc', 'ensure_finalized', 'env', 'error',
 'exception', 'execute', 'extra_args_first', 'extra_options_first',
 'finalize', 'finalize_attr', 'forward', 'forwarded_name', 'full_name',
 'get_args', 'get_callbacks', 'get_default', 'get_default_of',
 'get_options', 'get_output_params', 'get_summary_default',
 'has_output', 'has_output_params', 'info',
 'interactive_prompt_callback', 'internal_options',
 'json_friendly_attributes', 'log', 'log_messages', 'msg_summary',
 'msg_truncated', 'name', 'next', 'normalize', 'obj', 'obj_full_name',
 'obj_name', 'obj_version', 'options', 'output', 'output_for_cli',
 'output_params', 'params', 'params_2_args_options',
 'params_by_default', 'prompt_param', 'register_callback',
 'register_interactive_prompt_callback', 'run', 'summary',
 'takes_args', 'takes_options', 'topic', 'use_output_validation',
 'validate', 'validate_output', 'verify_client_version', 'version',
 'warning']
>>> help(api.Command.cert_find)
Traceback (most recent call last):
...
KeyError: <class 'ipaclient.frontend.MethodOverride'>
```


## Rational for an API facade package

An API facade has multiple benefits:

* It limits the scope of the supported interface to a manageable
  yet useful subset of attributes and commands.
* The abstraction layer makes it easier to provide backwards
  compatibility for APIs. It's not necessary to implement backwards
  compatibility in server plugins. Shims can be added directly to the
  facade API instead. In some cases it may be even possible to provide
  forward compatible enhancements.
* A separate package makes it possible to provide high level
  abstractions for older versions of IPA without changing the existing
  IPA packages.
* A facade package can be used to declare which Python classes and
  functions are considered stable with long term supported.

## Delivery

The public Python API is delivered as a separate Python package. The
Python package can either be used with official RPM packages from
Fedora, CentOS, and RHEL. Or it can be used with Python wheels from
PyPI. The package is compatible with Python versions 2.7 and 3.6+, and
IPA version 4.6 and newer. Backwards compatibility with IPA 4.5 is
possible with little extra effort.

The package provides a simple function that returns an initialized
API facade object. For most use cases, the API facade behaves like a
standard IPA API object. Internally the API facade wraps
``ipalib.api`` and provides a limit view of its features.

* Only ``api.env`` and ``api.Command`` are available. The objects
  ``api.Backend``, ``api.Method``, ``api.Object``, and ``api.Updater``
  as well as methods like ``api.bootstrap()`` are not exposed.
* The ``env`` attribute of the API facade provides a limit, read-only
  view of ``api.env``. Only some white-listed attributes like
  ``domain``, ``realm``, and ``basedn`` are available.
* The ``Command`` attribute provides access to the RPC interface. Only
  public commands are available (``NO_CLI`` is not True). Each command
  is a callable object with very few additional attributes (**TBD**).
  Since the ``Command`` attribute is a wrapper around
  ``ipalib.api.Command``, it provides features like auto-discovery of
  custom server-side plugins or server-side modifications.

Additionally to the API facade, the public API package exposes some
Python helpers from the ``ipaclient``, ``ipalib``, ``ipaplatform``, and
``ipapython`` packages. The scope of is to be determined.

* The ``errors`` sub-module contains a limit set of useful, public
  exceptions from ``ipalib.errors``.
* The ``DN`` class from ``ipapython.dn``.

All members, functions and attributes are part of the stable API
unless they are prefixed with an underscore (``_``).

# Exported API

```
get_api(
    context='ipaapi',
    confdir=default,
    tls_ca_cert=default,
    in_server=default,
    fallback=default,
    delegate=default,
    server=default,
    host=default,
    ca_host=default,
    debug=default,
    force_schema_check=default
) -> IPAAPI
```


## Existing python helpers

* ``DN`` from ``ipapython.dn``

* ``Principal`` from ``ipapython.kerberos``

## Exception objects

``ipaapi.errors`` exports a limited set of public exceptions from
``ipalib.errors``.

## Version

``ipaapi.version`` exports ``VERSION``, ``NUM_VERSION``, and
``API_VERSION`` from ``ipapython.version``.

## New Python helpers

* ``is_client_configured``
* ``is_server_configured``

## To be considered?

The API factory function should have some helpers to authenticate with
a keytab, user/password, and to deal with ccache (authenticate from
an existing ccache, refresh TGT, clear ccache on exit).

* Novajoin uses ``ipalib.install.kinit.kinit_keytab()``, however that
  function is not available in PyPI packages.

* login with username and password, https://pagure.io/freeipa/issue/7760

* ``krb5_format_service_principal_name`` and related from ``ipalib.krb_utils``

* wrapper around ``ipa-getkeytab``?

* ``ipapython.dnsutil.DNSName`` can be substituted by ``dns.name.Name``.

* ``ipalib.x509.IPACertificate`` can be substituted by
  ``cryptography.x509.Certificate``.

* modify logging and disable logging to stdout/stderr, see
  https://github.com/freeipa/ansible-freeipa/issues/67

* reconfigure logging (``~/.ipa/log``) and cache
  (``~/.cache/ipa``) directories

* cleanup log files

* reset schema cache / force_schema_check

* send / limit API version?

* fetch CA certificates from LDAP protected by Kerberos auth.

* manage ccache

# External applications that use ipalib / ipaclient

## Ansible FreeIPA

* https://github.com/freeipa/ansible-freeipa/blob/master/roles/ipaclient/module_utils/ansible_ipa_client.py
* https://github.com/freeipa/ansible-freeipa/blob/master/roles/ipaserver/module_utils/ansible_ipa_server.py
* https://github.com/freeipa/ansible-freeipa/blob/master/roles/ipareplica/module_utils/ansible_ipa_replica.py

## OpenStack

* https://github.com/openstack/novajoin/blob/master/novajoin/ipa.py
* https://github.com/openstack/novajoin/blob/master/scripts/novajoin-ipa-setup
* https://github.com/openstack/novajoin/blob/master/novajoin/configure_ipa.py

## Custodia

* https://github.com/latchset/custodia/blob/master/src/custodia/ipa/interface.py
* https://github.com/latchset/custodia/blob/master/src/custodia/ipa/certrequest.py

## Community Portal

* https://github.com/freeipa/freeipa-community-portal/blob/master/install/create-portal-user
* https://github.com/freeipa/freeipa-community-portal/tree/master/freeipa_community_portal/model