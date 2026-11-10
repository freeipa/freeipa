# macOS administration client (experimental)

This provider is intended for a native Python administration process on macOS
using explicit IPA configuration and existing Kerberos credentials. It does not
implement host enrolment, service management, SSSD, PAM, login integration or
server operation. Adding a provider does not establish general macOS support.

## Implementation boundary

Darwin already maps to `macos` in `ipaplatform.osinfo`. The provider supplies the
existing paths/constants/tasks/services interfaces and is included in the
explicit setuptools package list. It reuses base IPA configuration paths;
`IPA_CONFDIR` selects an application-specific directory, including the platform
CA and default configuration paths. Set it before importing IPA modules.
The host-installation package rejects import on Darwin before installation
code can modify local credentials or files. Unsupported service
management raises `NotImplementedError`. Host configuration tasks retain the
base unsupported behavior, with explicit errors for base installation hooks
that otherwise do nothing, and for resolver/NSS/automount mutations.

A generic remote-administration provider could eventually remove more host
assumptions, but would require a new platform-selection and support contract.
The dedicated provider fits the current Darwin detection without changing Linux
selection. A Linux override is not a supported macOS installation strategy.

The session-storage correction is tracked separately in
[PR #8708](https://github.com/freeipa/freeipa/pull/8708). It is not part of this
provider patch: `krb5_build_principal` is variadic, and
its ctypes `argtypes` must list only the four fixed parameters. Apple arm64
passes variadic arguments differently from fixed arguments. Call sites already
wrap the additional arguments explicitly. See the Python
[ctypes documentation](https://docs.python.org/3/library/ctypes.html#calling-variadic-functions).

## Native environment tested

Local validation used macOS 26.7.2, Darwin 25.6.0, arm64, Homebrew Python
3.12.16 and Homebrew MIT Kerberos 1.22.2 (`1.22.2_2` formula revision), with
python-gssapi 1.12.0 compiled against that MIT installation. System-default
Python 3.15.2 was inventoried but was not the validation interpreter.
The source revision was `f82a8548811cd19e3a9e3100506a976f6d498e0b`.

Local automated checks establish provider discovery, import and explicit
client bootstrap. The synthetic FILE-cache round trip was validated separately
with the ABI correction and is not evidence from this provider-only patch.

The operator additionally reports successful authenticated DNS-record and host
creation on macOS with the combined downstream setup. These are user-reported
results; no internal configuration or logs are included, and the isolated-realm
acceptance matrix has not been executed. They do not establish idempotence,
removal, check mode, expired-ticket handling or support for every client plugin.
Apple Kerberos and vault operations remain unverified.

## Dependency and configuration setup

Use a virtual environment. Native dependencies include Kerberos, OpenLDAP
(the DN implementation uses libldap even without LDAP administration), and
the dependencies declared by the four Python packages. This procedure assumes
Homebrew dependencies are already installed; installing them is a separate
machine setup step. Intel Homebrew paths differ and have not been tested.

```sh
/opt/homebrew/opt/python@3.12/bin/python3.12 -m venv /tmp/ipa-client-venv
source /tmp/ipa-client-venv/bin/activate
export GSSAPI_KRB5CONFIG=/opt/homebrew/opt/krb5/bin/krb5-config
export GSSAPI_MAIN_LIB=/opt/homebrew/opt/krb5/lib/libgssapi_krb5.dylib
export GSSAPI_COMPILER_ARGS="$(/opt/homebrew/opt/krb5/bin/krb5-config --cflags gssapi)"
export GSSAPI_LINKER_ARGS="$(/opt/homebrew/opt/krb5/bin/krb5-config --libs gssapi)"
python -m pip install --no-binary=gssapi --no-cache-dir gssapi==1.12.0
```

Specifying `krb5-config` alone does not override python-gssapi's default Apple
framework linkage. `GSSAPI_MAIN_LIB` also directs extension detection to MIT:
linking against MIT alone can still omit the credential-store extension.
Verify linkage with `otool -L` and confirm that
`gssapi.raw.acquire_cred_from` is available before using an explicit cache.
Use matching versions of the patched `ipapython`, `ipaplatform`, `ipalib` and
`ipaclient` wheels, built using the project's existing build process. During
local validation, generated metadata was substituted from source templates
with development version `4.14.0.dev0`, API `2.258`, plugin defaults from
`API.txt` and the installed MIT build version; a complete Autoconf build on
macOS has not been validated. Do not mix these wheels with released 4.13.1
components, whose metadata requires matching package versions.

Launch the Python process with the same MIT library directory used by gssapi:

```sh
export IPA_CONFDIR=/absolute/path/to/test-ipa-config
export KRB5_CONFIG="$IPA_CONFDIR/krb5.conf"
export KRB5CCNAME="FILE:$IPA_CONFDIR/test.ccache"
```

For direct native Python execution, set the loader directory when launching
the interpreter itself, without an intervening protected system launcher:

```sh
DYLD_LIBRARY_PATH=/opt/homebrew/opt/krb5/lib /absolute/path/to/venv/bin/python client.py
```

The session-storage loader still uses `libkrb5.dylib`. Verify its actual
resolved library as well as gssapi linkage. Local checks confirmed MIT via
`dladdr`; the environment variable alone is not proof. Protected macOS
launchers can remove `DYLD_*` variables, so this direct-launch example is not a
recipe for every shell script or automation wrapper. This provider patch does
not add a runtime library override or a downstream build/launcher helper.

Create `default.conf` in that directory, replacing only the example test-server
configuration with the isolated realm's values:

```ini
[global]
host = controller.ipa.test
domain = ipa.test
realm = IPA.TEST
server = ipa.ipa.test
xmlrpc_uri = https://ipa.ipa.test/ipa/xml
jsonrpc_uri = https://ipa.ipa.test/ipa/json
basedn = dc=ipa,dc=test
enable_ra = True
```

Copy the isolated server's public IPA CA certificate to `ca.crt` through a
trusted channel. Do not disable TLS verification. Create a private `krb5.conf`
pointing at that KDC and acquire credentials with the same Homebrew MIT `kinit`,
using the explicit FILE cache. Do not change global macOS authentication
configuration or assume that an Apple API cache is interchangeable.

```python
from ipalib import api

api.bootstrap(context="client", in_server=False, in_tree=False, log=None)
api.finalize()
api.Backend.rpcclient.connect()
try:
    api.Command.ping()
finally:
    if api.Backend.rpcclient.isconnected():
        api.Backend.rpcclient.disconnect()
```

Finalisation normally discovers the remote command schema and can contact the
server before an explicit backend connection. A missing CA is rejected before
that connection. Offline bootstrap does not prove successful finalisation.
Client plugins, notably vault, perform local processing; vault support must be
assessed separately using synthetic secrets in a disposable vault.

## Validation and limitations

Run the new Darwin/provider tests with the upstream pytest harness.
The macOS bootstrap smoke test explicitly disables source-tree/server mode.
The session-storage regression belongs to the separate ABI contribution.

Linux CI must run the relevant platform and session-storage tests, plus
`make fasttest` and `make fastlint` in a configured build. Those checks have
not been completed on Linux. Existing platform tests assume Linux accounts,
RPM version handling and Linux container detection; their behavior on macOS
needs separate test-harness work. Do not interpret mocked discovery or Linux
provider imports on a Mac as Linux runtime validation.

Ansible validation used ansible-core 2.21.6 and
`freeipa.ansible_freeipa` 1.17.0: `ipadnsrecord` and its common bindings imported
with no recorded bindings import error. The operator subsequently reported
successful DNS-record and host creation with the combined downstream setup;
these operations were not reproduced in an isolated realm by the agent.
Set `ipaapi_context: client`, use the native virtual-environment interpreter,
and pass the explicit IPA/Kerberos configuration to the delegated localhost task.
Verify the selected native libraries in the actual delegated interpreter;
setting a loader variable before a protected launcher is insufficient. The collection maps client context to IPA's
CLI context, so its finalisation path is distinct from the bootstrap smoke
test. Check mode, creation, idempotence and removal require the isolated server.
