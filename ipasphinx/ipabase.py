#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""IPA API initialization for Sphinx
"""
import os
import re
import sys

from sphinx.util import progress_message
from sphinx.ext.autodoc import mock as autodoc_mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, os.pardir))
VERSION_M4 = os.path.abspath(os.path.join(ROOT, "VERSION.m4"))

if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


ipa_mock_imports = [
    # no binary wheels available
    "dbus",
    "gssapi",
    "ldap",
    "ldif",  # python-ldap
    "ldapurl",  # python-ldap
    # dogtag-pki is client-only
    "pki",
    # PyPI packages not available
    "pyhbac",
    "pysss",
    "pysss_murmur",
    "pysss_nss_idmap",
    "samba",
    "SSSDConfig",
]


def parse_version_m4(filename=VERSION_M4):
    """Poor man's macro parser for VERSION.m4
    """
    def_re = re.compile(r"^define\(([\w]+)+,\s*(.*)\)\s*$")
    defs = {}

    with open(filename) as f:
        for line in f:
            mo = def_re.match(line)
            if mo is not None:
                k, v = mo.groups()
                try:
                    v = int(v)
                except ValueError:
                    pass
                defs[k] = v

    defs["IPA_NUM_VERSION"] = (
        "{IPA_VERSION_MAJOR:d}"
        "{IPA_VERSION_MINOR:02d}"
        "{IPA_VERSION_RELEASE:02d}"
    ).format(**defs)

    defs["IPA_API_VERSION"] = (
        "{IPA_API_VERSION_MAJOR}.{IPA_API_VERSION_MINOR}"
    ).format(**defs)

    if defs["IPA_VERSION_IS_GIT_SNAPSHOT"] == "yes":
        defs["IPA_GIT_VERSION"] = ".dev"
    else:
        defs["IPA_GIT_VERSION"] = ""

    defs["IPA_VERSION"] = (
        "{IPA_VERSION_MAJOR}."
        "{IPA_VERSION_MINOR}."
        "{IPA_VERSION_RELEASE}"
        "{IPA_VERSION_PRE_RELEASE}"
        "{IPA_GIT_VERSION}"
    ).format(**defs)
    return defs


def fake_ipaython_version(defs):
    """Fake ipapython.version module

    We don't want and cannot run autoconf on read the docs. Fake the auto-
    generated ipapython.version module.
    """

    class FakeIpapythonVersion:
        __name__ = "ipapython.version"

        VERSION = defs["IPA_VERSION"]
        VENDOR_VERSION = defs["IPA_VERSION"]
        NUM_VERSION = defs["IPA_NUM_VERSION"]
        API_VERSION = defs["IPA_API_VERSION"]
        DEFAULT_PLUGINS = frozenset()

    fake = FakeIpapythonVersion()
    sys.modules[fake.__name__] = fake


def init_api(
    context="doc",
    domain="ipa.example",
    server="server.ipa.example",
    in_server=True,
):
    import ipalib

    ipalib.api.bootstrap(
        context=context,
        in_server=in_server,
        logdir=None,
        log=None,
        domain=domain,
        realm=domain.upper(),
        server=server,
    )
    ipalib.api.finalize()
    return ipalib.api


def inject_mock_imports(app, config):
    """Add additional module mocks for ipaserver
    """
    mock_imports = set(getattr(config, "autodoc_mock_imports", []))
    mock_imports.update(ipa_mock_imports)
    config.autodoc_mock_imports = list(mock_imports)

    # ldap is a mocked package
    # ensure that ipapython.dn still use ctypes wrappers for str2dn/dn2str
    # otherwise api won't be able to initialize properly
    import ipapython.dn

    assert ipapython.dn.str2dn("cn=ipa") == [[("cn", "ipa", 1)]]


def init_ipalib_api(app, config):
    """Initialize ipalib.api

    1. Parse VERSION.m4
    2. Create fake ipapython.version module
    3. Initialize the API with mocked imports
    """
    defs = parse_version_m4()
    fake_ipaython_version(defs)

    with progress_message("initializing ipalib.api"):
        with autodoc_mock(config.autodoc_mock_imports):
            init_api(
                context=config.ipa_context,
                domain=config.ipa_domain,
                server=config.ipa_server_fqdn,
                in_server=config.ipa_in_server,
            )


def setup(app):
    app.setup_extension("sphinx.ext.autodoc")

    app.add_config_value("ipa_context", "doc", "env")
    app.add_config_value("ipa_domain", "ipa.example", "env")
    app.add_config_value("ipa_server_fqdn", "server.ipa.example", "env")
    app.add_config_value("ipa_in_server", True, "env")

    app.connect("config-inited", inject_mock_imports)
    app.connect("config-inited", init_ipalib_api)

    return {
        "version": "0.1",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
