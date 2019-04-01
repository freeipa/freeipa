#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""FreeIPA API package -- internal API wrapper
"""
from __future__ import absolute_import

import os

from ipalib import api

from .env import Env
from .command import CommandNamespace
from .common import APIWrapper, default


class IPAAPI(APIWrapper):
    """IPA API wrapper
    """

    __slots__ = ("_env", "_command")

    def __init__(self, api):
        super(IPAAPI, self).__init__(api)
        # api object must be already finalized
        self._env = Env(self._api)
        self._command = CommandNamespace._create(self._api)

    def connect(self):
        """Establish connection to server"""
        if self._api.env.in_server:
            if not self._api.Backend.ldap2.isconnected():
                self._api.Backend.ldap2.connect()
        else:
            if not self._api.Backend.rpcclient.isconnected():
                self._api.Backend.rpcclient.connect()

    def disconnect(self):
        """Disconnect from server"""
        if self._api.env.in_server:
            if self._api.Backend.ldap2.isconnected():
                self._api.Backend.ldap2.disconnect()
        else:
            if self._api.Backend.rpcclient.isconnected():
                self._api.Backend.rpcclient.disconnect()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    @property
    def env(self):
        """IPA configuration environment"""
        return self._env

    @property
    def Command(self):
        """IPA commands"""
        return self._command


def get_api(
    context=u"ipaapi",  # type: Text
    confdir=default,  # type: Text
    tls_ca_cert=default,  # type: Text
    in_server=default,  # type: bool
    fallback=default,  # type: bool
    delegate=default,  # type: bool
    server=default,  # type: Text
    host=default,  # type: Text
    ca_host=default,  # type: Text
    debug=default,  # type: bool
    force_schema_check=default,  # type: bool
):
    """Create IPA API wrapper instance

    :param context: ipa context name
    :param confdir: path to an IPA config directory
    :param tls_ca_cert: path to a CA cert PEM bundle
    :param in_server: use local LDAP connection instead of RPC
    :param fallback: only use the server configured IPA config file?
    :param delegate: delegate the TGT to the IPA server
    :param server: server hostname
    :param host: local hostname override
    :param ca_host: CA hostname override
    :param debug: enable debug logging
    :param force_schema_check: download schema again
    :return: IPAAPI instance
    """
    # config options are deliberately limited
    # filter kwargs and pre-check arguments
    kwargs = {"context": context}
    if confdir is not default:
        if not os.path.isdir(confdir):
            raise ValueError("confdir {} does not exist.".format(confdir))
        kwargs["confdir"] = confdir
    if tls_ca_cert is not default:
        if not os.path.isfile(confdir):
            raise ValueError(
                "tls_ca_cert file {} does not exist.".format(tls_ca_cert)
            )
        kwargs["tls_ca_cert"] = tls_ca_cert
    if in_server is not default:
        # check that server is not overwritten when in_server?
        kwargs["in_server"] = bool(in_server)
    if fallback is not default:
        kwargs["fallback"] = bool(fallback)
    if delegate is not default:
        if delegate and in_server:
            raise ValueError("delegate and in_server are mutually exclusive")
        kwargs["delegate"] = bool(delegate)
    if server is not default:
        kwargs["server"] = server
    if host is not default:
        kwargs["host"] = host
    if ca_host is not default:
        kwargs["ca_host"] = ca_host
    if debug is not default:
        kwargs["debug"] = bool(debug)
    if force_schema_check is not default:
        kwargs["force_schema_check"] = bool(force_schema_check)

    if not api.isdone("bootstrap"):
        api.bootstrap(**kwargs)
    else:
        for key, value in kwargs.items():
            if api.env[key] != value:
                raise ValueError(
                    "API was previously initialized with different "
                    "settings: {} != {}".format(key, value)
                )
    if not api.isdone("finalize"):
        api.finalize()

    return IPAAPI(api)
