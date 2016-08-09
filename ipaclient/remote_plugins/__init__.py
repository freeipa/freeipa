#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import collections
import errno
import json
import os

from . import compat
from . import schema
from ipaclient.plugins.rpcclient import rpcclient
from ipaplatform.paths import paths
from ipapython.dnsutil import DNSName
from ipapython.ipa_log_manager import log_mgr

logger = log_mgr.get_logger(__name__)


class ServerInfo(collections.MutableMapping):
    _DIR = os.path.join(paths.USER_CACHE_PATH, 'ipa', 'servers')

    def __init__(self, api):
        hostname = DNSName(api.env.server).ToASCII()
        self._path = os.path.join(self._DIR, hostname)
        self._dict = {}
        self._dirty = False

        self._read()

    def __enter__(self):
        return self

    def __exit__(self, *_exc_info):
        self.flush()

    def flush(self):
        if self._dirty:
            self._write()

    def _read(self):
        try:
            with open(self._path, 'r') as sc:
                self._dict = json.load(sc)
        except EnvironmentError as e:
            if e.errno != errno.ENOENT:
                logger.warning('Failed to read server info: {}'.format(e))

    def _write(self):
        try:
            try:
                os.makedirs(self._DIR)
            except EnvironmentError as e:
                if e.errno != errno.EEXIST:
                    raise
            with open(self._path, 'w') as sc:
                json.dump(self._dict, sc)
        except EnvironmentError as e:
            logger.warning('Failed to write server info: {}'.format(e))

    def __getitem__(self, key):
        return self._dict[key]

    def __setitem__(self, key, value):
        if key not in self._dict or self._dict[key] != value:
            self._dirty = True
        self._dict[key] = value

    def __delitem__(self, key):
        del self._dict[key]
        self._dirty = True

    def __iter__(self):
        return iter(self._dict)

    def __len__(self):
        return len(self._dict)


def get_package(api):
    if api.env.in_tree:
        from ipaserver import plugins
    else:
        client = rpcclient(api)
        client.finalize()

        try:
            server_info = api._server_info
        except AttributeError:
            server_info = api._server_info = ServerInfo(api)

        try:
            plugins = schema.get_package(api, server_info, client)
        except schema.NotAvailable:
            plugins = compat.get_package(api, server_info, client)
        finally:
            server_info.flush()
            if client.isconnected():
                client.disconnect()

    return plugins
