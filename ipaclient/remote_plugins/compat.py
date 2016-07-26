#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from distutils.version import LooseVersion
import importlib
import os
import re
import sys

import six

from ipaclient.frontend import ClientCommand, ClientMethod
from ipalib.frontend import Object

if six.PY3:
    unicode = str


class CompatCommand(ClientCommand):
    @property
    def forwarded_name(self):
        return self.name


class CompatMethod(ClientMethod, CompatCommand):
    pass


class CompatObject(Object):
    pass


def get_package(api, server_info, client):
    try:
        server_version = server_info['version']
    except KeyError:
        if not client.isconnected():
            client.connect(verbose=False)
        env = client.forward(u'env', u'api_version', version=u'2.0')
        try:
            server_version = env['result']['api_version']
        except KeyError:
            ping = client.forward(u'ping', u'api_version', version=u'2.0')
            try:
                match = re.search(u'API version (2\.[0-9]+)', ping['summary'])
            except KeyError:
                match = None
            if match is not None:
                server_version = match.group(1)
            else:
                server_version = u'2.0'
        server_info['version'] = server_version
    server_version = LooseVersion(server_version)

    package_names = {}
    base_name = __name__.rpartition('.')[0]
    base_dir = os.path.dirname(__file__)
    for name in os.listdir(base_dir):
        package_dir = os.path.join(base_dir, name)
        if name.startswith('2_') and os.path.isdir(package_dir):
            package_version = name.replace('_', '.')
            package_names[package_version] = '{}.{}'.format(base_name, name)

    package_version = None
    for version in sorted(package_names, key=LooseVersion):
        if (package_version is None or
                LooseVersion(package_version) < LooseVersion(version)):
            package_version = version
        if LooseVersion(version) >= server_version:
            break

    package_name = package_names[package_version]
    try:
        package = sys.modules[package_name]
    except KeyError:
        package = importlib.import_module(package_name)

    return package
