#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import importlib
import os
import re
import sys

import six

from ipaclient.frontend import ClientCommand, ClientMethod
from ipalib.frontend import Object
from ipapython.ipautil import APIVersion

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


def get_package(server_info, client):
    try:
        server_version = server_info['version']
    except KeyError:
        is_valid = False
    else:
        is_valid = server_info.is_valid()

    if not is_valid:
        if not client.isconnected():
            client.connect(verbose=False)
        env = client.forward(u'env', u'api_version', version=u'2.0')
        try:
            server_version = env['result']['api_version']
        except KeyError:
            ping = client.forward(u'ping', version=u'2.0')
            try:
                match = re.search(u'API version (2\.[0-9]+)', ping['summary'])
            except KeyError:
                match = None
            if match is not None:
                server_version = match.group(1)
            else:
                server_version = u'2.0'
        server_info['version'] = server_version
        server_info.update_validity()

    server_version = APIVersion(server_version)

    package_names = {}
    base_name = __name__.rpartition('.')[0]
    base_dir = os.path.dirname(__file__)
    for name in os.listdir(base_dir):
        package_dir = os.path.join(base_dir, name)
        if name.startswith('2_') and os.path.isdir(package_dir):
            package_version = APIVersion(name.replace('_', '.'))
            package_names[package_version] = '{}.{}'.format(base_name, name)

    package_version = None
    for version in sorted(package_names):
        if package_version is None or package_version < version:
            package_version = version
        if version >= server_version:
            break

    package_name = package_names[package_version]
    try:
        package = sys.modules[package_name]
    except KeyError:
        package = importlib.import_module(package_name)

    return package
