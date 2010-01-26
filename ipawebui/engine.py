# Authors: Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Engine to map ipalib plugins to wehjit widgets.
"""

from controllers import Command
from ipalib import crud

class ParamMapper(object):
    def __init__(self, api, app):
        self._api = api
        self._app = app
        self.__methods = dict()
        for name in dir(self):
            if name.startswith('_'):
                continue
            attr = getattr(self, name)
            if not callable(attr):
                continue
            self.__methods[name] = attr

    def __call__(self, param, cmd):
        key = param.__class__.__name__
        if key in self.__methods:
            method = self.__methods[key]
        else:
            method = self.Str
        return method(param, cmd)

    def Str(self, param, cmd):
        return self._app.new('TextRow',
            label=param.label,
            name=param.name,
            required=param.required,
            value=param.default,
        )

    def Password(self, param, cmd):
        return self._app.new('PasswordRow',
            name=param.name,
            required=param.required,
        )

    def Flag(self, param, cmd):
        return self._app.new('SelectRow',
            name=param.name,
            label=param.label,
        )


def filter_params(namespace):
    for param in namespace():
        if param.exclude and 'webui' in param.exclude:
            continue
        yield param


class Engine(object):

    cruds = frozenset(['add', 'show', 'mod', 'del', 'find'])

    def __init__(self, api, app):
        self.api = api
        self.app = app
        self.param_mapper = ParamMapper(api, app)
        self.pages = dict()
        self.jsonurl = self.api.Backend.jsonserver.url.rstrip('/')
        self.info_pages = []

    def add_object_menuitems(self, menu, name):
        obj = self.api.Object[name]
        for cmd in obj.methods():
            p = self.pages[cmd.name]
            menu.add(
                menu.new('MenuItem',
                    label=p.title,
                    href=p.url,
                )
            )

    def build(self):
        for obj in self.api.Object():
            if self.cruds.issubset(obj.methods) and obj.primary_key is not None:
                self.pages[obj.name] = self.build_cruds_page(obj)

        # Add landing page:
        landing = self.app.new('PageApp', id='', title='Welcome to FreeIPA')

        for page in self.pages.values() + [landing]:
            page.menu.label = 'FreeIPA'
            for name in sorted(self.pages):
                p = self.pages[name]
                page.menu.new_child('MenuItem', label=p.title, href=p.url)




        # Add in the info pages:
        page = self.app.new('PageApp', id='api', title='api')
        page.view.add(
            self.app.new('API', api=self.api)
        )
        self.info_pages.append(page)

        for kind in self.api:
            self.build_info_page(kind)
        for page in self.info_pages:
            for p in self.info_pages:
                page.menuset.add(
                    self.app.new('MenuItem',
                        href=p.url,
                        label=p.title,
                    )
                )

    def build_cruds_page(self, obj):
        page = self.app.new('PageGrid', title=obj.name, id=obj.name)

        # Setup CRUDS widget:
        page.cruds.autoload = True
        page.cruds.jsonrpc_url = self.api.Backend.jsonserver.url
        page.cruds.key = obj.primary_key.name
        page.cruds.method_create = obj.methods['add'].name
        page.cruds.method_retrieve = obj.methods['show'].name
        page.cruds.method_update = obj.methods['mod'].name
        page.cruds.method_delete = obj.methods['del'].name
        page.cruds.method_search = obj.methods['find'].name
        page.cruds.display_cols = tuple(
            dict(
                name=p.name,
                label=p.label,
                css_classes=None,
            )
            for p in obj.params()
        )

        # Setup the Grid widget:
        page.grid.cols = tuple(
            dict(
                name=p.name,
                label=p.label,
                css_classes=None,
            )
            for p in obj.params() if p.required
        )


        # Setup the create Dialog:
        cmd = obj.methods['add']
        page.create.title = cmd.summary.rstrip('.')
        for p in filter_params(cmd.params):
            page.create.fieldtable.add(self.param_mapper(p, cmd))

        # Setup the retrieve Dialog
        page.retrieve.title = 'Showing "{value}"'

        # Setup the update Dialog:
        page.update.title = 'Updating "{value}"'
        cmd = obj.methods['mod']
        for p in filter_params(cmd.options):
            page.update.fieldtable.add(self.param_mapper(p, cmd))

        # Setup the delete Dialog
        page.delete.title = 'Delete "{value}"?'

        return page

    def build_info_page(self, kind):
        # Add in the Object page:
        plugins = tuple(self.api[kind]())
        page = self.app.new('PageApp', id=kind, title=kind)
        info = self.app.new('IPAPlugins', kind=kind, plugins=plugins)
        quick_jump = self.app.new('QuickJump',
            options=tuple((p.name, p.name) for p in plugins)
        )
        page.view.add(info)
        page.actions.add(quick_jump)
        self.info_pages.append(page)
        if kind in self.app.widgets:
            info.add(
                self.app.new(kind)
            )
        return page
