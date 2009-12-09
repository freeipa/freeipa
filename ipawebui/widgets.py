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
Custom IPA widgets.
"""

from textwrap import dedent
from wehjit import Collection, base, freeze, builtins
from wehjit.util import Alternator
from wehjit import Static, Dynamic, StaticProp, DynamicProp
from ipaserver.rpcserver import extract_query


class IPAPlugins(base.Container):
    plugins = Static('plugins', default=tuple())
    kind = Static('kind')

    @DynamicProp
    def row(self):
        return Alternator(['odd', 'even'])

    xml = """
    <div
        xmlns:py="http://genshi.edgewall.org/"
        class="${css_classes}"
        id="${id}"
    >
    <p py:content="'%d %s plugins' % (len(plugins), kind)" />

    <div py:for="p in plugins">
    <h2 id="${p.name}"><a href="#${p.name}" py:content="p.name" /></h2>

    <table class="${row.reset()}">

    <tr class="${row.next()}">
    <td>module</td>
    <td>
    <a
        title="Link to module documentation"
        href="http://freeipa.org/developer-docs/${p.module}-module.html"
        py:content="p.module"
    />
    </td>
    </tr>

    <tr class="${row.next()}">
    <td>base(s)</td>
    <td py:content="', '.join(p.bases)" />
    </tr>

    <tr py:if="p.doc" class="${row.next()}">
    <td>docstring</td>
    <td><pre py:content="p.doc" /></td>
    </tr>

    <tr
        py:for="child in children"
        py:replace="child.generate(plugin=p, row=row)"
    />

    </table>
    </div>

    </div>
    """

    style_global = (
        ('tr.odd', (
            ('background-color', '#ddd'),
        )),
        ('tr.even', (
            ('background-color', '#eee'),
        )),

        ('td', (
            ('vertical-align', 'top'),
            ('padding', '0.25em 0.5em'),
        )),
    )

    style = (
        ('', (
            ('font-size', '%(font_size_mono)s'),
            ('font-family', 'monospace'),
        )),

        ('table', (
            ('width', '100%%'),
        )),

        ('pre', (
            ('margin', '0'),
        )),

        ('th', (
            ('color', '#0a0'),
        )),

        ('h2', (
            ('font-family', 'monospace'),
            ('font-weight', 'normal'),
            ('margin-top', '1.5em'),
            ('margin-bottom', '0'),
        )),

        ('h2 a', (
            ('text-decoration', 'none'),
            ('color', 'inherit'),
        )),

        ('h2 a:hover', (
            ('background-color', '#eee'),
        )),

        ('h2:target', (
            ('color', '#e02'),
        )),
    )


class API(base.Widget):
    api = Static('api')

    @DynamicProp
    def row(self):
        return Alternator(['odd', 'even'])

    xml = """
    <div
        xmlns:py="http://genshi.edgewall.org/"
        class="${css_classes}"
        id="${id}"
    >
    <p py:content="'%d namespaces in API' % len(api)" />
    <table>
    <tr py:for="key in api" class="${row.next()}">
    <td>
    <a href="${key}" py:content="'api.' + key" />
    </td>
    <td py:content="repr(api[key])" />
    </tr>
    </table>
    </div>
    """


class Command(base.Widget):
    xml = """
    <table
        xmlns:py="http://genshi.edgewall.org/"
        py:strip="True"
    >

    <tr py:if="plugin.obj" class="${row.next()}">
    <td>Object</td>
    <td>
    <a href="Object#${plugin.obj.name}" py:content="plugin.obj.fullname" />
    </td>
    </tr>

    <tr py:if="plugin.args" class="${row.next()}">
    <th colspan="2" py:content="'args (%d)' % len(plugin.args)" />
    </tr>
    <tr py:for="arg in plugin.args()" class="${row.next()}">
    <td py:content="arg.name"/>
    <td py:content="repr(arg)" />
    </tr>

    <tr py:if="plugin.options" class="${row.next()}">
    <th colspan="2" py:content="'options (%d)' % len(plugin.options)" />
    </tr>
    <tr py:for="option in plugin.options()" class="${row.next()}">
    <td py:content="option.name"/>
    <td py:content="repr(option)" />
    </tr>

    <tr py:if="plugin.output" class="${row.next()}">
    <th colspan="2" py:content="'output (%d)' % len(plugin.output)" />
    </tr>
    <tr py:for="param in plugin.output()" class="${row.next()}">
    <td py:content="param.name"/>
    <td py:content="repr(param)" />
    </tr>

    </table>
    """


class Object(base.Widget):
    xml = """
    <table
        xmlns:py="http://genshi.edgewall.org/"
        py:strip="True"
    >
    <tr py:if="plugin.methods" class="${row.next()}">
    <th colspan="2" py:content="'methods (%d)' % len(plugin.methods)" />
    </tr>
    <tr py:for="method in plugin.methods()" class="${row.next()}">
    <td><a href="${'Command#' + method.name}" py:content="method.name"/></td>
    <td py:content="method.summary" />
    </tr>

    <tr py:if="plugin.params" class="${row.next()}">
    <th colspan="2" py:content="'params (%d)' % len(plugin.params)" />
    </tr>
    <tr py:for="param in plugin.params()" class="${row.next()}">
    <td>${"param.name"}:</td>
    <td py:content="repr(param)" />
    </tr>

    </table>
    """



class Conditional(base.Container):

    mode = Static('mode', default='input')

    @DynamicProp
    def page_mode(self):
        if self.page is None:
            return
        return self.page.mode

    xml = """
    <div
        xmlns:py="http://genshi.edgewall.org/"
        py:if="mode == page_mode"
        py:strip="True"
    >
    <child py:for="child in children" py:replace="child.generate()" />
    </div>
    """


class Output(base.Widget):
    """
    Shows attributes form an LDAP entry.
    """

    order = Dynamic('order')
    labels = Dynamic('labels')
    result = Dynamic('result')

    xml = """
    <div
        xmlns:py="http://genshi.edgewall.org/"
        class="${klass}"
        id="${id}"
    >
    <table py:if="isinstance(result, dict)">
    <tr py:for="key in order" py:if="key in result">
    <th py:content="labels[key]" />
    <td py:content="result[key]" />
    </tr>
    </table>

    <table
        py:if="isinstance(result, (list, tuple)) and len(result) > 0"
    >
    <tr>
    <th
        py:for="key in order"
        py:if="key in result[0]"
        py:content="labels[key]"
    />
    </tr>
    <tr py:for="entry in result">
    <td
        py:for="key in order"
        py:if="key in result[0]"
        py:content="entry[key]"
    />
    </tr>
    </table>
    </div>
    """

    style = (
        ('table', (
            ('empty-cells', 'show'),
            ('border-collapse', 'collapse'),
        )),

        ('th', (
            ('text-align', 'right'),
            ('padding', '.25em 0.5em'),
            ('line-height', '%(height_bar)s'),
            ('vertical-align', 'top'),
        )),

        ('td', (
            ('padding', '.25em'),
            ('vertical-align', 'top'),
            ('text-align', 'left'),
            ('line-height', '%(height_bar)s'),
        )),
    )


class Hidden(base.Field):
    xml = """
    <input
        xmlns:py="http://genshi.edgewall.org/"
        type="hidden"
        name="${name}"
    />
    """


class Notification(base.Widget):
    message = Dynamic('message')
    error = Dynamic('error', default=False)

    @property
    def extra_css_classes(self):
        if self.error:
            yield 'error'
        else:
            yield 'okay'

    xml = """
    <p
        xmlns:py="http://genshi.edgewall.org/"
        class="${klass}"
        id="${id}"
        py:if="message"
        py:content="message"
    />
    """

    style = (
        ('', (
            ('font-weight', 'bold'),
            ('-moz-border-radius', '100%%'),
            ('background-color', '#eee'),
            ('border', '2px solid #966'),
            ('padding', '0.5em'),
            ('text-align', 'center'),
        )),
    )


class PageCmd(builtins.PageApp):
    cmd = Static('cmd')
    mode = Dynamic('mode', default='input')

    def controller(self, environ):
        query = extract_query(environ)
        self.mode = query.pop('__mode__', 'input')
        if self.mode == 'input':
            return
        soft = self.cmd.soft_validate(query)
        errors = soft['errors']
        values = soft['values']
        if errors:
            self.mode = 'input'
            for key in self.form:
                if key in errors:
                    self.form[key].error = errors[key]
                if key in values:
                    self.form[key].value = values[key]
            return
        output = self.cmd(**query)
        if isinstance(output, dict) and 'summary' in output:
            self.notification.message = output['summary']
        params = self.cmd.output_params
        if params:
            order = list(params)
            labels = dict((p.name, p.label) for p in params())
        else:
            order = sorted(entry)
            labels = dict((k, k) for k in order)
        self.show.order = order
        self.show.labels = labels
        self.show.result = output.get('result')


def create_widgets():
    widgets = Collection('freeIPA')
    widgets.register_builtins()

    widgets.register(API)
    widgets.register(IPAPlugins)
    widgets.register(Command)
    widgets.register(Object)
    widgets.register(Conditional)
    widgets.register(Output)
    widgets.register(Hidden)
    widgets.register(Notification)

    widgets.register(PageCmd)


    freeze(widgets)
    return widgets
