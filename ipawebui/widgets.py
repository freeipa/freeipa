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


class LandingPage(base.Widget):
    pages = Static('pages', default=tuple())

    xml = """
    <div
        xmlns:py="http://genshi.edgewall.org/"
        class="${css_classes}"
        id="${id}"
    >
    <a
        py:for="p in pages"
        py:content="p.title"
        href="${relurl(p.url)}"
    />
    </div>
    """


class Form(builtins.Form):
    js_class = 'Form'

    javascript = """
    Wehjit.bases.Form = new Class({
        Extends: Wehjit.bases.Widget,

        post_init: function() {
            this.focused = null;
            $each(this.el.elements, function(field) {
                field.connect('focus', this);
            }, this);
            var parent = this.get_parent();
            if (parent && parent.klass == 'Dialog') {
                parent.addEvent('run', this.on_run.bind(this));
                this.parent = parent;
            }
            this.formdata = null;
        },

        on_focus: function(field, event) {
            this.focused = field;
        },

        on_run: function(dialog, params) {
            console.assert(dialog == this.parent);
            this.refocus();
        },

        refocus: function() {
            console.log('refocus', this.id, this.focused);
            if (this.focused) {
                this.focused.focus();
                return true;
            }
            if (this.el.elements.length > 0) {
                this.el.elements[0].focus();
                return true;
            }
            return false;
        },

        get_data: function() {
            console.log('Form.get_data');
            var rawdata = this.el.get_data();
            var data = {};

            if (this.formdata == null) {
                $each(rawdata, function(value, key) {
                    if (value !== '') {
                        data[key] = value;
                    }
                });
            }
            else {
                $each(rawdata, function(value, key) {
                    var old = this.formdata[key];
                    if (old  == undefined && value === '') {
                        return;
                    }
                    if (old != value) {
                        console.log('changed: %s = %s', key, value);
                        data[key] = value;
                    }
                }, this);
            }

            return data;

        },

        set_data: function(data) {
            console.log('Form.set_data', data);
            this.focused = null;
            if ($type(data) == 'object') {
                this.formdata = data;
            }
            else {
                this.formdata = null;
            }
            this.el.set_data(data);
        },

        reset: function() {
            this.formdata = null;
            this.focused = null;
            this.el.reset();
        },

    });
    """


class CRUDS(builtins.CRUDS):
    display_cols = Static('display_cols', json=True, default=tuple())


class Display(builtins.Display):
    cols = None

    javascript = """
    Wehjit.bases.Display = new Class({
        Extends: Wehjit.bases.Widget,

        post_init: function() {
            var parent = this.get_parent();
            console.assert(parent);
            parent.addEvent('run', this.on_run.bind(this));
            this.cruds = Wehjit.get('cruds');
            this.cols = this.cruds.data.display_cols;
            console.assert(this.cols);
            if (this.cols.length == 0) {
                this.cols = Wehjit.data.grid.cols;
            }
        },

        on_run: function(dialog, row) {
            console.log('Display.on_run(%s, %s)', dialog, row);
            this.el.empty();
            if ($type(row) != 'object') {
                return;
            }
            this.cols.each(function(col) {
                var tr = new Element('tr');
                var th = new Element('th');
                th.textContent = col.label + ':';
                tr.appendChild(th);
                this.el.appendChild(tr);
                var td = new Element('td');
                var value = row[col.name];
                if ($type(value) == 'array') {
                    var value = value.join(',');
                }
                if ($type(value) != 'string') {
                    var value = '';
                }
                td.textContent = value;
                tr.appendChild(td);
            }, this);
        },

    });
    """





def create_widgets():
    widgets = Collection('freeIPA')
    widgets.register_builtins()

    widgets.register(API)
    widgets.register(IPAPlugins)
    widgets.register(Command)
    widgets.register(Object)
    widgets.register(LandingPage)
    widgets.register(Form, override=True)
    widgets.register(CRUDS, override=True)
    widgets.register(Display, override=True)


    freeze(widgets)
    return widgets
