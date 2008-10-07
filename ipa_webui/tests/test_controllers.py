# Authors: Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
Test the `ipa_webui.controller` module.
"""

from ipa_webui import controller



class test_Controller(object):
    """
    Test the `controller.Controller` class.
    """

    def test_init(self):
        """
        Test the `ipa_webui.controller.Controller.__init__()` method.
        """
        o = controller.Controller()
        assert o.template is None
        template = 'The template.'
        o = controller.Controller(template)
        assert o.template is template

    def test_output_xhtml(self):
        """
        Test the `ipa_webui.controller.Controller.output_xhtml` method.
        """
        class Template(object):
            def __init__(self):
                self.calls = 0
                self.kw = {}

            def serialize(self, **kw):
                self.calls += 1
                self.kw = kw
                return dict(kw)

        d = dict(output='xhtml-strict', format='pretty')
        t = Template()
        o = controller.Controller(t)
        assert o.output_xhtml() == d
        assert t.calls == 1

    def test_output_json(self):
        """
        Test the `ipa_webui.controller.Controller.output_json` method.
        """
        o = controller.Controller()
        assert o.output_json() == '{}'
        e = '{\n    "age": 27, \n    "first": "John", \n    "last": "Doe"\n}'
        j = o.output_json(last='Doe', first='John', age=27)
        assert j == e
