# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
Unit tests for `ipalib.plugable` module.
"""

from ipalib import plugable, errors


def test_to_cli():
	f = plugable.to_cli
	assert f('initialize') == 'initialize'
	assert f('find_everything') == 'find-everything'
	assert f('user__add') == 'user.add'
	assert f('meta_service__do_something') == 'meta-service.do-something'


def test_from_cli():
	f = plugable.from_cli
	assert f('initialize') == 'initialize'
	assert f('find-everything') == 'find_everything'
	assert f('user.add') == 'user__add'
	assert f('meta-service.do-something') == 'meta_service__do_something'


def test_Plugin():
	p = plugable.Plugin()
	assert p.name == 'Plugin'
	assert repr(p) == '%s.Plugin()' % plugable.__name__

	class some_plugin(plugable.Plugin):
		pass
	p = some_plugin()
	assert p.name == 'some_plugin'
	assert repr(p) == '%s.some_plugin()' % __name__


def test_Proxy():
	class CommandProxy(plugable.Proxy):
		__slots__ = (
			'validate',
			'__call__',
		)

	class do_something(object):
		def __repr__(self):
			return '<my repr>'

		def __call__(self, arg):
			return arg + 1

		def validate(self, arg):
			return arg + 2

		def not_public(self, arg):
			return arg + 3

	# Test basic Proxy functionality
	i = do_something()
	p = CommandProxy(i)
	assert '__dict__' not in dir(p)
	assert p.name == 'do_something'
	assert str(p) == 'do-something'
	assert repr(p) == 'CommandProxy(<my repr>)'
	assert p(1) == 2
	assert p.validate(1) == 3

	# Test that proxy_name can be overriden:
	i = do_something()
	p = CommandProxy(i, proxy_name='user__add')
	assert '__dict__' not in dir(p)
	assert p.name == 'user__add'
	assert str(p) == 'user.add'
	assert repr(p) == 'CommandProxy(<my repr>)'
	assert p(1) == 2
	assert p.validate(1) == 3

	# Test that attributes not listed in __slots__ are not present:
	name = 'not_public'
	i = do_something()
	p = CommandProxy(i)
	assert getattr(i, name)(1) == 4
	raised = False
	try:
		getattr(p, name)
	except AttributeError:
		raised = True
	assert raised

	# Test that attributes are read-only:
	name = 'validate'
	i = do_something()
	p = CommandProxy(i)
	assert getattr(p, name)(1) == 3
	raised = False
	try:
		# Test __setattr__()
		setattr(p, name, 'new_object')
	except AttributeError:
		raised = True
	assert raised
	raised = False
	try:
		# Test __delattr__()
		delattr(p, name)
	except AttributeError:
		raised = True
	assert raised





def test_Registrar():
	class Base1(object):
		pass
	class Base2(object):
		pass
	class Base3(object):
		pass
	class plugin1(Base1):
		pass
	class plugin2(Base2):
		pass
	class plugin3(Base3):
		pass

	# Test creation of Registrar:
	r = plugable.Registrar(Base1, Base2)
	assert sorted(r) == ['Base1', 'Base2']

	# Check that TypeError is raised trying to register something that isn't
	# a class:
	raised = False
	try:
		r(plugin1())
	except TypeError:
		raised = True
	assert raised

	# Check that SubclassError is raised trying to register a class that is
	# not a subclass of an allowed base:
	raised = False
	try:
		r(plugin3)
	except errors.SubclassError:
		raised = True
	assert raised

	# Check that registration works
	r(plugin1)
	sub_d = r['Base1']
	assert len(sub_d) == 1
	assert sub_d['plugin1'] is plugin1
	# Check that a copy is returned
	assert sub_d is not r['Base1']
	assert sub_d == r['Base1']

	# Check that DuplicateError is raised trying to register exact class
	# again:
	raised = False
	try:
		r(plugin1)
	except errors.DuplicateError:
		raised = True
	assert raised

	# Check that OverrideError is raised trying to register class with same
	# name and same base:
	orig1 = plugin1
	class base1_extended(Base1):
		pass
	class plugin1(base1_extended):
		pass
	raised = False
	try:
		r(plugin1)
	except errors.OverrideError:
		raised = True
	assert raised

	# Check that overriding works
	r(plugin1, override=True)
	sub_d = r['Base1']
	assert len(sub_d) == 1
	assert sub_d['plugin1'] is plugin1
	assert sub_d['plugin1'] is not orig1

	# Check that MissingOverrideError is raised trying to override a name
	# not yet registerd:
	raised = False
	try:
		r(plugin2, override=True)
	except errors.MissingOverrideError:
		raised = True
	assert raised

	# Check that additional plugin can be registered:
	r(plugin2)
	sub_d = r['Base2']
	assert len(sub_d) == 1
	assert sub_d['plugin2'] is plugin2
