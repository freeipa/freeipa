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
Unit tests for `ipalib.public` module.
"""

from tstutil import raises, getitem, no_set, no_del, read_only
from ipalib import public, plugable, errors


def test_RULE_FLAG():
    assert public.RULE_FLAG == 'validation_rule'


def test_rule():
    flag = public.RULE_FLAG
    rule = public.rule
    def my_func():
    	pass
    assert not hasattr(my_func, flag)
    rule(my_func)
    assert getattr(my_func, flag) is True
    @rule
    def my_func2():
    	pass
    assert getattr(my_func2, flag) is True


def test_is_rule():
    is_rule = public.is_rule
    flag = public.RULE_FLAG

    class no_call(object):
    	def __init__(self, value):
    		if value is not None:
    			assert value in (True, False)
    			setattr(self, flag, value)

    class call(no_call):
    	def __call__(self):
    		pass

    assert is_rule(call(True))
    assert not is_rule(no_call(True))
    assert not is_rule(call(False))
    assert not is_rule(call(None))


class test_option():
    def cls(self):
    	return public.option

    def sub(self):
    	rule = public.rule
    	class int_opt(self.cls()):
    		type = int
    		@rule
    		def rule_0(self, value):
    			if value == 0:
    				return 'cannot be 0'
    		@rule
    		def rule_1(self, value):
    			if value == 1:
    				return 'cannot be 1'
    		@rule
    		def rule_2(self, value):
    			if value == 2:
    				return 'cannot be 2'
    	return int_opt

    def test_class(self):
    	"""
    	Perform some tests on the class (not an instance).
    	"""
    	cls = self.cls()
    	#assert issubclass(cls, plugable.ReadOnly)
    	assert type(cls.rules) is property

    def test_normalize(self):
    	sub = self.sub()
    	i = sub()
    	# Test with values that can't be converted:
    	nope = (
    		'7.0'
    		'whatever',
    		object,
    		None,
    	)
    	for val in nope:
    		e = raises(errors.NormalizationError, i.normalize, val)
    		assert isinstance(e, errors.ValidationError)
    		assert e.name == 'int_opt'
    		assert e.value == val
    		assert e.error == "not <type 'int'>"
    		assert e.type is int
    	# Test with values that can be converted:
    	okay = (
    		7,
    		7.0,
    		7.2,
    		7L,
    		'7',
    		' 7 ',
    	)
    	for val in okay:
    		assert i.normalize(val) == 7

    def test_rules(self):
    	"""
    	Test the rules property.
    	"""
    	o = self.sub()()
    	assert len(o.rules) == 3
    	def get_rule(i):
    		return getattr(o, 'rule_%d' % i)
    	rules = tuple(get_rule(i) for i in xrange(3))
    	assert o.rules == rules

    def test_validation(self):
    	"""
    	Test the validation method.
    	"""
    	o = self.sub()()
    	o.validate(9)
    	for i in xrange(3):
    		e = raises(errors.RuleError, o.validate, i)
    		assert e.error == 'cannot be %d' % i
    		assert e.value == i



def test_cmd():
    cls = public.cmd
    assert issubclass(cls, plugable.Plugin)


def test_obj():
    cls = public.obj
    assert issubclass(cls, plugable.Plugin)



def test_attr():
    cls = public.attr
    assert issubclass(cls, plugable.Plugin)

    class api(object):
    	obj = dict(user='the user obj')

    class user_add(cls):
    	pass

    i = user_add()
    assert read_only(i, 'obj_name') == 'user'
    assert read_only(i, 'attr_name') == 'add'
    assert read_only(i, 'obj') is None
    i.finalize(api)
    assert read_only(i, 'api') is api
    assert read_only(i, 'obj') == 'the user obj'


def test_mthd():
    cls = public.mthd
    assert issubclass(cls, public.attr)
    assert issubclass(cls, public.cmd)


def test_prop():
    cls = public.prop
    assert issubclass(cls, public.attr)


def test_PublicAPI():
    cls = public.PublicAPI
    assert issubclass(cls, plugable.API)

    api = cls()

    class cmd1(public.cmd):
    	pass
    api.register(cmd1)

    class cmd2(public.cmd):
    	pass
    api.register(cmd2)

    api()
