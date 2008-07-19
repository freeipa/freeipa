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
Unit tests for `ipalib.base` module.
"""

from ipalib import base, exceptions


class test_NameSpace():
	"""
	Unit tests for `NameSpace` class.
	"""

	def	ns(self, kw):
		"""
		Returns a new NameSpace instance.
		"""
		return base.NameSpace(kw)

	def kw(self):
		"""
		Returns standard test kw dict suitable for passing to
		NameSpace.__init__().
		"""
		return dict(
			attr_a='Hello',
			attr_b='all',
			attr_c='yall!',
		)

	def std(self):
		"""
		Returns standard (kw, ns) tuple.
		"""
		kw = self.kw()
		ns = self.ns(kw)
		return (kw, ns)

	def test_public(self):
		"""
		Tests that a NameSpace instance created with empty dict has no public
		attributes (that would then conflict with names we want to assign to
		the NameSpace). Also tests that a NameSpace instance created with a
		non-empty dict has no unexpected public methods.
		"""
		ns = self.ns({})
		assert list(ns) == []
		assert len(ns) == 0
		for name in dir(ns):
			assert name.startswith('__') or name.startswith('_NameSpace__')
		(kw, ns) = self.std()
		keys = set(kw)
		for name in dir(ns):
			assert (
				name.startswith('__') or
				name.startswith('_NameSpace__') or
				name in keys
			)

	def test_dict_vs_attr(self):
		"""
		Tests that NameSpace.__getitem__() and NameSpace.__getattr__() return
		the same values.
		"""
		(kw, ns) = self.std()
		assert len(kw) > 0
		assert len(kw) == len(list(ns))
		for (key, val) in kw.items():
			assert ns[key] is val
			assert getattr(ns, key) is val

	def test_setattr(self):
		"""
		Tests that attributes cannot be set on NameSpace instance.
		"""
		(kw, ns) = self.std()
		value = 'new value'
		for key in kw:
			raised = False
			try:
				setattr(ns, key, value)
			except exceptions.SetAttributeError:
				raised = True
			assert raised
			assert getattr(ns, key, None) != value
			assert ns[key] != value

	def test_setitem(self):
		"""
		Tests that attributes cannot be set via NameSpace dict interface.
		"""
		(kw, ns) = self.std()
		value = 'new value'
		for key in kw:
			raised = False
			try:
				ns[key] = value
			except TypeError:
				raised = True
			assert raised
			assert getattr(ns, key, None) != value
			assert ns[key] != value

	def test_hasitem(self):
		"""
		Test __hasitem__() membership method.
		"""
		(kw, ns) = self.std()
		nope = [
			'attr_d',
			'attr_e',
			'whatever',
		]
		for key in kw:
			assert key in ns
		for key in nope:
			assert key not in kw
			assert key not in ns

	def test_iter(self):
		"""
		Tests that __iter__() method returns sorted list of attribute names.
		"""
		(kw, ns) = self.std()
		assert list(ns) == sorted(kw)
		assert [ns[k] for k in ns] == ['Hello', 'all', 'yall!']

	def test_len(self):
		"""
		Test __len__() method.
		"""
		(kw, ns) = self.std()
		assert len(kw) == len(ns) == 3
