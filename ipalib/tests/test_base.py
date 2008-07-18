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
		Test that NameSpace instance created with empty dict has no public
		attributes.
		"""
		ns = self.ns({})
		assert list(ns) == []
		for name in dir(ns):
			assert name.startswith('_') or name.startswith('_NameSpace__')

	def test_iter(self):
		"""
		Test that __iter__() method returns sorted list of attribute names.
		"""
		(kw, ns) = self.std()
		assert list(ns) == sorted(kw)
		assert [ns[k] for k in ns] == ['Hello', 'all', 'yall!']

	def test_dict_vs_attr(self):
		"""
		Tests NameSpace.__getitem__() and NameSpace.__getattr__() return the
		same values.
		"""
		(kw, ns) = self.std()
		for (key, val) in kw.items():
			assert ns[key] is val
			assert getattr(ns, key) is val
