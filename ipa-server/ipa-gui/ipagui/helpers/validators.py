# Copyright (C) 2007-2008 Red Hat
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
#

from formencode.validators import *
from formencode.compound import *
from formencode.api import Invalid, NoDefault
from formencode.schema import Schema
from formencode import ForEach

def _(s): return s # dummy

class UniqueList(FancyValidator):
    """
    Given a list, ensure that all of the values in it are unique.

    >>> x = UniqueList()
    >>> x.validate_python(['1','1'],'')
    Traceback (most recent call last):
    ...
    formencode.api.Invalid: Duplicate values are not allowed
    >>> x.validate_python(['1','2'],'')
    >>>
    """

    not_empty = None

    messages = {
        'notunique': _('Duplicate values are not allowed'),
        'empty': _('Empty values not allowed'),
    }

    def __initargs__(self, new_attrs):
        if self.not_empty is None:
            self.not_empty = True

    def validate_python(self, value, state):
        if not isinstance(value, list):
            return # just punt for now

        if self.not_empty:
            for v in value:
                if v is None or len(v) == 0:
                    raise Invalid(self.message('empty', state),
                                  value, state)

        orig = len(value)
        check = len(set(value))

        if orig > check:
            raise Invalid(self.message('notunique', state),
                          value, state)

class GoodName(Regex):
    """
    Test that the field contains only letters, numbers, underscore,
    dash, hyphen and $.

    Examples::

        >>> GoodName.to_python('_this9_')
        '_this9_'
        >>> GoodName.from_python('  this  ')
        '  this  '
        >>> GoodName(accept_python=False).from_python('  this  ')
        Traceback (most recent call last):
          ...
        Invalid: Enter only letters, numbers, _ (underscore), - (dash) or $')
        >>> GoodName(strip=True).to_python('  this  ')
        'this'
        >>> GoodName(strip=True).from_python('  this  ')
        'this'
    """

    regex = r"^[a-zA-Z0-9_.][a-zA-Z0-9_.-]{0,30}[a-zA-Z0-9_.$-]?$"

    messages = {
        'invalid': _('Enter only letters, numbers, _ (underscore), - (dash) or $'),
    }
