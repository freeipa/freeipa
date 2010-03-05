# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
Simple description of return values.
"""

from inspect import getdoc
from types import NoneType
from plugable import ReadOnly, lock
from text import _


class Output(ReadOnly):
    """
    Simple description of a member in the return value ``dict``.

    This class controls both the type of object being returned by
    a command as well as how the output will be displayed.

    For example, this class defines two return results: an entry
    and a value.

    >>> from ipalib import crud, output
    >>> class user(crud.Update):
    ...
    ...     has_output = (
    ...         output.Entry('result'),
    ...         output.value,
    ...     )

    The order of the values in has_output controls the order of output.
    If you have values that you don't want to be printed then add
    ``'no_display'`` to flags.

    The difference between ``'no_dipslay`` and ``'no_output'`` is
    that ``'no_output`` will prevent a Param value from being returned
    at all. ``'no_display'`` will cause the API to return a value, it
    simply won't be displayed to the user. This is so some things may
    be returned that while not interesting to us, but may be to others.

    >>> from ipalib import crud, output
    >>> myvalue = output.Output('myvalue', unicode,
    ...     'Do not print this value', flags=['no_display'],
    ... )
    >>> class user(crud.Update):
    ...
    ...     has_output = (
    ...         output.Entry('result'),
    ...         myvalue,
    ...     )
    """

    type = None
    validate = None
    doc = None
    flags = []

    def __init__(self, name, type=None, doc=None, flags=[]):
        self.name = name
        if type is not None:
            self.type = type
        if doc is not None:
            self.doc = doc
        self.flags = flags
        lock(self)

    def __repr__(self):
        return '%s(%r, %r, %r)' % (
            self.__class__.__name__, self.name, self.type, self.doc,
        )


class Entry(Output):
    type = dict
    doc = _('A dictionary representing an LDAP entry')


emsg = """%s.validate_output() => %s.validate():
  output[%r][%d]: need a %r; got a %r: %r"""

class ListOfEntries(Output):
    type = (list, tuple)
    doc = _('A list of LDAP entries')

    def validate(self, cmd, entries):
        assert isinstance(entries, self.type)
        for (i, entry) in enumerate(entries):
            if not isinstance(entry, dict):
                raise TypeError(emsg % (cmd.name, self.__class__.__name__,
                    self.name, i, dict, type(entry), entry)
                )


result = Output('result', doc=_('All commands should at least have a result'))

summary = Output('summary', (unicode, NoneType),
    'User-friendly description of action performed'
)

value = Output('value', unicode,
    "The primary_key value of the entry, e.g. 'jdoe' for a user",
    flags=['no_display'],
)

standard = (summary, result)

standard_entry = (
    summary,
    Entry('result'),
    value,
)

standard_list_of_entries = (
    summary,
    ListOfEntries('result'),
    Output('count', int, 'Number of entries returned'),
    Output('truncated', bool, 'True if not all results were returned'),
)

standard_delete = (
    summary,
    Output('result', bool, 'True means the operation was successful'),
    value,
)

standard_value = standard_delete
