# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Simple description of return values.
"""
import six

from ipalib.plugable import ReadOnly, lock
from ipalib.capabilities import client_has_capability
from ipalib.text import _
from ipalib.util import apirepr

if six.PY3:
    unicode = str

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

    The difference between ``'no_display'`` and ``'no_output'`` is
    that ``'no_output'`` will prevent a Param value from being returned
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
            if not isinstance(type, tuple):
                type = (type,)
            self.type = type
        if doc is not None:
            self.doc = doc
        self.flags = flags
        lock(self)

    def __repr__(self):
        return '%s(%s)' % (
            self.__class__.__name__,
            ', '.join(self.__repr_iter())
        )

    def __repr_iter(self):
        yield repr(self.name)
        for key in ('type', 'doc', 'flags'):
            value = self.__dict__.get(key)
            if not value:
                continue
            if isinstance(value, tuple):
                value = apirepr(list(value))
            else:
                value = repr(value)
            yield '%s=%s' % (key, value)


class Entry(Output):
    type = dict
    doc = _('A dictionary representing an LDAP entry')


emsg = """%s.validate_output() => %s.validate():
  output[%r][%d]: need a %r; got a %r: %r"""

class ListOfEntries(Output):
    type = (list, tuple)
    doc = _('A list of LDAP entries')

    def validate(self, cmd, entries, version):
        assert isinstance(entries, self.type)
        for (i, entry) in enumerate(entries):
            if not isinstance(entry, dict):
                raise TypeError(emsg % (cmd.name, self.__class__.__name__,
                    self.name, i, dict, type(entry), entry)
                )

class PrimaryKey(Output):
    def validate(self, cmd, value, version):
        if client_has_capability(version, 'primary_key_types'):
            if hasattr(cmd, 'obj') and cmd.obj and cmd.obj.primary_key:
                types = cmd.obj.primary_key.allowed_types
            else:
                types = (unicode,)
            types = types + (type(None),)
        else:
            types = (unicode,)
        if not isinstance(value, types):
            raise TypeError(
                "%s.validate_output() => %s.validate():\n"
                "  output[%r]: need %r; got %r: %r" % (
                    cmd.name, self.__class__.__name__, self.name,
                    types[0], type(value), value))

class ListOfPrimaryKeys(Output):
    def validate(self, cmd, values, version):
        if client_has_capability(version, 'primary_key_types'):
            types = (tuple, list)
        else:
            types = (unicode,)
        if not isinstance(values, types):
            raise TypeError(
                "%s.validate_output() => %s.validate():\n"
                "  output[%r]: need %r; got %r: %r" % (
                    cmd.name, self.__class__.__name__, self.name,
                    types[0], type(values), values))

        if client_has_capability(version, 'primary_key_types'):
            if hasattr(cmd, 'obj') and cmd.obj and cmd.obj.primary_key:
                types = cmd.obj.primary_key.allowed_types
            else:
                types = (unicode,)
            for (i, value) in enumerate(values):
                if not isinstance(value, types):
                    raise TypeError(emsg % (
                        cmd.name, self.__class__.__name__, i, self.name,
                        types[0], type(value), value))


result = Output('result', doc=_('All commands should at least have a result'))

summary = Output('summary', (unicode, type(None)),
    _('User-friendly description of action performed')
)

value = PrimaryKey('value', None,
    _("The primary_key value of the entry, e.g. 'jdoe' for a user"),
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
    Output('count', int, _('Number of entries returned')),
    Output('truncated', bool, _('True if not all results were returned')),
)

standard_delete = (
    summary,
    Output('result', dict, _('List of deletions that failed')),
    value,
)

standard_multi_delete = (
    summary,
    Output('result', dict, _('List of deletions that failed')),
    ListOfPrimaryKeys('value', flags=['no_display']),
)

standard_boolean = (
    summary,
    Output('result', bool, _('True means the operation was successful')),
    value,
)

standard_value = standard_boolean

simple_value = (
    summary,
    Output('result', bool, _('True means the operation was successful')),
    Output('value', unicode, flags=['no_display']),
)

# custom shim for commands like `trustconfig-show`,
# `automember-default-group-*` which put stuff into output['value'] despite not
# having primary key themselves. Designing commands like this is not a very
# good practice, so please do not use this for new code.
simple_entry = (
    summary,
    Entry('result'),
    Output('value', unicode, flags=['no_display']),
)
