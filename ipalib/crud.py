# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
Base classes for standard CRUD operations.

These base classes are for `Method` plugins that provide standard
Create, Retrieve, Updated, and Delete operations (CRUD) for their corresponding
`Object` plugin.  In particuar, these base classes provide logic to
automatically create the plugin args and options by inspecting the params on
their corresponding `Object` plugin.  This provides a single point of definition
for LDAP attributes and enforces a simple, consistent API for CRUD operations.

For example, say we want CRUD operations on a hypothetical "user" entry.  First
we need an `Object` plugin:

>>> from ipalib import Object, Str
>>> class user(Object):
...     takes_params = (
...         Str('login', primary_key=True),
...         Str('first'),
...         Str('last'),
...         Str('ipauniqueid', flags=['no_create', 'no_update']),
...     )
...

Next we need `Create`, `Retrieve`, `Updated`, and `Delete` plugins, and
optionally a `Search` plugin.  For brevity, we'll just define `Create` and
`Retrieve` plugins:

>>> from ipalib import crud
>>> class user_add(crud.Create):
...     pass
...
>>> class user_show(crud.Retrieve):
...     pass
...

Now we'll register the plugins and finalize the `plugable.API` instance:

>>> from ipalib import create_api
>>> api = create_api()
>>> api.add_plugin(user)
>>> api.add_plugin(user_add)
>>> api.add_plugin(user_show)
>>> api.finalize()

First, notice that our ``user`` `Object` has the params we defined with the
``takes_params`` tuple:

>>> list(api.Object.user.params)
['login', 'first', 'last', 'ipauniqueid']
>>> api.Object.user.params.login
Str('login', primary_key=True)

Although we defined neither ``takes_args`` nor ``takes_options`` for our
``user_add`` plugin, the `Create` base class automatically generated them for
us:

>>> list(api.Command.user_add.args)
['login']
>>> list(api.Command.user_add.options)
['first', 'last', 'all', 'raw', 'version']

Notice that ``'ipauniqueid'`` isn't included in the options for our ``user_add``
plugin.  This is because of the ``'no_create'`` flag we used when defining the
``ipauniqueid`` param.  Often times there are LDAP attributes that are
automatically created by the server and therefor should not be supplied as an
option to the `Create` plugin.  Often these same attributes shouldn't be
update-able either, in which case you can also supply the ``'no_update'`` flag,
as we did with our ``ipauniqueid`` param.  Lastly, you can also use the ``'no_search'`` flag for attributes that shouldn't be search-able (because, for
example, the attribute isn't indexed).

As with our ``user_add` plugin, we defined neither ``takes_args`` nor
``takes_options`` for our ``user_show`` plugin; instead the `Retrieve` base
class created them for us:

>>> list(api.Command.user_show.args)
['login']
>>> list(api.Command.user_show.options)
['all', 'raw', 'version']

As you can see, `Retrieve` plugins take a single argument (the primary key) and
no options.  If needed, you can still specify options for your `Retrieve` plugin
with a ``takes_options`` tuple.

Flags like ``'no_create'`` remove LDAP attributes from those that can be
supplied as *input* to a `Method`, but they don't effect the attributes that can
be returned as *output*.  Regardless of what flags have been used, the output
entry (or list of entries) can contain all the attributes defined on the
`Object` plugin (in our case, the above ``user.params``).

For example, compare ``user.params`` with ``user_add.output_params`` and
``user_show.output_params``:

>>> list(api.Object.user.params)
['login', 'first', 'last', 'ipauniqueid']
>>> list(api.Command.user_add.output_params)
['login', 'first', 'last', 'ipauniqueid']
>>> list(api.Command.user_show.output_params)
['login', 'first', 'last', 'ipauniqueid']

Note that the above are all equal.
"""

from ipalib.frontend import Method
from ipalib import backend
from ipalib import parameters
from ipalib import output
from ipalib.text import _


class Create(Method):
    """
    Create a new entry.
    """

    has_output = output.standard_entry

    def __clone(self, param, **kw):
        if 'optional_create' in param.flags:
            kw['required'] = False
        return param.clone(**kw) if kw else param

    def get_args(self):
        if self.obj.primary_key:
            yield self.__clone(self.obj.primary_key, attribute=True)
        for arg in super(Create, self).get_args():
            yield self.__clone(arg)

    def get_options(self):
        if self.extra_options_first:
            for option in super(Create, self).get_options():
                yield self.__clone(option)
        for option in self.obj.params_minus(self.args):
            attribute = 'virtual_attribute' not in option.flags
            if 'no_create' in option.flags:
                continue
            if 'ask_create' in option.flags:
                yield option.clone(
                    attribute=attribute, query=False, required=False,
                    autofill=False, alwaysask=True
                )
            else:
                yield self.__clone(option, attribute=attribute)
        if not self.extra_options_first:
            for option in super(Create, self).get_options():
                yield self.__clone(option)


class PKQuery(Method):
    """
    Base class for `Retrieve`, `Update`, and `Delete`.
    """

    def get_args(self):
        if self.obj.primary_key:
            # Don't enforce rules on the primary key so we can reference
            # any stored entry, legal or not
            yield self.obj.primary_key.clone(attribute=True, query=True)
        for arg in super(PKQuery, self).get_args():
            yield arg


class Retrieve(PKQuery):
    """
    Retrieve an entry by its primary key.
    """

    has_output = output.standard_entry


class Update(PKQuery):
    """
    Update one or more attributes on an entry.
    """

    has_output = output.standard_entry

    def get_options(self):
        if self.extra_options_first:
            for option in super(Update, self).get_options():
                yield option
        for option in self.obj.params_minus_pk():
            new_flags = option.flags
            attribute = 'virtual_attribute' not in option.flags
            if option.required:
                # Required options turn into non-required, since not specifying
                # them means that they are not changed.
                # However, they cannot be empty (i.e. explicitly set to None).
                new_flags = new_flags.union(['nonempty'])
            if 'no_update' in option.flags:
                continue
            if 'ask_update' in option.flags:
                yield option.clone(
                    attribute=attribute, query=False, required=False,
                    autofill=False, alwaysask=True, flags=new_flags,
                )
            elif 'req_update' in option.flags:
                yield option.clone(
                    attribute=attribute, required=True, alwaysask=False,
                    flags=new_flags,
                )
            else:
                yield option.clone(attribute=attribute, required=False,
                    autofill=False, flags=new_flags,
                )
        if not self.extra_options_first:
            for option in super(Update, self).get_options():
                yield option


class Delete(PKQuery):
    """
    Delete one or more entries.
    """

    has_output = output.standard_delete


class Search(Method):
    """
    Retrieve all entries that match a given search criteria.
    """

    has_output = output.standard_list_of_entries

    def get_args(self):
        yield parameters.Str(
            'criteria?', noextrawhitespace=False,
            doc=_('A string searched in all relevant object attributes'))
        for arg in super(Search, self).get_args():
            yield arg

    def get_options(self):
        if self.extra_options_first:
            for option in super(Search, self).get_options():
                yield option
        for option in self.obj.params_minus(self.args):
            attribute = 'virtual_attribute' not in option.flags
            if 'no_search' in option.flags:
                continue
            if 'ask_search' in option.flags:
                yield option.clone(
                    attribute=attribute, query=True, required=False,
                    autofill=False, alwaysask=True
                )
            elif isinstance(option, parameters.Flag):
                yield option.clone_retype(
                    option.name, parameters.Bool,
                    attribute=attribute, query=True, required=False, autofill=False
                )
            else:
                yield option.clone(
                    attribute=attribute, query=True, required=False, autofill=False
                )
        if not self.extra_options_first:
            for option in super(Search, self).get_options():
                yield option


class CrudBackend(backend.Connectible):
    """
    Base class defining generic CRUD backend API.
    """

    def create(self, **kw):
        """
        Create a new entry.

        This method should take key word arguments representing the
        attributes the created entry will have.

        If this methods constructs the primary_key internally, it should raise
        an exception if the primary_key was passed.  Likewise, if this method
        requires the primary_key to be passed in from the caller, it should
        raise an exception if the primary key was *not* passed.

        This method should return a dict of the exact entry as it was created
        in the backing store, including any automatically created attributes.
        """
        raise NotImplementedError('%s.create()' % self.name)

    def retrieve(self, primary_key, attributes):
        """
        Retrieve an existing entry.

        This method should take a two arguments: the primary_key of the
        entry in question and a list of the attributes to be retrieved.
        If the list of attributes is None then all non-operational
        attributes will be returned.

        If such an entry exists, this method should return a dict
        representing that entry.  If no such entry exists, this method
        should return None.
        """
        raise NotImplementedError('%s.retrieve()' % self.name)

    def update(self, primary_key, **kw):
        """
        Update an existing entry.

        This method should take one required argument, the primary_key of the
        entry to modify, plus optional keyword arguments for each of the
        attributes being updated.

        This method should return a dict representing the entry as it now
        exists in the backing store.  If no such entry exists, this method
        should return None.
        """
        raise NotImplementedError('%s.update()' % self.name)

    def delete(self, primary_key):
        """
        Delete an existing entry.

        This method should take one required argument, the primary_key of the
        entry to delete.
        """
        raise NotImplementedError('%s.delete()' % self.name)

    def search(self, **kw):
        """
        Return entries matching specific criteria.

        This method should take keyword arguments representing the search
        criteria.  If a key is the name of an entry attribute, the value
        should be treated as a filter on that attribute.  The meaning of
        keys outside this namespace is left to the implementation.

        This method should return and iterable containing the matched
        entries, where each entry is a dict.  If no entries are matched,
        this method should return an empty iterable.
        """
        raise NotImplementedError('%s.search()' % self.name)
