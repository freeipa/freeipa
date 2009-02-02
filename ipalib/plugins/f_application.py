# Authors:
#   Jakub Hrozek <jhrozek@redhat.com>
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
Frontend plugins for application policy containers.
"""

from ipalib import api, crud
from ipalib import Object, Command    # Plugin base classes
from ipalib import Str, StrEnum, Flag # Parameter types

def get_base_by_type(type):
    if type == 'config':
        return api.env.container_applications
    if type == 'role':
        return api.env.container_roles

class application(Object):
    'Application object'
    takes_params = (
        Str('cn',
            cli_name='appname',
            primary_key=True,
            doc='Application name',
        ),
        Str('description?',
            doc='Application description',
        ),
    )
api.register(application)

# The default attributes to query
default_attributes = ['cn','description']

class application_create(crud.Create):
    'Add a new application'
    takes_options = (
        StrEnum('type',
            values=(u'config', u'role'),
            doc='The type of the application',
        ),
    )

    def execute(self, cn, **kw):
        """
        Execute the application-create operation

        The dn should not be passed as a keyword argument, it
        should be constructed by this method.

        :param cn: The name of the application being added.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        self.log.info("IPA: application-create '%s'" % cn)

        assert 'dn' not in kw
        assert 'cn' not in kw
        ldap = self.api.Backend.ldap

        kw['objectClass'] = ['nsContainer', 'ipaContainer']
        if kw['type'] == 'config':
            kw['dn'] = ldap.make_application_dn(cn)
        if kw['type'] == 'role':
            kw['dn'] = ldap.make_role_application_dn(cn)
        kw['cn'] = cn

        del kw['type']
        return ldap.create(**kw)

    def output_for_cli(self, textui, result, *args, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_name(self.name)
        textui.print_entry(result)
        textui.print_dashed('Added application "%s"' % result['cn'])

api.register(application_create)

class application_find(crud.Search):
    'Search for applications'
    takes_options = (
        StrEnum('type',
            values=(u'config', u'role'),
            doc='The type of the application',
        ),
        Flag('all',
            doc='Retrieve all application attributes'
        ),
    )

    def execute(self, term, **kw):
        """
        Execute the application-find operation
        """
        ldap = self.api.Backend.ldap

        search_kw = dict()
        search_kw['cn'] = term
        search_kw['objectclass'] = 'ipaContainer'
        search_kw['base'] = get_base_by_type(kw['type'])
        search_kw['scope'] = 'one'
        if kw.get('all', False):
            search_kw['attributes'] = ['*']
        else:
            search_kw['attributes'] = default_attributes

        return ldap.search(**search_kw)

    def output_for_cli(self, textui, result, cn, **options):
        """
        Output result of this command to command line interface.
        """
        counter = result[0]
        apps = result[1:]
        if counter == 0 or len(apps) == 0:
            textui.print_plain("No applications found")
            return
        if len(apps) == 1:
            textui.print_entry(apps[0])
            return
        textui.print_name(self.name)
        for a in apps:
            textui.print_plain('%(cn)s:' % a)
            textui.print_entry(a)
            textui.print_plain('')
        if counter == -1:
            textui.print_plain('These results are truncated.')
            textui.print_plain('Please refine your search and try again.')
        textui.print_count(apps, '%d applications matched')

api.register(application_find)

class application_delete(crud.Del):
    'Delete an application'
    takes_options = (
        StrEnum('type',
            values=(u'config', u'role'),
            doc='The type of the application',
        ),
    )

    def execute(self, cn, **kw):
        """
        Delete the application container.

        :param cn: The name of the application being deleted.
        :param kw: Not used.
        """
        if cn == "Shell Applications":
            raise SyntaxError("Cannot delete shell application")
        self.log.info("IPA: application_delete '%s'" % cn)

        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn",
                                cn,
                                object_type='ipaContainer',
                                base=get_base_by_type(kw['type']))

        return ldap.delete(dn)

    def output_for_cli(self, textui, result, cn):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain('Deleted application "%s"' % cn)

api.register(application_delete)

class application_show(crud.Get):
    'Examine an existing application'
    takes_options = (
        StrEnum('type',
            values=(u'config', u'role'),
            doc='The type of the application',
        ),
        Flag('all',
            doc='Retrieve all application attributes'
        ),
    )
    def execute(self, cn, **kw):
        """
        Execute the application-show operation.
        """
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn",
                                cn,
                                object_type='ipaContainer',
                                base=get_base_by_type(kw['type']))

        if kw.get('all', False):
            return ldap.retrieve(dn)
        else:
            return ldap.retrieve(dn, default_attributes)

    def output_for_cli(self, textui, result, cn, **options):
        if result:
            textui.print_entry(result)

api.register(application_show)

class application_edit(crud.Mod):
    'Edit an existing application'
    takes_options = (
        StrEnum('type',
            values=(u'config', u'role'),
            doc='The type of the application',
        ),
    )

    def execute(self, cn, **kw):
        """
        Execute the application-edit operation

        :param cn: The name of the application to edit
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        self.log.info("IPA: application_edit '%s'" % cn)

        assert 'cn' not in kw
        assert 'dn' not in kw
        ldap = self.api.Backend.ldap
        dn = ldap.find_entry_dn("cn",
                                cn,
                                object_type='ipaContainer',
                                base=get_base_by_type(kw['type']))

        del kw['type']
        return ldap.update(dn, **kw)

    def output_for_cli(self, textui, result, cn, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_name(self.name)
        textui.print_entry(result)
        textui.print_dashed('Updated application "%s"' % result['cn'])

api.register(application_edit)
