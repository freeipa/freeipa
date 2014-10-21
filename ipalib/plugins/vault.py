# Authors:
#   Endi S. Dewata <edewata@redhat.com>
#
# Copyright (C) 2015  Red Hat
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

from ipalib import api, errors
from ipalib import Str, Flag
from ipalib import output
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import LDAPObject, LDAPCreate, LDAPDelete,\
    LDAPSearch, LDAPUpdate, LDAPRetrieve
from ipalib.request import context
from ipalib.plugins.user import split_principal
from ipalib import _, ngettext
from ipapython.dn import DN

__doc__ = _("""
Vaults
""") + _("""
Manage vaults.
""") + _("""
EXAMPLES:
""") + _("""
 List private vaults:
   ipa vault-find
""") + _("""
 List service vaults:
   ipa vault-find --service <service name>
""") + _("""
 List shared vaults:
   ipa vault-find --shared
""") + _("""
 List user vaults:
   ipa vault-find --user <username>
""") + _("""
 Add a private vault:
   ipa vault-add <name>
""") + _("""
 Add a service vault:
   ipa vault-add <name> --service <service name>
""") + _("""
 Add a shared vault:
   ipa vault-add <ame> --shared
""") + _("""
 Add a user vault:
   ipa vault-add <name> --user <username>
""") + _("""
 Show a private vault:
   ipa vault-show <name>
""") + _("""
 Show a service vault:
   ipa vault-show <name> --service <service name>
""") + _("""
 Show a shared vault:
   ipa vault-show <name> --shared
""") + _("""
 Show a user vault:
   ipa vault-show <name> --user <username>
""") + _("""
 Modify a private vault:
   ipa vault-mod <name> --desc <description>
""") + _("""
 Modify a service vault:
   ipa vault-mod <name> --service <service name> --desc <description>
""") + _("""
 Modify a shared vault:
   ipa vault-mod <name> --shared --desc <description>
""") + _("""
 Modify a user vault:
   ipa vault-mod <name> --user <username> --desc <description>
""") + _("""
 Delete a private vault:
   ipa vault-del <name>
""") + _("""
 Delete a service vault:
   ipa vault-del <name> --service <service name>
""") + _("""
 Delete a shared vault:
   ipa vault-del <name> --shared
""") + _("""
 Delete a user vault:
   ipa vault-del <name> --user <username>
""")

register = Registry()


vault_options = (
    Str(
        'service?',
        doc=_('Service name'),
    ),
    Flag(
        'shared?',
        doc=_('Shared vault'),
    ),
    Str(
        'user?',
        doc=_('Username'),
    ),
)


@register()
class vault(LDAPObject):
    __doc__ = _("""
    Vault object.
    """)

    container_dn = api.env.container_vault

    object_name = _('vault')
    object_name_plural = _('vaults')

    object_class = ['ipaVault']
    default_attributes = [
        'cn',
        'description',
    ]

    label = _('Vaults')
    label_singular = _('Vault')

    takes_params = (
        Str(
            'cn',
            cli_name='name',
            label=_('Vault name'),
            primary_key=True,
            pattern='^[a-zA-Z0-9_.-]+$',
            pattern_errmsg='may only include letters, numbers, _, ., and -',
            maxlength=255,
        ),
        Str(
            'description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('Vault description'),
        ),
    )

    def get_dn(self, *keys, **options):
        """
        Generates vault DN from parameters.
        """

        service = options.get('service')
        shared = options.get('shared')
        user = options.get('user')

        count = 0
        if service:
            count += 1

        if shared:
            count += 1

        if user:
            count += 1

        if count > 1:
            raise errors.MutuallyExclusiveError(
                reason=_('Service, shared, and user options ' +
                         'cannot be specified simultaneously'))

        # TODO: create container_dn after object initialization then reuse it
        container_dn = DN(self.container_dn, self.api.env.basedn)

        dn = super(vault, self).get_dn(*keys, **options)
        assert dn.endswith(container_dn)
        rdns = DN(*dn[:-len(container_dn)])

        if not count:
            principal = getattr(context, 'principal')

            if principal.startswith('host/'):
                raise errors.NotImplementedError(
                    reason=_('Host is not supported'))

            (name, realm) = split_principal(principal)
            if '/' in name:
                service = name
            else:
                user = name

        if service:
            parent_dn = DN(('cn', service), ('cn', 'services'), container_dn)
        elif shared:
            parent_dn = DN(('cn', 'shared'), container_dn)
        else:
            parent_dn = DN(('cn', user), ('cn', 'users'), container_dn)

        return DN(rdns, parent_dn)

    def create_container(self, dn):
        """
        Creates vault container and its parents.
        """

        # TODO: create container_dn after object initialization then reuse it
        container_dn = DN(self.container_dn, self.api.env.basedn)

        entries = []

        while dn:
            assert dn.endswith(container_dn)

            rdn = dn[0]
            entry = self.backend.make_entry(
                dn,
                {
                    'objectclass': ['nsContainer'],
                    'cn': rdn['cn'],
                })

            # if entry can be added, return
            try:
                self.backend.add_entry(entry)
                break

            except errors.NotFound:
                pass

            # otherwise, create parent entry first
            dn = DN(*dn[1:])
            entries.insert(0, entry)

        # then create the entries again
        for entry in entries:
            self.backend.add_entry(entry)


@register()
class vault_add(LDAPCreate):
    __doc__ = _('Create a new vault.')

    takes_options = LDAPCreate.takes_options + vault_options

    msg_summary = _('Added vault "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys,
                     **options):
        assert isinstance(dn, DN)

        try:
            parent_dn = DN(*dn[1:])
            self.obj.create_container(parent_dn)
        except errors.DuplicateEntry, e:
            pass

        return dn


@register()
class vault_del(LDAPDelete):
    __doc__ = _('Delete a vault.')

    takes_options = LDAPDelete.takes_options + vault_options

    msg_summary = _('Deleted vault "%(value)s"')


@register()
class vault_find(LDAPSearch):
    __doc__ = _('Search for vaults.')

    takes_options = LDAPSearch.takes_options + vault_options

    msg_summary = ngettext(
        '%(count)d vault matched',
        '%(count)d vaults matched',
        0,
    )

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args,
                     **options):
        assert isinstance(base_dn, DN)

        base_dn = self.obj.get_dn(*args, **options)

        return (filter, base_dn, scope)

    def exc_callback(self, args, options, exc, call_func, *call_args,
                     **call_kwargs):
        if call_func.__name__ == 'find_entries':
            if isinstance(exc, errors.NotFound):
                # ignore missing containers since they will be created
                # automatically on vault creation.
                raise errors.EmptyResult(reason=str(exc))

        raise exc


@register()
class vault_mod(LDAPUpdate):
    __doc__ = _('Modify a vault.')

    takes_options = LDAPUpdate.takes_options + vault_options

    msg_summary = _('Modified vault "%(value)s"')


@register()
class vault_show(LDAPRetrieve):
    __doc__ = _('Display information about a vault.')

    takes_options = LDAPRetrieve.takes_options + vault_options
