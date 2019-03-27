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

import six

from ipalib.frontend import Command, Object
from ipalib import api, errors
from ipalib import Bytes, Flag, Str, StrEnum
from ipalib import output
from ipalib.crud import PKQuery, Retrieve
from ipalib.parameters import Principal
from ipalib.plugable import Registry
from .baseldap import LDAPObject, LDAPCreate, LDAPDelete,\
    LDAPSearch, LDAPUpdate, LDAPRetrieve, LDAPAddMember, LDAPRemoveMember,\
    LDAPModMember, pkey_to_value
from ipalib.request import context
from .service import normalize_principal, validate_realm
from ipalib import _, ngettext
from ipapython import kerberos
from ipapython.dn import DN
from ipaserver.masters import is_service_enabled

if api.env.in_server:
    import pki.account
    import pki.key
    # pylint: disable=no-member
    try:
        # pki >= 10.4.0
        from pki.crypto import DES_EDE3_CBC_OID
    except ImportError:
        DES_EDE3_CBC_OID = pki.key.KeyClient.DES_EDE3_CBC_OID
    # pylint: enable=no-member


if six.PY3:
    unicode = str

__doc__ = _("""
Vaults
""") + _("""
Manage vaults.
""") + _("""
Vault is a secure place to store a secret. One vault can only
store one secret. When archiving a secret in a vault, the
existing secret (if any) is overwritten.
""") + _("""
Based on the ownership there are three vault categories:
* user/private vault
* service vault
* shared vault
""") + _("""
User vaults are vaults owned used by a particular user. Private
vaults are vaults owned the current user. Service vaults are
vaults owned by a service. Shared vaults are owned by the admin
but they can be used by other users or services.
""") + _("""
Based on the security mechanism there are three types of
vaults:
* standard vault
* symmetric vault
* asymmetric vault
""") + _("""
Standard vault uses a secure mechanism to transport and
store the secret. The secret can only be retrieved by users
that have access to the vault.
""") + _("""
Symmetric vault is similar to the standard vault, but it
pre-encrypts the secret using a password before transport.
The secret can only be retrieved using the same password.
""") + _("""
Asymmetric vault is similar to the standard vault, but it
pre-encrypts the secret using a public key before transport.
The secret can only be retrieved using the private key.
""") + _("""
EXAMPLES:
""") + _("""
 List vaults:
   ipa vault-find
       [--user <user>|--service <service>|--shared]
""") + _("""
 Add a standard vault:
   ipa vault-add <name>
       [--user <user>|--service <service>|--shared]
       --type standard
""") + _("""
 Add a symmetric vault:
   ipa vault-add <name>
       [--user <user>|--service <service>|--shared]
       --type symmetric --password-file password.txt
""") + _("""
 Add an asymmetric vault:
   ipa vault-add <name>
       [--user <user>|--service <service>|--shared]
       --type asymmetric --public-key-file public.pem
""") + _("""
 Show a vault:
   ipa vault-show <name>
       [--user <user>|--service <service>|--shared]
""") + _("""
 Modify vault description:
   ipa vault-mod <name>
       [--user <user>|--service <service>|--shared]
       --desc <description>
""") + _("""
 Modify vault type:
   ipa vault-mod <name>
       [--user <user>|--service <service>|--shared]
       --type <type>
       [old password/private key]
       [new password/public key]
""") + _("""
 Modify symmetric vault password:
   ipa vault-mod <name>
       [--user <user>|--service <service>|--shared]
       --change-password
   ipa vault-mod <name>
       [--user <user>|--service <service>|--shared]
       --old-password <old password>
       --new-password <new password>
   ipa vault-mod <name>
       [--user <user>|--service <service>|--shared]
       --old-password-file <old password file>
       --new-password-file <new password file>
""") + _("""
 Modify asymmetric vault keys:
   ipa vault-mod <name>
       [--user <user>|--service <service>|--shared]
       --private-key-file <old private key file>
       --public-key-file <new public key file>
""") + _("""
 Delete a vault:
   ipa vault-del <name>
       [--user <user>|--service <service>|--shared]
""") + _("""
 Display vault configuration:
   ipa vaultconfig-show
""") + _("""
 Archive data into standard vault:
   ipa vault-archive <name>
       [--user <user>|--service <service>|--shared]
       --in <input file>
""") + _("""
 Archive data into symmetric vault:
   ipa vault-archive <name>
       [--user <user>|--service <service>|--shared]
       --in <input file>
       --password-file password.txt
""") + _("""
 Archive data into asymmetric vault:
   ipa vault-archive <name>
       [--user <user>|--service <service>|--shared]
       --in <input file>
""") + _("""
 Retrieve data from standard vault:
   ipa vault-retrieve <name>
       [--user <user>|--service <service>|--shared]
       --out <output file>
""") + _("""
 Retrieve data from symmetric vault:
   ipa vault-retrieve <name>
       [--user <user>|--service <service>|--shared]
       --out <output file>
       --password-file password.txt
""") + _("""
 Retrieve data from asymmetric vault:
   ipa vault-retrieve <name>
       [--user <user>|--service <service>|--shared]
       --out <output file> --private-key-file private.pem
""") + _("""
 Add vault owners:
   ipa vault-add-owner <name>
       [--user <user>|--service <service>|--shared]
       [--users <users>]  [--groups <groups>] [--services <services>]
""") + _("""
 Delete vault owners:
   ipa vault-remove-owner <name>
       [--user <user>|--service <service>|--shared]
       [--users <users>] [--groups <groups>] [--services <services>]
""") + _("""
 Add vault members:
   ipa vault-add-member <name>
       [--user <user>|--service <service>|--shared]
       [--users <users>] [--groups <groups>] [--services <services>]
""") + _("""
 Delete vault members:
   ipa vault-remove-member <name>
       [--user <user>|--service <service>|--shared]
       [--users <users>] [--groups <groups>] [--services <services>]
""")


register = Registry()

vault_options = (
    Principal(
        'service?',
        validate_realm,
        doc=_('Service name of the service vault'),
        normalizer=normalize_principal,
    ),
    Flag(
        'shared?',
        doc=_('Shared vault'),
    ),
    Str(
        'username?',
        cli_name='user',
        doc=_('Username of the user vault'),
    ),
)


class VaultModMember(LDAPModMember):
    def get_options(self):
        for param in super(VaultModMember, self).get_options():
            if param.name == 'service' and param not in vault_options:
                param = param.clone_rename('services')
            yield param

    def get_member_dns(self, **options):
        if 'services' in options:
            options['service'] = options.pop('services')
        else:
            options.pop('service', None)
        return super(VaultModMember, self).get_member_dns(**options)

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        for fail in failed.values():
            fail['services'] = fail.pop('service', [])
        self.obj.get_container_attribute(entry_attrs, options)
        return completed, dn


@register()
class vaultcontainer(LDAPObject):
    __doc__ = _("""
    Vault Container object.
    """)

    container_dn = api.env.container_vault

    object_name = _('vaultcontainer')
    object_name_plural = _('vaultcontainers')
    object_class = ['ipaVaultContainer']
    permission_filter_objectclasses = ['ipaVaultContainer']

    attribute_members = {
        'owner': ['user', 'group', 'service'],
    }

    label = _('Vault Containers')
    label_singular = _('Vault Container')

    managed_permissions = {
        'System: Read Vault Containers': {
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN(api.env.container_vault, api.env.basedn),
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'cn', 'description', 'owner',
            },
            'default_privileges': {'Vault Administrators'},
        },
        'System: Add Vault Containers': {
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN(api.env.container_vault, api.env.basedn),
            'ipapermright': {'add'},
            'default_privileges': {'Vault Administrators'},
        },
        'System: Delete Vault Containers': {
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN(api.env.container_vault, api.env.basedn),
            'ipapermright': {'delete'},
            'default_privileges': {'Vault Administrators'},
        },
        'System: Modify Vault Containers': {
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN(api.env.container_vault, api.env.basedn),
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'objectclass', 'cn', 'description',
            },
            'default_privileges': {'Vault Administrators'},
        },
        'System: Manage Vault Container Ownership': {
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN(api.env.container_vault, api.env.basedn),
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'owner',
            },
            'default_privileges': {'Vault Administrators'},
        },
    }

    takes_params = (
        Str(
            'owner_user?',
            label=_('Owner users'),
        ),
        Str(
            'owner_group?',
            label=_('Owner groups'),
        ),
        Str(
            'owner_service?',
            label=_('Owner services'),
        ),
        Str(
            'owner?',
            label=_('Failed owners'),
        ),
        Str(
            'service?',
            label=_('Vault service'),
            flags={'virtual_attribute'},
        ),
        Flag(
            'shared?',
            label=_('Shared vault'),
            flags={'virtual_attribute'},
        ),
        Str(
            'username?',
            label=_('Vault user'),
            flags={'virtual_attribute'},
        ),
    )

    def get_dn(self, *keys, **options):
        """
        Generates vault DN from parameters.
        """
        service = options.get('service')
        shared = options.get('shared')
        user = options.get('username')

        count = (bool(service) + bool(shared) + bool(user))
        if count > 1:
            raise errors.MutuallyExclusiveError(
                reason=_('Service, shared and user options ' +
                         'cannot be specified simultaneously'))

        parent_dn = super(vaultcontainer, self).get_dn(*keys, **options)

        if not count:
            principal = kerberos.Principal(getattr(context, 'principal'))

            if principal.is_host:
                raise errors.NotImplementedError(
                    reason=_('Host is not supported'))
            elif principal.is_service:
                service = unicode(principal)
            else:
                user = principal.username

        if service:
            dn = DN(('cn', service), ('cn', 'services'), parent_dn)
        elif shared:
            dn = DN(('cn', 'shared'), parent_dn)
        elif user:
            dn = DN(('cn', user), ('cn', 'users'), parent_dn)
        else:
            raise RuntimeError

        return dn

    def get_container_attribute(self, entry, options):
        if options.get('raw', False):
            return
        container_dn = DN(self.container_dn, self.api.env.basedn)
        if entry.dn.endswith(DN(('cn', 'services'), container_dn)):
            entry['service'] = entry.dn[0]['cn']
        elif entry.dn.endswith(DN(('cn', 'shared'), container_dn)):
            entry['shared'] = True
        elif entry.dn.endswith(DN(('cn', 'users'), container_dn)):
            entry['username'] = entry.dn[0]['cn']


@register()
class vaultcontainer_show(LDAPRetrieve):
    __doc__ = _('Display information about a vault container.')

    takes_options = LDAPRetrieve.takes_options + vault_options

    has_output_params = LDAPRetrieve.has_output_params

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        if not self.api.Command.kra_is_enabled()['result']:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.get_container_attribute(entry_attrs, options)
        return dn


@register()
class vaultcontainer_del(LDAPDelete):
    __doc__ = _('Delete a vault container.')

    takes_options = LDAPDelete.takes_options + vault_options

    msg_summary = _('Deleted vault container')

    subtree_delete = False

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)

        if not self.api.Command.kra_is_enabled()['result']:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        return dn

    def execute(self, *keys, **options):
        keys = keys + (u'',)
        return super(vaultcontainer_del, self).execute(*keys, **options)


@register()
class vaultcontainer_add_owner(VaultModMember, LDAPAddMember):
    __doc__ = _('Add owners to a vault container.')

    takes_options = LDAPAddMember.takes_options + vault_options

    member_attributes = ['owner']
    member_param_label = _('owner %s')
    member_count_out = ('%i owner added.', '%i owners added.')

    has_output = (
        output.Entry('result'),
        output.Output(
            'failed',
            type=dict,
            doc=_('Owners that could not be added'),
        ),
        output.Output(
            'completed',
            type=int,
            doc=_('Number of owners added'),
        ),
    )


@register()
class vaultcontainer_remove_owner(VaultModMember, LDAPRemoveMember):
    __doc__ = _('Remove owners from a vault container.')

    takes_options = LDAPRemoveMember.takes_options + vault_options

    member_attributes = ['owner']
    member_param_label = _('owner %s')
    member_count_out = ('%i owner removed.', '%i owners removed.')

    has_output = (
        output.Entry('result'),
        output.Output(
            'failed',
            type=dict,
            doc=_('Owners that could not be removed'),
        ),
        output.Output(
            'completed',
            type=int,
            doc=_('Number of owners removed'),
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
    permission_filter_objectclasses = ['ipaVault']
    default_attributes = [
        'cn',
        'description',
        'ipavaulttype',
        'ipavaultsalt',
        'ipavaultpublickey',
        'owner',
        'member',
    ]
    search_display_attributes = [
        'cn',
        'description',
        'ipavaulttype',
    ]
    attribute_members = {
        'owner': ['user', 'group', 'service'],
        'member': ['user', 'group', 'service'],
    }

    label = _('Vaults')
    label_singular = _('Vault')

    managed_permissions = {
        'System: Read Vaults': {
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN(api.env.container_vault, api.env.basedn),
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass', 'cn', 'description', 'ipavaulttype',
                'ipavaultsalt', 'ipavaultpublickey', 'owner', 'member',
                'memberuser', 'memberhost',
            },
            'default_privileges': {'Vault Administrators'},
        },
        'System: Add Vaults': {
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN(api.env.container_vault, api.env.basedn),
            'ipapermright': {'add'},
            'default_privileges': {'Vault Administrators'},
        },
        'System: Delete Vaults': {
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN(api.env.container_vault, api.env.basedn),
            'ipapermright': {'delete'},
            'default_privileges': {'Vault Administrators'},
        },
        'System: Modify Vaults': {
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN(api.env.container_vault, api.env.basedn),
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'objectclass', 'cn', 'description', 'ipavaulttype',
                'ipavaultsalt', 'ipavaultpublickey',
            },
            'default_privileges': {'Vault Administrators'},
        },
        'System: Manage Vault Ownership': {
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN(api.env.container_vault, api.env.basedn),
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'owner',
            },
            'default_privileges': {'Vault Administrators'},
        },
        'System: Manage Vault Membership': {
            'ipapermlocation': api.env.basedn,
            'ipapermtarget': DN(api.env.container_vault, api.env.basedn),
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'member',
            },
            'default_privileges': {'Vault Administrators'},
        },
    }

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
        StrEnum(
            'ipavaulttype?',
            cli_name='type',
            label=_('Type'),
            doc=_('Vault type'),
            values=(u'standard', u'symmetric', u'asymmetric', ),
            default=u'symmetric',
            autofill=True,
        ),
        Bytes(
            'ipavaultsalt?',
            cli_name='salt',
            label=_('Salt'),
            doc=_('Vault salt'),
            flags=['no_search'],
        ),
        Bytes(
            'ipavaultpublickey?',
            cli_name='public_key',
            label=_('Public key'),
            doc=_('Vault public key'),
            flags=['no_search'],
        ),
        Str(
            'owner_user?',
            label=_('Owner users'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str(
            'owner_group?',
            label=_('Owner groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str(
            'owner_service?',
            label=_('Owner services'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str(
            'owner?',
            label=_('Failed owners'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str(
            'service?',
            label=_('Vault service'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Flag(
            'shared?',
            label=_('Shared vault'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'username?',
            label=_('Vault user'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
    )

    def get_dn(self, *keys, **options):
        """
        Generates vault DN from parameters.
        """
        service = options.get('service')
        shared = options.get('shared')
        user = options.get('username')

        count = (bool(service) + bool(shared) + bool(user))
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
            principal = kerberos.Principal(getattr(context, 'principal'))

            if principal.is_host:
                raise errors.NotImplementedError(
                    reason=_('Host is not supported'))
            elif principal.is_service:
                service = unicode(principal)
            else:
                user = principal.username

        if service:
            parent_dn = DN(('cn', service), ('cn', 'services'), container_dn)
        elif shared:
            parent_dn = DN(('cn', 'shared'), container_dn)
        elif user:
            parent_dn = DN(('cn', user), ('cn', 'users'), container_dn)
        else:
            raise RuntimeError

        return DN(rdns, parent_dn)

    def create_container(self, dn, owner_dn):
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
                    'objectclass': ['ipaVaultContainer'],
                    'cn': rdn['cn'],
                    'owner': [owner_dn],
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

    def get_key_id(self, dn):
        """
        Generates a client key ID to archive/retrieve data in KRA.
        """

        # TODO: create container_dn after object initialization then reuse it
        container_dn = DN(self.container_dn, self.api.env.basedn)

        # make sure the DN is a vault DN
        if not dn.endswith(container_dn, 1):
            raise ValueError('Invalid vault DN: %s' % dn)

        # construct the vault ID from the bottom up
        id = u''
        for rdn in dn[:-len(container_dn)]:
            name = rdn['cn']
            id = u'/' + name + id

        return 'ipa:' + id

    def get_container_attribute(self, entry, options):
        if options.get('raw', False):
            return
        container_dn = DN(self.container_dn, self.api.env.basedn)
        if entry.dn.endswith(DN(('cn', 'services'), container_dn)):
            entry['service'] = entry.dn[1]['cn']
        elif entry.dn.endswith(DN(('cn', 'shared'), container_dn)):
            entry['shared'] = True
        elif entry.dn.endswith(DN(('cn', 'users'), container_dn)):
            entry['username'] = entry.dn[1]['cn']


@register()
class vault_add_internal(LDAPCreate):
    __doc__ = _('Add a vault.')

    NO_CLI = True

    takes_options = LDAPCreate.takes_options + vault_options

    msg_summary = _('Added vault "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys,
                     **options):
        assert isinstance(dn, DN)

        if not self.api.Command.kra_is_enabled()['result']:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        principal = kerberos.Principal(getattr(context, 'principal'))
        if principal.is_service:
            owner_dn = self.api.Object.service.get_dn(unicode(principal))
        else:
            owner_dn = self.api.Object.user.get_dn(principal.username)

        parent_dn = DN(*dn[1:])

        try:
            self.obj.create_container(parent_dn, owner_dn)
        except (errors.DuplicateEntry, errors.ACIError):
            pass

        # vault should be owned by the creator
        entry_attrs['owner'] = owner_dn

        return dn

    def post_callback(self, ldap, dn, entry, *keys, **options):
        self.obj.get_container_attribute(entry, options)
        return dn


@register()
class vault_del(LDAPDelete):
    __doc__ = _('Delete a vault.')

    takes_options = LDAPDelete.takes_options + vault_options

    msg_summary = _('Deleted vault "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)

        if not self.api.Command.kra_is_enabled()['result']:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        return dn

    def post_callback(self, ldap, dn, *args, **options):
        assert isinstance(dn, DN)

        with self.api.Backend.kra.get_client() as kra_client:
            kra_account = pki.account.AccountClient(kra_client.connection)
            kra_account.login()

            client_key_id = self.obj.get_key_id(dn)

            # deactivate vault record in KRA
            response = kra_client.keys.list_keys(
                client_key_id, pki.key.KeyClient.KEY_STATUS_ACTIVE)

            for key_info in response.key_infos:
                kra_client.keys.modify_key_status(
                    key_info.get_key_id(),
                    pki.key.KeyClient.KEY_STATUS_INACTIVE)

            kra_account.logout()

        return True


@register()
class vault_find(LDAPSearch):
    __doc__ = _('Search for vaults.')

    takes_options = LDAPSearch.takes_options + vault_options + (
        Flag(
            'services?',
            doc=_('List all service vaults'),
        ),
        Flag(
            'users?',
            doc=_('List all user vaults'),
        ),
    )

    has_output_params = LDAPSearch.has_output_params

    msg_summary = ngettext(
        '%(count)d vault matched',
        '%(count)d vaults matched',
        0,
    )

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args,
                     **options):
        assert isinstance(base_dn, DN)

        if not self.api.Command.kra_is_enabled()['result']:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        if options.get('users') or options.get('services'):
            mutex = ['service', 'services', 'shared', 'username', 'users']
            count = sum(bool(options.get(option)) for option in mutex)
            if count > 1:
                raise errors.MutuallyExclusiveError(
                    reason=_('Service(s), shared, and user(s) options ' +
                             'cannot be specified simultaneously'))

            scope = ldap.SCOPE_SUBTREE
            container_dn = DN(self.obj.container_dn,
                              self.api.env.basedn)

            if options.get('services'):
                base_dn = DN(('cn', 'services'), container_dn)
            else:
                base_dn = DN(('cn', 'users'), container_dn)
        else:
            base_dn = self.obj.get_dn(None, **options)

        return filter, base_dn, scope

    def post_callback(self, ldap, entries, truncated, *args, **options):
        for entry in entries:
            self.obj.get_container_attribute(entry, options)
        return truncated

    def exc_callback(self, args, options, exc, call_func, *call_args,
                     **call_kwargs):
        if call_func.__name__ == 'find_entries':
            if isinstance(exc, errors.NotFound):
                # ignore missing containers since they will be created
                # automatically on vault creation.
                raise errors.EmptyResult(reason=str(exc))

        raise exc


@register()
class vault_mod_internal(LDAPUpdate):
    __doc__ = _('Modify a vault.')

    NO_CLI = True

    takes_options = LDAPUpdate.takes_options + vault_options

    msg_summary = _('Modified vault "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list,
                     *keys, **options):

        assert isinstance(dn, DN)

        if not self.api.Command.kra_is_enabled()['result']:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.get_container_attribute(entry_attrs, options)
        return dn


@register()
class vault_show(LDAPRetrieve):
    __doc__ = _('Display information about a vault.')

    takes_options = LDAPRetrieve.takes_options + vault_options

    has_output_params = LDAPRetrieve.has_output_params

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        if not self.api.Command.kra_is_enabled()['result']:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.get_container_attribute(entry_attrs, options)
        return dn


@register()
class vaultconfig(Object):
    __doc__ = _('Vault configuration')

    takes_params = (
        Bytes(
            'transport_cert',
            label=_('Transport Certificate'),
        ),
        Str(
            'kra_server_server*',
            label=_('IPA KRA servers'),
            doc=_('IPA servers configured as key recovery agents'),
            flags={'virtual_attribute', 'no_create', 'no_update'}
        )
    )


@register()
class vaultconfig_show(Retrieve):
    __doc__ = _('Show vault configuration.')

    takes_options = (
        Str(
            'transport_out?',
            doc=_('Output file to store the transport certificate'),
        ),
    )

    def execute(self, *args, **options):

        if not self.api.Command.kra_is_enabled()['result']:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        with self.api.Backend.kra.get_client() as kra_client:
            transport_cert = kra_client.system_certs.get_transport_cert()
            config = {'transport_cert': transport_cert.binary}

        self.api.Object.config.show_servroles_attributes(
            config, "KRA server", **options)

        return {
            'result': config,
            'value': None,
        }


@register()
class vault_archive_internal(PKQuery):
    __doc__ = _('Archive data into a vault.')

    NO_CLI = True

    takes_options = vault_options + (
        Bytes(
            'session_key',
            doc=_('Session key wrapped with transport certificate'),
        ),
        Bytes(
            'vault_data',
            doc=_('Vault data encrypted with session key'),
        ),
        Bytes(
            'nonce',
            doc=_('Nonce'),
        ),
    )

    has_output = output.standard_entry

    msg_summary = _('Archived data into vault "%(value)s"')

    def execute(self, *args, **options):

        if not self.api.Command.kra_is_enabled()['result']:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        wrapped_vault_data = options.pop('vault_data')
        nonce = options.pop('nonce')
        wrapped_session_key = options.pop('session_key')

        # retrieve vault info
        vault = self.api.Command.vault_show(*args, **options)['result']

        # connect to KRA
        with self.api.Backend.kra.get_client() as kra_client:
            kra_account = pki.account.AccountClient(kra_client.connection)
            kra_account.login()

            client_key_id = self.obj.get_key_id(vault['dn'])

            # deactivate existing vault record in KRA
            response = kra_client.keys.list_keys(
                client_key_id,
                pki.key.KeyClient.KEY_STATUS_ACTIVE)

            for key_info in response.key_infos:
                kra_client.keys.modify_key_status(
                    key_info.get_key_id(),
                    pki.key.KeyClient.KEY_STATUS_INACTIVE)

            # forward wrapped data to KRA
            kra_client.keys.archive_encrypted_data(
                client_key_id,
                pki.key.KeyClient.PASS_PHRASE_TYPE,
                wrapped_vault_data,
                wrapped_session_key,
                algorithm_oid=DES_EDE3_CBC_OID,
                nonce_iv=nonce,
            )

            kra_account.logout()

        response = {
            'value': args[-1],
            'result': {},
        }

        response['summary'] = self.msg_summary % response

        return response


@register()
class vault_retrieve_internal(PKQuery):
    __doc__ = _('Retrieve data from a vault.')

    NO_CLI = True

    takes_options = vault_options + (
        Bytes(
            'session_key',
            doc=_('Session key wrapped with transport certificate'),
        ),
    )

    has_output = output.standard_entry

    msg_summary = _('Retrieved data from vault "%(value)s"')

    def execute(self, *args, **options):

        if not self.api.Command.kra_is_enabled()['result']:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        wrapped_session_key = options.pop('session_key')

        # retrieve vault info
        vault = self.api.Command.vault_show(*args, **options)['result']

        # connect to KRA
        with self.api.Backend.kra.get_client() as kra_client:
            kra_account = pki.account.AccountClient(kra_client.connection)
            kra_account.login()

            client_key_id = self.obj.get_key_id(vault['dn'])

            # find vault record in KRA
            response = kra_client.keys.list_keys(
                client_key_id,
                pki.key.KeyClient.KEY_STATUS_ACTIVE)

            if not len(response.key_infos):
                raise errors.NotFound(reason=_('No archived data.'))

            key_info = response.key_infos[0]

            # retrieve encrypted data from KRA
            key = kra_client.keys.retrieve_key(
                key_info.get_key_id(),
                wrapped_session_key)

            kra_account.logout()

        response = {
            'value': args[-1],
            'result': {
                'vault_data': key.encrypted_data,
                'nonce': key.nonce_data,
            },
        }

        response['summary'] = self.msg_summary % response

        return response


@register()
class vault_add_owner(VaultModMember, LDAPAddMember):
    __doc__ = _('Add owners to a vault.')

    takes_options = LDAPAddMember.takes_options + vault_options

    member_attributes = ['owner']
    member_param_label = _('owner %s')
    member_count_out = ('%i owner added.', '%i owners added.')

    has_output = (
        output.Entry('result'),
        output.Output(
            'failed',
            type=dict,
            doc=_('Owners that could not be added'),
        ),
        output.Output(
            'completed',
            type=int,
            doc=_('Number of owners added'),
        ),
    )


@register()
class vault_remove_owner(VaultModMember, LDAPRemoveMember):
    __doc__ = _('Remove owners from a vault.')

    takes_options = LDAPRemoveMember.takes_options + vault_options

    member_attributes = ['owner']
    member_param_label = _('owner %s')
    member_count_out = ('%i owner removed.', '%i owners removed.')

    has_output = (
        output.Entry('result'),
        output.Output(
            'failed',
            type=dict,
            doc=_('Owners that could not be removed'),
        ),
        output.Output(
            'completed',
            type=int,
            doc=_('Number of owners removed'),
        ),
    )


@register()
class vault_add_member(VaultModMember, LDAPAddMember):
    __doc__ = _('Add members to a vault.')

    takes_options = LDAPAddMember.takes_options + vault_options


@register()
class vault_remove_member(VaultModMember, LDAPRemoveMember):
    __doc__ = _('Remove members from a vault.')

    takes_options = LDAPRemoveMember.takes_options + vault_options


@register()
class kra_is_enabled(Command):
    __doc__ = _('Checks if any of the servers has the KRA service enabled')
    NO_CLI = True

    has_output = output.standard_value

    def execute(self, *args, **options):
        result = is_service_enabled('KRA', conn=self.api.Backend.ldap2)
        return dict(result=result, value=pkey_to_value(None, options))
