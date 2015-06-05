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

import base64
import json
import os
import sys
import tempfile

import nss.nss as nss
import krbV

from ipalib.frontend import Command, Object, Local
from ipalib import api, errors
from ipalib import Bytes, Str, Flag
from ipalib import output
from ipalib.crud import PKQuery, Retrieve, Update
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import LDAPObject, LDAPCreate, LDAPDelete,\
    LDAPSearch, LDAPUpdate, LDAPRetrieve
from ipalib.request import context
from ipalib.plugins.user import split_principal
from ipalib import _, ngettext
from ipaplatform.paths import paths
from ipapython.dn import DN
from ipapython.nsslib import current_dbdir

if api.env.in_server:
    import pki.account
    import pki.key

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
""") + _("""
 Display vault configuration:
   ipa vault-config
""") + _("""
 Archive data into private vault:
   ipa vault-archive <name> --in <input file>
""") + _("""
 Archive data into service vault:
   ipa vault-archive <name> --service <service name> --in <input file>
""") + _("""
 Archive data into shared vault:
   ipa vault-archive <name> --shared --in <input file>
""") + _("""
 Archive data into user vault:
   ipa vault-archive <name> --user <username> --in <input file>
""") + _("""
 Retrieve data from private vault:
   ipa vault-retrieve <name> --out <output file>
""") + _("""
 Retrieve data from service vault:
   ipa vault-retrieve <name> --service <service name> --out <output file>
""") + _("""
 Retrieve data from shared vault:
   ipa vault-retrieve <name> --shared --out <output file>
""") + _("""
 Retrieve data from user vault:
   ipa vault-retrieve <name> --user <user name> --out <output file>
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


@register()
class vault_add(LDAPCreate):
    __doc__ = _('Create a new vault.')

    takes_options = LDAPCreate.takes_options + vault_options

    msg_summary = _('Added vault "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys,
                     **options):
        assert isinstance(dn, DN)

        if not self.api.env.enable_kra:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

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

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)

        if not self.api.env.enable_kra:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        return dn

    def post_callback(self, ldap, dn, *args, **options):
        assert isinstance(dn, DN)

        kra_client = self.api.Backend.kra.get_client()

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

    takes_options = LDAPSearch.takes_options + vault_options

    msg_summary = ngettext(
        '%(count)d vault matched',
        '%(count)d vaults matched',
        0,
    )

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args,
                     **options):
        assert isinstance(base_dn, DN)

        if not self.api.env.enable_kra:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

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

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list,
                     *keys, **options):

        assert isinstance(dn, DN)

        if not self.api.env.enable_kra:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        return dn


@register()
class vault_show(LDAPRetrieve):
    __doc__ = _('Display information about a vault.')

    takes_options = LDAPRetrieve.takes_options + vault_options

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        if not self.api.env.enable_kra:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        return dn


@register()
class vaultconfig(Object):
    __doc__ = _('Vault configuration')

    takes_params = (
        Bytes(
            'transport_cert',
            label=_('Transport Certificate'),
        ),
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

    def forward(self, *args, **options):

        file = options.get('transport_out')

        # don't send these parameters to server
        if 'transport_out' in options:
            del options['transport_out']

        response = super(vaultconfig_show, self).forward(*args, **options)

        if file:
            with open(file, 'w') as f:
                f.write(response['result']['transport_cert'])

        return response

    def execute(self, *args, **options):

        if not self.api.env.enable_kra:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        kra_client = self.api.Backend.kra.get_client()
        transport_cert = kra_client.system_certs.get_transport_cert()
        return {
            'result': {
                'transport_cert': transport_cert.binary
            },
            'value': None,
        }


@register()
class vault_archive(PKQuery, Local):
    __doc__ = _('Archive data into a vault.')

    takes_options = vault_options + (
        Bytes(
            'data?',
            doc=_('Binary data to archive'),
        ),
        Str(  # TODO: use File parameter
            'in?',
            doc=_('File containing data to archive'),
        ),
    )

    has_output = output.standard_entry

    msg_summary = _('Archived data into vault "%(value)s"')

    def forward(self, *args, **options):

        data = options.get('data')
        input_file = options.get('in')

        # don't send these parameters to server
        if 'data' in options:
            del options['data']
        if 'in' in options:
            del options['in']

        # get data
        if data and input_file:
            raise errors.MutuallyExclusiveError(
                reason=_('Input data specified multiple times'))

        if input_file:
            with open(input_file, 'rb') as f:
                data = f.read()

        elif not data:
            data = ''

        if self.api.env.in_server:
            backend = self.api.Backend.ldap2
        else:
            backend = self.api.Backend.rpcclient
        if not backend.isconnected():
            backend.connect(ccache=krbV.default_context().default_ccache())

        # initialize NSS database
        current_dbdir = paths.IPA_NSSDB_DIR
        nss.nss_init(current_dbdir)

        # retrieve transport certificate
        config = self.api.Command.vaultconfig_show()
        transport_cert_der = config['result']['transport_cert']
        nss_transport_cert = nss.Certificate(transport_cert_der)

        # generate session key
        mechanism = nss.CKM_DES3_CBC_PAD
        slot = nss.get_best_slot(mechanism)
        key_length = slot.get_best_key_length(mechanism)
        session_key = slot.key_gen(mechanism, None, key_length)

        # wrap session key with transport certificate
        public_key = nss_transport_cert.subject_public_key_info.public_key
        wrapped_session_key = nss.pub_wrap_sym_key(mechanism,
                                                   public_key,
                                                   session_key)

        options['session_key'] = wrapped_session_key.data

        nonce_length = nss.get_iv_length(mechanism)
        nonce = nss.generate_random(nonce_length)
        options['nonce'] = nonce

        vault_data = {}
        vault_data[u'data'] = base64.b64encode(data).decode('utf-8')

        json_vault_data = json.dumps(vault_data)

        # wrap vault_data with session key
        iv_si = nss.SecItem(nonce)
        iv_param = nss.param_from_iv(mechanism, iv_si)

        encoding_ctx = nss.create_context_by_sym_key(mechanism,
                                                     nss.CKA_ENCRYPT,
                                                     session_key,
                                                     iv_param)

        wrapped_vault_data = encoding_ctx.cipher_op(json_vault_data)\
            + encoding_ctx.digest_final()

        options['vault_data'] = wrapped_vault_data

        response = self.api.Command.vault_archive_encrypted(*args, **options)

        response['result'] = {}
        del response['summary']

        return response


@register()
class vault_archive_encrypted(Update):
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

    def execute(self, *args, **options):

        if not self.api.env.enable_kra:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        wrapped_vault_data = options.pop('vault_data')
        nonce = options.pop('nonce')
        wrapped_session_key = options.pop('session_key')

        # retrieve vault info
        result = self.api.Command.vault_show(*args, **options)
        vault = result['result']

        # connect to KRA
        kra_client = self.api.Backend.kra.get_client()

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
            None,
            nonce,
        )

        kra_account.logout()

        return result


@register()
class vault_retrieve(PKQuery, Local):
    __doc__ = _('Retrieve a data from a vault.')

    takes_options = vault_options + (
        Str(
            'out?',
            doc=_('File to store retrieved data'),
        ),
    )

    has_output = output.standard_entry
    has_output_params = (
        Bytes(
            'data',
            label=_('Data'),
        ),
    )

    msg_summary = _('Retrieved data from vault "%(value)s"')

    def forward(self, *args, **options):

        output_file = options.get('out')

        # don't send these parameters to server
        if 'out' in options:
            del options['out']

        if self.api.env.in_server:
            backend = self.api.Backend.ldap2
        else:
            backend = self.api.Backend.rpcclient
        if not backend.isconnected():
            backend.connect(ccache=krbV.default_context().default_ccache())

        # initialize NSS database
        current_dbdir = paths.IPA_NSSDB_DIR
        nss.nss_init(current_dbdir)

        # retrieve transport certificate
        config = self.api.Command.vaultconfig_show()
        transport_cert_der = config['result']['transport_cert']
        nss_transport_cert = nss.Certificate(transport_cert_der)

        # generate session key
        mechanism = nss.CKM_DES3_CBC_PAD
        slot = nss.get_best_slot(mechanism)
        key_length = slot.get_best_key_length(mechanism)
        session_key = slot.key_gen(mechanism, None, key_length)

        # wrap session key with transport certificate
        public_key = nss_transport_cert.subject_public_key_info.public_key
        wrapped_session_key = nss.pub_wrap_sym_key(mechanism,
                                                   public_key,
                                                   session_key)

        # send retrieval request to server
        options['session_key'] = wrapped_session_key.data

        response = self.api.Command.vault_retrieve_encrypted(*args, **options)

        result = response['result']
        nonce = result['nonce']

        # unwrap data with session key
        wrapped_vault_data = result['vault_data']

        iv_si = nss.SecItem(nonce)
        iv_param = nss.param_from_iv(mechanism, iv_si)

        decoding_ctx = nss.create_context_by_sym_key(mechanism,
                                                     nss.CKA_DECRYPT,
                                                     session_key,
                                                     iv_param)

        json_vault_data = decoding_ctx.cipher_op(wrapped_vault_data)\
            + decoding_ctx.digest_final()

        vault_data = json.loads(json_vault_data)
        data = base64.b64decode(vault_data[u'data'].encode('utf-8'))

        if output_file:
            with open(output_file, 'w') as f:
                f.write(data)

        response['result'] = {'data': data}
        del response['summary']

        return response


@register()
class vault_retrieve_encrypted(Retrieve):
    NO_CLI = True

    takes_options = vault_options + (
        Bytes(
            'session_key',
            doc=_('Session key wrapped with transport certificate'),
        ),
    )

    def execute(self, *args, **options):

        if not self.api.env.enable_kra:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        wrapped_session_key = options.pop('session_key')

        # retrieve vault info
        result = self.api.Command.vault_show(*args, **options)
        vault = result['result']

        # connect to KRA
        kra_client = self.api.Backend.kra.get_client()

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

        vault['vault_data'] = key.encrypted_data
        vault['nonce'] = key.nonce_data

        kra_account.logout()

        return result
