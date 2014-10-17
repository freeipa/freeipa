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
import getpass
import json
import os
import sys
import tempfile

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key,\
    load_pem_private_key

import nss.nss as nss
import krbV

from ipalib.frontend import Command, Object, Local
from ipalib import api, errors
from ipalib import Bytes, Str, Flag
from ipalib import output
from ipalib.crud import PKQuery, Retrieve, Update
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import LDAPObject, LDAPCreate, LDAPDelete,\
    LDAPSearch, LDAPUpdate, LDAPRetrieve, LDAPAddMember, LDAPRemoveMember,\
    pkey_to_value
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
Vault is a secure place to store a secret.
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
 Add a symmetric vault:
   ipa vault-add <name> --type symmetric --password-file password.txt
""") + _("""
 Add an asymmetric vault:
   ipa vault-add <name> --type asymmetric --public-key-file public.pem
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
   ipa vaultconfig-show
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
 Archive data into symmetric vault:
   ipa vault-archive <name> --in <input file>
""") + _("""
 Archive data into asymmetric vault:
   ipa vault-archive <name> --in <input file>
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
   ipa vault-retrieve <name> --user <username> --out <output file>
""") + _("""
 Retrieve data from symmetric vault:
   ipa vault-retrieve <name> --out data.bin
""") + _("""
 Retrieve data from asymmetric vault:
   ipa vault-retrieve <name> --out data.bin --private-key-file private.pem
""") + _("""
 Add a vault owner:
   ipa vault-add-owner <name> --users <usernames>
""") + _("""
 Delete a vault owner:
   ipa vault-remove-owner <name> --users <usernames>
""") + _("""
 Add a vault member:
   ipa vault-add-member <name> --users <usernames>
""") + _("""
 Delete a vault member:
   ipa vault-remove-member <name> --users <usernames>
""")

register = Registry()


vault_options = (
    Str(
        'service?',
        doc=_('Service name of the service vault'),
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
        'owner': ['user', 'group'],
        'member': ['user', 'group'],
    }

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
        Str(
            'ipavaulttype?',
            cli_name='type',
            label=_('Type'),
            doc=_('Vault type'),
            default=u'standard',
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
    )

    def get_dn(self, *keys, **options):
        """
        Generates vault DN from parameters.
        """

        service = options.get('service')
        shared = options.get('shared')
        user = options.get('username')

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

    def get_new_password(self):
        """
        Gets new password from user and verify it.
        """
        while True:
            password = getpass.getpass('New password: ').decode(
                sys.stdin.encoding)
            password2 = getpass.getpass('Verify password: ').decode(
                sys.stdin.encoding)

            if password == password2:
                return password

            print '  ** Passwords do not match! **'

    def get_existing_password(self, new=False):
        """
        Gets existing password from user.
        """
        return getpass.getpass('Password: ').decode(sys.stdin.encoding)

    def generate_symmetric_key(self, password, salt):
        """
        Generates symmetric key from password and salt.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        return base64.b64encode(kdf.derive(password.encode('utf-8')))

    def encrypt(self, data, symmetric_key=None, public_key=None):
        """
        Encrypts data with symmetric key or public key.
        """
        if symmetric_key:
            fernet = Fernet(symmetric_key)
            return fernet.encrypt(data)

        elif public_key:
            rsa_public_key = load_pem_public_key(
                data=public_key,
                backend=default_backend()
            )
            return rsa_public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )

    def decrypt(self, data, symmetric_key=None, private_key=None):
        """
        Decrypts data with symmetric key or public key.
        """
        if symmetric_key:
            try:
                fernet = Fernet(symmetric_key)
                return fernet.decrypt(data)
            except InvalidToken:
                raise errors.AuthenticationError(
                    message=_('Invalid credentials'))

        elif private_key:
            try:
                rsa_private_key = load_pem_private_key(
                    data=private_key,
                    password=None,
                    backend=default_backend()
                )
                return rsa_private_key.decrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA1()),
                        algorithm=hashes.SHA1(),
                        label=None
                    )
                )
            except AssertionError:
                raise errors.AuthenticationError(
                    message=_('Invalid credentials'))


@register()
class vault_add(PKQuery, Local):
    __doc__ = _('Create a new vault.')

    takes_options = LDAPCreate.takes_options + vault_options + (
        Str(
            'description?',
            cli_name='desc',
            doc=_('Vault description'),
        ),
        Str(
            'ipavaulttype?',
            cli_name='type',
            doc=_('Vault type'),
        ),
        Str(
            'password?',
            cli_name='password',
            doc=_('Vault password'),
        ),
        Str(  # TODO: use File parameter
            'password_file?',
            cli_name='password_file',
            doc=_('File containing the vault password'),
        ),
        Bytes(
            'ipavaultpublickey?',
            cli_name='public_key',
            doc=_('Vault public key'),
        ),
        Str(  # TODO: use File parameter
            'public_key_file?',
            cli_name='public_key_file',
            doc=_('File containing the vault public key'),
        ),
    )

    has_output = output.standard_entry

    def forward(self, *args, **options):

        vault_type = options.get('ipavaulttype', u'standard')
        password = options.get('password')
        password_file = options.get('password_file')
        public_key = options.get('ipavaultpublickey')
        public_key_file = options.get('public_key_file')

        # don't send these parameters to server
        if 'password' in options:
            del options['password']
        if 'password_file' in options:
            del options['password_file']
        if 'public_key_file' in options:
            del options['public_key_file']

        if self.api.env.in_server:
            backend = self.api.Backend.ldap2
        else:
            backend = self.api.Backend.rpcclient
        if not backend.isconnected():
            backend.connect(ccache=krbV.default_context().default_ccache())

        if vault_type == u'standard':

            pass

        elif vault_type == u'symmetric':

            # get password
            if password and password_file:
                raise errors.MutuallyExclusiveError(
                    reason=_('Password specified multiple times'))

            elif password:
                pass

            elif password_file:
                with open(password_file, 'rb') as f:
                    password = f.read().rstrip('\n').decode('utf-8')

            else:
                password = self.obj.get_new_password()

            # generate vault salt
            options['ipavaultsalt'] = os.urandom(16)

        elif vault_type == u'asymmetric':

            # get new vault public key
            if public_key and public_key_file:
                raise errors.MutuallyExclusiveError(
                    reason=_('Public key specified multiple times'))

            elif public_key:
                pass

            elif public_key_file:
                with open(public_key_file, 'rb') as f:
                    public_key = f.read()

                # store vault public key
                options['ipavaultpublickey'] = public_key

            else:
                raise errors.ValidationError(
                    name='ipavaultpublickey',
                    error=_('Missing vault public key'))

        # create vault
        response = self.api.Command.vault_add_internal(*args, **options)

        # prepare parameters for archival
        opts = options.copy()
        if 'description' in opts:
            del opts['description']
        if 'ipavaulttype' in opts:
            del opts['ipavaulttype']

        if vault_type == u'symmetric':
            opts['password'] = password
            del opts['ipavaultsalt']

        elif vault_type == u'asymmetric':
            del opts['ipavaultpublickey']

        # archive blank data
        self.api.Command.vault_archive(*args, **opts)

        return response


@register()
class vault_add_internal(LDAPCreate):

    NO_CLI = True

    takes_options = vault_options

    msg_summary = _('Added vault "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys,
                     **options):
        assert isinstance(dn, DN)

        if not self.api.Command.kra_is_enabled()['result']:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

        principal = getattr(context, 'principal')
        (name, realm) = split_principal(principal)
        if '/' in name:
            owner_dn = self.api.Object.service.get_dn(name)
        else:
            owner_dn = self.api.Object.user.get_dn(name)

        try:
            parent_dn = DN(*dn[1:])
            self.obj.create_container(parent_dn, owner_dn)
        except errors.DuplicateEntry, e:
            pass

        entry_attrs['owner'] = owner_dn

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

        if not self.api.Command.kra_is_enabled()['result']:
            raise errors.InvocationError(
                format=_('KRA service is not enabled'))

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

        if not self.api.Command.kra_is_enabled()['result']:
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
        Str(
            'password?',
            cli_name='password',
            doc=_('Vault password'),
        ),
        Str(  # TODO: use File parameter
            'password_file?',
            cli_name='password_file',
            doc=_('File containing the vault password'),
        ),
    )

    has_output = output.standard_entry

    def forward(self, *args, **options):

        name = args[-1]

        data = options.get('data')
        input_file = options.get('in')

        password = options.get('password')
        password_file = options.get('password_file')

        # don't send these parameters to server
        if 'data' in options:
            del options['data']
        if 'in' in options:
            del options['in']
        if 'password' in options:
            del options['password']
        if 'password_file' in options:
            del options['password_file']

        # get data
        if data and input_file:
            raise errors.MutuallyExclusiveError(
                reason=_('Input data specified multiple times'))

        elif input_file:
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

        # retrieve vault info
        vault = self.api.Command.vault_show(*args, **options)['result']

        vault_type = vault['ipavaulttype'][0]

        if vault_type == u'standard':

            encrypted_key = None

        elif vault_type == u'symmetric':

            # get password
            if password and password_file:
                raise errors.MutuallyExclusiveError(
                    reason=_('Password specified multiple times'))

            elif password:
                pass

            elif password_file:
                with open(password_file) as f:
                    password = f.read().rstrip('\n').decode('utf-8')

            else:
                password = self.obj.get_existing_password()

            # verify password by retrieving existing data
            opts = options.copy()
            opts['password'] = password
            try:
                self.api.Command.vault_retrieve(*args, **opts)
            except errors.NotFound:
                pass

            salt = vault['ipavaultsalt'][0]

            # generate encryption key from vault password
            encryption_key = self.obj.generate_symmetric_key(
                password, salt)

            # encrypt data with encryption key
            data = self.obj.encrypt(data, symmetric_key=encryption_key)

            encrypted_key = None

        elif vault_type == u'asymmetric':

            public_key = vault['ipavaultpublickey'][0].encode('utf-8')

            # generate encryption key
            encryption_key = base64.b64encode(os.urandom(32))

            # encrypt data with encryption key
            data = self.obj.encrypt(data, symmetric_key=encryption_key)

            # encrypt encryption key with public key
            encrypted_key = self.obj.encrypt(
                encryption_key, public_key=public_key)

        else:
            raise errors.ValidationError(
                name='vault_type',
                error=_('Invalid vault type'))

        # initialize NSS database
        current_dbdir = paths.IPA_NSSDB_DIR
        nss.nss_init(current_dbdir)

        # retrieve transport certificate
        config = self.api.Command.vaultconfig_show()['result']
        transport_cert_der = config['transport_cert']
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

        if encrypted_key:
            vault_data[u'encrypted_key'] = base64.b64encode(encrypted_key)\
                .decode('utf-8')

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

        return self.api.Command.vault_archive_internal(*args, **options)


@register()
class vault_archive_internal(PKQuery):

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

        response = {
            'value': args[-1],
            'result': {},
        }

        response['summary'] = self.msg_summary % response

        return response


@register()
class vault_retrieve(PKQuery, Local):
    __doc__ = _('Retrieve a data from a vault.')

    takes_options = vault_options + (
        Str(
            'out?',
            doc=_('File to store retrieved data'),
        ),
        Str(
            'password?',
            cli_name='password',
            doc=_('Vault password'),
        ),
        Str(  # TODO: use File parameter
            'password_file?',
            cli_name='password_file',
            doc=_('File containing the vault password'),
        ),
        Bytes(
            'private_key?',
            cli_name='private_key',
            doc=_('Vault private key'),
        ),
        Str(  # TODO: use File parameter
            'private_key_file?',
            cli_name='private_key_file',
            doc=_('File containing the vault private key'),
        ),
    )

    has_output = output.standard_entry
    has_output_params = (
        Bytes(
            'data',
            label=_('Data'),
        ),
    )

    def forward(self, *args, **options):

        name = args[-1]

        output_file = options.get('out')

        password = options.get('password')
        password_file = options.get('password_file')
        private_key = options.get('private_key')
        private_key_file = options.get('private_key_file')

        # don't send these parameters to server
        if 'out' in options:
            del options['out']
        if 'password' in options:
            del options['password']
        if 'password_file' in options:
            del options['password_file']
        if 'private_key' in options:
            del options['private_key']
        if 'private_key_file' in options:
            del options['private_key_file']

        if self.api.env.in_server:
            backend = self.api.Backend.ldap2
        else:
            backend = self.api.Backend.rpcclient
        if not backend.isconnected():
            backend.connect(ccache=krbV.default_context().default_ccache())

        # retrieve vault info
        vault = self.api.Command.vault_show(*args, **options)['result']

        vault_type = vault['ipavaulttype'][0]

        # initialize NSS database
        current_dbdir = paths.IPA_NSSDB_DIR
        nss.nss_init(current_dbdir)

        # retrieve transport certificate
        config = self.api.Command.vaultconfig_show()['result']
        transport_cert_der = config['transport_cert']
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

        response = self.api.Command.vault_retrieve_internal(*args, **options)

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

        encrypted_key = None

        if 'encrypted_key' in vault_data:
            encrypted_key = base64.b64decode(vault_data[u'encrypted_key']
                                             .encode('utf-8'))

        if vault_type == u'standard':

            pass

        elif vault_type == u'symmetric':

            salt = vault['ipavaultsalt'][0]

            # get encryption key from vault password
            if password and password_file:
                raise errors.MutuallyExclusiveError(
                    reason=_('Password specified multiple times'))

            elif password:
                pass

            elif password_file:
                with open(password_file) as f:
                    password = f.read().rstrip('\n').decode('utf-8')

            else:
                password = self.obj.get_existing_password()

            # generate encryption key from password
            encryption_key = self.obj.generate_symmetric_key(password, salt)

            # decrypt data with encryption key
            data = self.obj.decrypt(data, symmetric_key=encryption_key)

        elif vault_type == u'asymmetric':

            # get encryption key with vault private key
            if private_key and private_key_file:
                raise errors.MutuallyExclusiveError(
                    reason=_('Private key specified multiple times'))

            elif private_key:
                pass

            elif private_key_file:
                with open(private_key_file, 'rb') as f:
                    private_key = f.read()

            else:
                raise errors.ValidationError(
                    name='private_key',
                    error=_('Missing vault private key'))

            # decrypt encryption key with private key
            encryption_key = self.obj.decrypt(
                encrypted_key, private_key=private_key)

            # decrypt data with encryption key
            data = self.obj.decrypt(data, symmetric_key=encryption_key)

        else:
            raise errors.ValidationError(
                name='vault_type',
                error=_('Invalid vault type'))

        if output_file:
            with open(output_file, 'w') as f:
                f.write(data)

        else:
            response['result'] = {'data': data}

        return response


@register()
class vault_retrieve_internal(PKQuery):

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
class vault_add_owner(LDAPAddMember):
    __doc__ = _('Add owners to a vault.')

    takes_options = LDAPAddMember.takes_options + vault_options

    member_attributes = ['owner']
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
class vault_remove_owner(LDAPRemoveMember):
    __doc__ = _('Remove owners from a vault.')

    takes_options = LDAPRemoveMember.takes_options + vault_options

    member_attributes = ['owner']
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
class vault_add_member(LDAPAddMember):
    __doc__ = _('Add members to a vault.')

    takes_options = LDAPAddMember.takes_options + vault_options


@register()
class vault_remove_member(LDAPRemoveMember):
    __doc__ = _('Remove members from a vault.')

    takes_options = LDAPRemoveMember.takes_options + vault_options


@register()
class kra_is_enabled(Command):
    NO_CLI = True

    has_output = output.standard_value

    def execute(self, *args, **options):
        base_dn = DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'),
                     self.api.env.basedn)
        filter = '(&(objectClass=ipaConfigObject)(cn=KRA))'
        try:
            self.api.Backend.ldap2.find_entries(
                base_dn=base_dn, filter=filter, attrs_list=[])
        except errors.NotFound:
            result = False
        else:
            result = True
        return dict(result=result, value=pkey_to_value(None, options))
