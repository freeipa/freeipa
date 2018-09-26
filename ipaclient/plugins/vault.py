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

from __future__ import print_function

import base64
import errno
import io
import json
import logging
import os
import tempfile

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key, load_pem_private_key)

from ipaclient.frontend import MethodOverride
from ipalib import x509
from ipalib.constants import USER_CACHE_PATH
from ipalib.frontend import Local, Method, Object
from ipalib.util import classproperty
from ipalib import api, errors
from ipalib import Bytes, Flag, Str
from ipalib.plugable import Registry
from ipalib import _
from ipapython import ipautil
from ipapython.dnsutil import DNSName

logger = logging.getLogger(__name__)


def validated_read(argname, filename, mode='r', encoding=None):
    """Read file and catch errors

    IOError and UnicodeError (for text files) are turned into a
    ValidationError
    """
    try:
        with io.open(filename, mode=mode, encoding=encoding) as f:
            data = f.read()
    except IOError as exc:
        raise errors.ValidationError(
            name=argname,
            error=_("Cannot read file '%(filename)s': %(exc)s") % {
                'filename': filename, 'exc': exc.args[1]
                }
        )
    except UnicodeError as exc:
        raise errors.ValidationError(
            name=argname,
            error=_("Cannot decode file '%(filename)s': %(exc)s") % {
                'filename': filename, 'exc': exc
                }
        )
    return data


register = Registry()

MAX_VAULT_DATA_SIZE = 2**20  # = 1 MB


def generate_symmetric_key(password, salt):
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


def encrypt(data, symmetric_key=None, public_key=None):
    """
    Encrypts data with symmetric key or public key.
    """
    if symmetric_key is not None:
        if public_key is not None:
            raise ValueError(
                "Either a symmetric or a public key is required, not both."
            )
        fernet = Fernet(symmetric_key)
        return fernet.encrypt(data)

    elif public_key is not None:
        public_key_obj = load_pem_public_key(
            data=public_key,
            backend=default_backend()
        )
        return public_key_obj.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
    else:
        raise ValueError("Either a symmetric or a public key is required.")


def decrypt(data, symmetric_key=None, private_key=None):
    """
    Decrypts data with symmetric key or public key.
    """
    if symmetric_key is not None:
        if private_key is not None:
            raise ValueError(
                "Either a symmetric or a private key is required, not both."
            )
        try:
            fernet = Fernet(symmetric_key)
            return fernet.decrypt(data)
        except InvalidToken:
            raise errors.AuthenticationError(
                message=_('Invalid credentials'))

    elif private_key is not None:
        try:
            private_key_obj = load_pem_private_key(
                data=private_key,
                password=None,
                backend=default_backend()
            )
            return private_key_obj.decrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )
        except ValueError:
            raise errors.AuthenticationError(
                message=_('Invalid credentials'))
    else:
        raise ValueError("Either a symmetric or a private key is required.")


@register(no_fail=True)
class _fake_vault(Object):
    name = 'vault'


@register(no_fail=True)
class _fake_vault_add_internal(Method):
    name = 'vault_add_internal'
    NO_CLI = True


@register()
class vault_add(Local):
    __doc__ = _('Create a new vault.')

    takes_options = (
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
        Str(  # TODO: use File parameter
            'public_key_file?',
            cli_name='public_key_file',
            doc=_('File containing the vault public key'),
        ),
    )

    @classmethod
    def __NO_CLI_getter(cls):
        return (api.Command.get_plugin('vault_add_internal') is
                _fake_vault_add_internal)

    NO_CLI = classproperty(__NO_CLI_getter)

    @property
    def api_version(self):
        return self.api.Command.vault_add_internal.api_version

    def get_args(self):
        for arg in self.api.Command.vault_add_internal.args():
            yield arg
        for arg in super(vault_add, self).get_args():
            yield arg

    def get_options(self):
        for option in self.api.Command.vault_add_internal.options():
            if option.name not in ('ipavaultsalt', 'version'):
                yield option
        for option in super(vault_add, self).get_options():
            yield option

    def get_output_params(self):
        for param in self.api.Command.vault_add_internal.output_params():
            yield param
        for param in super(vault_add, self).get_output_params():
            yield param

    def _iter_output(self):
        return self.api.Command.vault_add_internal.output()

    def forward(self, *args, **options):

        vault_type = options.get('ipavaulttype')

        if vault_type is None:
            internal_cmd = self.api.Command.vault_add_internal
            vault_type = internal_cmd.params.ipavaulttype.default

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

        if vault_type != u'symmetric' and (password or password_file):
            raise errors.MutuallyExclusiveError(
                reason=_('Password can be specified only for '
                         'symmetric vault')
            )

        if vault_type != u'asymmetric' and (public_key or public_key_file):
            raise errors.MutuallyExclusiveError(
                reason=_('Public key can be specified only for '
                         'asymmetric vault')
            )

        if self.api.env.in_server:
            backend = self.api.Backend.ldap2
        else:
            backend = self.api.Backend.rpcclient
        if not backend.isconnected():
            backend.connect()

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
                password = validated_read('password-file',
                                          password_file,
                                          encoding='utf-8')
                password = password.rstrip('\n')

            else:
                password = self.api.Backend.textui.prompt_password(
                    'New password')

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
                public_key = validated_read('public-key-file',
                                            public_key_file,
                                            mode='rb')

                # store vault public key
                options['ipavaultpublickey'] = public_key

            else:
                raise errors.ValidationError(
                    name='ipavaultpublickey',
                    error=_('Missing vault public key'))

            # validate public key and prevent users from accidentally
            # sending a private key to the server.
            try:
                load_pem_public_key(
                    data=public_key,
                    backend=default_backend()
                )
            except ValueError as e:
                raise errors.ValidationError(
                    name='ipavaultpublickey',
                    error=_('Invalid or unsupported vault public key: %s') % e,
                )

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


@register(no_fail=True)
class _fake_vault_mod_internal(Method):
    name = 'vault_mod_internal'
    NO_CLI = True


@register()
class vault_mod(Local):
    __doc__ = _('Modify a vault.')

    takes_options = (
        Flag(
            'change_password?',
            doc=_('Change password'),
        ),
        Str(
            'old_password?',
            cli_name='old_password',
            doc=_('Old vault password'),
        ),
        Str(  # TODO: use File parameter
            'old_password_file?',
            cli_name='old_password_file',
            doc=_('File containing the old vault password'),
        ),
        Str(
            'new_password?',
            cli_name='new_password',
            doc=_('New vault password'),
        ),
        Str(  # TODO: use File parameter
            'new_password_file?',
            cli_name='new_password_file',
            doc=_('File containing the new vault password'),
        ),
        Bytes(
            'private_key?',
            cli_name='private_key',
            doc=_('Old vault private key'),
        ),
        Str(  # TODO: use File parameter
            'private_key_file?',
            cli_name='private_key_file',
            doc=_('File containing the old vault private key'),
        ),
        Str(  # TODO: use File parameter
            'public_key_file?',
            cli_name='public_key_file',
            doc=_('File containing the new vault public key'),
        ),
    )

    @classmethod
    def __NO_CLI_getter(cls):
        return (api.Command.get_plugin('vault_mod_internal') is
                _fake_vault_mod_internal)

    NO_CLI = classproperty(__NO_CLI_getter)

    @property
    def api_version(self):
        return self.api.Command.vault_mod_internal.api_version

    def get_args(self):
        for arg in self.api.Command.vault_mod_internal.args():
            yield arg
        for arg in super(vault_mod, self).get_args():
            yield arg

    def get_options(self):
        for option in self.api.Command.vault_mod_internal.options():
            if option.name != 'version':
                yield option
        for option in super(vault_mod, self).get_options():
            yield option

    def get_output_params(self):
        for param in self.api.Command.vault_mod_internal.output_params():
            yield param
        for param in super(vault_mod, self).get_output_params():
            yield param

    def _iter_output(self):
        return self.api.Command.vault_mod_internal.output()

    def forward(self, *args, **options):

        vault_type = options.pop('ipavaulttype', False)
        salt = options.pop('ipavaultsalt', False)
        change_password = options.pop('change_password', False)

        old_password = options.pop('old_password', None)
        old_password_file = options.pop('old_password_file', None)
        new_password = options.pop('new_password', None)
        new_password_file = options.pop('new_password_file', None)

        old_private_key = options.pop('private_key', None)
        old_private_key_file = options.pop('private_key_file', None)
        new_public_key = options.pop('ipavaultpublickey', None)
        new_public_key_file = options.pop('public_key_file', None)

        if self.api.env.in_server:
            backend = self.api.Backend.ldap2
        else:
            backend = self.api.Backend.rpcclient
        if not backend.isconnected():
            backend.connect()

        # determine the vault type based on parameters specified
        if vault_type:
            pass

        elif change_password or new_password or new_password_file or salt:
            vault_type = u'symmetric'

        elif new_public_key or new_public_key_file:
            vault_type = u'asymmetric'

        # if vault type is specified, retrieve existing secret
        if vault_type:
            opts = options.copy()
            opts.pop('description', None)

            opts['password'] = old_password
            opts['password_file'] = old_password_file
            opts['private_key'] = old_private_key
            opts['private_key_file'] = old_private_key_file

            response = self.api.Command.vault_retrieve(*args, **opts)
            data = response['result']['data']

        opts = options.copy()

        # if vault type is specified, update crypto attributes
        if vault_type:
            opts['ipavaulttype'] = vault_type

            if vault_type == u'standard':
                opts['ipavaultsalt'] = None
                opts['ipavaultpublickey'] = None

            elif vault_type == u'symmetric':
                if salt:
                    opts['ipavaultsalt'] = salt
                else:
                    opts['ipavaultsalt'] = os.urandom(16)

                opts['ipavaultpublickey'] = None

            elif vault_type == u'asymmetric':

                # get new vault public key
                if new_public_key and new_public_key_file:
                    raise errors.MutuallyExclusiveError(
                        reason=_('New public key specified multiple times'))

                elif new_public_key:
                    pass

                elif new_public_key_file:
                    new_public_key = validated_read('public_key_file',
                                                    new_public_key_file,
                                                    mode='rb')

                else:
                    raise errors.ValidationError(
                        name='ipavaultpublickey',
                        error=_('Missing new vault public key'))

                opts['ipavaultsalt'] = None
                opts['ipavaultpublickey'] = new_public_key

        response = self.api.Command.vault_mod_internal(*args, **opts)

        # if vault type is specified, rearchive existing secret
        if vault_type:
            opts = options.copy()
            opts.pop('description', None)

            opts['data'] = data
            opts['password'] = new_password
            opts['password_file'] = new_password_file
            opts['override_password'] = True

            self.api.Command.vault_archive(*args, **opts)

        return response


class _TransportCertCache:
    def __init__(self):
        self._dirname = os.path.join(
                USER_CACHE_PATH, 'ipa', 'kra-transport-certs'
        )

    def _get_filename(self, domain):
        basename = DNSName(domain).ToASCII() + '.pem'
        return os.path.join(self._dirname, basename)

    def load_cert(self, domain):
        """Load cert from cache

        :param domain: IPA domain
        :return: cryptography.x509.Certificate or None
        """
        filename = self._get_filename(domain)
        try:
            try:
                return x509.load_certificate_from_file(filename)
            except EnvironmentError as e:
                if e.errno != errno.ENOENT:
                    raise
        except Exception:
            logger.warning("Failed to load %s", filename, exc_info=True)

    def store_cert(self, domain, transport_cert):
        """Store a new cert or override existing cert

        :param domain: IPA domain
        :param transport_cert: cryptography.x509.Certificate
        :return: True if cert was stored successfully
        """
        filename = self._get_filename(domain)
        pem = transport_cert.public_bytes(serialization.Encoding.PEM)
        try:
            try:
                os.makedirs(self._dirname)
            except EnvironmentError as e:
                if e.errno != errno.EEXIST:
                    raise
            with tempfile.NamedTemporaryFile(dir=self._dirname, delete=False,
                                             mode='wb') as f:
                try:
                    f.write(pem)
                    ipautil.flush_sync(f)
                    f.close()
                    os.rename(f.name, filename)
                except Exception:
                    os.unlink(f.name)
                    raise
        except Exception:
            logger.warning("Failed to save %s", filename, exc_info=True)
            return False
        else:
            return True

    def remove_cert(self, domain):
        """Remove a cert from cache, ignores errors

        :param domain: IPA domain
        :return: True if cert was found and removed
        """
        filename = self._get_filename(domain)
        try:
            os.unlink(filename)
        except EnvironmentError as e:
            if e.errno != errno.ENOENT:
                logger.warning("Failed to remove %s", filename, exc_info=True)
            return False
        else:
            return True


_transport_cert_cache = _TransportCertCache()


@register(override=True, no_fail=True)
class vaultconfig_show(MethodOverride):
    def forward(self, *args, **options):

        file = options.get('transport_out')

        # don't send these parameters to server
        if 'transport_out' in options:
            del options['transport_out']

        response = super(vaultconfig_show, self).forward(*args, **options)

        # cache transport certificate
        transport_cert = x509.load_der_x509_certificate(
                response['result']['transport_cert'])

        _transport_cert_cache.store_cert(
            self.api.env.domain, transport_cert
        )

        if file:
            with open(file, 'wb') as f:
                f.write(response['result']['transport_cert'])

        return response


class ModVaultData(Local):
    def _generate_session_key(self):
        key_length = max(algorithms.TripleDES.key_sizes)
        algo = algorithms.TripleDES(os.urandom(key_length // 8))
        return algo

    def _do_internal(self, algo, transport_cert, raise_unexpected,
                     *args, **options):
        public_key = transport_cert.public_key()

        # wrap session key with transport certificate
        wrapped_session_key = public_key.encrypt(
            algo.key,
            padding.PKCS1v15()
        )
        options['session_key'] = wrapped_session_key

        name = self.name + '_internal'
        try:
            # ipalib.errors.NotFound exception can be propagated
            return self.api.Command[name](*args, **options)
        except (errors.InternalError,
                errors.ExecutionError,
                errors.GenericError):
            _transport_cert_cache.remove_cert(self.api.env.domain)
            if raise_unexpected:
                raise

    def internal(self, algo, *args, **options):
        """
        Calls the internal counterpart of the command.
        """
        domain = self.api.env.domain

        # try call with cached transport certificate
        transport_cert = _transport_cert_cache.load_cert(domain)
        if transport_cert is not None:
            result = self._do_internal(algo, transport_cert, False,
                                       *args, **options)
            if result is not None:
                return result

        # retrieve transport certificate (cached by vaultconfig_show)
        response = self.api.Command.vaultconfig_show()
        transport_cert = x509.load_der_x509_certificate(
            response['result']['transport_cert'])
        # call with the retrieved transport certificate
        return self._do_internal(algo, transport_cert, True,
                                 *args, **options)


@register(no_fail=True)
class _fake_vault_archive_internal(Method):
    name = 'vault_archive_internal'
    NO_CLI = True


@register()
class vault_archive(ModVaultData):
    __doc__ = _('Archive data into a vault.')

    takes_options = (
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
        Flag(
            'override_password?',
            doc=_('Override existing password'),
        ),
    )

    @classmethod
    def __NO_CLI_getter(cls):
        return (api.Command.get_plugin('vault_archive_internal') is
                _fake_vault_archive_internal)

    NO_CLI = classproperty(__NO_CLI_getter)

    @property
    def api_version(self):
        return self.api.Command.vault_archive_internal.api_version

    def get_args(self):
        for arg in self.api.Command.vault_archive_internal.args():
            yield arg
        for arg in super(vault_archive, self).get_args():
            yield arg

    def get_options(self):
        for option in self.api.Command.vault_archive_internal.options():
            if option.name not in ('nonce',
                                   'session_key',
                                   'vault_data',
                                   'version'):
                yield option
        for option in super(vault_archive, self).get_options():
            yield option

    def get_output_params(self):
        for param in self.api.Command.vault_archive_internal.output_params():
            yield param
        for param in super(vault_archive, self).get_output_params():
            yield param

    def _iter_output(self):
        return self.api.Command.vault_archive_internal.output()

    def _wrap_data(self, algo, json_vault_data):
        """Encrypt data with wrapped session key and transport cert

        :param bytes algo: wrapping algorithm instance
        :param bytes json_vault_data: dumped vault data
        :return:
        """
        nonce = os.urandom(algo.block_size // 8)

        # wrap vault_data with session key
        padder = PKCS7(algo.block_size).padder()
        padded_data = padder.update(json_vault_data)
        padded_data += padder.finalize()

        cipher = Cipher(algo, modes.CBC(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        wrapped_vault_data = encryptor.update(padded_data) + encryptor.finalize()

        return nonce, wrapped_vault_data

    def forward(self, *args, **options):
        data = options.get('data')
        input_file = options.get('in')

        password = options.get('password')
        password_file = options.get('password_file')

        override_password = options.pop('override_password', False)

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

        elif data:
            if len(data) > MAX_VAULT_DATA_SIZE:
                raise errors.ValidationError(name="data", error=_(
                    "Size of data exceeds the limit. Current vault data size "
                    "limit is %(limit)d B")
                    % {'limit': MAX_VAULT_DATA_SIZE})

        elif input_file:
            try:
                stat = os.stat(input_file)
            except OSError as exc:
                raise errors.ValidationError(name="in", error=_(
                    "Cannot read file '%(filename)s': %(exc)s")
                    % {'filename': input_file, 'exc': exc.args[1]})
            if stat.st_size > MAX_VAULT_DATA_SIZE:
                raise errors.ValidationError(name="in", error=_(
                    "Size of data exceeds the limit. Current vault data size "
                    "limit is %(limit)d B")
                    % {'limit': MAX_VAULT_DATA_SIZE})
            data = validated_read('in', input_file, mode='rb')

        else:
            data = b''

        if self.api.env.in_server:
            backend = self.api.Backend.ldap2
        else:
            backend = self.api.Backend.rpcclient
        if not backend.isconnected():
            backend.connect()

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
                password = validated_read('password-file',
                                          password_file,
                                          encoding='utf-8')
                password = password.rstrip('\n')

            else:
                if override_password:
                    password = self.api.Backend.textui.prompt_password(
                        'New password')
                else:
                    password = self.api.Backend.textui.prompt_password(
                        'Password', confirm=False)

            if not override_password:
                # verify password by retrieving existing data
                opts = options.copy()
                opts['password'] = password
                try:
                    self.api.Command.vault_retrieve(*args, **opts)
                except errors.NotFound:
                    pass

            salt = vault['ipavaultsalt'][0]

            # generate encryption key from vault password
            encryption_key = generate_symmetric_key(password, salt)

            # encrypt data with encryption key
            data = encrypt(data, symmetric_key=encryption_key)

            encrypted_key = None

        elif vault_type == u'asymmetric':

            public_key = vault['ipavaultpublickey'][0]

            # generate encryption key
            encryption_key = base64.b64encode(os.urandom(32))

            # encrypt data with encryption key
            data = encrypt(data, symmetric_key=encryption_key)

            # encrypt encryption key with public key
            encrypted_key = encrypt(encryption_key, public_key=public_key)

        else:
            raise errors.ValidationError(
                name='vault_type',
                error=_('Invalid vault type'))


        vault_data = {
            'data': base64.b64encode(data).decode('utf-8')
        }
        if encrypted_key:
            vault_data[u'encrypted_key'] = base64.b64encode(encrypted_key)\
                .decode('utf-8')

        json_vault_data = json.dumps(vault_data).encode('utf-8')

        # generate session key
        algo = self._generate_session_key()
        # wrap vault data
        nonce, wrapped_vault_data = self._wrap_data(algo, json_vault_data)
        options.update(
            nonce=nonce,
            vault_data=wrapped_vault_data
        )
        return self.internal(algo, *args, **options)


@register(no_fail=True)
class _fake_vault_retrieve_internal(Method):
    name = 'vault_retrieve_internal'
    NO_CLI = True


@register()
class vault_retrieve(ModVaultData):
    __doc__ = _('Retrieve a data from a vault.')

    takes_options = (
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

    has_output_params = (
        Bytes(
            'data',
            label=_('Data'),
        ),
    )

    @classmethod
    def __NO_CLI_getter(cls):
        return (api.Command.get_plugin('vault_retrieve_internal') is
                _fake_vault_retrieve_internal)

    NO_CLI = classproperty(__NO_CLI_getter)

    @property
    def api_version(self):
        return self.api.Command.vault_retrieve_internal.api_version

    def get_args(self):
        for arg in self.api.Command.vault_retrieve_internal.args():
            yield arg
        for arg in super(vault_retrieve, self).get_args():
            yield arg

    def get_options(self):
        for option in self.api.Command.vault_retrieve_internal.options():
            if option.name not in ('session_key', 'version'):
                yield option
        for option in super(vault_retrieve, self).get_options():
            yield option

    def get_output_params(self):
        for param in self.api.Command.vault_retrieve_internal.output_params():
            yield param
        for param in super(vault_retrieve, self).get_output_params():
            yield param

    def _iter_output(self):
        return self.api.Command.vault_retrieve_internal.output()

    def _unwrap_response(self, algo, nonce, vault_data):
        cipher = Cipher(algo, modes.CBC(nonce), backend=default_backend())
        # decrypt
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(vault_data)
        padded_data += decryptor.finalize()
        # remove padding
        unpadder = PKCS7(algo.block_size).unpadder()
        json_vault_data = unpadder.update(padded_data)
        json_vault_data += unpadder.finalize()
        # load JSON
        return json.loads(json_vault_data.decode('utf-8'))

    def forward(self, *args, **options):
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
            backend.connect()

        # retrieve vault info
        vault = self.api.Command.vault_show(*args, **options)['result']
        vault_type = vault['ipavaulttype'][0]

        # generate session key
        algo = self._generate_session_key()
        # send retrieval request to server
        response = self.internal(algo, *args, **options)
        # unwrap data with session key
        vault_data = self._unwrap_response(
            algo,
            response['result']['nonce'],
            response['result']['vault_data']
        )
        del algo

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
                password = validated_read('password-file',
                                          password_file,
                                          encoding='utf-8')
                password = password.rstrip('\n')

            else:
                password = self.api.Backend.textui.prompt_password(
                    'Password', confirm=False)

            # generate encryption key from password
            encryption_key = generate_symmetric_key(password, salt)

            # decrypt data with encryption key
            data = decrypt(data, symmetric_key=encryption_key)

        elif vault_type == u'asymmetric':

            # get encryption key with vault private key
            if private_key and private_key_file:
                raise errors.MutuallyExclusiveError(
                    reason=_('Private key specified multiple times'))

            elif private_key:
                pass

            elif private_key_file:
                private_key = validated_read('private-key-file',
                                             private_key_file,
                                             mode='rb')

            else:
                raise errors.ValidationError(
                    name='private_key',
                    error=_('Missing vault private key'))

            # decrypt encryption key with private key
            encryption_key = decrypt(encrypted_key, private_key=private_key)

            # decrypt data with encryption key
            data = decrypt(data, symmetric_key=encryption_key)

        else:
            raise errors.ValidationError(
                name='vault_type',
                error=_('Invalid vault type'))

        if output_file:
            with open(output_file, 'wb') as f:
                f.write(data)

        else:
            response['result'] = {'data': data}

        return response
