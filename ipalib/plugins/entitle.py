# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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

from ipalib import api, SkipPluginModule
try:
    from rhsm.connection import *
    from rhsm.certificate import EntitlementCertificate
    import M2Crypto
    if api.env.in_server and api.env.context in ['lite', 'server']:
        from ipaserver.install.certs import NSS_DIR
except ImportError, e:
    if not api.env.validate_api:
        raise SkipPluginModule(reason=str(e))

import os
from ipalib import api, errors
from ipalib import Flag, Int, Str, Password, File
from ipalib.plugins.baseldap import *
from ipalib.plugins.virtual import *
from ipalib import _, ngettext
from ipalib.output import Output, standard_list_of_entries
from ipalib.request import context
from ipapython import ipautil
import tempfile
import shutil
import socket
import base64
from OpenSSL import crypto
from ipapython.ipautil import run
from ipalib.request import context
from ipalib.plugins.service import validate_certificate
from ipalib import x509

import locale

__doc__ = _("""
Entitlements

Manage entitlements for client machines

Entitlements can be managed either by registering with an entitlement
server with a username and password or by manually importing entitlement
certificates. An entitlement certificate contains embedded information
such as the product being entitled, the quantity and the validity dates.

An entitlement server manages the number of client entitlements available.
To mark these entitlements as used by the IPA server you provide a quantity
and they are marked as consumed on the entitlement server.

 Register with an entitlement server:
   ipa entitle-register consumer

 Import an entitlement certificate:
   ipa entitle-import /home/user/ipaclient.pem

 Display current entitlements:
   ipa entitle-status

 Retrieve details on entitlement certificates:
   ipa entitle-get

 Consume some entitlements from the entitlement server:
   ipa entitle-consume 50

The registration ID is a Unique Identifier (UUID). This ID will be
IMPORTED if you have used entitle-import.

Changes to /etc/rhsm/rhsm.conf require a restart of the httpd service.
""")

def read_file(filename):
    fp = open(filename, 'r')
    data = fp.readlines()
    fp.close()
    data = ''.join(data)
    return data

def write_file(filename, pem):
    cert_file = open(filename, 'w')
    cert_file.write(pem)
    cert_file.close()

def read_pkcs12_pin():
    pwdfile = '%s/pwdfile.txt' % NSS_DIR
    fp = open(pwdfile, 'r')
    pwd = fp.read()
    fp.close()
    return pwd

def get_pool(ldap):
    """
    Get our entitlement pool. Assume there is only one pool.
    """
    db = None
    try:
        (db, uuid, certfile, keyfile) = get_uuid(ldap)
        if db is None:
            # db is None means manual registration
            return (None, uuid)

        cp = UEPConnection(handler='/candlepin', cert_file=certfile, key_file=keyfile)

        pools = cp.getPoolsList(uuid)
        poolid = pools[0]['id']

        pool = cp.getPool(poolid)
    finally:
        if db:
            shutil.rmtree(db, ignore_errors=True)

    return (pool, uuid)

def get_uuid(ldap):
    """
    Retrieve our UUID, certificate and key from LDAP.

    Except on error the caller is responsible for removing temporary files
    """
    db = None
    try:
        db = tempfile.mkdtemp(prefix = "tmp-")
        registrations = api.Command['entitle_find'](all=True)
        if registrations['count'] == 0:
            shutil.rmtree(db, ignore_errors=True)
            raise errors.NotRegisteredError()
        result = registrations['result'][0]
        uuid = str(result['ipaentitlementid'][0])

        entry_attrs = dict(ipaentitlementid=uuid)
        dn = ldap.make_dn(
            entry_attrs, 'ipaentitlementid', api.env.container_entitlements,
        )
        if not ldap.can_read(dn, 'userpkcs12'):
            raise errors.ACIError(
                info=_('not allowed to perform this command'))

        if not 'userpkcs12' in result:
            return (None, uuid, None, None)
        data = result['userpkcs12'][0]
        pkcs12 = crypto.load_pkcs12(data, read_pkcs12_pin())
        cert = pkcs12.get_certificate()
        key = pkcs12.get_privatekey()
        write_file(db + '/cert.pem',
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        write_file(db + '/key.pem',
            crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    except Exception, e:
        if db is not None:
            shutil.rmtree(db, ignore_errors=True)
        raise e

    return (db, uuid, db + '/cert.pem', db + '/key.pem')

output_params = (
    Str('ipaentitlementid?',
        label='UUID',
    ),
    Str('usercertificate',
        label=_('Certificate'),
    ),
)

class entitle(LDAPObject):
    """
    Entitlement object
    """
    container_dn = api.env.container_entitlements
    object_name = _('entitlement')
    object_name_plural = _('entitlements')
    object_class = ['ipaobject', 'ipaentitlement']
    search_attributes = ['usercertificate']
    default_attributes = ['ipaentitlement']
    uuid_attribute = 'ipaentitlementid'

    label = _('Entitlements')
    label_singular = _('Entitlement')

    """
    def get_dn(self, *keys, **kwargs):
        try:
            (dn, entry_attrs) = self.backend.find_entry_by_attr(
                self.primary_key.name, keys[-1], self.object_class, [''],
                self.container_dn
            )
        except errors.NotFound:
            dn = super(entitle, self).get_dn(*keys, **kwargs)
        return dn
    """

api.register(entitle)

class entitle_status(VirtualCommand):
    __doc__ = _('Display current entitlements.')

    operation="show entitlement"

    has_output_params = (
        Str('uuid',
            label=_('UUID'),
        ),
        Str('product',
            label=_('Product'),
        ),
        Int('quantity',
            label=_('Quantity'),
        ),
        Int('consumed',
            label=_('Consumed'),
        ),
    )

    has_output = (
        Output('result',
            type=dict,
            doc=_('Dictionary mapping variable name to value'),
        ),
    )

    def execute(self, *keys, **kw):
        ldap = self.api.Backend.ldap2

        os.environ['LANG'] = 'en_US'
        locale.setlocale(locale.LC_ALL, '')

        (pool, uuid) = get_pool(ldap)

        if pool is None:
            # This assumes there is only 1 product
            quantity = 0
            product = ''
            registrations = api.Command['entitle_find'](all=True)['result'][0]
            if u'usercertificate' in registrations:
                certs = registrations['usercertificate']
                for cert in certs:
                    cert = x509.make_pem(base64.b64encode(cert))
                    try:
                        pc = EntitlementCertificate(cert)
                        o = pc.getOrder()
                        if o.getQuantityUsed():
                            quantity = quantity + int(o.getQuantityUsed())
                        product = o.getName()
                    except M2Crypto.X509.X509Error, e:
                        self.error('Invalid entitlement certificate, skipping.')
            pool = dict(productId=product, quantity=quantity,
                consumed=quantity, uuid=unicode(uuid))

        result={'product': unicode(pool['productId']),
            'quantity': pool['quantity'],
            'consumed': pool['consumed'],
            'uuid': unicode(uuid),
        }

        return dict(
            result=result
        )

api.register(entitle_status)


class entitle_consume(LDAPUpdate):
    __doc__ = _('Consume an entitlement.')

    operation="consume entitlement"

    msg_summary = _('Consumed %(value)s entitlement(s).')

    takes_args = (
        Int('quantity',
            label=_('Quantity'),
            minvalue=1,
        ),
    )

    # We don't want rights or add/setattr
    takes_options = (
        # LDAPUpdate requires at least one option so autofill one
        # This isn't otherwise used.
        Int('hidden',
            label=_('Quantity'),
            minvalue=1,
            autofill=True,
            default=1,
            flags=['no_option', 'no_output']
        ),
    )

    has_output_params = output_params + (
        Str('product',
            label=_('Product'),
        ),
        Int('consumed',
            label=_('Consumed'),
        ),
    )

    def execute(self, *keys, **options):
        """
        Override this so we can set value to the number of entitlements
        consumed.
        """
        result = super(entitle_consume, self).execute(*keys, **options)
        result['value'] = unicode(keys[-1])
        return result

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        quantity = keys[-1]

        os.environ['LANG'] = 'en_US'
        locale.setlocale(locale.LC_ALL, '')

        (db, uuid, certfile, keyfile) = get_uuid(ldap)
        entry_attrs['ipaentitlementid'] = uuid
        dn = ldap.make_dn(
            entry_attrs, self.obj.uuid_attribute, self.obj.container_dn
        )
        if db is None:
            raise errors.NotRegisteredError()
        try:
            (pool, uuid) = get_pool(ldap)

            result=api.Command['entitle_status']()['result']
            available = result['quantity'] - result['consumed']

            if quantity > available:
                raise errors.ValidationError(
                    name='quantity',
                    error=_('There are only %d entitlements left') % available)

            try:
                cp = UEPConnection(handler='/candlepin', cert_file=certfile, key_file=keyfile)
                cp.bindByEntitlementPool(uuid, pool['id'], quantity=quantity)
            except RestlibException, e:
                raise errors.ACIError(info=e.msg)
            results = cp.getCertificates(uuid)
            usercertificate = []
            for cert in results:
                usercertificate.append(x509.normalize_certificate(cert['cert']))
            entry_attrs['usercertificate'] = usercertificate
            entry_attrs['ipaentitlementid'] = uuid
        finally:
            if db:
                shutil.rmtree(db, ignore_errors=True)

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        """
        Returning the certificates isn't very interesting. Return the
        status of entitlements instead.
        """
        assert isinstance(dn, DN)
        if 'usercertificate' in entry_attrs:
            del entry_attrs['usercertificate']
        if 'userpkcs12' in entry_attrs:
            del entry_attrs['userpkcs12']
        result = api.Command['entitle_status']()
        for attr in result['result']:
            entry_attrs[attr] = result['result'][attr]

        return dn

api.register(entitle_consume)


class entitle_get(VirtualCommand):
    __doc__ = _('Retrieve the entitlement certs.')

    operation="retrieve entitlement"

    has_output_params = (
        Str('product',
            label=_('Product'),
        ),
        Int('quantity',
            label=_('Quantity'),
        ),
        Str('start',
            label=_('Start'),
        ),
        Str('end',
            label=_('End'),
        ),
        Str('serial',
            label=_('Serial Number'),
        ),
    )

    has_output = output.standard_list_of_entries

    def execute(self, *keys, **kw):
        ldap = self.api.Backend.ldap2

        os.environ['LANG'] = 'en_US'
        locale.setlocale(locale.LC_ALL, '')

        (db, uuid, certfile, keyfile) = get_uuid(ldap)
        if db is None:
            quantity = 0
            product = ''
            registrations = api.Command['entitle_find'](all=True)['result'][0]
            certs = []
            if u'usercertificate' in registrations:
                # make it look like a UEP cert
                for cert in registrations['usercertificate']:
                    certs.append(dict(cert = x509.make_pem(base64.b64encode(cert))))
        else:
            try:
                cp = UEPConnection(handler='/candlepin', cert_file=certfile, key_file=keyfile)
                certs = cp.getCertificates(uuid)
            finally:
                if db:
                    shutil.rmtree(db, ignore_errors=True)

        entries = []
        for c in certs:
            try:
                pc = EntitlementCertificate(c['cert'])
            except M2Crypto.X509.X509Error:
                raise errors.CertificateFormatError(error=_('Not an entitlement certificate'))
            order = pc.getOrder()
            quantity = 0
            if order.getQuantityUsed():
                quantity = order.getQuantityUsed()
            result={'product': unicode(order.getName()),
                    'quantity': int(order.getQuantityUsed()),
                    'start': unicode(order.getStart()),
                    'end': unicode(order.getEnd()),
                    'serial': unicode(pc.serialNumber()),
                    'certificate': unicode(c['cert']),
            }
            entries.append(result)
            del pc
            del order

        return dict(
            result=entries,
            count=len(entries),
            truncated=False,
        )

api.register(entitle_get)

class entitle_find(LDAPSearch):
    __doc__ = _('Search for entitlement accounts.')

    has_output_params = output_params
    INTERNAL = True

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if len(entries) == 0:
            raise errors.NotRegisteredError()
        return truncated

api.register(entitle_find)

class entitle_register(LDAPCreate):
    __doc__ = _('Register to the entitlement system.')

    operation="register entitlement"

    msg_summary = _('Registered to entitlement server.')

    takes_args = (
        Str('username',
            label=_('Username'),
        ),
    )

    takes_options = LDAPCreate.takes_options + (
        Str('ipaentitlementid?',
            label='UUID',
            doc=_('Enrollment UUID (not implemented)'),
            flags=['no_create', 'no_update'],
        ),
        Password('password',
            label=_('Password'),
            doc=_('Registration password'),
            confirm=False,
        ),
    )

    """
    has_output_params = (
    )

    has_output = (
        Output('result',
            type=dict,
            doc=_('Dictionary mapping variable name to value'),
        ),
    )
    """

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        dn = DN(self.obj.container_dn, self.api.env.basedn)
        if not ldap.can_add(dn):
            raise errors.ACIError(info=_('No permission to register'))
        os.environ['LANG'] = 'en_US'
        locale.setlocale(locale.LC_ALL, '')

        if 'ipaentitlementid' in options:
            raise errors.ValidationError(name='ipaentitlementid',
                error=_('Registering to specific UUID is not supported yet.'))

        try:
            registrations = api.Command['entitle_find']()
            raise errors.AlreadyRegisteredError()
        except errors.NotRegisteredError:
            pass
        try:
            admin_cp = UEPConnection(handler='/candlepin', username=keys[-1], password=options.get('password'))
            result = admin_cp.registerConsumer(name=api.env.realm, type="domain")
            uuid = result['uuid']
            db = None
            try:
                # Create a PKCS#12 file to store the private key and
                # certificate in LDAP. Encrypt using the Apache cert
                # database password.
                db = tempfile.mkdtemp(prefix = "tmp-")
                write_file(db + '/in.cert', result['idCert']['cert'])
                write_file(db + '/in.key', result['idCert']['key'])
                args = ['/usr/bin/openssl', 'pkcs12',
                        '-export',
                        '-in', db + '/in.cert',
                        '-inkey', db + '/in.key',
                        '-out', db + '/out.p12',
                        '-name', 'candlepin',
                        '-passout', 'pass:%s' % read_pkcs12_pin()
                       ]

                (stdout, stderr, rc) = run(args, raiseonerr=False)
                pkcs12 = read_file(db + '/out.p12')

                entry_attrs['ipaentitlementid'] = uuid
                entry_attrs['userpkcs12'] = pkcs12
            finally:
                if db is not None:
                    shutil.rmtree(db, ignore_errors=True)
        except RestlibException, e:
            if e.code == 401:
                raise errors.ACIError(info=e.msg)
            else:
                raise e
        except socket.gaierror:
            raise errors.ACIError(info=e.args[1])

        dn = ldap.make_dn(
            entry_attrs, self.obj.uuid_attribute, self.obj.container_dn
        )
        return dn

api.register(entitle_register)


class entitle_import(LDAPUpdate):
    __doc__ = _('Import an entitlement certificate.')

    has_output_params = (
        Str('product',
            label=_('Product'),
        ),
        Int('quantity',
            label=_('Quantity'),
        ),
        Int('consumed',
            label=_('Consumed'),
        ),
    )

    has_output = (
        Output('result',
            type=dict,
            doc=_('Dictionary mapping variable name to value'),
        ),
    )

    takes_args = (
        File('usercertificate*', validate_certificate,
            cli_name='certificate_file',
        ),
    )

    # any update requires at least 1 option to be set so force an invisible
    # one here by setting the uuid.
    takes_options = LDAPCreate.takes_options + (
        Str('uuid?',
            label=_('UUID'),
            doc=_('Enrollment UUID'),
            flags=['no_create', 'no_update'],
            autofill=True,
            default=u'IMPORTED',
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        try:
            (db, uuid, certfile, keyfile) = get_uuid(ldap)
            if db is not None:
                raise errors.AlreadyRegisteredError()
        except errors.NotRegisteredError:
            pass

        try:
            entry_attrs['ipaentitlementid'] = unicode('IMPORTED')
            newcert = x509.normalize_certificate(keys[-1][0])
            cert = x509.make_pem(base64.b64encode(newcert))
            try:
                pc = EntitlementCertificate(cert)
                o = pc.getOrder()
                if o is None:
                    raise errors.CertificateFormatError(error=_('Not an entitlement certificate'))
            except M2Crypto.X509.X509Error:
                raise errors.CertificateFormatError(error=_('Not an entitlement certificate'))
            dn = DN(('ipaentitlementid', entry_attrs['ipaentitlementid']), dn)
            (dn, current_attrs) = ldap.get_entry(
                dn, ['*'], normalize=self.obj.normalize_dn
            )
            entry_attrs['usercertificate'] = current_attrs['usercertificate']
            entry_attrs['usercertificate'].append(newcert)
        except errors.NotFound:
            # First import, create the entry
            entry_attrs['ipaentitlementid'] = unicode('IMPORTED')
            entry_attrs['objectclass'] = self.obj.object_class
            entry_attrs['usercertificate'] = x509.normalize_certificate(keys[-1][0])
            ldap.add_entry(dn, entry_attrs)
            setattr(context, 'entitle_import', True)

        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        """
        If we are adding the first entry there are no updates so EmptyModlist
        will get thrown. Ignore it.
        """
        if call_func.func_name == 'update_entry':
            if isinstance(exc, errors.EmptyModlist):
                if not getattr(context, 'entitle_import', False):
                    raise exc
                return (call_args, {})
        raise exc

    def execute(self, *keys, **options):
        super(entitle_import, self).execute(*keys, **options)

        return dict(
            result=api.Command['entitle_status']()['result']
        )

api.register(entitle_import)

class entitle_sync(LDAPUpdate):
    __doc__ = _('Re-sync the local entitlement cache with the entitlement server.')

    operation="sync entitlement"

    msg_summary = _('Entitlement(s) synchronized.')

    # We don't want rights or add/setattr
    takes_options = (
        # LDAPUpdate requires at least one option so autofill one
        # This isn't otherwise used.
        Int('hidden',
            label=_('Quantity'),
            minvalue=1,
            autofill=True,
            default=1,
            flags=['no_option', 'no_output']
        ),
    )

    has_output_params = output_params + (
        Str('product',
            label=_('Product'),
        ),
        Int('consumed',
            label=_('Consumed'),
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        os.environ['LANG'] = 'en_US'
        locale.setlocale(locale.LC_ALL, '')

        (db, uuid, certfile, keyfile) = get_uuid(ldap)
        if db is None:
            raise errors.NotRegisteredError()
        try:
            (pool, uuid) = get_pool(ldap)

            cp = UEPConnection(handler='/candlepin', cert_file=certfile, key_file=keyfile)
            results = cp.getCertificates(uuid)
            usercertificate = []
            for cert in results:
                usercertificate.append(x509.normalize_certificate(cert['cert']))
            entry_attrs['usercertificate'] = usercertificate
            entry_attrs['ipaentitlementid'] = uuid
        finally:
            if db:
                shutil.rmtree(db, ignore_errors=True)

        dn = ldap.make_dn(
            entry_attrs, self.obj.uuid_attribute, self.obj.container_dn
        )
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        """
        Returning the certificates isn't very interesting. Return the
        status of entitlements instead.
        """
        assert isinstance(dn, DN)
        if 'usercertificate' in entry_attrs:
            del entry_attrs['usercertificate']
        if 'userpkcs12' in entry_attrs:
            del entry_attrs['userpkcs12']
        result = api.Command['entitle_status']()
        for attr in result['result']:
            entry_attrs[attr] = result['result'][attr]

        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        if call_func.func_name == 'update_entry':
            if isinstance(exc, errors.EmptyModlist):
                # If there is nothing to change we are already synchronized.
                return
        raise exc

api.register(entitle_sync)
