#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import base64

import six

from ipalib import api, errors, messages, output, Bytes, DNParam, Flag, Str
from ipalib.constants import IPA_CA_CN
from ipalib.plugable import Registry
from ipapython.dn import ATTR_NAME_BY_OID
from ipaserver.plugins.baseldap import (
    LDAPObject, LDAPSearch, LDAPCreate, LDAPDelete,
    LDAPUpdate, LDAPRetrieve, LDAPQuery, pkey_to_value)
from ipaserver.plugins.cert import ca_enabled_check
from ipalib import _, ngettext, x509


__doc__ = _("""
Manage Certificate Authorities
""") + _("""
Subordinate Certificate Authorities (Sub-CAs) can be added for scoped issuance
of X.509 certificates.
""") + _("""
CAs are enabled on creation, but their use is subject to CA ACLs unless the
operator has permission to bypass CA ACLs.
""") + _("""
All CAs except the 'IPA' CA can be disabled or re-enabled.  Disabling a CA
prevents it from issuing certificates but does not affect the validity of its
certificate.
""") + _("""
CAs (all except the 'IPA' CA) can be deleted.  Deleting a CA causes its signing
certificate to be revoked and its private key deleted.
""") + _("""
EXAMPLES:
""") + _("""
  Create new CA, subordinate to the IPA CA.

    ipa ca-add puppet --desc "Puppet" \\
        --subject "CN=Puppet CA,O=EXAMPLE.COM"
""") + _("""
  Disable a CA.

    ipa ca-disable puppet
""") + _("""
  Re-enable a CA.

    ipa ca-enable puppet
""") + _("""
  Delete a CA.

    ipa ca-del puppet
""")


register = Registry()


@register()
class ca(LDAPObject):
    """
    Lightweight CA Object
    """
    container_dn = api.env.container_ca
    object_name = _('Certificate Authority')
    object_name_plural = _('Certificate Authorities')
    object_class = ['ipaca']
    permission_filter_objectclasses = ['ipaca']
    default_attributes = [
        'cn', 'description', 'ipacaid', 'ipacaissuerdn', 'ipacasubjectdn',
    ]
    rdn_attribute = 'cn'
    allow_rename = True
    label = _('Certificate Authorities')
    label_singular = _('Certificate Authority')

    takes_params = (
        Str('cn',
            primary_key=True,
            cli_name='name',
            label=_('Name'),
            doc=_('Name for referencing the CA'),
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('Description of the purpose of the CA'),
        ),
        Str('ipacaid',
            cli_name='id',
            label=_('Authority ID'),
            doc=_('Dogtag Authority ID'),
            flags=['no_create', 'no_update'],
        ),
        DNParam('ipacasubjectdn',
            cli_name='subject',
            label=_('Subject DN'),
            doc=_('Subject Distinguished Name'),
            flags=['no_update'],
        ),
        DNParam('ipacaissuerdn',
            cli_name='issuer',
            label=_('Issuer DN'),
            doc=_('Issuer Distinguished Name'),
            flags=['no_create', 'no_update'],
        ),
        Bytes(
            'certificate',
            label=_("Certificate"),
            doc=_("Base-64 encoded certificate."),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Bytes(
            'certificate_chain*',
            label=_("Certificate chain"),
            doc=_("X.509 certificate chain"),
            flags={'no_create', 'no_update', 'no_search'},
        ),
    )

    permission_filter_objectclasses = ['ipaca']
    managed_permissions = {
        'System: Read CAs': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn',
                'description',
                'ipacaid',
                'ipacaissuerdn',
                'ipacasubjectdn',
                'objectclass',
            },
        },
        'System: Add CA': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=cas,cn=ca,$SUFFIX")(version 3.0;acl "permission:Add CA";allow (add) groupdn = "ldap:///cn=Add CA,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'CA Administrator'},
        },
        'System: Delete CA': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///cn=*,cn=cas,cn=ca,$SUFFIX")(version 3.0;acl "permission:Delete CA";allow (delete) groupdn = "ldap:///cn=Delete CA,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'CA Administrator'},
        },
        'System: Modify CA': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'cn',
                'description',
            },
            'replaces': [
                '(targetattr = "cn || description")(target = "ldap:///cn=*,cn=cas,cn=ca,$SUFFIX")(version 3.0;acl "permission:Modify CA";allow (write) groupdn = "ldap:///cn=Modify CA,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'CA Administrator'},
        },
    }


def set_certificate_attrs(entry, options, want_cert=True):
    """
    Set certificate attributes into the entry.  Depending on
    options, this may contact Dogtag to retrieve certificate or
    chain.  If the retrieval fails with 404 (which can occur under
    normal operation due to lightweight CA key replication delay),
    return a message object that should be set in the response.

    """
    try:
        ca_id = entry['ipacaid'][0]
    except KeyError:
        return None
    full = options.get('all', False)
    want_chain = options.get('chain', False)

    want_data = want_cert or want_chain or full
    if not want_data:
        return None

    msg = None

    with api.Backend.ra_lightweight_ca as ca_api:
        if want_cert or full:
            try:
                der = ca_api.read_ca_cert(ca_id)
                entry['certificate'] = base64.b64encode(der).decode('ascii')
            except errors.HTTPRequestError as e:
                if e.status == 404:  # pylint: disable=no-member
                    msg = messages.LightweightCACertificateNotAvailable(
                        ca=entry['cn'][0])
                else:
                    raise e

        if want_chain or full:
            try:
                pkcs7_der = ca_api.read_ca_chain(ca_id)
                certs = x509.pkcs7_to_certs(pkcs7_der, x509.DER)
                ders = [cert.public_bytes(x509.Encoding.DER) for cert in certs]
                entry['certificate_chain'] = ders
            except errors.HTTPRequestError as e:
                if e.status == 404:  # pylint: disable=no-member
                    msg = messages.LightweightCACertificateNotAvailable(
                        ca=entry['cn'][0])
                else:
                    raise e

    return msg

@register()
class ca_find(LDAPSearch):
    __doc__ = _("Search for CAs.")
    msg_summary = ngettext(
        '%(count)d CA matched', '%(count)d CAs matched', 0
    )

    def execute(self, *keys, **options):
        ca_enabled_check(self.api)
        result = super(ca_find, self).execute(*keys, **options)
        if not options.get('pkey_only', False):
            for entry in result['result']:
                msg = set_certificate_attrs(entry, options, want_cert=False)
                if msg:
                    self.add_message(msg)
        return result


_chain_flag = Flag(
    'chain',
    default=False,
    doc=_('Include certificate chain in output'),
)


@register()
class ca_show(LDAPRetrieve):
    __doc__ = _("Display the properties of a CA.")

    takes_options = LDAPRetrieve.takes_options + (
        _chain_flag,
    )

    def execute(self, *keys, **options):
        ca_enabled_check(self.api)
        result = super(ca_show, self).execute(*keys, **options)
        msg = set_certificate_attrs(result['result'], options)
        if msg:
            self.add_message(msg)
        return result


@register()
class ca_add(LDAPCreate):
    __doc__ = _("Create a CA.")
    msg_summary = _('Created CA "%(value)s"')

    takes_options = LDAPCreate.takes_options + (
        _chain_flag,
    )

    def pre_callback(self, ldap, dn, entry, entry_attrs, *keys, **options):
        ca_enabled_check(self.api)
        if not ldap.can_add(dn[1:], 'ipaca'):
            raise errors.ACIError(
                info=_("Insufficient 'add' privilege for entry '%s'.") % dn)

        # check that DN only includes standard naming attributes
        dn_attrs = {
            ava.attr.lower()
            for rdn in options['ipacasubjectdn']
            for ava in rdn
        }
        x509_attrs = {
            attr.lower()
            for attr in six.viewvalues(ATTR_NAME_BY_OID)
        }
        unknown_attrs = dn_attrs - x509_attrs
        if len(unknown_attrs) > 0:
            raise errors.ValidationError(
                name=_("Subject DN"),
                error=_("Unrecognized attributes: %(attrs)s")
                    % dict(attrs=", ".join(unknown_attrs))
            )

        # check for name collision before creating CA in Dogtag
        try:
            api.Object.ca.get_dn_if_exists(keys[-1])
            self.obj.handle_duplicate_entry(*keys)
        except errors.NotFound:
            pass

        # check for subject collision before creating CA in Dogtag
        result = api.Command.ca_find(ipacasubjectdn=options['ipacasubjectdn'])
        if result['count'] > 0:
            raise errors.DuplicateEntry(message=_(
                "Subject DN is already used by CA '%s'"
                ) % result['result'][0]['cn'][0])

        # Create the CA in Dogtag.
        with self.api.Backend.ra_lightweight_ca as ca_api:
            resp = ca_api.create_ca(options['ipacasubjectdn'])
        entry['ipacaid'] = [resp['id']]
        entry['ipacaissuerdn'] = [resp['issuerDN']]

        # In the event that the issued certificate's subject DN
        # differs from what was requested, record the actual DN.
        #
        entry['ipacasubjectdn'] = [resp['dn']]
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        msg = set_certificate_attrs(entry_attrs, options)
        if msg:
            self.add_message(msg)
        return dn


@register()
class ca_del(LDAPDelete):
    __doc__ = _('Delete a CA.')

    msg_summary = _('Deleted CA "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        ca_enabled_check(self.api)

        # ensure operator has permission to delete CA
        # before contacting Dogtag
        if not ldap.can_delete(dn):
            raise errors.ACIError(info=_(
                "Insufficient privilege to delete a CA."))

        if keys[0] == IPA_CA_CN:
            raise errors.ProtectedEntryError(
                label=_("CA"),
                key=keys[0],
                reason=_("IPA CA cannot be deleted"))

        ca_id = self.api.Command.ca_show(keys[0])['result']['ipacaid'][0]
        with self.api.Backend.ra_lightweight_ca as ca_api:
            ca_api.disable_ca(ca_id)
            ca_api.delete_ca(ca_id)

        return dn


@register()
class ca_mod(LDAPUpdate):
    __doc__ = _("Modify CA configuration.")
    msg_summary = _('Modified CA "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        ca_enabled_check(self.api)

        if 'rename' in options or 'cn' in entry_attrs:
            if keys[0] == IPA_CA_CN:
                raise errors.ProtectedEntryError(
                    label=_("CA"),
                    key=keys[0],
                    reason=u'IPA CA cannot be renamed')

        return dn


class CAQuery(LDAPQuery):
    has_output = output.standard_value

    def execute(self, cn, **options):
        ca_enabled_check(self.api)

        ca_obj = self.api.Command.ca_show(cn)['result']

        # ensure operator has permission to modify CAs
        if not self.api.Backend.ldap2.can_write(ca_obj['dn'], 'description'):
            raise errors.ACIError(info=_(
                "Insufficient privilege to modify a CA."))

        with self.api.Backend.ra_lightweight_ca as ca_api:
            self.perform_action(ca_api, ca_obj['ipacaid'][0])

        return dict(
            result=True,
            value=pkey_to_value(cn, options),
        )

    def perform_action(self, ca_api, ca_id):
        raise NotImplementedError


@register()
class ca_disable(CAQuery):
    __doc__ = _('Disable a CA.')
    msg_summary = _('Disabled CA "%(value)s"')

    def execute(self, cn, **options):
        if cn == IPA_CA_CN:
            raise errors.ProtectedEntryError(
                label=_("CA"),
                key=cn,
                reason=_("IPA CA cannot be disabled"))

        return super(ca_disable, self).execute(cn, **options)

    def perform_action(self, ca_api, ca_id):
        ca_api.disable_ca(ca_id)


@register()
class ca_enable(CAQuery):
    __doc__ = _('Enable a CA.')
    msg_summary = _('Enabled CA "%(value)s"')

    def perform_action(self, ca_api, ca_id):
        ca_api.enable_ca(ca_id)
