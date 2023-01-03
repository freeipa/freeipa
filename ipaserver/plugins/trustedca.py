#
# Copyright (C) 2023  FreeIPA Contributors see COPYING for license
#


from ipalib import api
from ipalib import Bytes, DNParam, Str
from ipalib.parameters import Certificate
from ipalib.plugable import Registry
from ipalib import x509
from ipaserver.plugins.baseldap import LDAPObject, LDAPSearch, LDAPRetrieve
from ipaserver.plugins.cert import AbstractCertObject
from ipalib import _, ngettext


__doc__ = _("""
Manage trusted Certificate Authorities (ipa-catrust-manage)
""")


register = Registry()


@register()
class trustedca(LDAPObject, AbstractCertObject):
    """Trusted CA object
    """
    container_dn = api.env.container_trustedca
    object_name = _('Trusted CA certificate')
    object_name_plural = _('Trusted CAs certificates')
    object_class = ['ipacertificate', 'pkiCA']
    permission_filter_objectclasses = ['ipacertificate']
    default_attributes = [
        'cn', 'cacertificate', 'ipakeyextusage', ' ipakeytrust',
    ]
    rdn_attribute = 'cn'
    allow_rename = True
    label = _('Trusted CA certificates')
    label_singular = _('Trusted CA certificate')

    takes_params = (
        Str(
            'cn',
            primary_key=True,
            cli_name='name',
            label=_('Name'),
            doc=_('Name for referencing the CA'),
        ),
        Str(
            'ipacertissuerserial',
            cli_name='issuerserial',
            label=_('Issuer & Serial'),
            doc=_('Certificate issuer and serial number'),
            flags={'no_display', 'no_create', 'no_update', 'no_search'},
        ),
        DNParam(
            'ipacertsubject',
            cli_name='subject',
            label=_('Subject DN'),
            doc=_('Subject Distinguished Name'),
            flags={'no_display', 'no_create', 'no_update', 'no_search'},
        ),
        Bytes(
            'ipapublickey',
            label=_("public key"),
            doc=_("Base-64 encoded public key of the certificate."),
            flags={'no_display', 'no_create', 'no_update', 'no_search'},
        ),
        Certificate(
            'cacertificate',
            label=_("CA Certificate"),
            doc=_("Base-64 encoded certificate."),
            flags={'no_create', 'no_update', 'no_search'},
        ),
    ) + AbstractCertObject.x509v1_params + AbstractCertObject.san_params + (
        Str(
            'ipakeyextusage*',
            cli_name='eku',
            label=_('Extended key usage'),
            doc=_('Extended key usage'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'ipakeytrust',
            cli_name='keytrust',
            label=_('Trust'),
            doc=_('Trust'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
    )

    managed_permissions = {}

    def _parse_cacertificate(self, obj, full=True):
        if "cacertificate" in obj:
            cert = obj["cacertificate"][0]
            self._parse_x509v1(cert, obj, full=full)
            self._parse_san(cert, obj, full=full)
        # human readable EKU, sorted by OID
        if "ipakeyextusage" in obj:
            obj["ipakeyextusage"] = [
                x509.EKU_NAMES.get(eku, eku)
                for eku in sorted(obj["ipakeyextusage"])
            ]

    def get_params(self):
        for param in super(trustedca, self).get_params():
            if param.name == 'cacertificate':
                param = param.clone(flags=param.flags - {'no_search'})
            yield param


@register()
class trustedca_find(LDAPSearch):
    __doc__ = _("Search for trusted CAs certificates.")
    msg_summary = ngettext(
        '%(count)d CA matched', '%(count)d CAs matched', 0
    )

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if not options.get("raw"):
            all = options.get("all")
            for entry in entries:
                self.obj._parse_cacertificate(entry, all)

        return truncated


@register()
class trustedca_show(LDAPRetrieve):
    __doc__ = _("Display the properties of a trusted CA certificate.")

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if not options.get("raw"):
            all = options.get("all")
            self.obj._parse_cacertificate(entry_attrs, all)
        return dn
