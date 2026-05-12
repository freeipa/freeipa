#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#

import logging
import string
from cryptography.hazmat.primitives.serialization import pkcs12
from urllib.parse import urlparse

from .baseldap import (
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve,
    add_missing_object_class,
)
from ipalib import api, errors, Bytes, Password, Str, StrEnum, _, ngettext
from ipalib.parameters import Certificate
from ipalib.plugable import Registry
from ipalib.x509 import Encoding
from ipapython.dn import DN
from ipapython.ipautil import template_str
from copy import deepcopy
from itertools import chain

logger = logging.getLogger(__name__)

__doc__ = _("""
External Identity Provider References
""") + _("""
Manage External Identity Provider References.
""") + _("""
IPA supports the use of an external Identity Provider for OAuth2.0 Device Flow
authentication.
""") + _("""
EXAMPLES:
""") + _("""
 Add a new external Identity Provider reference:
   ipa idp-add MyIdP --client-id jhkQty13 \
      --auth-uri https://oauth2.idp.com/auth \
      --token-uri https://oauth2.idp.com/token --secret
""") + _("""
 Add a new external Identity Provider reference using github predefined
 endpoints:
   ipa idp-add MyIdp --client-id jhkQty13 --provider github --secret
""") + _("""
 Add a new external Identity Provider reference using JWT assertion
 authentication:
   ipa idp-add MyIdP --provider keycloak \
      --org myrealm --base-url keycloak.example.com \
      --client-id ipa-client \
      --client-auth-method private_key_jwt \
      --client-cert-p12-file idp-client.p12
""") + _("""
 Add a new external Identity Provider reference using mTLS authentication:
   ipa idp-add MyIdP --provider keycloak \
      --org myrealm --base-url keycloak.example.com \
      --client-id ipa-client \
      --client-auth-method tls_client_auth \
      --client-cert-p12-file idp-client.p12
""") + _("""
 Find all external Identity Provider references whose entries include the string
 "test.com":
   ipa idp-find test.com
""") + _("""
 Examine the configuration of an external Identity Provider reference:
   ipa idp-show MyIdP
""") + _("""
 Change the secret:
   ipa idp-mod MyIdP --secret
""") + _("""
 Delete an external Identity Provider reference:
   ipa idp-del MyIdP
""")

register = Registry()


def normalize_baseurl(url):
    if url.startswith('https://'):
        return url[len('https://'):]
    return url


def validate_uri(ugettext, uri):
    try:
        parsed = urlparse(uri, 'https')
    except Exception:
        return _('Invalid URI: not an https scheme')

    if not parsed.netloc:
        return _('Invalid URI: missing netloc')

    return None


class Pkcs12Bytes(Bytes):
    """
    A data type for pkcs12 data to avoid logging the content

    The Bytes type does not hide the content.
    """

    def safe_value(self, value):
        return u'********'


@register()
class idp(LDAPObject):
    """
    Identity Provider object.
    """
    container_dn = api.env.container_idp
    object_name = _('Identity Provider reference')
    object_name_plural = _('Identity Provider references')
    object_class = ['ipaidp']
    possible_objectclasses = ['ipaidpclientauth']
    default_attributes = [
        'cn', 'ipaidpauthendpoint', 'ipaidpdevauthendpoint',
        'ipaidpuserinfoendpoint', 'ipaidpkeysendpoint',
        'ipaidptokenendpoint', 'ipaidpissuerurl',
        'ipaidpclientid', 'ipaidpscope', 'ipaidpsub',
        'ipaidpclientauthmethod',
    ]
    search_attributes = [
        'cn', 'ipaidpauthendpoint', 'ipaidpdevauthendpoint',
        'ipaidptokenendpoint', 'ipaidpuserinfoendpoint',
        'ipaidpkeysendpoint', 'ipaidpscope', 'ipaidpsub',
    ]
    allow_rename = True
    label = _('Identity Provider references')
    label_singular = _('Identity Provider reference')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Identity Provider reference name'),
            primary_key=True,
            ),
        Str('ipaidpauthendpoint?',
            validate_uri,
            cli_name='auth_uri',
            label=_('Authorization URI'),
            doc=_('OAuth 2.0 authorization endpoint'),
            ),
        Str('ipaidpdevauthendpoint?',
            validate_uri,
            cli_name='dev_auth_uri',
            label=_('Device authorization URI'),
            doc=_('Device authorization endpoint'),
            ),
        Str('ipaidptokenendpoint?',
            validate_uri,
            cli_name='token_uri',
            label=_('Token URI'),
            doc=_('Token endpoint'),
            ),
        Str('ipaidpuserinfoendpoint?',
            validate_uri,
            cli_name='userinfo_uri',
            label=_('User info URI'),
            doc=_('User information endpoint'),
            ),
        Str('ipaidpkeysendpoint?',
            validate_uri,
            cli_name='keys_uri',
            label=_('JWKS URI'),
            doc=_('JWKS endpoint'),
            ),
        Str('ipaidpissuerurl?',
            cli_name='issuer_url',
            label=_('OIDC URL'),
            doc=_(
                'The Identity Provider OIDC URL'),
            ),
        Str('ipaidpclientid',
            cli_name='client_id',
            label=_('Client identifier'),
            doc=_(
                'OAuth 2.0 client identifier'),
            ),
        Password('ipaidpclientsecret?',
                 cli_name='secret',
                 label=_('Secret'),
                 doc=_('OAuth 2.0 client secret'),
                 confirm=True,
                 flags={'no_display'},
                 ),
        Str('ipaidpscope?',
            cli_name='scope',
            label=_('Scope'),
            doc=_('OAuth 2.0 scope. Multiple scopes separated by space'),
            ),
        Str('ipaidpsub?',
            cli_name='idp_user_id',
            label=_('External IdP user identifier attribute'),
            doc=_('Attribute for user identity in OAuth 2.0 userinfo'),
            ),
        StrEnum('ipaidpclientauthmethod?',
                cli_name='client_auth_method',
                label=_('Client Authentication Method'),
                doc=_('Method used for client authentication to the IdP'),
                values=('client_secret', 'private_key_jwt', 'tls_client_auth')
                ),
        Pkcs12Bytes(
            'userpkcs12?',
            cli_name='client_cert_p12',
            label=_('Client pkcs12 bundle'),
            doc=_('Pkcs12 bundle used for client authentication to the IdP'),
            flags=['no_output', 'no_option'],
        ),
        Certificate('usercertificate*',
                    label=_('Certificate'),
                    doc=_('Base-64 encoded user certificate'),
                    flags=['no_option', 'no_create', 'no_update'],
                    ),
    )

    permission_filter_objectclasses = ['ipaidp']
    managed_permissions = {
        'System: Add External IdP server': {
            'ipapermright': {'add'},
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'ipapermtargetfilter': {
                '(objectclass=ipaidp)'},
            'default_privileges': {'External IdP server Administrators'}
        },
        'System: Read External IdP server': {
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'objectclass', 'ipaidpauthendpoint',
                'ipaidpdevauthendpoint', 'ipaidpuserinfoendpoint',
                'ipaidptokenendpoint', 'ipaidpkeysendpoint',
                'ipaidpissuerurl', 'ipaidpclientid', 'ipaidpscope',
                'ipaidpsub', 'ipaidpclientauthmethod',
                'usercertificate',
            },
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'ipapermtargetfilter': {
                '(objectclass=ipaidp)'},
            'default_privileges': {'External IdP server Administrators'}
        },
        'System: Modify External IdP server': {
            'ipapermright': {'write'},
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'ipapermdefaultattr': {
                'cn', 'objectclass', 'ipaidpauthendpoint',
                'ipaidpdevauthendpoint', 'ipaidpuserinfoendpoint',
                'ipaidptokenendpoint', 'ipaidpkeysendpoint',
                'ipaidpissuerurl', 'ipaidpclientid', 'ipaidpscope',
                'ipaidpclientsecret', 'ipaidpsub', 'ipaidpclientauthmethod',
                'usercertificate',
            },
            'default_privileges': {'External IdP server Administrators'}
        },
        'System: Delete External IdP server': {
            'ipapermright': {'delete'},
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'ipapermtargetfilter': {
                '(objectclass=ipaidp)'},
            'default_privileges': {'External IdP server Administrators'}
        },
        'System: Read External IdP server client secret': {
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermlocation': DN(container_dn, api.env.basedn),
            'ipapermdefaultattr': {
                'cn', 'objectclass', 'ipaidpauthendpoint',
                'ipaidpdevauthendpoint', 'ipaidpuserinfoendpoint',
                'ipaidptokenendpoint', 'ipaidpissuerurl',
                'ipaidpkeysendpoint', 'ipaidpclientid', 'ipaidpscope',
                'ipaidpclientsecret', 'ipaidpsub', 'ipaidpclientauthmethod',
                'usercertificate', 'userpkcs12',
            },
            'ipapermtargetfilter': {
                '(objectclass=ipaidp)'},
        }
    }

    def convert_usercertificate_post(self, entry_attrs, **options):
        for attrname in ['usercertificate', 'userpkcs12']:
            if attrname + ';binary' in entry_attrs:
                entry_attrs[attrname] = entry_attrs.pop(attrname + ';binary')

    def check_client_auth_attrs(self, entry_attrs):
        # When private_key_jwt or tls_client_auth, P12file required
        if 'userpkcs12' not in entry_attrs:
            raise errors.RequirementError(name='client-cert-p12-file')
        # The client secret is also required
        if 'ipaidpclientsecret' not in entry_attrs:
            raise errors.RequirementError(name='PKCS12 password')

    def fill_usercertificate(self, entry_attrs):
        p12file_data = entry_attrs.get('userpkcs12', None)
        if not p12file_data:
            return

        # Empty string is converted to None but None.encode() raises
        # an exception. Assume the p12 data is protected by an empty pwd
        secret = entry_attrs['ipaidpclientsecret'] or ''
        try:
            key, cert, _other_certs = pkcs12.load_key_and_certificates(
                p12file_data, secret.encode())
        except ValueError as e:
            raise errors.ValidationError(
                name='client_cert_p12_file',
                error=_(f"Cannot decode PKCS12 file: {e}")
            )
        if not key:
            raise errors.ValidationError(
                name='client_cert_p12_file',
                error=_("No private key found in PKCS12 file")
            )
        if not cert:
            raise errors.ValidationError(
                name='client_cert_p12_file',
                error=_("No certificate matching key in PKCS12 file")
            )

        entry_attrs['usercertificate;binary'] = cert.public_bytes(Encoding.DER)

        # transform also pkcs12 with ;binary option
        entry_attrs['userpkcs12;binary'] = entry_attrs.pop('userpkcs12')


@register()
class idp_add(LDAPCreate):
    __doc__ = _('Add a new Identity Provider reference.')
    msg_summary = _('Added Identity Provider reference "%(value)s"')

    # List of pre-populated idp endpoints
    # key = provider,
    # value = dictionary of overidden attributes
    idp_providers = {
        'google': {
            'ipaidpauthendpoint':
                'https://accounts.google.com/o/oauth2/auth',
            'ipaidpdevauthendpoint':
                'https://oauth2.googleapis.com/device/code',
            'ipaidptokenendpoint':
                'https://oauth2.googleapis.com/token',
            'ipaidpuserinfoendpoint':
                'https://openidconnect.googleapis.com/v1/userinfo',
            'ipaidpkeysendpoint':
                'https://www.googleapis.com/oauth2/v3/certs',
            'ipaidpscope': 'openid email',
            'ipaidpsub': 'email'},
        'github': {
            'ipaidpauthendpoint':
                'https://github.com/login/oauth/authorize',
            'ipaidpdevauthendpoint':
                'https://github.com/login/device/code',
            'ipaidptokenendpoint':
                'https://github.com/login/oauth/access_token',
            'ipaidpuserinfoendpoint':
                'https://api.github.com/user',
            'ipaidpscope': 'user',
            'ipaidpsub': 'login'},
        'microsoft': {
            'ipaidpauthendpoint':
                'https://login.microsoftonline.com/${ipaidporg}/oauth2/v2.0/'
                'authorize',
            'ipaidpdevauthendpoint':
                'https://login.microsoftonline.com/${ipaidporg}/oauth2/v2.0/'
                'devicecode',
            'ipaidptokenendpoint':
                'https://login.microsoftonline.com/${ipaidporg}/oauth2/v2.0/'
                'token',
            'ipaidpuserinfoendpoint':
                'https://graph.microsoft.com/oidc/userinfo',
            'ipaidpkeysendpoint':
                'https://login.microsoftonline.com/common/discovery/v2.0/keys',
            'ipaidpscope': 'openid email',
            'ipaidpsub': 'email',
        },
        'okta': {
            'ipaidpauthendpoint':
                'https://${ipaidpbaseurl}/oauth2/v1/authorize',
            'ipaidpdevauthendpoint':
                'https://${ipaidpbaseurl}/oauth2/v1/device/authorize',
            'ipaidptokenendpoint':
                'https://${ipaidpbaseurl}/oauth2/v1/token',
            'ipaidpuserinfoendpoint':
                'https://${ipaidpbaseurl}/oauth2/v1/userinfo',
            'ipaidpscope': 'openid email',
            'ipaidpsub': 'email'},
        'keycloak': {
            'ipaidpauthendpoint':
                'https://${ipaidpbaseurl}/realms/${ipaidporg}/protocol/'
                'openid-connect/auth',
            'ipaidpdevauthendpoint':
                'https://${ipaidpbaseurl}/realms/${ipaidporg}/protocol/'
                'openid-connect/auth/device',
            'ipaidptokenendpoint':
                'https://${ipaidpbaseurl}/realms/${ipaidporg}/protocol/'
                'openid-connect/token',
            'ipaidpuserinfoendpoint':
                'https://${ipaidpbaseurl}/realms/${ipaidporg}/protocol/'
                'openid-connect/userinfo',
            'ipaidpscope': 'openid email',
            'ipaidpsub': 'email'},
    }

    takes_options = LDAPCreate.takes_options + (
        StrEnum(
            'ipaidpprovider?',
            cli_name='provider',
            label=_('IdP provider template'),
            doc=_('Choose a pre-defined template to use'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'nosearch'},
            values=tuple(idp_providers.keys()),
        ),
        Str('ipaidporg?',
            cli_name='organization',
            label=_('Organization'),
            doc=_('Organization ID or Realm name for IdP provider templates'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'nosearch'}),
        Str('ipaidpbaseurl?',
            cli_name='base_url',
            label=_('Base URL'),
            doc=_('Base URL for IdP provider templates'),
            normalizer=normalize_baseurl,
            flags={'virtual_attribute', 'no_create', 'no_update', 'nosearch'}),
    )

    def _convert_provider_to_endpoints(self, entry_attrs,
                                       provider=None, elements=None):
        """
        Converts provider options to auth-uri and token-uri
        """
        if provider:
            if provider not in self.idp_providers:
                raise errors.ValidationError(
                    name='provider',
                    error=_('unknown provider')
                )
            # For each string in the template check if a variable
            # is required, it is provided as an option
            points = deepcopy(self.idp_providers[provider])
            r = string.Template.pattern
            for (k,v) in points.items():
                # build list of variables to be replaced
                subs = list(chain.from_iterable(
                            (filter(None, s) for s in r.findall(v))))
                if subs:
                    for s in subs:
                        if s not in elements:
                            raise errors.ValidationError(
                                name=self.options[s].cli_name,
                                error=_('value is missing'))
                    points[k] = template_str(v, elements)
                elif k in elements:
                    points[k] = elements[k]

            entry_attrs.update(points)

    def get_options(self):
        # Some URIs are not mandatory as they can be built from the value of
        # provider.
        for option in super(idp_add, self).get_options():
            if option.name in ('ipaidpauthendpoint', 'ipaidpdevauthendpoint',
                               'ipaidptokenendpoint', 'ipaidpuserinfoendpoint',
                               'ipaidpkeysendpoint'):
                yield option.clone(required=False, alwaysask=False)
            else:
                yield option

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys,
                     **options):
        # The valid calls are
        # ipa idp-add --provider provider IDP [client details]
        # ipa idp-add --dev-auth-uri auth --token-uri token-uri IDP
        auth = options.get('ipaidpauthendpoint')
        devauth = options.get('ipaidpdevauthendpoint')
        token = options.get('ipaidptokenendpoint')
        userinfo = options.get('ipaidpuserinfoendpoint')
        jwks = options.get('ipaidpkeysendpoint')
        provider = options.get('ipaidpprovider')

        # If the provider is supplied, reject individual endpoints
        if any([devauth, auth, token, userinfo, jwks]):
            if provider:
                raise errors.MutuallyExclusiveError(
                    reason=_('cannot specify both individual endpoints '
                             'and IdP provider'))

        # If there is no --provider, individual endpoints required
        if not provider and not devauth:
            raise errors.RequirementError(name='dev-auth-uri or provider')
        if not provider and not auth:
            raise errors.RequirementError(name='auth-uri or provider')
        if not provider and not token:
            raise errors.RequirementError(name='token-uri or provider')
        if not provider and not userinfo:
            raise errors.RequirementError(name='userinfo-uri or provider')

        # if the command is called with --provider we need to add
        # ipaidpdevauthendpoint, ipaidpauthendpoint, and ipaidptokenendpoint
        # to the attrs list in order to display the resulting value in
        # the command output
        for endpoint in ['ipaidpauthendpoint', 'ipaidpdevauthendpoint',
                         'ipaidptokenendpoint', 'ipaidpuserinfoendpoint',
                         'ipaidpkeysendpoint']:
            if endpoint not in attrs_list:
                attrs_list.append(endpoint)

        self._convert_provider_to_endpoints(entry_attrs,
                                            provider=provider,
                                            elements=options)

        # Checks for client authentication
        if (
            entry_attrs.get('ipaidpclientauthmethod', 'client_secret')
            == 'client_secret'
        ):
            # When no value is provided or client_secret, do not accept
            # a PKCS12 file and usercertificate
            if 'userpkcs12' in entry_attrs:
                raise errors.MutuallyExclusiveError(
                    reason=_('cannot use client_secret authentication '
                             'and client-cert-p12-file'))
            # Drop the auth method if it is client secret
            # as it is the default value
            entry_attrs['ipaidpclientauthmethod'] = None
        else:
            self.obj.check_client_auth_attrs(entry_attrs)

        if entry_attrs.get('ipaidpclientauthmethod', None):
            add_missing_object_class(ldap, 'ipaidpclientauth', dn,
                                     entry_attrs, update=False)

        self.obj.fill_usercertificate(entry_attrs)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.convert_usercertificate_post(entry_attrs, **options)
        return dn


@register()
class idp_del(LDAPDelete):
    __doc__ = _('Delete an Identity Provider reference.')
    msg_summary = _('Deleted Identity Provider reference "%(value)s"')


@register()
class idp_mod(LDAPUpdate):
    __doc__ = _('Modify an Identity Provider reference.')
    msg_summary = _('Modified Identity Provider reference "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        try:
            old_attrs = ldap.get_entry(dn, ['*'])
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        old_meth = old_attrs.single_value.get(
            'ipaidpclientauthmethod', 'client_secret')
        new_meth = entry_attrs.get('ipaidpclientauthmethod', old_meth)

        # The objectclasses either come from the existing entry
        # or from new values
        if 'objectclass' in entry_attrs:
            ocs = entry_attrs['objectclass']
        else:
            ocs = entry_attrs['objectclass'] = old_attrs['objectclass']
        # IMPORTANT: compare objectclasses as case insensitive
        obj_classes = [o.lower() for o in ocs]

        # Check if there is a change in auth method
        if old_meth != new_meth:
            # If the method switches to cert auth, ensure we have p12data
            # and secret
            if old_meth == "client_secret":
                self.obj.check_client_auth_attrs(entry_attrs)
                self.obj.fill_usercertificate(entry_attrs)
                if 'ipaidpclientauth' not in obj_classes:
                    entry_attrs['objectclass'].append('ipaidpclientauth')
            elif new_meth == "client_secret":
                if 'userpkcs12' in entry_attrs:
                    raise errors.MutuallyExclusiveError(
                        reason=_('cannot use client_secret authentication '
                                 'and client-cert-p12-file'))
                # switching from something to client-secret:
                # remove the certificate and p12 file
                entry_attrs['usercertificate;binary'] = None
                entry_attrs['userpkcs12;binary'] = None
            else:
                # switching between tls_client_auth and private_key_jwt
                # ensure the p12data is either already available or
                # provided with the options
                if 'userpkcs12;binary' not in old_attrs:
                    if 'userpkcs12' not in entry_attrs:
                        raise errors.RequirementError(
                            name='client-cert-p12-file')

        # Drop the auth method if it is client secret
        # as it is the default value
        if new_meth == 'client_secret':
            entry_attrs['ipaidpclientauthmethod'] = None
            if 'ipaidpclientauth' in obj_classes:
                entry_attrs['objectclass'].remove('ipaidpclientauth')
        self.obj.fill_usercertificate(entry_attrs)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.convert_usercertificate_post(entry_attrs, **options)
        return dn


@register()
class idp_find(LDAPSearch):
    __doc__ = _('Search for Identity Provider references.')
    msg_summary = ngettext(
        '%(count)d Identity Provider reference matched',
        '%(count)d Identity Provider references matched', 0
    )

    def get_options(self):
        # do not propose --client-id or --secret in ipa idp-find
        for option in super(idp_find, self).get_options():
            if option.name in ('ipaidpclientsecret', 'ipaidpclientid'):
                option = option.clone(flags={'no_option'})

            yield option


@register()
class idp_show(LDAPRetrieve):
    __doc__ = _('Display information about an Identity Provider '
                'reference.')

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.convert_usercertificate_post(entry_attrs, **options)
        return dn
