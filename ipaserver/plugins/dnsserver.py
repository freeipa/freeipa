#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

from ipalib import (
    _,
    ngettext,
    api,
    DNSNameParam,
    Str,
    StrEnum,
    errors,
)
from ipalib.frontend import Local
from ipalib.plugable import Registry
from ipalib.util import (
    normalize_hostname,
    hostname_validator,
    validate_bind_forwarder,
)
from ipaserver.plugins.baseldap import (
    LDAPObject,
    LDAPRetrieve,
    LDAPUpdate,
    LDAPSearch,
    LDAPCreate,
    LDAPDelete,
)
from .dns import dns_container_exists
from ipapython.dn import DN


__doc__ = _("""
DNS server configuration
""") + _("""
Manipulate DNS server configuration
""") + _("""
EXAMPLES:
""") + _("""
  Show configuration of a specific DNS server:
    ipa dnsserver-show
""") + _("""
  Update configuration of a specific DNS server:
    ipa dnsserver-mod
""")


register = Registry()

topic = None

dnsserver_object_class = ['top', 'idnsServerConfigObject']

@register()
class dnsserver(LDAPObject):
    """
    DNS Servers
    """
    container_dn = api.env.container_dnsservers
    object_name = _('DNS server')
    object_name_plural = _('DNS servers')
    object_class = dnsserver_object_class
    default_attributes = [
        'idnsServerId',
        'idnsSOAmName',
        'idnsForwarders',
        'idnsForwardPolicy',
    ]
    label = _('DNS Servers')
    label_singular = _('DNS Server')

    permission_filter_objectclasses = ['idnsServerConfigObject']

    managed_permissions = {
        'System: Read DNS Servers Configuration': {
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'objectclass',
                'idnsServerId',
                'idnsSOAmName',
                'idnsForwarders',
                'idnsForwardPolicy',
                'idnsSubstitutionVariable',
            },
            'ipapermlocation': api.env.basedn,
            'default_privileges': {
                'DNS Servers',
                'DNS Administrators'
            },
        },
        'System: Modify DNS Servers Configuration': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'idnsSOAmName',
                'idnsForwarders',
                'idnsForwardPolicy',
                'idnsSubstitutionVariable',
            },
            'ipapermlocation': api.env.basedn,
            'default_privileges': {'DNS Administrators'},
        },
    }

    takes_params = (
        Str(
            'idnsserverid',
            hostname_validator,
            cli_name='hostname',
            primary_key=True,
            label=_('Server name'),
            doc=_('DNS Server name'),
            normalizer=normalize_hostname,
        ),
        DNSNameParam(
            'idnssoamname?',
            cli_name='soa_mname_override',
            label=_('SOA mname override'),
            doc=_('SOA mname (authoritative server) override'),
        ),
        Str(
            'idnsforwarders*',
            validate_bind_forwarder,
            cli_name='forwarder',
            label=_('Forwarders'),
            doc=_(
                'Per-server forwarders. A custom port can be specified '
                'for each forwarder using a standard format '
                '"IP_ADDRESS port PORT"'
            ),
        ),
        StrEnum(
            'idnsforwardpolicy?',
            cli_name='forward_policy',
            label=_('Forward policy'),
            doc=_(
                'Per-server conditional forwarding policy. Set to "none" to '
                'disable forwarding to global forwarder for this zone. In '
                'that case, conditional zone forwarders are disregarded.'
            ),
            values=(u'only', u'first', u'none'),
        ),
    )

    def get_dn(self, *keys, **options):
        if not dns_container_exists(self.api.Backend.ldap2):
            raise errors.NotFound(reason=_('DNS is not configured'))
        return super(dnsserver, self).get_dn(*keys, **options)


@register()
class dnsserver_mod(LDAPUpdate):
    __doc__ = _('Modify DNS server configuration')
    topic = 'dns'

    msg_summary = _('Modified DNS server "%(value)s"')


@register()
class dnsserver_find(LDAPSearch):
    __doc__ = _('Search for DNS servers.')
    topic = 'dns'

    msg_summary = ngettext(
        '%(count)d DNS server matched',
        '%(count)d DNS servers matched', 0
    )

    def pre_callback(self, ldap, filters, attrs_list,
                     base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)

        if not dns_container_exists(self.api.Backend.ldap2):
            raise errors.InvocationError(
                format=_('IPA DNS Server is not installed'))

        return (filters, base_dn, scope)


@register()
class dnsserver_show(LDAPRetrieve):
    __doc__=_('Display configuration of a DNS server.')
    topic = 'dns'


@register()
class dnsserver_add(LDAPCreate, Local):
    """
    Only for internal use, this is not part of public API on purpose.
    Be careful in future this will be transformed to public API call
    """
    __doc__ = _('Add a new DNS server.')
    topic = 'dns'

    msg_summary = _('Added new DNS server "%(value)s"')


@register()
class dnsserver_del(LDAPDelete, Local):
    """
    Only for internal use, this is not part of public API on purpose.
    Be careful in future this will be transformed to public API call
    """
    __doc__ = _('Delete a DNS server')
    topic = 'dns'

    msg_summary = _('Deleted DNS server "%(value)s"')
