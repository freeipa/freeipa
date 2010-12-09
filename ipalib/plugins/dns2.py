# Authors:
#   Pavel Zuna <pzuna@redhat.com>
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
"""
Domain Name System (DNS)

Manage DNS zone and resource records.

EXAMPLES:

 Add new zone:
   ipa dnszone-add example.com --name_server nameserver.example.com
                               --admin_email admin@example.com

 edd second nameserver for example.com:
   ipa dnsrecord-add example.com @ --ns-rec nameserver2.example.com

 Delete previously added nameserver from example.com:
   ipa dnsrecord-del example.com @ --ns-rec nameserver2.example.com

 Add new A record for www.example.com: (random IP)
   ipa dnsrecord-add example.com www --a-rec 80.142.15.2

 Add new PTR record for www.example.com
   ipa dnsrecord 15.142.80.in-addr.arpa 2 --ptr-rec www.example.com.

 Show zone example.com:
   ipa dnszone-show example.com

 Find zone with "example" in it's domain name:
   ipa dnszone-find example

 Find records for resources with "www" in their name in zone example.com:
   ipa dnsrecord-find example.com www

 Find A records with value 10.10.0.1 in zone example.com
   ipa dnsrecord-find example.com --a-rec 10.10.0.1

 Show records for resource www in zone example.com
   ipa dnsrecord-show example.com www

 Delete zone example.com with all resource records:
   ipa dnszone-del example.com

 Resolve a host name to see if it exists (will add default IPA domain
 if one is not included):
   ipa dns-resolve www.example.com
   ipa dns-resolve www

"""

import netaddr
import time

from ipalib import api, errors, output
from ipalib import Command
from ipalib import Flag, Int, List, Str, StrEnum
from ipalib.plugins.baseldap import *
from ipalib import _, ngettext
from ipapython import dnsclient

# supported resource record types
_record_types = (
    u'A', u'AAAA', u'A6', u'AFSDB', u'APL', u'CERT', u'CNAME', u'DHCID', u'DLV',
    u'DNAME', u'DNSKEY', u'DS', u'HINFO', u'HIP', u'IPSECKEY', u'KEY', u'KX',
    u'LOC', u'MD', u'MINFO', u'MX', u'NAPTR', u'NS', u'NSEC', u'NSEC3',
    u'NSEC3PARAM', u'NXT', u'PTR', u'RRSIG', u'RP', u'SIG', u'SPF', u'SRV',
    u'SSHFP', u'TA', u'TKEY', u'TSIG', u'TXT',
)

# attributes derived from record types
_record_attributes = [str('%srecord' % t.lower()) for t in _record_types]

# supported DNS classes, IN = internet, rest is almost never used
_record_classes = (u'IN', u'CS', u'CH', u'HS')

# normalizer for admin email
def _rname_normalizer(value):
    value = value.replace('@', '.')
    if not value.endswith('.'):
        value += '.'
    return value

def _create_zone_serial(**kwargs):
    """Generate serial number for zones."""
    return int('%s01' % time.strftime('%Y%d%m'))

def _validate_ipaddr(ugettext, ipaddr):
    try:
        ip = netaddr.IPAddress(ipaddr)
    except netaddr.AddrFormatError:
        return u'invalid address format'
    return None

def _validate_ipnet(ugettext, ipnet):
    try:
        net = netaddr.IPNetwork(ipnet)
    except (UnboundLocalError, ValueError):
        return u'invalid format'
    return None

_record_validators = {
    u'A': _validate_ipaddr,
    u'AAAA': _validate_ipaddr,
    u'APL': _validate_ipnet,
}


class dnszone(LDAPObject):
    """
    DNS Zone, container for resource records.
    """
    container_dn = api.env.container_dns
    object_name = 'DNS zone'
    object_name_plural = 'DNS zones'
    object_class = ['top', 'idnsrecord', 'idnszone']
    default_attributes = [
        'idnsname', 'idnszoneactive', 'idnssoamname', 'idnssoarname',
        'idnssoaserial', 'idnssoarefresh', 'idnssoaretry', 'idnssoaexpire',
        'idnssoaminimum'
    ] + _record_attributes
    label = _('DNS')

    takes_params = (
        Str('idnsname',
            cli_name='name',
            label=_('Zone name'),
            doc=_('Zone name (FQDN)'),
            normalizer=lambda value: value.lower(),
            primary_key=True,
        ),
        Str('idnssoamname',
            cli_name='name_server',
            label=_('Authoritative name server'),
            doc=_('Authoritative name server'),
        ),
        Str('idnssoarname',
            cli_name='admin_email',
            label=_('Administrator e-mail address'),
            doc=_('Administrator e-mail address'),
            default_from=lambda idnsname: 'root.%s' % idnsname,
            normalizer=_rname_normalizer,
        ),
        Int('idnssoaserial?',
            cli_name='serial',
            label=_('SOA serial'),
            doc=_('SOA record serial number'),
            create_default=_create_zone_serial,
            autofill=True,
        ),
        Int('idnssoarefresh?',
            cli_name='refresh',
            label=_('SOA refresh'),
            doc=_('SOA record refresh time'),
            default=3600,
            autofill=True,
        ),
        Int('idnssoaretry?',
            cli_name='retry',
            label=_('SOA retry'),
            doc=_('SOA record retry time'),
            default=900,
            autofill=True,
        ),
        Int('idnssoaexpire?',
            cli_name='expire',
            label=_('SOA expire'),
            doc=_('SOA record expire time'),
            default=1209600,
            autofill=True,
        ),
        Int('idnssoaminimum?',
            cli_name='minimum',
            label=_('SOA minimum'),
            doc=_('SOA record minimum value'),
            default=3600,
            autofill=True,
        ),
        Int('idnssoamaximum?',
            cli_name='maximum',
            label=_('SOA maximum'),
            doc=_('SOA record maximum value'),
        ),
        Int('dnsttl?',
            cli_name='ttl',
            label=_('SOA time to live'),
            doc=_('SOA record time to live'),
        ),
        StrEnum('dnsclass?',
            cli_name='class',
            label=_('SOA class'),
            doc=_('SOA record class'),
            values=_record_classes,
        ),
        Str('idnsupdatepolicy?',
            cli_name='update_policy',
            label=_('BIND update policy'),
            doc=_('BIND update policy'),
        ),
    )

    def check_container_exists(self):
        try:
            self.backend.get_entry(self.container_dn, [])
        except errors.NotFound:
            raise errors.NotFound(reason=_('DNS is not configured'))

api.register(dnszone)


class dnszone_add(LDAPCreate):
    """
    Create new DNS zone (SOA record).
    """
    takes_options = (
        Flag('idnsallowdynupdate',
            cli_name='allow_dynupdate',
            label=_('Dynamic update'),
            doc=_('allow dynamic update?'),
            attribute=True,
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.obj.check_container_exists()
        entry_attrs['idnszoneactive'] = 'TRUE'
        entry_attrs['idnsallowdynupdate'] = str(
            entry_attrs.get('idnsallowdynupdate', False)
        ).upper()
        return dn

api.register(dnszone_add)


class dnszone_del(LDAPDelete):
    """
    Delete DNS zone (SOA record).
    """

api.register(dnszone_del)


class dnszone_mod(LDAPUpdate):
    """
    Modify DNS zone (SOA record).
    """
    takes_options = (
        Flag('idnsallowdynupdate',
            cli_name='allow_dynupdate',
            label=_('Dynamic update'),
            doc=_('allow dynamic update?'),
            attribute=True,
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, *keys, **options):
        entry_attrs['idnsallowdynupdate'] = str(
            entry_attrs.get('idnsallowdynupdate', False)
        ).upper()
        return dn

api.register(dnszone_mod)


class dnszone_find(LDAPSearch):
    """
    Search for DNS zones (SOA records).
    """

api.register(dnszone_find)


class dnszone_show(LDAPRetrieve):
    """
    Display information about a DNS zone (SOA record).
    """

api.register(dnszone_show)


class dnszone_disable(LDAPQuery):
    """
    Disable DNS Zone.
    """
    has_output = output.standard_value
    msg_summary = _('Disabled DNS zone "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        try:
            ldap.update_entry(dn, {'idnszoneactive': 'FALSE'})
        except errors.EmptyModlist:
            pass

        return dict(result=True, value=keys[-1])

api.register(dnszone_disable)


class dnszone_enable(LDAPQuery):
    """
    Enable DNS Zone.
    """
    has_output = output.standard_value
    msg_summary = _('Enabled DNS zone "%(value)s"')

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        try:
            ldap.update_entry(dn, {'idnszoneactive': 'TRUE'})
        except errors.EmptyModlist:
            pass

        return dict(result=True, value=keys[-1])

api.register(dnszone_enable)


class dnsrecord(LDAPObject):
    """
    DNS record.
    """
    parent_object = 'dnszone'
    container_dn = api.env.container_dns
    object_name = 'DNS resource record'
    object_name_plural = 'DNS resource records'
    object_class = ['top', 'idnsrecord']
    default_attributes = _record_attributes + ['idnsname']

    label = _('DNS resource record')

    takes_params = (
        Str('idnsname',
            cli_name='name',
            label=_('Record name'),
            doc=_('Record name'),
            primary_key=True,
        ),
        Int('dnsttl?',
            cli_name='ttl',
            label=_('Time to live'),
            doc=_('Time to live'),
        ),
        StrEnum('dnsclass?',
            cli_name='class',
            label=_('Class'),
            doc=_('DNS class'),
            values=_record_classes,
        ),
    )

    def is_pkey_zone_record(*keys):
        idnsname = keys[-1]
        if idnsname == '@' or idnsname == ('%s.' % keys[-2]):
            return True
        return False

    def get_dn(self, *keys, **options):
        if self.is_pkey_zone_record(*keys):
            return self.api.Object[self.parent_object].get_dn(*keys[:-1], **options)
        return super(dnsrecord, self).get_dn(*keys, **options)

api.register(dnsrecord)


class dnsrecord_cmd_w_record_options(Command):
    """
    Base class for DNS record commands with record options.
    """
    record_param_doc = 'comma-separated list of %s records'

    def get_record_options(self):
        for t in _record_types:
            t = t.encode('utf-8')
            doc = self.record_param_doc % t
            validator = _record_validators.get(t)
            if validator:
                yield List(
                    '%srecord?' % t.lower(), validator,
                    cli_name='%s_rec' % t.lower(), doc=doc,
                    label='%s record' % t, attribute=True
                )
            else:
                yield List(
                    '%srecord?' % t.lower(), cli_name='%s_rec' % t.lower(),
                    doc=doc, label='%s record' % t, attribute=True
                )

    def record_options_2_entry(self, **options):
        return dict((t, options.get(t, [])) for t in _record_attributes)


class dnsrecord_mod_record(LDAPQuery, dnsrecord_cmd_w_record_options):
    """
    Base class for adding/removing records from DNS resource entries.
    """
    has_output = output.standard_entry

    def get_options(self):
        for option in super(dnsrecord_mod_record, self).get_options():
            yield option
        for option in self.get_record_options():
            yield option

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)

        entry_attrs = self.record_options_2_entry(**options)

        try:
            (dn, old_entry_attrs) = ldap.get_entry(dn, entry_attrs.keys())
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        self.update_old_entry_callback(entry_attrs, old_entry_attrs)

        try:
            ldap.update_entry(dn, old_entry_attrs)
        except errors.EmptyModlist:
            pass

        if options.get('all', False):
            attrs_list = ['*']
        else:
            attrs_list = list(
                set(self.obj.default_attributes + entry_attrs.keys())
            )

        try:
            (dn, entry_attrs) = ldap.get_entry(dn, attrs_list)
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        if self.obj.is_pkey_zone_record(*keys):
            entry_attrs[self.obj.primary_key.name] = [u'@']

        self.post_callback(keys, entry_attrs)

        return dict(result=entry_attrs, value=keys[-1])

    def update_old_entry_callback(self, entry_attrs, old_entry_attrs):
        pass

    def post_callback(self, keys, entry_attrs):
        pass


class dnsrecord_add_record(dnsrecord_mod_record):
    """
    Add records to DNS resource.
    """
    INTERNAL = True

    def update_old_entry_callback(self, entry_attrs, old_entry_attrs):
        for (a, v) in entry_attrs.iteritems():
            if not isinstance(v, (list, tuple)):
                v = [v]
            old_entry_attrs.setdefault(a, [])
            old_entry_attrs[a] += v

api.register(dnsrecord_add_record)


class dnsrecord_add(LDAPCreate, dnsrecord_cmd_w_record_options):
    """
    Add new DNS resource record.
    """
    def get_options(self):
        for option in super(dnsrecord_add, self).get_options():
            yield option
        for option in self.get_record_options():
            yield option

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        if call_func.func_name == 'add_entry':
            if isinstance(exc, errors.DuplicateEntry):
                self.obj.methods.add_record(
                    *keys, **self.record_options_2_entry(**options)
                )
                return
        raise exc

api.register(dnsrecord_add)


class dnsrecord_delentry(LDAPDelete):
    """
    Delete DNS record entry.
    """
    INTERNAL = True

api.register(dnsrecord_delentry)


class dnsrecord_del(dnsrecord_mod_record):
    """
    Delete DNS resource record.
    """
    def update_old_entry_callback(self, entry_attrs, old_entry_attrs):
        for (a, v) in entry_attrs.iteritems():
            if not isinstance(v, (list, tuple)):
                v = [v]
            for val in v:
                try:
                    old_entry_attrs[a].remove(val)
                except (KeyError, ValueError):
                    pass

    def post_callback(self, keys, entry_attrs):
        if not self.obj.is_pkey_zone_record(*keys):
            for a in _record_attributes:
                if a in entry_attrs and entry_attrs[a]:
                    return
            self.obj.methods.delentry(*keys)

api.register(dnsrecord_del)


class dnsrecord_show(LDAPRetrieve, dnsrecord_cmd_w_record_options):
    """
    Display DNS resource.
    """
    def has_output_params(self):
        for option in self.get_record_options():
            yield option

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if self.obj.is_pkey_zone_record(*keys):
            entry_attrs[self.obj.primary_key.name] = [u'@']
        return dn

api.register(dnsrecord_show)


class dnsrecord_find(LDAPSearch, dnsrecord_cmd_w_record_options):
    """
    Search for DNS resources.
    """
    def get_options(self):
        for option in super(dnsrecord_find, self).get_options():
            yield option
        for option in self.get_record_options():
            yield option.clone(query=True)

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
        record_attrs = self.record_options_2_entry(**options)
        record_filter = ldap.make_filter(record_attrs, rules=ldap.MATCH_ALL)
        filter = ldap.combine_filters(
            (filter, record_filter), rules=ldap.MATCH_ALL
        )
        return (filter, base_dn, ldap.SCOPE_SUBTREE)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if entries:
            zone_obj = self.api.Object[self.obj.parent_object]
            zone_dn = zone_obj.get_dn(args[0])
            if entries[0][0] == zone_dn:
                entries[0][1][zone_obj.primary_key.name] = [u'@']

api.register(dnsrecord_find)

