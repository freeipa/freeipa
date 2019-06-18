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
Test the `ipaserver/plugins/dns.py` module.
"""

import nose
from ipalib import api, errors
from ipalib.util import normalize_zone
from ipapython.dnsutil import DNSName
from ipapython.dn import DN
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import Declarative, fuzzy_digits
import pytest

try:
    from ipaserver.plugins.ldap2 import ldap2
except ImportError:
    have_ldap2 = False
else:
    have_ldap2 = True

_dns_zone_record = DNSName(u'@')

# default value of idnssoamname is local DNS server
self_server_ns = normalize_zone(api.env.host)
self_server_ns_dnsname = DNSName(self_server_ns)

zone1 = u'dnszone.test'
zone1_dnsname = DNSName(zone1)
zone1_absolute = u'%s.' % zone1
zone1_absolute_dnsname = DNSName(zone1_absolute)
zone1_ip = u'172.16.29.111'
zone1_dn = DN(('idnsname',zone1_absolute), api.env.container_dns, api.env.basedn)
zone1_ns = u'ns1.%s' % zone1_absolute
zone1_ns_dnsname = DNSName(zone1_ns)
zone1_ns_dn = DN(('idnsname','ns1'), zone1_dn)
zone1_self_server_ns_dn = DN(('idnsname',self_server_ns), zone1_dn)
zone1_rname = u'root.%s' % zone1_absolute
zone1_rname_dnsname = DNSName(zone1_rname)
zone1_permission = u'Manage DNS zone %s' % zone1_absolute
zone1_permission_dn = DN(('cn',zone1_permission),
                            api.env.container_permission,api.env.basedn)
zone1_txtrec_dn = DN(('idnsname', '_kerberos'), zone1_dn)

zone1_sub = u'sub.%s' % zone1_absolute
zone1_sub_dnsname = DNSName(zone1_sub)
zone1_sub_dn = DN(('idnsname', zone1_sub),
                  api.env.container_dns, api.env.basedn)

zone1_sub_fw = u'fw.%s' % zone1_sub
zone1_sub_fw_dnsname = DNSName(zone1_sub_fw)
zone1_sub_fw_dn = DN(('idnsname', zone1_sub_fw),
                     api.env.container_dns, api.env.basedn)

zone1_sub2_fw = u'fw.sub2.%s' % zone1_sub
zone1_sub2_fw_dnsname = DNSName(zone1_sub2_fw)
zone1_sub2_fw_dn = DN(('idnsname', zone1_sub2_fw),
                      api.env.container_dns, api.env.basedn)

zone2 = u'zone2.test'
zone2_dnsname = DNSName(zone2)
zone2_absolute = u'%s.' % zone2
zone2_absolute_dnsname = DNSName(zone2_absolute)
zone2_dn = DN(('idnsname', zone2_absolute), api.env.container_dns, api.env.basedn)
zone2_ns = u'ns1.%s' % zone2_absolute
zone2_ns_dnsname = DNSName(zone2_ns)
zone2_rname = u'root.%s' % zone2_absolute
zone2_rname_dnsname = DNSName(zone2_rname)

zone3 = u'zone3.test'
zone3_dnsname = DNSName(zone3)
zone3_absolute = u'%s.' % zone3
zone3_absolute_dnsname = DNSName(zone3_absolute)
zone3_ip = u'172.16.70.1'
zone3_ip2 = u'172.16.70.129'
zone3_dn = DN(('idnsname', zone3_absolute), api.env.container_dns, api.env.basedn)
zone3_ns = u'ns1.%s' % zone3_absolute
zone3_ns_dnsname = DNSName(zone3_ns)
zone3_ns2 = u'ns2.%s' % zone3_absolute
zone3_ns2_dnsname = DNSName(zone3_ns2)
zone3_rname = u'root.%s' % zone3_absolute
zone3_rname_dnsname = DNSName(zone3_rname)

zone3_ns2_arec = u'ns2'
zone3_ns2_arec_dnsname = DNSName(zone3_ns2_arec)
zone3_ns2_arec_dn = DN(('idnsname',zone3_ns2_arec), zone3_dn)
zone3_ns2_arec_absolute = u'%s.%s' % (zone3_ns2_arec, zone3_absolute)

zone4_upper = u'ZONE4.test'
zone4 = u'zone4.test.'
zone4_dnsname = DNSName(zone4)
zone4_dn = DN(('idnsname', zone4), api.env.container_dns, api.env.basedn)
zone4_ns = u'ns1.%s' % zone4
zone4_ns_dnsname = DNSName(zone4_ns)
zone4_rname = u'root.%s' % zone4
zone4_rname_dnsname = DNSName(zone4_rname)

zone5 = u'zone--5.test.'
zone5_dnsname = DNSName(zone5)
zone5_dn = DN(('idnsname', zone5), api.env.container_dns, api.env.basedn)
zone5_ns = u'ns1.%s' % zone5
zone5_ns_dnsname = DNSName(zone5_ns)
zone5_rname = u'root.%s' % zone5
zone5_rname_dnsname = DNSName(zone5_rname)

zone6b = u'zone6b.test'
zone6b_absolute = u'%s.' % zone6b
zone6b_dnsname = DNSName(zone6b)
zone6b_absolute_dnsname = DNSName(zone6b_absolute)
zone6b_dn = DN(('idnsname', zone6b), api.env.container_dns, api.env.basedn)
zone6b_absolute_dn = DN(('idnsname', zone6b_absolute),
                        api.env.container_dns, api.env.basedn)
zone6b_rname = u'hostmaster'
zone6b_rname_dnsname = DNSName(zone6b_rname)
zone6b_ip = u'172.16.70.1'
zone6b_ns_arec = u'ns'
zone6b_ns = u'%s.%s' % (zone6b_ns_arec, zone6b_absolute)
zone6b_ns_arec_dnsname = DNSName(zone6b_ns_arec)
zone6b_ns_arec_dn = DN(('idnsname', zone6b_ns_arec), zone6b_dn)
zone6b_ns_dnsname = DNSName(zone6b_ns)
zone6b_absolute_arec_dn = DN(('idnsname', zone6b_ns_arec), zone6b_absolute_dn)

zone6 = u'zone6.test'
zone6_invalid = u'invalid-zone.zone6..test'
zone6_absolute = u'%s.' % zone6
zone6_dnsname = DNSName(zone6)
zone6_absolute_dnsname = DNSName(zone6_absolute)
zone6_dn = DN(('idnsname', zone6), api.env.container_dns, api.env.basedn)
zone6_absolute_dn = DN(('idnsname', zone6_absolute),
                       api.env.container_dns, api.env.basedn)
zone6_ns_relative = u'ns1'
zone6_absolute_arec_dn = DN(('idnsname', zone6_ns_relative), zone6_absolute_dn)
zone6_ns = u'%s.%s' % (zone6_ns_relative, zone6_absolute)
zone6_ns_relative_dnsname = DNSName(zone6_ns_relative)
zone6_ns_dnsname = DNSName(zone6_ns)
zone6_ns_arec_dnsname = DNSName(zone6_ns_relative)
zone6_ns_invalid_dnsname = u'invalid name server! ..%s' % zone6_absolute
zone6_rname = u'root.%s' % zone6_absolute
zone6_rname_dnsname = DNSName(zone6_rname)
zone6_rname_default = u'hostmaster'
zone6_rname_default_dnsname = DNSName(zone6_rname_default)
zone6_rname_relative_dnsname = DNSName(u'root')
zone6_rname_absolute_dnsname = DNSName(u'root.%s' % zone6_absolute)
zone6_rname_invalid_dnsname = u'invalid ! @ ! .. root..%s' % zone6_absolute
zone6_unresolvable_ns_relative = u'unresolvable'
zone6_unresolvable_ns = u'%s.%s' % (zone6_unresolvable_ns_relative,
                                    zone6_absolute)
zone6_unresolvable_ns_dnsname = DNSName(zone6_unresolvable_ns)
zone6_unresolvable_ns_relative_dnsname = DNSName(zone6_unresolvable_ns_relative)

revzone1 = u'31.16.172.in-addr.arpa.'
revzone1_dnsname = DNSName(revzone1)
revzone1_ip = u'172.16.31.0'
revzone1_ipprefix = u'172.16.31.'
revzone1_dn = DN(('idnsname', revzone1), api.env.container_dns, api.env.basedn)

revzone2 = u'18.198.in-addr.arpa.'
revzone2_dnsname = DNSName(revzone2)
revzone2_ip = u'198.18.0.30/16'
revzone2_dn = DN(('idnsname',revzone2), api.env.container_dns, api.env.basedn)

revzone3_classless1 = u'70.16.172.in-addr.arpa.'
revzone3_classless1_dnsname = DNSName(revzone3_classless1)
revzone3_classless1_ip = u'172.16.70.0'
revzone3_classless1_ipprefix = u'172.16.70.'
revzone3_classless1_dn = DN(('idnsname', revzone3_classless1), api.env.container_dns, api.env.basedn)

revzone3_classless2 = u'128/25.70.16.172.in-addr.arpa.'
revzone3_classless2_dnsname = DNSName(revzone3_classless2)
revzone3_classless2_ip = u'172.16.70.128'
revzone3_classless2_ipprefix = u'172.16.70.'
revzone3_classless2_dn = DN(('idnsname', revzone3_classless2), api.env.container_dns, api.env.basedn)

revzone3_classless2_permission = u'Manage DNS zone %s' % revzone3_classless2
revzone3_classless2_permission_dn = DN(('cn', revzone3_classless2_permission),
                           api.env.container_permission, api.env.basedn)

name1 = u'testdnsres'
name1_dnsname = DNSName(name1)
name1_dn = DN(('idnsname',name1), zone1_dn)

name_ns = u'testdnsres-ns'
name_ns_dnsname = DNSName(name_ns)
name_ns_dn = DN(('idnsname',name_ns), zone1_dn)
name_ns_renamed = u'testdnsres-ns-renamed'
name_ns_renamed_dnsname = DNSName(name_ns_renamed)

revname1 = u'80'
revname1_dnsname = DNSName(revname1)
revname1_ip = revzone1_ipprefix + revname1
revname1_dn = DN(('idnsname',revname1), revzone1_dn)

revname2 = u'81'
revname2_dnsname = DNSName(revname2)
revname2_ip = revzone1_ipprefix + revname2
revname2_dn = DN(('idnsname',revname2), revzone1_dn)

cname = u'testcnamerec'
cname_dnsname = DNSName(cname)
cname_dn = DN(('idnsname',cname), zone1_dn)

dname = u'testdns-dname'
dname_dnsname = DNSName(dname)
dname_dn = DN(('idnsname',dname), zone1_dn)

dlv = u'dlv'
dlv_dnsname = DNSName(dlv)
dlv_dn = DN(('idnsname', dlv), zone1_dn)

dlvrec = u'60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118'

ds = u'ds'
ds_dnsname = DNSName(ds)
ds_dn = DN(('idnsname', ds), zone1_dn)

ds_rec = u'0 0 0 00'

tlsa = u'tlsa'
tlsa_dnsname = DNSName(tlsa)
tlsa_dn = DN(('idnsname', tlsa), zone1_dn)

tlsarec_err1 = u'300 0 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971'
tlsarec_err2 = u'0 300 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971'
tlsarec_err3 = u'0 0 300 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971'
tlsarec_ok = u'0 0 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971'

wildcard_rec1 = u'*.test'
wildcard_rec1_dnsname = DNSName(wildcard_rec1)
wildcard_rec1_dn = DN(('idnsname',wildcard_rec1), zone1_dn)
wildcard_rec1_addr = u'172.16.15.55'
wildcard_rec1_test1 = u'a.test.%s' % zone1_absolute
wildcard_rec1_test2 = u'b.test.%s' % zone1_absolute

nsrev = u'128/28'
nsrev_dnsname = DNSName(nsrev)
nsrev_dn = DN(('idnsname',nsrev), revzone3_classless1_dn)

cnamerev = u'129'
cnamerev_dnsname = DNSName(cnamerev)
cnamerev_dn = DN(('idnsname',cnamerev), revzone3_classless1_dn)
cnamerev_hostname = u'129.128/25.70.16.172.in-addr.arpa.'

ptr_revzone3 = u'129'
ptr_revzone3_dnsname = DNSName(ptr_revzone3)
ptr_revzone3_dn = DN(('idnsname',cnamerev), revzone3_classless2_dn)
ptr_revzone3_hostname = zone3_ns2

relnxname = u'does-not-exist-test'
absnxname = u'does.not.exist.test.'

arec1 = u'172.16.29.111'
arec2 = u'172.31.254.222'
arec3 = u'172.16.250.123'
aaaarec1 = u'ff02::1'

fwd_ip = u'172.16.31.80'
allowtransfer_tofwd = u'%s;' % fwd_ip

# 198.18.0.0/15 testing range reserved by RFC2544
allowquery_restricted_in = u'!198.18.2.0/24;any;'
allowquery_restricted_out = u'!198.18.2.0/24;any;'

idnzone1 = u'\u010d.test.'
idnzone1_punycoded = u'xn--bea.test.'
idnzone1_dnsname = DNSName(idnzone1)
idnzone1_dn = DN(('idnsname',idnzone1_punycoded), api.env.container_dns, api.env.basedn)
idnzone1_mname = u'ns1.%s' % idnzone1
idnzone1_mname_punycoded = u'ns1.%s' % idnzone1_punycoded
idnzone1_mname_dnsname = DNSName(idnzone1_mname)
idnzone1_mname_dn = DN(('idnsname','ns1'), idnzone1_dn)
idnzone1_rname = u'root.%s' % idnzone1
idnzone1_rname_punycoded = u'root.%s' % idnzone1_punycoded
idnzone1_rname_dnsname = DNSName(idnzone1_rname)
idnzone1_ip = u'172.16.11.1'

revidnzone1 = u'15.16.172.in-addr.arpa.'
revidnzone1_dnsname = DNSName(revidnzone1)
revidnzone1_ip = u'172.16.15.0/24'
revidnzone1_dn = DN(('idnsname', revidnzone1), api.env.container_dns, api.env.basedn)
idnzone1_permission = u'Manage DNS zone %s' % idnzone1
idnzone1_permission_dn = DN(('cn',idnzone1_permission),
                            api.env.container_permission,api.env.basedn)
idnres1 = u'sk\xfa\u0161ka'
idnres1_punycoded = u'xn--skka-rra23d'
idnres1_dnsname = DNSName(idnres1)
idnres1_dn = DN(('idnsname',idnres1_punycoded), idnzone1_dn)

idnrescname1 = u'\u0161\u0161'
idnrescname1_punycoded = u'xn--pgaa'
idnrescname1_dnsname = DNSName(idnrescname1)
idnrescname1_dn = DN(('idnsname',idnrescname1_punycoded), idnzone1_dn)

idnresdname1 = u'\xe1\xe1'
idnresdname1_punycoded = u'xn--1caa'
idnresdname1_dnsname = DNSName(idnresdname1)
idnresdname1_dn = DN(('idnsname',idnresdname1_punycoded), idnzone1_dn)

idndomain1 = u'\u010d\u010d\u010d.test'
idndomain1_punycoded = u'xn--beaaa.test'
idndomain1_dnsname = DNSName(idndomain1)

dnsafsdbres1 = u'sk\xfa\u0161ka-c'
dnsafsdbres1_punycoded = u'xn--skka-c-qya83f'
dnsafsdbres1_dnsname = DNSName(dnsafsdbres1)
dnsafsdbres1_dn = DN(('idnsname',dnsafsdbres1_punycoded), idnzone1_dn)

idnzone1_txtrec_dn = DN(('idnsname', '_kerberos'), idnzone1_dn)

fwzone1 = u'fwzone1.test.'
fwzone1_dnsname = DNSName(fwzone1)
fwzone1_dn = DN(('idnsname', fwzone1), api.env.container_dns, api.env.basedn)

fwzone1_permission = u'Manage DNS zone %s' % fwzone1
fwzone1_permission_dn = DN(('cn', fwzone1_permission),
                           api.env.container_permission, api.env.basedn)

fwzone2 = u'fwzone2.test.'
fwzone2_dnsname = DNSName(fwzone2)
fwzone2_dn = DN(('idnsname', fwzone2), api.env.container_dns, api.env.basedn)

fwzone3 = u'fwzone3.test.'
fwzone3_dnsname = DNSName(fwzone3)
fwzone3_dn = DN(('idnsname', fwzone3), api.env.container_dns, api.env.basedn)

fwzone_search_all_name = u'fwzone'

forwarder1 = u'172.16.15.1'
forwarder2 = u'172.16.15.2'
forwarder3 = u'172.16.15.3'
forwarder4 = u'172.16.15.4'

zone_findtest = u'.find.test.'

zone_findtest_master = u'master.find.test.'
zone_findtest_master_dnsname = DNSName(zone_findtest_master)
zone_findtest_master_dn = DN(('idnsname', zone_findtest_master),
                             api.env.container_dns, api.env.basedn)
zone_findtest_master_ns = u'ns1.%s' % zone_findtest_master
zone_findtest_master_ns_dnsname = DNSName(zone_findtest_master_ns)
zone_findtest_master_rname = u'root.%s' % zone_findtest_master
zone_findtest_master_rname_dnsname = DNSName(zone_findtest_master_rname)

zone_findtest_forward = u'forward.find.test.'
zone_findtest_forward_dnsname = DNSName(zone_findtest_forward)
zone_findtest_forward_dn = DN(('idnsname', zone_findtest_forward), api.env.container_dns, api.env.basedn)

zone_fw_wildcard = u'*.wildcardforwardzone.test.'

nonexistent_fwzone = u'non-existent.fwzone.test.'
nonexistent_fwzone_dnsname = DNSName(nonexistent_fwzone)

zone_root = u'.'
zone_root_dnsname = DNSName(zone_root)
zone_root_ip = u'172.16.29.222'
zone_root_dn = DN(('idnsname', zone_root),
                  api.env.container_dns, api.env.basedn)
zone_root_ns = u'ns'
zone_root_ns_dnsname = DNSName(zone_root_ns)
zone_root_ns_dn = DN(('idnsname', zone_root_ns), zone_root_dn)
zone_root_rname = u'root.example.com.'
zone_root_rname_dnsname = DNSName(zone_root_rname)
zone_root_permission = u'Manage DNS zone %s' % zone_root
zone_root_permission_dn = DN(('cn', zone_root_permission),
                             api.env.container_permission, api.env.basedn)


def _get_nameservers_ldap(conn):
    base_dn = DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)
    ldap_filter = '(&(objectClass=ipaConfigObject)(cn=DNS))'
    dns_masters = []

    try:
        entries = conn.find_entries(filter=ldap_filter, base_dn=base_dn)[0]

        for entry in entries:
            try:
                master = entry.dn[1]['cn']
                dns_masters.append(master)
            except (IndexError, KeyError):
                pass
    except errors.NotFound:
        return []

    return dns_masters


def get_nameservers():
        ldap = ldap2(api)
        ldap.connect()
        nameservers = [normalize_zone(x) for x in _get_nameservers_ldap(ldap)]
        return nameservers

# FIXME to avoid this hack with nameservers, tests should be functional
nameservers = []
# get list of nameservers from LDAP
get_nameservers_error = None
if have_ldap2:
    try:
        nameservers = get_nameservers()
    except Exception as e:
        get_nameservers_error = e
    else:
        if not nameservers:
            # if DNS is installed there must be at least one IPA DNS server
            get_nameservers_error = "No DNS servers found in LDAP"


@pytest.mark.tier1
class test_dns(Declarative):

    @classmethod
    def setup_class(cls):
        super(test_dns, cls).setup_class()

        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()

        if not have_ldap2:
            raise nose.SkipTest('server plugin not available')

        if get_nameservers_error is not None:
            raise nose.SkipTest('unable to get list of nameservers (%s)' % get_nameservers_error)

        try:
           api.Command['dnszone_add'](zone1,
               idnssoarname = zone1_rname,
           )
           api.Command['dnszone_del'](zone1)
        except errors.NotFound:
            raise nose.SkipTest('DNS is not configured')
        except errors.DuplicateEntry:
            pass

    cleanup_commands = [
        ('dnszone_del', [zone1, zone2, zone3, zone4, zone5, revzone1, revzone2,
                         revzone3_classless1, revzone3_classless2,
                         idnzone1, revidnzone1],
            {'continue': True}),
        ('dnsconfig_mod', [], {'idnsforwarders' : None,
                               'idnsforwardpolicy' : None,
                               'idnsallowsyncptr' : None,
                               }),
        ('permission_del', [zone1_permission, idnzone1_permission,
                            revzone3_classless2_permission], {'force': True}
        ),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent zone %r' % zone1,
            command=('dnszone_show', [zone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % zone1_absolute),
        ),

        dict(
            desc='Try to retrieve non-existent IDN zone %r' % idnzone1,
            command=('dnszone_show', [idnzone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % idnzone1),
        ),

        dict(
            desc='Try to update non-existent zone %r' % zone1,
            command=('dnszone_mod', [zone1], {'idnssoaminimum': 3500}),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % zone1_absolute),
        ),


        dict(
            desc='Try to delete non-existent zone %r' % zone1,
            command=('dnszone_del', [zone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % zone1_absolute),
        ),


        dict(
            desc='Create zone %r' % zone1,
            command=(
                'dnszone_add', [zone1], {
                    'idnssoarname': zone1_rname,
                }
            ),
            expected={
                'value': zone1_absolute_dnsname,
                'summary': None,
                'result': {
                    'dn': zone1_dn,
                    'idnsname': [zone1_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-self * A; '
                                         u'grant %(realm)s krb5-self * AAAA; '
                                         u'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(
            desc='Try to create duplicate zone %r' % zone1,
            command=(
                'dnszone_add', [zone1], {
                    'idnssoarname': zone1_rname,
                }
            ),
            expected=errors.DuplicateEntry(
                message=u'DNS zone with name "%s" already exists' % zone1_absolute),
        ),

        dict(
            desc='Try to create a zone with nonexistent NS entry',
            command=(
                'dnszone_add', [zone2], {
                    'idnssoamname': zone2_ns,
                    'idnssoarname': zone2_rname,
                }
            ),
            expected=errors.NotFound(reason='Nameserver \'%s\' does not have a corresponding A/AAAA record' % (zone2_ns)),
        ),

        dict(
            desc='Create a zone with nonexistent NS entry with --force',
            command=(
                'dnszone_add', [zone2], {
                    'idnssoamname': zone2_ns,
                    'idnssoarname': zone2_rname,
                    'force': True,
                }
            ),
            expected={
                'value': zone2_absolute_dnsname,
                'summary': None,
                'result': {
                    'dn': zone2_dn,
                    'idnsname': [zone2_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [zone2_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone2_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-self * A; '
                                         u'grant %(realm)s krb5-self * AAAA; '
                                         u'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
                'messages': (
                    {'message': u"Semantic of setting Authoritative nameserver "
                                u"was changed. "
                                u"It is used only for setting the SOA MNAME "
                                u"attribute.\n"
                                u"NS record(s) can be edited in zone "
                                u"apex - '@'. ",
                     'code': 13005,
                     'type': u'warning',
                     'name': u'OptionSemanticChangedWarning',
                     'data': {
                        'current_behavior': u"It is used only for setting the "
                                            u"SOA MNAME attribute.",
                        'hint': u"NS record(s) can be edited in zone apex - "
                                u"'@'. ",
                        'label': u"setting Authoritative nameserver"
                     }},
                )
            },
        ),

        dict(
            desc='Try to remove value of "idnssomrname" attribute using dnszone-mod --name-server=',
            command=(
                'dnszone_mod', [zone2], {
                    'idnssoamname': None,
                }
            ),
            expected=errors.ValidationError(name='name_server', error=u"is required"),
        ),

        dict(
            desc='Create a zone with upper case name',
            command=(
                'dnszone_add', [zone4_upper], {
                    'idnssoarname': zone4_rname,
                }
            ),
            expected={
                'value': zone4_dnsname,
                'summary': None,
                'result': {
                    'dn': zone4_dn,
                    'idnsname': [zone4_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone4_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-self * A; '
                                         u'grant %(realm)s krb5-self * AAAA; '
                                         u'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(  # https://fedorahosted.org/freeipa/ticket/4268
            desc='Create a zone with consecutive dash characters',
            command=(
                'dnszone_add', [zone5], {
                    'idnssoarname': zone5_rname,
                }
            ),
            expected={
                'value': zone5_dnsname,
                'summary': None,
                'result': {
                    'dn': zone5_dn,
                    'idnsname': [zone5_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone5_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-self * A; '
                                         u'grant %(realm)s krb5-self * AAAA; '
                                         u'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(
            desc='Retrieve zone %r' % zone1,
            command=('dnszone_show', [zone1], {}),
            expected={
                'value': zone1_absolute_dnsname,
                'summary': None,
                'result': {
                    'dn': zone1_dn,
                    'idnsname': [zone1_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
            },
        ),


        dict(
            desc='Update zone %r' % zone1,
            command=('dnszone_mod', [zone1], {'idnssoarefresh': 5478}),
            expected={
                'value': zone1_absolute_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [zone1_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
            },
        ),

        dict(
            desc='Try to add invalid NSEC3PARAM record to zone %s' % (zone1),
            command=('dnszone_mod', [zone1], {'nsec3paramrecord': u'0 0 0 0 X'}),
            expected=errors.ValidationError(name="nsec3param_rec",
                        error=(u'expected format: <0-255> <0-255> <0-65535> '
                               u'even-length_hexadecimal_digits_or_hyphen')
            )
        ),


        dict(
            desc='Try to add invalid NSEC3PARAM record to zone %s' % (zone1),
            command=('dnszone_mod', [zone1], {'nsec3paramrecord': u'0 0 0 X'}),
            expected=errors.ValidationError(name="nsec3param_rec",
                        error=(u'expected format: <0-255> <0-255> <0-65535> '
                               u'even-length_hexadecimal_digits_or_hyphen')
            )
        ),


        dict(
            desc='Try to add invalid NSEC3PARAM record to zone %s' % (zone1),
            command=('dnszone_mod', [zone1], {'nsec3paramrecord': u'333 0 0 -'}),
            expected=errors.ValidationError(name="nsec3param_rec",
                        error=u'algorithm value: allowed interval 0-255'
            )
        ),


        dict(
            desc='Try to add invalid NSEC3PARAM record to zone %s' % (zone1),
            command=('dnszone_mod', [zone1], {'nsec3paramrecord': u'0 333 0 -'}),
            expected=errors.ValidationError(name="nsec3param_rec",
                        error=u'flags value: allowed interval 0-255'
            )
        ),


        dict(
            desc='Try to add invalid NSEC3PARAM record to zone %s' % (zone1),
            command=('dnszone_mod', [zone1], {'nsec3paramrecord': u'0 0 65536 -'}),
            expected=errors.ValidationError(name="nsec3param_rec",
                        error=u'iterations value: allowed interval 0-65535'
            )
        ),


        dict(
            desc='Try to add invalid NSEC3PARAM record to zone %s' % (zone1),
            command=('dnszone_mod', [zone1], {'nsec3paramrecord': u'0 0 0 A'}),
            expected=errors.ValidationError(name="nsec3param_rec",
                        error=(u'expected format: <0-255> <0-255> <0-65535> '
                               u'even-length_hexadecimal_digits_or_hyphen')
            )
        ),


        dict(
            desc='Add NSEC3PARAM record to zone %s' % (zone1),
            command=('dnszone_mod', [zone1], {'nsec3paramrecord': u'0 0 0 -'}),
            expected={
                'value': zone1_absolute_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [zone1_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'nsec3paramrecord': [u'0 0 0 -'],
                },
            },
        ),


        dict(
            desc='Delete NSEC3PARAM record from zone %s' % (zone1),
            command=('dnszone_mod', [zone1], {'nsec3paramrecord': u''}),
            expected={
                'value': zone1_absolute_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [zone1_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
            },
        ),


        dict(
            desc='Try to create reverse zone %r with NS record in it' % revzone1,
            command=(
                'dnszone_add', [revzone1], {
                    'idnssoamname': u'ns',
                    'idnssoarname': zone1_rname,
                }
            ),
            expected=errors.ValidationError(name='name-server',
                error=u"Nameserver for reverse zone cannot be a relative DNS name"),
        ),


        dict(
            desc='Create reverse zone %r' % revzone1,
            command=(
                'dnszone_add', [revzone1], {
                    'idnssoarname': zone1_rname,
                }
            ),
            expected={
                'value': revzone1_dnsname,
                'summary': None,
                'result': {
                    'dn': revzone1_dn,
                    'idnsname': [revzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-subdomain %(zone)s PTR;'
                                         % dict(realm=api.env.realm, zone=revzone1)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(
            desc='Search for zones with admin email %r' % (zone1_rname),
            command=('dnszone_find', [], {'idnssoarname': zone1_rname}),
            expected={
                'summary': None,
                'count': 2,
                'truncated': False,
                'result': [{
                    'dn': revzone1_dn,
                    'idnsname': [revzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
                {
                    'dn': zone1_dn,
                    'idnsname': [zone1_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                }],
            },
        ),


        dict(
            desc='Search for zones with admin email %r with --forward-only' % zone1_rname,
            command=('dnszone_find', [], {'idnssoarname': zone1_rname, 'forward_only' : True}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [{
                    'dn': zone1_dn,
                    'idnsname': [zone1_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                }],
            },
        ),


        dict(
            desc='Delete reverse zone %r' % revzone1,
            command=('dnszone_del', [revzone1], {}),
            expected={
                'value': [revzone1_dnsname],
                'summary': u'Deleted DNS zone "%s"' % revzone1,
                'result': {'failed': []},
            },
        ),


        dict(
            desc='Try to retrieve non-existent record %r in zone %r' % (name1, zone1),
            command=('dnsrecord_show', [zone1, name1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS resource record not found' % name1),
        ),


        dict(
            desc='Try to delete non-existent record %r in zone %r' % (name1, zone1),
            command=('dnsrecord_del', [zone1, name1], {'del_all' : True}),
            expected=errors.NotFound(
                reason=u'%s: DNS resource record not found' % name1),
        ),


        dict(
            desc='Try to delete root zone record \'@\' in %r' % (zone1),
            command=('dnsrecord_del', [zone1, u'@'], {'del_all' : True}),
            expected=errors.ValidationError(name='del_all',
                error=u"Zone record '@' cannot be deleted"),
        ),


        dict(
            desc='Create record %r in zone %r' % (zone1, name1),
            command=('dnsrecord_add', [zone1, name1], {'arecord': arec2}),
            expected={
                'value': name1_dnsname,
                'summary': None,
                'result': {
                    'dn': name1_dn,
                    'idnsname': [name1_dnsname],
                    'objectclass': objectclasses.dnsrecord,
                    'arecord': [arec2],
                },
            },
        ),


        dict(
            desc='Search for all records in zone %r' % zone1,
            command=('dnsrecord_find', [zone1], {}),
            expected={
                'summary': None,
                'count': 3,
                'truncated': False,
                'result': [
                    {
                        'dn': zone1_dn,
                        'nsrecord': nameservers,
                        'idnsname': [_dns_zone_record],
                    },
                    {
                        'dn': zone1_txtrec_dn,
                        'txtrecord': [api.env.realm],
                        'idnsname': [DNSName(u'_kerberos')],
                    },
                    {
                        'dn': name1_dn,
                        'idnsname': [name1_dnsname],
                        'arecord': [arec2],
                    },
                ],
            },
        ),


        dict(
            desc='Add A record to %r in zone %r' % (name1, zone1),
            command=('dnsrecord_add', [zone1, name1], {'arecord': arec3}),
            expected={
                'value': name1_dnsname,
                'summary': None,
                'result': {
                    'dn': name1_dn,
                    'idnsname': [name1_dnsname],
                    'arecord': [arec2, arec3],
                    'objectclass': objectclasses.dnsrecord,
                },
            },
        ),


        dict(
            desc='Remove A record from %r in zone %r' % (name1, zone1),
            command=('dnsrecord_del', [zone1, name1], {'arecord': arec2}),
            expected={
                'value': [name1_dnsname],
                'summary': None,
                'result': {
                    'idnsname': [name1_dnsname],
                    'arecord': [arec3],
                },
            },
        ),


        dict(
            desc='Add AAAA record to %r in zone %r using dnsrecord_mod' % (name1, zone1),
            command=('dnsrecord_mod', [zone1, name1], {'aaaarecord': u'::1'}),
            expected={
                'value': name1_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [name1_dnsname],
                    'arecord': [arec3],
                    'aaaarecord': [u'::1'],
                },
            },
        ),


        dict(
            desc='Try to modify nonexistent record in zone %r' % zone1,
            command=('dnsrecord_mod',
                [zone1, u'ghostname'],
                {'aaaarecord': u'f001:baad::1'}),
            expected=errors.NotFound(
                reason=u'ghostname: DNS resource record not found'),
        ),


        dict(
            desc='Modify AAAA record in %r in zone %r' % (name1, zone1),
            command=(
                'dnsrecord_mod', [zone1, name1], {'aaaarecord': aaaarec1}
            ),
            expected={
                'value': name1_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [name1_dnsname],
                    'arecord': [arec3],
                    'aaaarecord': [aaaarec1],
                },
            },
        ),

        dict(
            desc=('Show record %r in zone %r with --structured and --all '
                  'options' % (name1, zone1)),
            command=('dnsrecord_show', [zone1, name1],
                     {'structured': True, 'all': True}),
            expected=lambda o, x: (
                'result' in x and
                'dnsrecords' in x['result'] and
                (len(x['result']['dnsrecords']) in (1, 2)) and
                (any(y[u'dnsdata'] in (aaaarec1, arec3)
                     for y in x['result']['dnsrecords']))),
        ),

        dict(
            desc='Remove AAAA record from %r in zone %r using dnsrecord_mod' % (name1, zone1),
            command=('dnsrecord_mod', [zone1, name1], {'aaaarecord': u''}),
            expected={
                'value': name1_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [name1_dnsname],
                    'arecord': [arec3],
                },
            },
        ),

        dict(
            desc='Try to add invalid MX record to zone %r using dnsrecord_add' % (zone1),
            command=('dnsrecord_add', [zone1, u'@'], {'mxrecord': zone1_ns }),
            expected=errors.ValidationError(name='mx_rec',
                error=u'format must be specified as "PREFERENCE EXCHANGER" ' +
                    u' (see RFC 1035 for details)'),
        ),

        dict(
            desc='Add MX record to zone %r using dnsrecord_add' % (zone1),
            command=('dnsrecord_add', [zone1, u'@'], {'mxrecord': u"0 %s" % zone1_ns }),
            expected={
                'value': _dns_zone_record,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnszone,
                    'dn': zone1_dn,
                    'idnsname': [_dns_zone_record],
                    'mxrecord': [u"0 %s" % zone1_ns],
                    'nsrecord': nameservers,
                },
            },
        ),

        dict(
            desc='Try to add invalid SRV record to zone %r using dnsrecord_add' % (zone1),
            command=('dnsrecord_add', [zone1, u'_foo._tcp'], {'srvrecord': zone1_ns}),
            expected=errors.ValidationError(name='srv_rec',
                error=u'format must be specified as "PRIORITY WEIGHT PORT TARGET" ' +
                    u' (see RFC 2782 for details)'),
        ),


        dict(
            desc='Try to add SRV record to zone %r both via parts and a raw value' % (zone1),
            command=('dnsrecord_add', [zone1, u'_foo._tcp'], {'srv_part_priority': 0,
                                                                 'srv_part_weight' : 0,
                                                                 'srv_part_port' : 123,
                                                                 'srv_part_target' : u'foo.bar.',
                                                                 'srvrecord': [u"1 100 1234 %s" \
                                                                     % zone1_ns]}),
            expected=lambda x, output: (
                type(x) == errors.ValidationError and
                str(x).endswith('Raw value of a DNS record was already '
                                'set by "srv_rec" option'),
            ),
        ),

        dict(
            desc='Add SRV record to zone %r using dnsrecord_add' % (zone1),
            command=('dnsrecord_add', [zone1, u'_foo._tcp'], {'srvrecord': u"0 100 1234 %s" % zone1_ns}),
            expected={
                'value': DNSName(u'_foo._tcp'),
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': DN(('idnsname', u'_foo._tcp'), zone1_dn),
                    'idnsname': [DNSName(u'_foo._tcp')],
                    'srvrecord': [u"0 100 1234 %s" % zone1_ns],
                },
            },
        ),

        dict(
            desc='Try to modify SRV record in zone %r without specifying modified value' % (zone1),
            command=('dnsrecord_mod', [zone1, u'_foo._tcp'], {'srv_part_priority': 1,}),
            expected=errors.RequirementError(name='srv_rec'),
        ),

        dict(
            desc='Try to modify SRV record in zone %r with non-existent modified value' % (zone1),
            command=('dnsrecord_mod', [zone1, u'_foo._tcp'], {'srv_part_priority': 1,
                                                  'srvrecord' : [u"0 100 1234 %s" % absnxname] }),
            expected=errors.AttrValueNotFound(attr='SRV record',
                value=u'0 100 1234 %s' % absnxname),
        ),

        dict(
            desc='Try to modify SRV record in zone %r with invalid part value' % (zone1),
            command=('dnsrecord_mod', [zone1, u'_foo._tcp'], {'srv_part_priority': 100000,
                                                  'srvrecord' : [u"0 100 1234 %s" % zone1_ns] }),
            expected=errors.ValidationError(name='srv_priority', error=u'can be at most 65535'),
        ),

        dict(
            desc='Modify SRV record in zone %r using parts' % (zone1),
            command=('dnsrecord_mod', [zone1, u'_foo._tcp'], {'srv_part_priority': 1,
                                                  'srvrecord' : [u"0 100 1234 %s" % zone1_ns] }),
            expected={
                'value': DNSName(u'_foo._tcp'),
                'summary': None,
                'result': {
                    'idnsname': [DNSName(u'_foo._tcp')],
                    'srvrecord': [u"1 100 1234 %s" % zone1_ns],
                },
            },
        ),

        dict(
            desc='Try to add invalid LOC record to zone %r using dnsrecord_add' % (zone1),
            command=('dnsrecord_add', [zone1, u'@'], {'locrecord': u"91 11 42.4 N 16 36 29.6 E 227.64" }),
            expected=errors.ValidationError(name='lat_deg',
                error=u'can be at most 90'),
        ),

        dict(
            desc='Add LOC record to zone %r using dnsrecord_add' % (zone1),
            command=('dnsrecord_add', [zone1, u'@'], {'locrecord': u"49 11 42.4 N 16 36 29.6 E 227.64m 10m 10.0m 0.1"}),
            expected={
                'value': _dns_zone_record,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnszone,
                    'dn': zone1_dn,
                    'idnsname': [_dns_zone_record],
                    'mxrecord': [u"0 %s" % zone1_ns],
                    'nsrecord': nameservers,
                    'locrecord': [u"49 11 42.400 N 16 36 29.600 E 227.64 10.00 10.00 0.10"],
                },
            },
        ),

        dict(
            desc='Try to add CNAME record to %r using dnsrecord_add' % (name1),
            command=('dnsrecord_add', [zone1, name1], {'cnamerecord': absnxname}),
            expected=errors.ValidationError(name='cnamerecord',
                error=u'CNAME record is not allowed to coexist with any other '
                      u'record (RFC 1034, section 3.6.2)'),
        ),

        dict(
            desc='Try to add multiple CNAME record %r using dnsrecord_add' % (cname),
            command=('dnsrecord_add', [zone1, cname], {'cnamerecord':
                [u'1.%s' % absnxname, u'2.%s' % absnxname]}),
            expected=errors.ValidationError(name='cnamerecord',
                error=u'only one CNAME record is allowed per name (RFC 2136, section 1.1.5)'),
        ),

        dict(
            desc='Add CNAME record to %r using dnsrecord_add' % (cname),
            command=('dnsrecord_add', [zone1, cname], {'cnamerecord': absnxname}),
            expected={
                'value': cname_dnsname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': cname_dn,
                    'idnsname': [cname_dnsname],
                    'cnamerecord': [absnxname],
                },
            },
        ),

        dict(
            desc='Try to add other record to CNAME record %r using dnsrecord_add' % (cname),
            command=('dnsrecord_add', [zone1, cname], {'arecord': arec1}),
            expected=errors.ValidationError(name='cnamerecord',
                error=u'CNAME record is not allowed to coexist with any other '
                      u'record (RFC 1034, section 3.6.2)'),
        ),

        dict(
            desc='Try to add other record to CNAME record %r using dnsrecord_mod' % (cname),
            command=('dnsrecord_mod', [zone1, cname], {'arecord': arec1}),
            expected=errors.ValidationError(name='cnamerecord',
                error=u'CNAME record is not allowed to coexist with any other '
                      u'record (RFC 1034, section 3.6.2)'),
        ),

        dict(
            desc='Add A record and delete CNAME record in %r with dnsrecord_mod' % (cname),
            command=('dnsrecord_mod', [zone1, cname], {'arecord': arec1,
                                                                'cnamerecord': None}),
            expected={
                'value': cname_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [cname_dnsname],
                    'arecord': [arec1],
                },
            },
        ),

        dict(
            desc='Try to add multiple DNAME records to %r using dnsrecord_add' % (dname),
            command=('dnsrecord_add', [zone1, name1], {'dnamerecord':
                [u'foo-1.%s' % absnxname, u'foo-2.%s' % absnxname]}),
            expected=errors.ValidationError(name='dnamerecord',
                error=u'only one DNAME record is allowed per name (RFC 6672, section 2.4)'),
        ),


        dict(
            desc='Add DNAME record to %r using dnsrecord_add' % (dname),
            command=('dnsrecord_add', [zone1, dname],
                {'dnamerecord': u'd.%s' % absnxname, 'arecord': arec1}),
            expected={
                'value': dname_dnsname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': dname_dn,
                    'idnsname': [dname_dnsname],
                    'dnamerecord': [u'd.%s' % absnxname],
                    'arecord': [arec1],
                },
            },
        ),

        dict(
            desc='Try to add CNAME record to %r using dnsrecord_add' % (dname),
            command=('dnsrecord_add', [zone1, dname], {'cnamerecord': u'foo-1.%s'
                % absnxname}),
            expected=errors.ValidationError(name='cnamerecord',
                error=u'CNAME record is not allowed to coexist with any other '
                      u'record (RFC 1034, section 3.6.2)'),
        ),

        dict(
            desc='Try to add NS record to %r using dnsrecord_add' % (dname),
            command=('dnsrecord_add', [zone1, dname],
                {'nsrecord': u'%s.%s.' % (name1, zone1)}),
            expected=errors.ValidationError(name='nsrecord',
                error=u'NS record is not allowed to coexist with an DNAME '
                      u'record except when located in a zone root record '
                      '(RFC 2181, section 6.1)'),
        ),

        dict(
            desc='Add NS+DNAME record to %r zone record using dnsrecord_add' % (zone2),
            command=('dnsrecord_add', [zone2, u'@'],
                {'dnamerecord': u'd.%s' % absnxname,
                 'nsrecord': zone1_ns, 'force': True}),
            expected = {
                'value': _dns_zone_record,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnszone,
                    'dnamerecord': [u'd.%s' % absnxname],
                    'dn': zone2_dn,
                    'nsrecord': [zone1_ns] + nameservers,
                    'idnsname': [_dns_zone_record]
                }
            },
        ),


        dict(
            desc='Delete zone %r' % zone2,
            command=('dnszone_del', [zone2], {}),
            expected={
                'value': [zone2_absolute_dnsname],
                'summary': u'Deleted DNS zone "%s"' % zone2_absolute,
                'result': {'failed': []},
            },
        ),

        dict(
            desc='Try to add invalid KX record %r using dnsrecord_add' % (name1),
            command=('dnsrecord_add', [zone1, name1], {'kxrecord': absnxname}),
            expected=errors.ValidationError(name='kx_rec',
                error=u'format must be specified as "PREFERENCE EXCHANGER" ' +
                    u' (see RFC 2230 for details)'),
        ),

        dict(
            desc='Add KX record to %r using dnsrecord_add' % (name1),
            command=('dnsrecord_add', [zone1, name1], {'kxrecord': u'1 foo-1' }),
            expected={
                'value': name1_dnsname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': name1_dn,
                    'idnsname': [name1_dnsname],
                    'arecord': [arec3],
                    'kxrecord': [u'1 foo-1'],
                },
            },
        ),

        dict(
            desc='Add TXT record to %r using dnsrecord_add' % (name1),
            command=('dnsrecord_add', [zone1, name1], {'txtrecord': u'foo bar' }),
            expected={
                'value': name1_dnsname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': name1_dn,
                    'idnsname': [name1_dnsname],
                    'arecord': [arec3],
                    'kxrecord': [u'1 foo-1'],
                    'txtrecord': [u'foo bar'],
                },
            },
        ),


        dict(
            desc='Try to add unresolvable absolute NS record to %r using dnsrecord_add' % (name_ns),
            command=('dnsrecord_add', [zone1, name_ns], {'nsrecord': absnxname}),
            expected=errors.NotFound(reason=u"Nameserver '%s' does not have a corresponding A/AAAA record" % absnxname),
        ),

        dict(
            desc='Try to add unresolvable relative NS record to %r using dnsrecord_add' % (name_ns),
            command=('dnsrecord_add', [zone1, name_ns], {'nsrecord': relnxname}),
            expected=errors.NotFound(reason=u"Nameserver '%s.%s.' does not "
                "have a corresponding A/AAAA record" % (relnxname, zone1)),
        ),

        dict(
            desc='Add unresolvable NS record with --force to %r using dnsrecord_add' % (name_ns),
            command=('dnsrecord_add', [zone1, name_ns], {'nsrecord': absnxname,
                                                            'force' : True}),
            expected={
                'value': name_ns_dnsname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': name_ns_dn,
                    'idnsname': [name_ns_dnsname],
                    'nsrecord': [absnxname],
                },
            },
        ),

        dict(
            desc='Try to to rename DNS zone %r root record' % (zone1),
            command=('dnsrecord_mod', [zone1, u'@'], {'rename': u'renamed-zone',}),
            expected=errors.ValidationError(name='rename',
                           error=u'DNS zone root record cannot be renamed')
        ),


        dict(
            desc='Rename DNS record %r to %r' % (name_ns, name_ns_renamed),
            command=('dnsrecord_mod', [zone1, name_ns], {'rename': name_ns_renamed,}),
            expected={
                'value': name_ns_dnsname,
                'summary': None,
                'result': {
                'idnsname': [name_ns_renamed_dnsname],
                'nsrecord': [absnxname],
                },
            },
        ),


        dict(
            desc='Delete record %r in zone %r' % (name1, zone1),
            command=('dnsrecord_del', [zone1, name1],
                     {'del_all': True}),
            expected={
                'value': [name1_dnsname],
                'summary': u'Deleted record "%s"' % name1,
                'result': {'failed': []},
            },
        ),


        dict(
            desc='Add DLV record to %r using dnsrecord_add' % (dlv),
            command=('dnsrecord_add', [zone1, dlv], {'dlvrecord': dlvrec}),
            expected={
                'value': dlv_dnsname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': dlv_dn,
                    'idnsname': [dlv_dnsname],
                    'dlvrecord': [dlvrec],
                },
            },
        ),


        dict(
            desc='Try to add DS record to zone %r apex, using dnsrecord_add' % (zone1),
            command=('dnsrecord_add', [zone1, zone1_absolute], {'dsrecord': ds_rec}),
            expected=errors.ValidationError(
                name="dsrecord",
                error=u'DS record must not be in zone apex (RFC 4035 section 2.4)'
            ),
        ),


        dict(
            desc='Try to add DS record %r without NS record in RRset, using dnsrecord_add' % (ds),
            command=('dnsrecord_add', [zone1, ds], {'dsrecord': ds_rec}),
            expected=errors.ValidationError(
                name="dsrecord",
                error=u'DS record requires to coexist with an NS record (RFC 4592 section 4.6, RFC 4035 section 2.4)'
            ),
        ),


        dict(
            desc='Add NS record to %r using dnsrecord_add' % (ds),
            command=('dnsrecord_add', [zone1, ds],
                     {'nsrecord': zone1_ns, 'force': True}),
            expected={
                'value': ds_dnsname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': ds_dn,
                    'idnsname': [ds_dnsname],
                    'nsrecord': [zone1_ns],
                },
            },
        ),


        dict(
            desc='Add DS record to %r using dnsrecord_add' % (ds),
            command=('dnsrecord_add', [zone1, ds],
                     {'dsrecord': ds_rec}),
            expected={
                'value': ds_dnsname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': ds_dn,
                    'idnsname': [ds_dnsname],
                    'nsrecord': [zone1_ns],
                    'dsrecord': [ds_rec],
                },
            },
        ),


        dict(
            desc='Try to delete NS record (with DS record) %r using dnsrecord_del' % (ds),
            command=('dnsrecord_del', [zone1, ds],
                     {'nsrecord': zone1_ns}),
            expected=errors.ValidationError(
                name="dsrecord",
                error=u'DS record requires to coexist with an NS record (RFC 4592 section 4.6, RFC 4035 section 2.4)'
            ),
        ),


        dict(
            desc='Delete NS+DS record %r in zone %r' % (ds, zone1),
            command=('dnsrecord_del', [zone1, ds], {'nsrecord': zone1_ns, 'dsrecord': ds_rec}),
            expected={
                'value': [ds_dnsname],
                'summary': u'Deleted record "%s"' % ds,
                'result': {'failed': []},
            },
        ),


        dict(
            desc='Delete record %r in zone %r' % (dlv, zone1),
            command=('dnsrecord_del', [zone1, dlv], {'del_all': True}),
            expected={
                'value': [dlv_dnsname],
                'summary': u'Deleted record "%s"' % dlv,
                'result': {'failed': []},
            },
        ),


        dict(
            desc='Try to add invalid TLSA record to %r using dnsrecord_add (1)' % (tlsa),
            command=('dnsrecord_add', [zone1, tlsa], {'tlsarecord': tlsarec_err1}),
            expected=errors.ValidationError(
                name="cert_usage",
                error=u'can be at most 255'
            ),
        ),


        dict(
            desc='Try to add invalid TLSA record to %r using dnsrecord_add (2)' % (tlsa),
            command=('dnsrecord_add', [zone1, tlsa], {'tlsarecord': tlsarec_err2}),
            expected=errors.ValidationError(
                name="selector",
                error=u'can be at most 255'
            ),
        ),


        dict(
            desc='Try to add invalid TLSA record to %r using dnsrecord_add (3)' % (tlsa),
            command=('dnsrecord_add', [zone1, tlsa], {'tlsarecord': tlsarec_err3}),
            expected=errors.ValidationError(
                name="matching_type",
                error=u'can be at most 255'
            ),
        ),


        dict(
            desc='Add TLSA record to %r using dnsrecord_add' % (tlsa),
            command=('dnsrecord_add', [zone1, tlsa], {'tlsarecord': tlsarec_ok}),
            expected={
                'value': tlsa_dnsname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': tlsa_dn,
                    'idnsname': [tlsa_dnsname],
                    'tlsarecord': [tlsarec_ok],
                },
            },
        ),


        dict(
            desc='Remove record using dnsrecord-mod %r in zone %r' % (tlsa, zone1),
            command=('dnsrecord_mod', [zone1, tlsa], {'tlsarecord': ''}),
            expected={
                'value': tlsa_dnsname,
                'summary': u'Deleted record "%s"' % tlsa,
                'result': {'failed': []},
            },
        ),


        dict(
            desc='Try to create a reverse zone from invalid IP',
            command=(
                'dnszone_add', [], {
                    'name_from_ip': u'foo',
                    'idnssoamname': zone1_ns,
                    'idnssoarname': zone1_rname,
                }
            ),
            expected=errors.ValidationError(name='name_from_ip',
                error=u'invalid IP network format'),
        ),

        dict(
            desc='Create reverse zone from IP/netmask %r using name_from_ip option' % revzone1_ip,
            command=(
                'dnszone_add', [], {
                    'name_from_ip': revzone1_ip,
                    'idnssoarname': zone1_rname,
                }
            ),
            expected={
                'value': revzone1_dnsname,
                'summary': None,
                'result': {
                    'dn': revzone1_dn,
                    'idnsname': [revzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-subdomain %(zone)s PTR;'
                                         % dict(realm=api.env.realm, zone=revzone1)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(
            desc='Create reverse zone from IP %r using name_from_ip option' % revzone2_ip,
            command=(
                'dnszone_add', [], {
                    'name_from_ip': revzone2_ip,
                    'idnssoarname': zone1_rname,
                }
            ),
            expected={
                'value': revzone2_dnsname,
                'summary': None,
                'result': {
                    'dn': revzone2_dn,
                    'idnsname': [revzone2_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-subdomain %(zone)s PTR;'
                                         % dict(realm=api.env.realm, zone=revzone2)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(
            desc='Add PTR record %r to %r using dnsrecord_add' % (revname1, revzone1),
            command=('dnsrecord_add', [revzone1, revname1], {'ptrrecord': absnxname}),
            expected={
                'value': revname1_dnsname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': revname1_dn,
                    'idnsname': [revname1_dnsname],
                    'ptrrecord': [absnxname],
                },
            },
        ),

        dict(
            desc='Show record %r in zone %r with --structured and --all options'\
                    % (revname1, revzone1),
            command=('dnsrecord_show', [revzone1, revname1],
                {'structured': True, 'all': True}),
            expected={
                'value': revname1_dnsname,
                'summary': None,
                'result': {
                    'dn': revname1_dn,
                    'idnsname': [revname1_dnsname],
                    'objectclass': objectclasses.dnsrecord,
                    'dnsrecords': [
                        {
                            'dnstype': u'PTR',
                            'dnsdata': absnxname,
                            'ptr_part_hostname': absnxname,
                        },
                    ],
                },
            },
        ),

        dict(
            desc='Update global DNS settings',
            command=('dnsconfig_mod', [], {'idnsforwarders' : [fwd_ip],}),
            expected={
                'value': None,
                'summary': None,
                u'messages': (
                    {u'message': lambda x: x.startswith(
                        u"Forwarding policy conflicts with some "
                        "automatic empty zones."),
                     u'code': 13021,
                     u'type': u'warning',
                     u'name': u'DNSForwardPolicyConflictWithEmptyZone',
                     u'data': {}},
                    {u'message': lambda x: x.startswith(
                        u"DNS server %s: query '. SOA':" % fwd_ip),
                     u'code': 13006,
                     u'type':u'warning',
                     u'name': u'DNSServerValidationWarning',
                     u'data': {
                        u'error': lambda x: x.startswith(u"query '. SOA':"),
                        u'server': u"%s" % fwd_ip
                     }},
                ),
                'result': {
                    'dns_server_server': [api.env.host],
                    'idnsforwarders': [fwd_ip],
                },
            },
        ),

        dict(
            desc='Update global DNS settings - rollback',
            command=('dnsconfig_mod', [], {'idnsforwarders' : None,}),
            expected={
                'value': None,
                'summary': u'Global DNS configuration is empty',
                'result': {'dns_server_server': [api.env.host]},
            },
        ),

        dict(
            desc='Try to add invalid allow-query to zone %r' % zone1,
            command=('dnszone_mod', [zone1], {'idnsallowquery': u'foo'}),
            expected=errors.ValidationError(name='allow_query',
                error=u"failed to detect a valid IP address from 'foo'"),
        ),

        dict(
            desc='Add allow-query ACL to zone %r' % zone1,
            command=('dnszone_mod', [zone1], {'idnsallowquery': allowquery_restricted_in}),
            expected={
                'value': zone1_absolute_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [zone1_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'mxrecord': [u'0 ns1.dnszone.test.'],
                    'locrecord': [u"49 11 42.400 N 16 36 29.600 E 227.64 10.00 10.00 0.10"],
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowquery': [allowquery_restricted_out],
                    'idnsallowtransfer': [u'none;'],
                },
            },
        ),


        dict(
            desc='Try to add invalid allow-transfer to zone %r' % zone1,
            command=('dnszone_mod', [zone1], {'idnsallowtransfer': u'10.'}),
            expected=errors.ValidationError(name='allow_transfer',
                error=u"failed to detect a valid IP address from '10.'"),
        ),

        dict(
            desc='Add allow-transer ACL to zone %r' % zone1,
            command=('dnszone_mod', [zone1], {'idnsallowtransfer': fwd_ip}),
            expected={
                'value': zone1_absolute_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [zone1_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'mxrecord': [u'0 ns1.dnszone.test.'],
                    'locrecord': [u"49 11 42.400 N 16 36 29.600 E 227.64 10.00 10.00 0.10"],
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowquery': [allowquery_restricted_out],
                    'idnsallowtransfer': [allowtransfer_tofwd],
                },
            },
        ),


        dict(
            desc='Set SOA serial of zone %r to high number' % zone1,
            command=('dnszone_mod', [zone1], {'idnssoaserial': 4294967295}),
            expected={
                'value': zone1_absolute_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [zone1_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'mxrecord': [u'0 ns1.dnszone.test.'],
                    'locrecord': [u"49 11 42.400 N 16 36 29.600 E 227.64 10.00 10.00 0.10"],
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [u'4294967295'],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowquery': [allowquery_restricted_out],
                    'idnsallowtransfer': [allowtransfer_tofwd],
                },
            },
        ),


        dict(
            desc='Try to create duplicate PTR record for %r with --a-create-reverse' % name1,
            command=('dnsrecord_add', [zone1, name1], {'arecord': revname1_ip,
                                                            'a_extra_create_reverse' : True}),
            expected=errors.DuplicateEntry(message=u'Reverse record for IP '
                'address %s already exists in reverse zone '
                '%s.' % (revname1_ip, revzone1)),
        ),


        dict(
            desc='Create A record %r in zone %r with --a-create-reverse' % (name1, zone1),
            command=('dnsrecord_add', [zone1, name1], {'arecord': revname2_ip,
                                                            'a_extra_create_reverse' : True}),
            expected={
                'value': name1_dnsname,
                'summary': None,
                'result': {
                    'dn': name1_dn,
                    'idnsname': [name1_dnsname],
                    'objectclass': objectclasses.dnsrecord,
                    'arecord': [revname2_ip],
                },
            },
        ),


        dict(
            desc='Check reverse record for %r created via --a-create-reverse' % name1,
            command=('dnsrecord_show', [revzone1, revname2], {}),
            expected={
                'value': revname2_dnsname,
                'summary': None,
                'result': {
                    'dn': revname2_dn,
                    'idnsname': [revname2_dnsname],
                    'ptrrecord': [name1 + '.' + zone1 + '.'],
                },
            },
        ),

        dict(
            desc='Modify ttl of record %r in zone %r' % (name1, zone1),
            command=('dnsrecord_mod', [zone1, name1], {'dnsttl': 500}),
            expected={
                'value': name1_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [name1_dnsname],
                    'dnsttl': ['500'],
                    'arecord': [revname2_ip],
                },
            },
        ),


        dict(
            desc='Delete ttl of record %r in zone %r' % (name1, zone1),
            command=('dnsrecord_mod', [zone1, name1], {'dnsttl': None}),
            expected={
                'value': name1_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [name1_dnsname],
                    'arecord': [revname2_ip],
                },
            },
        ),


        dict(
            desc='Try to add per-zone permission for unknown zone',
            command=('dnszone_add_permission', [absnxname], {}),
            expected=errors.NotFound(reason=u'%s: DNS zone not found' % absnxname)
        ),


        dict(
            desc='Add per-zone permission for zone %r' % zone1,
            command=(
                'dnszone_add_permission', [zone1], {}
            ),
            expected=dict(
                result=True,
                value=zone1_permission,
                summary=u'Added system permission "%s"' % zone1_permission,
            ),
        ),


        dict(
            desc='Try to add duplicate per-zone permission for zone %r' % zone1,
            command=(
                'dnszone_add_permission', [zone1], {}
            ),
            expected=errors.DuplicateEntry(message=u'permission with name '
                '"%s" already exists' % zone1_permission)
        ),

        dict(
            desc='Make sure the permission was created %r' % zone1,
            command=(
                'permission_show', [zone1_permission], {}
            ),
            expected=dict(
                value=zone1_permission,
                summary=None,
                result={
                    'dn': zone1_permission_dn,
                    'cn': [zone1_permission],
                    'objectclass': objectclasses.system_permission,
                    'ipapermissiontype': [u'SYSTEM'],
                },
            ),
        ),

        dict(
            desc='Retrieve the permission %r with --all --raw' % zone1,
            command=(
                'permission_show', [zone1_permission], {}
            ),
            expected=dict(
                value=zone1_permission,
                summary=None,
                result={
                    'dn': zone1_permission_dn,
                    'cn': [zone1_permission],
                    'objectclass': objectclasses.system_permission,
                    'ipapermissiontype': [u'SYSTEM'],
                },
            ),
        ),

        dict(
            desc='Try to remove per-zone permission for unknown zone',
            command=('dnszone_remove_permission', [absnxname], {}),
            expected=errors.NotFound(reason=u'%s: DNS zone not found'
                % absnxname)
        ),

        dict(
            desc='Remove per-zone permission for zone %r' % zone1,
            command=(
                'dnszone_remove_permission', [zone1], {}
            ),
            expected=dict(
                result=True,
                value=zone1_permission,
                summary=u'Removed system permission "%s"' % zone1_permission,
            ),
        ),


        dict(
            desc='Make sure the permission for zone %r was deleted' % zone1,
            command=(
                'permission_show', [zone1_permission], {}
            ),
            expected=errors.NotFound(reason=u'%s: permission not found'
                                     % zone1_permission)
        ),


        dict(
            desc='Try to remove non-existent per-zone permission for zone %r' % zone1,
            command=(
                'dnszone_remove_permission', [zone1], {}
            ),
            expected=errors.NotFound(reason=u'%s: permission not found'
                                     % zone1_permission)
        ),


        dict(
            desc='Try to create zone %r with relative nameserver' % zone3,
            command=(
                'dnszone_add', [zone3], {
                    'idnssoamname': u'ns',
                    'idnssoarname': zone3_rname,
                }
            ),
            expected=errors.NotFound(reason=u"Nameserver 'ns.%s' does not have a corresponding A/AAAA record"
                                            % zone3_absolute)
        ),

        dict(
            desc='Try to create zone %r with nameserver in the zone itself' % zone3,
            command=(
                'dnszone_add', [zone3], {
                    'idnssoamname': zone3_absolute,
                    'idnssoarname': zone3_rname,
                }
            ),
            expected=errors.NotFound(reason=u"Nameserver '%s' does not have a corresponding A/AAAA record"
                                            % zone3_absolute)
        ),


        dict(
            desc='Create zone %r' % zone3,
            command=(
                'dnszone_add', [zone3], {
                    'idnssoarname': zone3_rname,
                }
            ),
            expected={
                'value': zone3_absolute_dnsname,
                'summary': None,
                'result': {
                    'dn': zone3_dn,
                    'idnsname': [zone3_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone3_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-self * A; '
                                         u'grant %(realm)s krb5-self * AAAA; '
                                         u'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),

        dict(
            desc='Add A record to %r in zone %r' % (zone3_ns2_arec, zone3),
            command=('dnsrecord_add', [zone3, zone3_ns2_arec], {'arecord': zone3_ip2}),
            expected={
                'value': zone3_ns2_arec_dnsname,
                'summary': None,
                'result': {
                    'dn': zone3_ns2_arec_dn,
                    'idnsname': [zone3_ns2_arec_dnsname],
                    'arecord': [zone3_ip2],
                    'objectclass': objectclasses.dnsrecord,
                },
            },
        ),

        dict(
            desc='Create reverse zone %r' % revzone3_classless1,
            command=(
                'dnszone_add', [revzone3_classless1], {
                    'idnssoarname': zone3_rname,
                }
            ),
            expected={
                'value': revzone3_classless1_dnsname,
                'summary': None,
                'result': {
                    'dn': revzone3_classless1_dn,
                    'idnsname': [revzone3_classless1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone3_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-subdomain %(zone)s PTR;'
                                         % dict(realm=api.env.realm, zone=revzone3_classless1)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),

        dict(
            desc='Create classless reverse zone %r' % revzone3_classless2,
            command=(
                'dnszone_add', [revzone3_classless2], {
                    'idnssoarname': zone3_rname,
                }
            ),
            expected={
                'value': revzone3_classless2_dnsname,
                'summary': None,
                'result': {
                    'dn': revzone3_classless2_dn,
                    'idnsname': [revzone3_classless2_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone3_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-subdomain %(zone)s PTR;'
                                         % dict(realm=api.env.realm, zone=revzone3_classless2)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(
            desc='Add per-zone permission for classless zone %r' % revzone3_classless2,
            command=(
                'dnszone_add_permission', [revzone3_classless2], {}
            ),
            expected=dict(
                result=True,
                value=revzone3_classless2_permission,
                summary=u'Added system permission "%s"' % revzone3_classless2_permission,
            ),
        ),


        dict(
            desc='Remove per-zone permission for classless zone %r' % revzone3_classless2,
            command=(
                'dnszone_remove_permission', [revzone3_classless2], {}
            ),
            expected=dict(
                result=True,
                value=revzone3_classless2_permission,
                summary=u'Removed system permission "%s"' % revzone3_classless2_permission,
            ),
        ),


        dict(
            desc='Add NS record to %r in revzone %r' % (nsrev, revzone3_classless1),
            command=('dnsrecord_add', [revzone3_classless1, nsrev], {'nsrecord': zone3_ns2_arec_absolute}),
            expected={
                'value': nsrev_dnsname,
                'summary': None,
                'result': {
                    'dn': nsrev_dn,
                    'idnsname': [nsrev_dnsname],
                    'nsrecord': [zone3_ns2_arec_absolute],
                    'objectclass': objectclasses.dnsrecord,
                    },
            },
        ),

        dict(
            desc='Add CNAME record to %r in revzone %r' % (cnamerev, revzone3_classless1),
            command=('dnsrecord_add', [revzone3_classless1, cnamerev], {'cnamerecord': cnamerev_hostname}),
            expected={
                'value': cnamerev_dnsname,
                'summary': None,
                'result': {
                    'dn': cnamerev_dn,
                    'idnsname': [cnamerev_dnsname],
                    'cnamerecord': [cnamerev_hostname],
                    'objectclass': objectclasses.dnsrecord,
                },
            },
        ),

        dict(
            desc='Add PTR record to %r in revzone %r' % (ptr_revzone3, revzone3_classless2),
            command=('dnsrecord_add', [revzone3_classless2, cnamerev],
                     {'ptrrecord': ptr_revzone3_hostname}),
            expected={
                'value': ptr_revzone3_dnsname,
                'summary': None,
                'result': {
                    'dn': ptr_revzone3_dn,
                    'idnsname': [ptr_revzone3_dnsname],
                    'ptrrecord': [ptr_revzone3_hostname],
                    'objectclass': objectclasses.dnsrecord,
                },
            },
        ),

        dict(
            desc='Create IDN zone %r' % idnzone1,
            command=(
                'dnszone_add', [idnzone1], {
                    'idnssoarname': idnzone1_rname,
                }
            ),
            expected={
                'value': idnzone1_dnsname,
                'summary': None,
                'result': {
                    'dn': idnzone1_dn,
                    'idnsname': [idnzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [idnzone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-self * A; '
                                         u'grant %(realm)s krb5-self * AAAA; '
                                         u'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),

        dict(
            desc='Retrieve zone %r' % idnzone1,
            command=(
                'dnszone_show', [idnzone1], {}
            ),
            expected={
                'value': idnzone1_dnsname,
                'summary': None,
                'result': {
                    'dn': idnzone1_dn,
                    'idnsname': [idnzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [idnzone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
            },
        ),

        dict(
            desc='Retrieve zone raw %r' % idnzone1,
            command=(
                'dnszone_show', [idnzone1], {u'raw' : True,}
            ),
            expected={
                'value': idnzone1_dnsname,
                'summary': None,
                'result': {
                    'dn': idnzone1_dn,
                    'idnsname': [idnzone1_punycoded],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns],
                    'idnssoarname': [idnzone1_rname_punycoded],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
            },
        ),


        dict(
            desc='Find zone %r' % idnzone1,
            command=(
                'dnszone_find', [idnzone1], {}
            ),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [
                    {   'dn': idnzone1_dn,
                        'idnsname': [idnzone1_dnsname],
                        'idnszoneactive': [u'TRUE'],
                        'nsrecord': nameservers,
                        'idnssoamname': [self_server_ns_dnsname],
                        'idnssoarname': [idnzone1_rname_dnsname],
                        'idnssoaserial': [fuzzy_digits],
                        'idnssoarefresh': [fuzzy_digits],
                        'idnssoaretry': [fuzzy_digits],
                        'idnssoaexpire': [fuzzy_digits],
                        'idnssoaminimum': [fuzzy_digits],
                        'idnsallowtransfer': [u'none;'],
                        'idnsallowquery': [u'any;'],
                    },
                ],
            },
        ),


        dict(
            desc='Find zone %r raw' % idnzone1_punycoded,
            command=(
                'dnszone_find', [idnzone1_punycoded], {'raw': True,}
            ),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [
                    {   'dn': idnzone1_dn,
                        'idnsname': [idnzone1_punycoded],
                        'idnszoneactive': [u'TRUE'],
                        'nsrecord': nameservers,
                        'idnssoamname': [self_server_ns],
                        'idnssoarname': [idnzone1_rname_punycoded],
                        'idnssoaserial': [fuzzy_digits],
                        'idnssoarefresh': [fuzzy_digits],
                        'idnssoaretry': [fuzzy_digits],
                        'idnssoaexpire': [fuzzy_digits],
                        'idnssoaminimum': [fuzzy_digits],
                        'idnsallowtransfer': [u'none;'],
                        'idnsallowquery': [u'any;'],
                    },
                ],
            },
        ),

        dict(
            desc='Update zone %r' % idnzone1,
            command=('dnszone_mod', [idnzone1], {'idnssoarefresh': 5478}),
            expected={
                'value': idnzone1_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [idnzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [idnzone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
            },
        ),

        dict(
            desc='Create reverse zone %r' % revidnzone1,
            command=(
                'dnszone_add', [revidnzone1], {
                    'idnssoarname': idnzone1_rname,
                }
            ),
            expected={
                'value': revidnzone1_dnsname,
                'summary': None,
                'result': {
                    'dn': revidnzone1_dn,
                    'idnsname': [revidnzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [idnzone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-subdomain %(zone)s PTR;'
                                         % dict(realm=api.env.realm, zone=revidnzone1)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),

        dict(
            desc='Delete reverse zone %r' % revidnzone1,
            command=('dnszone_del', [revidnzone1], {}),
            expected={
                'value': [revidnzone1_dnsname],
                'summary': u'Deleted DNS zone "%s"' % revidnzone1,
                'result': {'failed': []},
            },
        ),

        dict(
            desc='Search for zones with name %r' % idnzone1,
            command=('dnszone_find', [idnzone1], {}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [{
                    'dn': idnzone1_dn,
                    'idnsname': [idnzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [idnzone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [u'5478'],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                }],
            },
        ),

        dict(
            desc='Try to retrieve non-existent record %r in zone %r' % (idnres1, idnzone1),
            command=('dnsrecord_show', [idnzone1, idnres1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS resource record not found' % idnres1),
        ),

        dict(
            desc='Create record %r in zone %r' % (idnzone1, idnres1),
            command=('dnsrecord_add', [idnzone1, idnres1], {'arecord': u'127.0.0.1'}),
            expected={
                'value': idnres1_dnsname,
                'summary': None,
                'result': {
                    'dn': idnres1_dn,
                    'idnsname': [idnres1_dnsname],
                    'objectclass': objectclasses.dnsrecord,
                    'arecord': [u'127.0.0.1'],
                },
            },
        ),


        dict(
            desc='Search for all records in zone %r' % idnzone1,
            command=('dnsrecord_find', [idnzone1], {}),
            expected={
                'summary': None,
                'count': 2,
                'truncated': False,
                'result': [
                    {
                        'dn': idnzone1_dn,
                        'nsrecord': nameservers,
                        'idnsname': [_dns_zone_record],
                    },
                    {
                        'dn': idnres1_dn,
                        'idnsname': [idnres1_dnsname],
                        'arecord': [u'127.0.0.1'],
                    },
                ],
            },
        ),


        dict(
            desc='Search for all records in zone %r with --pkey-only' % idnzone1,
            command=('dnsrecord_find', [idnzone1], {'pkey_only':True,}),
            expected={
                'summary': None,
                'count': 2,
                'truncated': False,
                'result': [
                    {
                        'dn': idnzone1_dn,
                        'idnsname': [_dns_zone_record],
                    },
                    {
                        'dn': idnres1_dn,
                        'idnsname': [idnres1_dnsname],
                    },
                ],
            },
        ),


        dict(
            desc='Find %r record in zone %r' % (idnzone1, idnzone1),
            command=('dnsrecord_find', [idnzone1, idnzone1], {}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [
                    {
                        'dn': idnzone1_dn,
                        'nsrecord': nameservers,
                        'idnsname': [_dns_zone_record],
                    },
                ],
            },
        ),


        dict(
            desc='Find %r record in zone %r' % (idnres1, idnzone1),
            command=('dnsrecord_find', [idnzone1, idnres1], {}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [
                    {
                        'dn': idnres1_dn,
                        'idnsname': [idnres1_dnsname],
                        'arecord': [u'127.0.0.1'],
                    },
                ],
            },
        ),


        dict(
            desc='Find %r record in zone %r with --pkey-only' % (idnres1, idnzone1),
            command=('dnsrecord_find', [idnzone1, idnres1], {'pkey_only':True,}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [
                    {
                        'dn': idnres1_dn,
                        'idnsname': [idnres1_dnsname],
                    },
                ],
            },
        ),


        dict(
            desc='Find raw %r record in zone %r with --pkey-only' % (idnres1, idnzone1),
            command=('dnsrecord_find', [idnzone1, idnres1],
                     {'pkey_only' : True, 'raw' : True,}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [
                    {
                        'dn': idnres1_dn,
                        'idnsname': [idnres1_punycoded],
                    },
                ],
            },
        ),


        dict(
            desc='Find raw %r record in zone %r with --pkey-only' % (idnres1_punycoded, idnzone1),
            command=('dnsrecord_find', [idnzone1, idnres1_punycoded], {'pkey_only':True, 'raw' : True}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [
                    {
                        'dn': idnres1_dn,
                        'idnsname': [idnres1_punycoded],
                    },
                ],
            },
        ),


        dict(
            desc='Add A record to %r in zone %r' % (idnres1, idnzone1),
            command=('dnsrecord_add', [idnzone1, idnres1], {'arecord': u'10.10.0.1'}),
            expected={
                'value': idnres1_dnsname,
                'summary': None,
                'result': {
                    'dn': idnres1_dn,
                    'idnsname': [idnres1_dnsname],
                    'arecord': [u'127.0.0.1', u'10.10.0.1'],
                    'objectclass': objectclasses.dnsrecord,
                },
            },
        ),


        dict(
            desc='Remove A record from %r in zone %r' % (idnres1, idnzone1),
            command=('dnsrecord_del', [idnzone1, idnres1], {'arecord': u'127.0.0.1'}),
            expected={
                'value': [idnres1_dnsname],
                'summary': None,
                'result': {
                    'idnsname': [idnres1_dnsname],
                    'arecord': [u'10.10.0.1'],
                },
            },
        ),

        dict(
            desc='Add MX record to zone %r using dnsrecord_add' % (idnzone1),
            command=('dnsrecord_add', [idnzone1, u'@'], {'mxrecord': u"0 %s" % idnzone1_mname }),
            expected={
                'value': _dns_zone_record,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnszone,
                    'dn': idnzone1_dn,
                    'idnsname': [_dns_zone_record],
                    'mxrecord': [u"0 %s" % idnzone1_mname],
                    'nsrecord': nameservers,
                },
            },
        ),


        #https://fedorahosted.org/freeipa/ticket/4232
        dict(
            desc='Add MX record (2) to zone %r using dnsrecord_add' % (idnzone1),
            command=('dnsrecord_add', [idnzone1, idnzone1], {'mxrecord': u"10 %s" % idnzone1_mname }),
            expected={
                'value': idnzone1_dnsname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnszone,
                    'dn': idnzone1_dn,
                    'idnsname': [_dns_zone_record],
                    'mxrecord': [u"0 %s" % idnzone1_mname, u"10 %s" % idnzone1_mname],
                    'nsrecord': nameservers,
                },
            },
        ),


        dict(
            desc='Remove MX record (2) from zone %r using dnsrecord_add' % (idnzone1),
            command=('dnsrecord_del', [idnzone1, idnzone1], {'mxrecord': u"10 %s" % idnzone1_mname }),
            expected={
                'value': [idnzone1_dnsname],
                'summary': None,
                'result': {
                    'idnsname': [_dns_zone_record],
                    'mxrecord': [u"0 %s" % idnzone1_mname],
                    'nsrecord': nameservers,
                },
            },
        ),


        dict(
            desc='Add KX record to zone %r using dnsrecord_add' % (idnzone1),
            command=('dnsrecord_add', [idnzone1, u'@'], {'kxrecord': u"0 %s" % idnzone1_mname }),
            expected={
                'value': _dns_zone_record,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnszone,
                    'dn': idnzone1_dn,
                    'idnsname': [_dns_zone_record],
                    'mxrecord': [u"0 %s" % idnzone1_mname],
                    'kxrecord': [u"0 %s" % idnzone1_mname],
                    'nsrecord': nameservers,
                },
            },
        ),

        dict(
            desc='Retrieve raw zone record of zone %r using dnsrecord_show' % (idnzone1),
            command=('dnsrecord_show', [idnzone1, u'@'], {u'raw' : True}),
            expected={
                'value': _dns_zone_record,
                'summary': None,
                'result': {
                    'dn': idnzone1_dn,
                    'idnsname': [u'@'],
                    'mxrecord': [u"0 %s" % idnzone1_mname_punycoded],
                    'kxrecord': [u"0 %s" % idnzone1_mname_punycoded],
                    'nsrecord': nameservers,
                },
            },
        ),

        dict(
            desc='Add CNAME record to %r using dnsrecord_add' % (idnrescname1),
            command=('dnsrecord_add', [idnzone1, idnrescname1], {'cnamerecord': idndomain1 + u'.'}),
            expected={
                'value': idnrescname1_dnsname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': idnrescname1_dn,
                    'idnsname': [idnrescname1_dnsname],
                    'cnamerecord': [idndomain1 + u'.'],
                },
            },
        ),

        dict(
            desc='Show raw record %r in zone %r' % (idnrescname1, idnzone1),
            command=('dnsrecord_show', [idnzone1, idnrescname1], {u'raw' : True}),
            expected={
                'value': idnrescname1_dnsname,
                'summary': None,
                'result': {
                    'dn': idnrescname1_dn,
                    'idnsname': [idnrescname1_punycoded],
                    'cnamerecord': [idndomain1_punycoded + u'.'],
                },
            },
        ),

        dict(
            desc='Add DNAME record to %r using dnsrecord_add' % (idnresdname1),
            command=('dnsrecord_add', [idnzone1, idnresdname1], {'dnamerecord': idndomain1 + u'.'}),
            expected={
                'value': idnresdname1_dnsname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': idnresdname1_dn,
                    'idnsname': [idnresdname1_dnsname],
                    'dnamerecord': [idndomain1 + u'.'],
                },
            },
        ),

        dict(
            desc='Show raw record %r in zone %r' % (idnresdname1, idnzone1),
            command=('dnsrecord_show', [idnzone1, idnresdname1], {u'raw' : True}),
            expected={
                'value': idnresdname1_dnsname,
                'summary': None,
                'result': {
                    'dn': idnresdname1_dn,
                    'idnsname': [idnresdname1_punycoded],
                    'dnamerecord': [idndomain1_punycoded + u'.'],
                },
            },
        ),

        dict(
            desc='Add SRV record to zone %r using dnsrecord_add' % (idnzone1),
            command=('dnsrecord_add', [idnzone1, u'_foo._tcp'], {'srvrecord': u"0 100 1234 %s" % idnzone1_mname}),
            expected={
                'value': DNSName(u'_foo._tcp'),
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': DN(('idnsname', u'_foo._tcp'), idnzone1_dn),
                    'idnsname': [DNSName(u'_foo._tcp')],
                    'srvrecord': [u"0 100 1234 %s" % idnzone1_mname],
                },
            },
        ),

        dict(
            desc='Show raw record %r in zone %r' % (u'_foo._tcp', idnzone1),
            command=('dnsrecord_show', [idnzone1, u'_foo._tcp'], {u'raw' : True}),
            expected={
                'value': DNSName(u'_foo._tcp'),
                'summary': None,
                'result': {
                    'dn': DN(('idnsname', u'_foo._tcp'), idnzone1_dn),
                    'idnsname': [u'_foo._tcp'],
                    'srvrecord': [u"0 100 1234 %s" % idnzone1_mname_punycoded],
                },
            },
        ),

        dict(
            desc='Show raw record %r in zone %r' % (u'_foo._tcp', idnzone1_punycoded),
            command=('dnsrecord_show', [idnzone1, u'_foo._tcp'], {u'raw' : True}),
            expected={
                'value': DNSName(u'_foo._tcp'),
                'summary': None,
                'result': {
                    'dn': DN(('idnsname', u'_foo._tcp'), idnzone1_dn),
                    'idnsname': [u'_foo._tcp'],
                    'srvrecord': [u"0 100 1234 %s" % idnzone1_mname_punycoded],
                },
            },
        ),

        dict(
            desc='Show structured record %r in zone %r' % (
                u'_foo._tcp', idnzone1
            ),
            command=(
                'dnsrecord_show', [idnzone1, u'_foo._tcp'],
                {u'structured': True, u'all': True}
            ),
            expected={
                'value': DNSName(u'_foo._tcp'),
                'summary': None,
                'result': {
                    'dn': DN(('idnsname', u'_foo._tcp'), idnzone1_dn),
                    'idnsname': [DNSName(u'_foo._tcp')],
                    'dnsrecords': [{
                        u'dnsdata': u'0 100 1234 {}'.format(
                            idnzone1_mname_punycoded),
                        u'dnstype': u'SRV',
                        u'srv_part_port': u'1234',
                        u'srv_part_priority': u'0',
                        u'srv_part_target': idnzone1_mname,
                        u'srv_part_weight': u'100'
                    }],
                    'objectclass': objectclasses.dnsrecord,
                },
            },
        ),

        dict(
            desc='Add AFSDB record to %r using dnsrecord_add' % (dnsafsdbres1),
            command=('dnsrecord_add', [idnzone1, dnsafsdbres1], {
                'afsdb_part_subtype': 0,
                'afsdb_part_hostname' : idnzone1_mname}),
            expected={
                'value': dnsafsdbres1_dnsname,
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': dnsafsdbres1_dn,
                    'idnsname': [dnsafsdbres1_dnsname],
                    'afsdbrecord': [u'0 ' + idnzone1_mname],
                },
            },
        ),

        dict(
            desc='Show raw record %r in zone %r' % (dnsafsdbres1, idnzone1),
            command=('dnsrecord_show', [idnzone1, dnsafsdbres1], {u'raw' : True}),
            expected={
                'value': dnsafsdbres1_dnsname,
                'summary': None,
                'result': {
                    'dn': dnsafsdbres1_dn,
                    'idnsname': [dnsafsdbres1_punycoded],
                    'afsdbrecord': [u'0 ' + idnzone1_mname_punycoded],
                },
            },
        ),


        dict(
            desc='Add A denormalized record in zone %r' % (idnzone1),
            command=('dnsrecord_add', [idnzone1, u'gro\xdf'], {'arecord': u'172.16.0.1'}),
            expected=errors.ConversionError(name='name',
                error=u'domain name \'gro\xdf\' should be normalized to: gross')
        ),


        dict(
            desc='Add A record to %r in zone %r' % (wildcard_rec1, zone1),
            command=('dnsrecord_add', [zone1, wildcard_rec1], {'arecord': wildcard_rec1_addr}),
            expected={
                'value': wildcard_rec1_dnsname,
                'summary': None,
                'result': {
                    'dn': wildcard_rec1_dn,
                    'idnsname': [wildcard_rec1_dnsname],
                    'arecord': [wildcard_rec1_addr],
                    'objectclass': objectclasses.dnsrecord,
                },
            },
        ),


        dict(
            desc='Resolve name %r (wildcard)' % (wildcard_rec1_test1),
            command=('dns_resolve', [wildcard_rec1_test1], {}),
            expected={
                    'result': True,
                    'summary': "Found '%s'" % wildcard_rec1_test1,
                    'value': wildcard_rec1_test1,
                    'messages': ({
                        'message': u"'dns-resolve' is deprecated. The "
                                   u"command may return an unexpected result, "
                                   u"the resolution of the DNS domain is done "
                                   u"on a randomly chosen IPA server.",
                        'code': 13015,
                        'type': u'warning',
                        'name': u'CommandDeprecatedWarning',
                        'data': {
                            'command': u"dns-resolve",
                            'additional_info': u"The command may return an "
                                               u"unexpected result, the "
                                               u"resolution of the DNS domain "
                                               u"is done on a randomly chosen "
                                               u"IPA server."
                        }
                    },)
            },
        ),


        dict(
            desc='Resolve name %r (wildcard)' % (wildcard_rec1_test2),
            command=('dns_resolve', [wildcard_rec1_test2], {}),
            expected={
                    'result': True,
                    'summary': "Found '%s'" % wildcard_rec1_test2,
                    'value': wildcard_rec1_test2,
                    'messages': ({
                        'message': u"'dns-resolve' is deprecated. The "
                                   u"command may return an unexpected result, "
                                   u"the resolution of the DNS domain is done "
                                   u"on a randomly chosen IPA server.",
                        'code': 13015,
                        'type': u'warning',
                        'name': u'CommandDeprecatedWarning',
                        'data': {
                            'command': u"dns-resolve",
                            'additional_info': u"The command may return an "
                                               u"unexpected result, the "
                                               u"resolution of the DNS domain "
                                               u"is done on a randomly chosen "
                                               u"IPA server."
                        }
                    },)
            },
        ),


        dict(
            desc='Try to add NS record to wildcard owner %r in zone %r' % (wildcard_rec1, zone1),
            command=('dnsrecord_add', [zone1, wildcard_rec1], {'nsrecord': zone2_ns, 'force': True}),
            expected=errors.ValidationError(
                name='idnsname',
                error=(u'owner of DNAME, DS, NS records '
                    'should not be a wildcard domain name (RFC 4592 section 4)')
            )
        ),


        dict(
            desc='Try to add DNAME record to wildcard owner %r in zone %r' % (wildcard_rec1, zone1),
            command=('dnsrecord_add', [zone1, wildcard_rec1], {'dnamerecord': u'dname.test.'}),
            expected=errors.ValidationError(
                name='idnsname',
                error=(u'owner of DNAME, DS, NS records '
                    'should not be a wildcard domain name (RFC 4592 section 4)')
            )
        ),


        dict(
            desc='Try to add DS record to wildcard owner %r in zone %r' % (wildcard_rec1, zone1),
            command=('dnsrecord_add', [zone1, wildcard_rec1], {'dsrecord': u'0 0 0 00'}),
            expected=errors.ValidationError(
                name='idnsname',
                error=(u'owner of DNAME, DS, NS records '
                    'should not be a wildcard domain name (RFC 4592 section 4)')
            )
        ),


        dict(
            desc='Disable zone %r' % zone1,
            command=('dnszone_disable', [zone1], {}),
            expected={
                'value': zone1_absolute_dnsname,
                'summary': u'Disabled DNS zone "%s"' % zone1_absolute,
                'result': True,
            },
        ),


        dict(
            desc='Check if zone %r is really disabled' % zone1,
            command=('dnszone_show', [zone1], {}),
            expected={
                'value': zone1_absolute_dnsname,
                'summary': None,
                'result': {
                    'dn': zone1_dn,
                    'idnsname': [zone1_absolute_dnsname],
                    'idnszoneactive': [u'FALSE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'172.16.31.80;'],
                    'idnsallowquery': [allowquery_restricted_out],
                    'mxrecord': [u'0 ns1.dnszone.test.'],
                    'locrecord': [u"49 11 42.400 N 16 36 29.600 E 227.64 10.00 10.00 0.10"],
                },
            },
        ),


        dict(
            desc='Enable zone %r' % zone1,
            command=('dnszone_enable', [zone1], {}),
            expected={
                'value': zone1_absolute_dnsname,
                'summary': u'Enabled DNS zone "%s"' % zone1_absolute,
                'result': True,
            },
        ),


        dict(
            desc='Check if zone %r is really enabled' % zone1,
            command=('dnszone_show', [zone1_absolute], {}),
            expected={
                'value': zone1_absolute_dnsname,
                'summary': None,
                'result': {
                    'dn': zone1_dn,
                    'idnsname': [zone1_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [zone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'172.16.31.80;'],
                    'idnsallowquery': [allowquery_restricted_out],
                    'mxrecord': [u'0 ns1.dnszone.test.'],
                    'locrecord': [u"49 11 42.400 N 16 36 29.600 E 227.64 10.00 10.00 0.10"],
                },
            },
        ),

        dict(
            desc='Disable zone %r' % idnzone1,
            command=('dnszone_disable', [idnzone1], {}),
            expected={
                'value': idnzone1_dnsname,
                'summary': u'Disabled DNS zone "%s"' % idnzone1,
                'result': True,
            },
        ),


        dict(
            desc='Check if zone %r is really disabled' % idnzone1,
            command=('dnszone_show', [idnzone1], {}),
            expected={
                'value': idnzone1_dnsname,
                'summary': None,
                'result': {
                    'dn': idnzone1_dn,
                    'idnsname': [idnzone1_dnsname],
                    'idnszoneactive': [u'FALSE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [idnzone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'mxrecord': [u"0 %s" % idnzone1_mname],
                    'kxrecord': [u"0 %s" % idnzone1_mname],
                },
            },
        ),


        dict(
            desc='Enable zone %r' % idnzone1,
            command=('dnszone_enable', [idnzone1], {}),
            expected={
                'value': idnzone1_dnsname,
                'summary': u'Enabled DNS zone "%s"' % idnzone1,
                'result': True,
            },
        ),


        dict(
            desc='Check if zone %r is really enabled' % idnzone1,
            command=('dnszone_show', [idnzone1], {}),
            expected={
                'value': idnzone1_dnsname,
                'summary': None,
                'result': {
                    'dn': idnzone1_dn,
                    'idnsname': [idnzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': nameservers,
                    'idnssoamname': [self_server_ns_dnsname],
                    'idnssoarname': [idnzone1_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'mxrecord': [u"0 %s" % idnzone1_mname],
                    'kxrecord': [u"0 %s" % idnzone1_mname],
                },
            },
        ),


        dict(
            desc='Delete zone %r' % zone1,
            command=('dnszone_del', [zone1], {}),
            expected={
                'value': [zone1_absolute_dnsname],
                'summary': u'Deleted DNS zone "%s"' % zone1_absolute,
                'result': {'failed': []},
            },
        ),

    ]


@pytest.mark.tier1
class test_root_zone(Declarative):

    @classmethod
    def setup_class(cls):
        super(test_root_zone, cls).setup_class()

        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()

        if not have_ldap2:
            raise nose.SkipTest('server plugin not available')

        if get_nameservers_error is not None:
            raise nose.SkipTest('unable to get list of nameservers (%s)' % get_nameservers_error)

        try:
            api.Command['dnszone_add'](zone1, idnssoarname=zone1_rname,)
            api.Command['dnszone_del'](zone1)
        except errors.NotFound:
            raise nose.SkipTest('DNS is not configured')
        except errors.DuplicateEntry:
            pass

    cleanup_commands = [
        ('dnszone_del', [zone_root, ],
            {'continue': True}),
        ('permission_del', [zone_root_permission, ], {'force': True}),
    ]

    tests = [

        dict(
            desc='Create zone %r' % zone_root,
            command=(
                'dnszone_add', [zone_root], {
                    'idnssoarname': zone_root_rname,
                    'skip_overlap_check': True
                }
            ),
            expected={
                'value': zone_root_dnsname,
                'summary': None,
                'result': {
                    'dn': zone_root_dn,
                    'idnsname': [zone_root_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone_root_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-self * A; '
                                         u'grant %(realm)s krb5-self * AAAA; '
                                         u'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),

        dict(
            desc='Add per-zone permission for zone %r' % zone_root,
            command=(
                'dnszone_add_permission', [zone_root], {}
            ),
            expected=dict(
                result=True,
                value=zone_root_permission,
                summary=u'Added system permission "%s"' % zone_root_permission,
            ),
        ),

    ]


@pytest.mark.tier1
class test_forward_zones(Declarative):
    # https://fedorahosted.org/freeipa/ticket/4750

    @classmethod
    def setup_class(cls):
        super(test_forward_zones, cls).setup_class()

        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()

        if not have_ldap2:
            raise nose.SkipTest('server plugin not available')

        try:
            api.Command['dnszone_add'](zone1, idnssoarname=zone1_rname,)
            api.Command['dnszone_del'](zone1)
        except errors.NotFound:
            raise nose.SkipTest('DNS is not configured')
        except errors.DuplicateEntry:
            pass


    cleanup_commands = [
        ('dnsforwardzone_del', [zone_fw_wildcard, fwzone1, fwzone2, fwzone3],
            {'continue': True}),
        ('permission_del', [fwzone1_permission, ], {'force': True}),
    ]

    tests = [

        dict(
            desc='Search for forward zone with --forward-policy=none (no zones)',
            command=('dnsforwardzone_find', [], {'idnsforwardpolicy': u'none'}),
            expected={
                'summary': None,
                'count': 0,
                'truncated': False,
                'result': [],
            },
        ),


        dict(
            desc='Search for forward zone with --forward-policy=only (no zones)',
            command=('dnsforwardzone_find', [], {'idnsforwardpolicy': u'only'}),
            expected={
                'summary': None,
                'count': 0,
                'truncated': False,
                'result': [],
            },
        ),


        dict(
            desc='Search for forward zone with --forward-policy=first (no zones)',
            command=('dnsforwardzone_find', [], {'idnsforwardpolicy': u'first'}),
            expected={
                'summary': None,
                'count': 0,
                'truncated': False,
                'result': [],
            },
        ),


        dict(
            desc='Try to create forward zone %r with wildcard domain name' % zone_fw_wildcard,
            command=(
                'dnsforwardzone_add', [zone_fw_wildcard], {'idnsforwardpolicy': u'none'}
            ),
            expected=errors.ValidationError(name='name',
                                        error=u'should not be a wildcard domain name (RFC 4592 section 4)')
        ),


        dict(
            desc='Try to create forward zone with empty name',
            command=(
                'dnsforwardzone_add', [u''], {}
            ),
            expected=errors.RequirementError(name='name')
        ),


        dict(
            desc='Try to create forward zone %r with invalid name' % 'invalid..name.fwzone.test.',
            command=(
                'dnsforwardzone_add', [u'invalid..name.fwzone.test.', ], {}
            ),
            expected=errors.ConversionError(
                name='name',
                error=u'empty DNS label')
        ),


        dict(
            desc='Try to create forward zone %r without forwarders with default "(first)" policy' % fwzone1,
            command=(
                'dnsforwardzone_add', [fwzone1], {}
            ),
            expected=errors.ValidationError(name='idnsforwarders',
                                        error=u'Please specify forwarders.')
        ),


        dict(
            desc='Try to create forward zone %r without forwarders with "only" policy' % fwzone1,
            command=(
                'dnsforwardzone_add', [fwzone1], {'idnsforwardpolicy': u'only'}
            ),
            expected=errors.ValidationError(name='idnsforwarders',
                                        error=u'Please specify forwarders.')
        ),


        dict(
            desc='Try to create forward zone %r without forwarders with "first" policy' % fwzone1,
            command=(
                'dnsforwardzone_add', [fwzone1], {'idnsforwardpolicy': u'first'}
            ),
            expected=errors.ValidationError(
                name='idnsforwarders',
                error=u'Please specify forwarders.')
        ),


        dict(
            desc='Try to create forward zone %r with "only" policy and invalid IP address' % fwzone1,
            command=(
                'dnsforwardzone_add', [fwzone1], {
                    'idnsforwardpolicy': u'only',
                    'idnsforwarders': [u'127.0.0.999', ]
                }
            ),
            expected=errors.ValidationError(
                name='forwarder',
                error=u'invalid IP address format')
        ),


        dict(
            desc='Try to create forward zone %r with "first" policy and invalid IP address' % fwzone1,
            command=(
                'dnsforwardzone_add', [fwzone1], {
                    'idnsforwardpolicy': u'first',
                    'idnsforwarders': [u'127.0.0.999', ]
                }
            ),
            expected=errors.ValidationError(
                name='forwarder',
                error=u'invalid IP address format')
        ),


        dict(
            desc='Try to create forward zone %r with invalid policy' % fwzone1,
            command=(
                'dnsforwardzone_add', [fwzone1], {
                    'idnsforwardpolicy': u'invalid',
                }
            ),
            expected=errors.ValidationError(
                name='forward_policy',
                error=u"must be one of 'only', 'first', 'none'")
        ),


        dict(
            desc='Create forward zone %r without forwarders with "none" policy' % fwzone1,
            command=(
                'dnsforwardzone_add', [fwzone1], {'idnsforwardpolicy': u'none'}
            ),
            expected={
                'value': fwzone1_dnsname,
                'summary': None,
                'result': {
                    'dn': fwzone1_dn,
                    'idnsname': [fwzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'none'],
                    'objectclass': objectclasses.dnsforwardzone,
                },
            },
        ),


        dict(
            desc='Try to create duplicate forward zone %r' % fwzone1,
            command=(
                'dnsforwardzone_add', [fwzone1], {'idnsforwardpolicy': u'none'}
            ),
            expected=errors.DuplicateEntry(
                message=u'DNS forward zone with name "%s" already exists' % fwzone1),
        ),


        dict(
            desc='Create forward zone %r with forwarders with default ("first") policy' % fwzone2,
            command=(
                'dnsforwardzone_add', [fwzone2], {'idnsforwarders': [forwarder1]}
            ),
            expected={
                'value': fwzone2_dnsname,
                'summary': None,
                u'messages': ({u'message': lambda x: x.startswith(
                        u"DNS server %s: query '%s SOA':" %
                        (forwarder1, fwzone2)),
                     u'code': 13006,
                     u'type':u'warning',
                     u'name': u'DNSServerValidationWarning',
                     u'data': {
                        u'error': lambda x: x.startswith(
                            u"query '%s SOA':" % fwzone2),
                        u'server': u"%s" % forwarder1
                     }},
                ),
                'result': {
                    'dn': fwzone2_dn,
                    'idnsname': [fwzone2_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'first'],
                    'idnsforwarders': [forwarder1],
                    'objectclass': objectclasses.dnsforwardzone,
                },
            },
        ),


        dict(
            desc='Delete forward zone %r (cleanup)' % fwzone2,
            command=('dnsforwardzone_del', [fwzone2], {}),
            expected={
                'value': [fwzone2_dnsname],
                'summary': u'Deleted DNS forward zone "%s"' % fwzone2,
                'result': {'failed': []},
            },
        ),


        dict(
            desc='Create forward zone %r with three forwarders with "only" policy' % fwzone2,
            command=(
                'dnsforwardzone_add', [fwzone2], {
                    'idnsforwarders': [forwarder1, forwarder2, forwarder3],
                    'idnsforwardpolicy': u'only'
                }
            ),
            expected={
                'value': fwzone2_dnsname,
                'summary': None,
                'messages': lambda x: True,  # fake forwarders - ignore message
                'result': {
                    'dn': fwzone2_dn,
                    'idnsname': [fwzone2_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'only'],
                    'idnsforwarders': [forwarder1, forwarder2, forwarder3],
                    'objectclass': objectclasses.dnsforwardzone,
                },
            },
        ),


        dict(
            desc='Delete forward zone %r (cleanup)' % fwzone2,
            command=('dnsforwardzone_del', [fwzone2], {}),
            expected={
                'value': [fwzone2_dnsname],
                'summary': u'Deleted DNS forward zone "%s"' % fwzone2,
                'result': {'failed': []},
            },
        ),


        dict(
            desc='Create forward zone %r with one forwarder with "only" policy' % fwzone2,
            command=(
                'dnsforwardzone_add', [fwzone2], {
                    'idnsforwarders': forwarder2, 'idnsforwardpolicy': u'only'
                }
            ),
            expected={
                'value': fwzone2_dnsname,
                'summary': None,
                'messages': lambda x: True,  # fake forwarders - ignore message
                'result': {
                    'dn': fwzone2_dn,
                    'idnsname': [fwzone2_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'only'],
                    'idnsforwarders': [forwarder2],
                    'objectclass': objectclasses.dnsforwardzone,
                },
            },
        ),


        dict(
            desc='Create forward zone %r with three forwarders with "first" policy' % fwzone3,
            command=(
                'dnsforwardzone_add', [fwzone3], {
                    'idnsforwarders': [forwarder1, forwarder2, forwarder3],
                    'idnsforwardpolicy': u'first'
                }
            ),
            expected={
                'value': fwzone3_dnsname,
                'summary': None,
                'messages': lambda x: True,  # fake forwarders - ignore message
                'result': {
                    'dn': fwzone3_dn,
                    'idnsname': [fwzone3_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'first'],
                    'idnsforwarders': [forwarder1, forwarder2, forwarder3],
                    'objectclass': objectclasses.dnsforwardzone,
                },
            },
        ),


        dict(
            desc='Delete forward zone %r (cleanup)' % fwzone3,
            command=('dnsforwardzone_del', [fwzone3], {}),
            expected={
                'value': [fwzone3_dnsname],
                'summary': u'Deleted DNS forward zone "%s"' % fwzone3,
                'result': {'failed': []},
            },
        ),


        dict(
            desc='Create forward zone %r with one forwarder with "first" policy' % fwzone3,
            command=(
                'dnsforwardzone_add', [fwzone3], {
                    'idnsforwarders': forwarder3, 'idnsforwardpolicy': u'first'
                }
            ),
            expected={
                'value': fwzone3_dnsname,
                'summary': None,
                'messages': lambda x: True,  # fake forwarders - ignore message
                'result': {
                    'dn': fwzone3_dn,
                    'idnsname': [fwzone3_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'first'],
                    'idnsforwarders': [forwarder3],
                    'objectclass': objectclasses.dnsforwardzone,
                },
            },
        ),



        dict(
            desc='Modify forward zone %r change one forwarder' % fwzone3,
            command=(
                'dnsforwardzone_mod', [fwzone3], {
                    'idnsforwarders': forwarder1,
                }
            ),
            expected={
                'value': fwzone3_dnsname,
                'summary': None,
                'messages': lambda x: True,  # fake forwarders - ignore message
                'result': {
                    'idnsname': [fwzone3_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'first'],
                    'idnsforwarders': [forwarder1],
                },
            },
        ),


        dict(
            desc='Modify forward zone %r add one forwarder' % fwzone3,
            command=(
                'dnsforwardzone_mod', [fwzone3], {
                    'idnsforwarders': [forwarder1, forwarder2]
                }
            ),
            expected={
                'value': fwzone3_dnsname,
                'summary': None,
                'messages': lambda x: True,  # fake forwarders - ignore message
                'result': {
                    'idnsname': [fwzone3_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'first'],
                    'idnsforwarders': [forwarder1, forwarder2],
                },
            },
        ),


        dict(
            desc='Modify forward zone %r change one forwarder if two exists' % fwzone3,
            command=(
                'dnsforwardzone_mod', [fwzone3], {
                    'idnsforwarders': [forwarder1, forwarder3]
                }
            ),
            expected={
                'value': fwzone3_dnsname,
                'summary': None,
                'messages': lambda x: True,  # fake forwarders - ignore message
                'result': {
                    'idnsname': [fwzone3_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'first'],
                    'idnsforwarders': [forwarder1, forwarder3],
                },
            },
        ),


        dict(
            desc='Modify forward zone %r change two forwarders if two exists' % fwzone3,
            command=(
                'dnsforwardzone_mod', [fwzone3], {
                    'idnsforwarders': [forwarder2, forwarder4]
                }
            ),
            expected={
                'value': fwzone3_dnsname,
                'summary': None,
                'messages': lambda x: True,  # fake forwarders - ignore message
                'result': {
                    'idnsname': [fwzone3_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'first'],
                    'idnsforwarders': [forwarder2, forwarder4],
                },
            },
        ),


        dict(
            desc='Modify forward zone %r with --policy=none, add forwarders' % fwzone1,
            command=(
                'dnsforwardzone_mod', [fwzone1], {
                    'idnsforwardpolicy': u'none',
                    'idnsforwarders': [forwarder3],
                }
            ),
            expected={
                'value': fwzone1_dnsname,
                'summary': None,
                'messages': lambda x: True,  # fake forwarders - ignore message
                'result': {
                    'idnsname': [fwzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'none'],
                    'idnsforwarders': [forwarder3],
                },
            },
        ),


        dict(
            desc='Modify forward zone %r change --policy=none' % fwzone2,
            command=(
                'dnsforwardzone_mod', [fwzone2], {
                    'idnsforwardpolicy': u'none',
                }
            ),
            expected={
                'value': fwzone2_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [fwzone2_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'none'],
                    'idnsforwarders': [forwarder2],
                },
            },
        ),


        dict(
            desc='Modify forward zone %r change --policy=only (was "none", FW exists)' % fwzone2,
            command=(
                'dnsforwardzone_mod', [fwzone2], {
                    'idnsforwardpolicy': u'only',
                }
            ),
            expected={
                'value': fwzone2_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [fwzone2_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'only'],
                    'idnsforwarders': [forwarder2],
                },
            },
        ),


        dict(
            desc='Modify forward zone %r with --policy=first (was "none", FW exists)' % fwzone1,
            command=(
                'dnsforwardzone_mod', [fwzone1], {
                    'idnsforwardpolicy': u'first',
                    'idnsforwarders': [forwarder3],
                }
            ),
            expected={
                'value': fwzone1_dnsname,
                'summary': None,
                'messages': lambda x: True,  # fake forwarders - ignore message
                'result': {
                    'idnsname': [fwzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'first'],
                    'idnsforwarders': [forwarder3],
                },
            },
        ),


        dict(
            desc='Modify forward zone %r with --policy=none, forwarder empty' % fwzone1,
            command=(
                'dnsforwardzone_mod', [fwzone1], {
                    'idnsforwardpolicy': u'none',
                    'idnsforwarders': [],
                }
            ),
            expected={
                'value': fwzone1_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [fwzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'none'],
                },
            },
        ),


        dict(
            desc='Modify forward zone %r --policy=only, add forwarders"' % fwzone1,
            command=(
                'dnsforwardzone_mod', [fwzone1], {
                    'idnsforwardpolicy': u'only',
                    'idnsforwarders': [forwarder1, forwarder2]
                }
            ),
            expected={
                'value': fwzone1_dnsname,
                'summary': None,
                'messages': lambda x: True,  # fake forwarders - ignore message
                'result': {
                    'idnsname': [fwzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'only'],
                    'idnsforwarders': [forwarder1, forwarder2],
                },
            },
        ),


        dict(
            desc='Modify forward zone %r --policy=first (was "only")' % fwzone1,
            command=(
                'dnsforwardzone_mod', [fwzone1], {
                    'idnsforwardpolicy': u'first',
                }
            ),
            expected={
                'value': fwzone1_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [fwzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'first'],
                    'idnsforwarders': [forwarder1, forwarder2],
                },
            },
        ),


        dict(
            desc='Modify forward zone %r --policy=only (was "first")' % fwzone1,
            command=(
                'dnsforwardzone_mod', [fwzone1], {
                    'idnsforwardpolicy': u'only',
                }
            ),
            expected={
                'value': fwzone1_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [fwzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'only'],
                    'idnsforwarders': [forwarder1, forwarder2],
                },
            },
        ),


        dict(
            desc='Modify forward zone %r with --policy=none, forwarder empty (cleanup)' % fwzone1,
            command=(
                'dnsforwardzone_mod', [fwzone1], {
                    'idnsforwardpolicy': u'none',
                    'idnsforwarders': [],
                }
            ),
            expected={
                'value': fwzone1_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [fwzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'none'],
                },
            },
        ),


        dict(
            desc='Try to modify non-existent forward zone %r' % nonexistent_fwzone,
            command=(
                'dnsforwardzone_mod', [nonexistent_fwzone], {
                    'idnsforwardpolicy': u'only'
                }
            ),
            expected=errors.NotFound(reason="%s: DNS forward zone not found" %
                                     nonexistent_fwzone)
        ),


        dict(
            desc='Try to modify forward zone %r without forwarders with "only" policy' % fwzone1,
            command=(
                'dnsforwardzone_mod', [fwzone1], {
                    'idnsforwardpolicy': u'only'
                }
            ),
            expected=errors.ValidationError(name='idnsforwarders',
                                        error=u'Please specify forwarders.')
        ),


        dict(
            desc='Try to modify forward zone %r without forwarders with "first" policy' % fwzone1,
            command=(
                'dnsforwardzone_mod', [fwzone1], {
                    'idnsforwardpolicy': u'first'
                }
            ),
            expected=errors.ValidationError(name='idnsforwarders',
                                        error=u'Please specify forwarders.')
        ),


        dict(
            desc='Try to modify forward zone %r with "only" policy change empty forwarders' % fwzone2,
            command=(
                'dnsforwardzone_mod', [fwzone2], {
                    'idnsforwarders': [],
                }
            ),
            expected=errors.ValidationError(
                name='idnsforwarders',
                error=u'Please specify forwarders.')
        ),


        dict(
            desc='Try to modify forward zone %r with "first" policy change empty forwarders' % fwzone3,
            command=(
                'dnsforwardzone_mod', [fwzone3], {
                    'idnsforwarders': [],
                }
            ),
            expected=errors.ValidationError(
                name='idnsforwarders',
                error=u'Please specify forwarders.')
        ),


        dict(
            desc='Try to modify forward zone %r with "only" policy change invalid forwarder IP' % fwzone2,
            command=(
                'dnsforwardzone_mod', [fwzone2], {
                    'idnsforwarders': [u'127.0.0.999', ],
                }
            ),
            expected=errors.ValidationError(
                name='forwarder',
                error=u'invalid IP address format')
        ),


        dict(
            desc='Try to modify forward zone %r with "first" policy change invalid forwarder IP' % fwzone3,
            command=(
                'dnsforwardzone_mod', [fwzone3], {
                    'idnsforwarders': [u'127.0.0.999', ],
                }
            ),
            expected=errors.ValidationError(
                name='forwarder',
                error=u'invalid IP address format')
        ),


        dict(
            desc='Try to modify forward zone %r with invalid policy' % fwzone1,
            command=(
                'dnsforwardzone_mod', [fwzone1], {
                    'idnsforwardpolicy': u'invalid',
                }
            ),
            expected=errors.ValidationError(
                name='forward_policy',
                error=u"must be one of 'only', 'first', 'none'")
        ),


        dict(
            desc='Retrieve forward zone %r' % fwzone1,
            command=(
                'dnsforwardzone_show', [fwzone1], {}
            ),
            expected={
                'value': fwzone1_dnsname,
                'summary': None,
                'result': {
                    'dn': fwzone1_dn,
                    'idnsname': [fwzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'none'],
                },
            },
        ),


        dict(
            desc='Try to retrieve nonexistent forward zone %r' % nonexistent_fwzone,
            command=(
                'dnsforwardzone_show', [nonexistent_fwzone], {}
            ),
            expected=errors.NotFound(reason="%s: DNS forward zone not found" %
                                     nonexistent_fwzone)
        ),


        dict(
            desc='Search for all forward zones',
            command=('dnsforwardzone_find', [], {}),
            expected={
                'summary': None,
                'count': 3,
                'truncated': False,
                'result': [
                    {
                        'dn': fwzone1_dn,
                        'idnsname': [fwzone1_dnsname],
                        'idnszoneactive': [u'TRUE'],
                        'idnsforwardpolicy': [u'none'],
                    },
                    {
                        'dn': fwzone2_dn,
                        'idnsname': [fwzone2_dnsname],
                        'idnszoneactive': [u'TRUE'],
                        'idnsforwardpolicy': [u'only'],
                        'idnsforwarders': [forwarder2],
                    },
                    {
                        'dn': fwzone3_dn,
                        'idnsname': [fwzone3_dnsname],
                        'idnszoneactive': [u'TRUE'],
                        'idnsforwardpolicy': [u'first'],
                        'idnsforwarders': [forwarder2, forwarder4],
                    },
                ],
            },
        ),


        dict(
            desc='Search for all forward zones with --pkey-only',
            command=('dnsforwardzone_find', [], {'pkey_only': True}),
            expected={
                'summary': None,
                'count': 3,
                'truncated': False,
                'result': [
                    {
                        'dn': fwzone1_dn,
                        'idnsname': [fwzone1_dnsname],
                    },
                    {
                        'dn': fwzone2_dn,
                        'idnsname': [fwzone2_dnsname],
                    },
                    {
                        'dn': fwzone3_dn,
                        'idnsname': [fwzone3_dnsname],
                    },
                ],
            },
        ),


        dict(
            desc='Search for forward zone %r' % fwzone1,
            command=('dnsforwardzone_find', [fwzone1], {}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [{
                    'dn': fwzone1_dn,
                    'idnsname': [fwzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'none'],
                }],
            },
        ),


        dict(
            desc='Search for 3 forward zones search with criteria "%r"' % fwzone_search_all_name,
            command=('dnsforwardzone_find', [fwzone_search_all_name], {}),
            expected={
                'summary': None,
                'count': 3,
                'truncated': False,
                'result': [
                    {
                        'dn': fwzone1_dn,
                        'idnsname': [fwzone1_dnsname],
                        'idnszoneactive': [u'TRUE'],
                        'idnsforwardpolicy': [u'none'],
                    },
                    {
                        'dn': fwzone2_dn,
                        'idnsname': [fwzone2_dnsname],
                        'idnszoneactive': [u'TRUE'],
                        'idnsforwardpolicy': [u'only'],
                        'idnsforwarders': [forwarder2],
                    },
                    {
                        'dn': fwzone3_dn,
                        'idnsname': [fwzone3_dnsname],
                        'idnszoneactive': [u'TRUE'],
                        'idnsforwardpolicy': [u'first'],
                        'idnsforwarders': [forwarder2, forwarder4],
                    },
                ],
            },
        ),


        dict(
            desc='Search for forward zone with --name %r' % fwzone1,
            command=('dnsforwardzone_find', [], {'idnsname': fwzone1}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [
                    {
                        'dn': fwzone1_dn,
                        'idnsname': [fwzone1_dnsname],
                        'idnszoneactive': [u'TRUE'],
                        'idnsforwardpolicy': [u'none'],
                    }
                ],
            },
        ),


        dict(
            desc='Search for forward zone with --forward-policy=none',
            command=('dnsforwardzone_find', [], {'idnsforwardpolicy': u'none'}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [
                    {
                        'dn': fwzone1_dn,
                        'idnsname': [fwzone1_dnsname],
                        'idnszoneactive': [u'TRUE'],
                        'idnsforwardpolicy': [u'none'],
                    }
                ],
            },
        ),


        dict(
            desc='Search for forward zone with --forward-policy=only',
            command=('dnsforwardzone_find', [], {'idnsforwardpolicy': u'only'}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [
                    {
                        'dn': fwzone2_dn,
                        'idnsname': [fwzone2_dnsname],
                        'idnszoneactive': [u'TRUE'],
                        'idnsforwardpolicy': [u'only'],
                        'idnsforwarders': [forwarder2],
                    }
                ],
            },
        ),


        dict(
            desc='Search for forward zone with --forward-policy=first',
            command=('dnsforwardzone_find', [], {'idnsforwardpolicy': u'first'}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [
                    {
                        'dn': fwzone3_dn,
                        'idnsname': [fwzone3_dnsname],
                        'idnszoneactive': [u'TRUE'],
                        'idnsforwardpolicy': [u'first'],
                        'idnsforwarders': [forwarder2, forwarder4],
                    }
                ],
            },
        ),


        dict(
            desc='Try to search for non-existent forward zone',
            command=('dnsforwardzone_find', [nonexistent_fwzone], {}),
            expected={
                'summary': None,
                'count': 0,
                'truncated': False,
                'result': [],
            },
        ),


        dict(
            desc='Try to search for non-existent forward zone with --name',
            command=('dnsforwardzone_find', [], {'idnsname': nonexistent_fwzone}),
            expected={
                'summary': None,
                'count': 0,
                'truncated': False,
                'result': [],
            },
        ),


        dict(
            desc='Delete forward zone %r' % fwzone2,
            command=('dnsforwardzone_del', [fwzone2], {}),
            expected={
                'value': [fwzone2_dnsname],
                'summary': u'Deleted DNS forward zone "%s"' % fwzone2,
                'result': {'failed': []},
            },
        ),


        dict(
            desc='Delete forward zone %r with --continue' % fwzone3,
            command=('dnsforwardzone_del', [fwzone3], {'continue': True}),
            expected={
                'value': [fwzone3_dnsname],
                'summary': u'Deleted DNS forward zone "%s"' % fwzone3,
                'result': {'failed': []},
            },
        ),


        dict(
            desc='Try to delete non-existent forward zone',
            command=('dnsforwardzone_del', [nonexistent_fwzone], {}),
            expected=errors.NotFound(reason="%s: DNS forward zone not found" %
                                     nonexistent_fwzone)
        ),


        dict(
            desc='Try to delete non-existent forward zone with --continue',
            command=('dnsforwardzone_del', [nonexistent_fwzone], {'continue': True}),
            expected={
                'value': [],
                'summary': u'Deleted DNS forward zone ""',
                'result': {
                    'failed': [nonexistent_fwzone_dnsname],
                }
            }
        ),


        dict(
            desc='Try to add per-zone permission for unknown forward zone',
            command=('dnsforwardzone_add_permission', [absnxname], {}),
            expected=errors.NotFound(reason=u'%s: DNS forward zone not found' % absnxname)
        ),


        dict(
            desc='Add per-zone permission for forward zone %r' % fwzone1,
            command=(
                'dnsforwardzone_add_permission', [fwzone1], {}
            ),
            expected=dict(
                result=True,
                value=fwzone1_permission,
                summary=u'Added system permission "%s"' % fwzone1_permission,
            ),
        ),


        dict(
            desc='Try to add duplicate per-zone permission for forward zone %r' % fwzone1,
            command=(
                'dnsforwardzone_add_permission', [fwzone1], {}
            ),
            expected=errors.DuplicateEntry(message=u'permission with name '
                '"%s" already exists' % fwzone1_permission)
        ),

        dict(
            desc='Make sure the permission was created %r' % fwzone1,
            command=(
                'permission_show', [fwzone1_permission], {}
            ),
            expected=dict(
                value=fwzone1_permission,
                summary=None,
                result={
                    'dn': fwzone1_permission_dn,
                    'cn': [fwzone1_permission],
                    'objectclass': objectclasses.system_permission,
                    'ipapermissiontype': [u'SYSTEM'],
                },
            ),
        ),

        dict(
            desc='Retrieve the permission %r with --all --raw' % fwzone1,
            command=(
                'permission_show', [fwzone1_permission], {}
            ),
            expected=dict(
                value=fwzone1_permission,
                summary=None,
                result={
                    'dn': fwzone1_permission_dn,
                    'cn': [fwzone1_permission],
                    'objectclass': objectclasses.system_permission,
                    'ipapermissiontype': [u'SYSTEM'],
                },
            ),
        ),

        dict(
            desc='Try to remove per-zone permission for unknown forward zone',
            command=('dnsforwardzone_remove_permission', [absnxname], {}),
            expected=errors.NotFound(reason=u'%s: DNS forward zone not found'
                % absnxname)
        ),

        dict(
            desc='Remove per-zone permission for forward zone %r' % fwzone1,
            command=(
                'dnsforwardzone_remove_permission', [fwzone1], {}
            ),
            expected=dict(
                result=True,
                value=fwzone1_permission,
                summary=u'Removed system permission "%s"' % fwzone1_permission,
            ),
        ),


        dict(
            desc='Make sure the permission for forward zone %r was deleted' % fwzone1,
            command=(
                'permission_show', [fwzone1_permission], {}
            ),
            expected=errors.NotFound(reason=u'%s: permission not found'
                                     % fwzone1_permission)
        ),


        dict(
            desc='Try to remove per-zone permission for forward zone %r (permission does not exist)' % fwzone1,
            command=(
                'dnsforwardzone_remove_permission', [fwzone1], {}
            ),
            expected=errors.NotFound(reason=u'%s: permission not found'
                                     % fwzone1_permission)
        ),


        dict(
            desc='Disable forward zone %r' % fwzone1,
            command=('dnsforwardzone_disable', [fwzone1], {}),
            expected={
                'value': fwzone1_dnsname,
                'summary': u'Disabled DNS forward zone "%s"' % fwzone1,
                'result': True,
            },
        ),


        dict(
            desc='Check if forward zone %r is really disabled' % fwzone1,
            command=('dnsforwardzone_show', [fwzone1], {}),
            expected={
                'value': fwzone1_dnsname,
                'summary': None,
                'result': {
                    'dn': fwzone1_dn,
                    'idnsname': [fwzone1_dnsname],
                    'idnszoneactive': [u'FALSE'],
                    'idnsforwardpolicy': [u'none'],
                },
            },
        ),


        dict(
            desc='Disable already disabled forward zone %r' % fwzone1,
            command=('dnsforwardzone_disable', [fwzone1], {}),
            expected={
                'value': fwzone1_dnsname,
                'summary': u'Disabled DNS forward zone "%s"' % fwzone1,
                'result': True,
            },
        ),


        dict(
            desc='Try to disable non-existent forward zone',
            command=('dnsforwardzone_disable', [nonexistent_fwzone], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS forward zone not found' % nonexistent_fwzone
                )
        ),


        dict(
            desc='Enable forward zone %r' % fwzone1,
            command=('dnsforwardzone_enable', [fwzone1], {}),
            expected={
                'value': fwzone1_dnsname,
                'summary': u'Enabled DNS forward zone "%s"' % fwzone1,
                'result': True,
            },
        ),


        dict(
            desc='Check if forward zone %r is really enabled' % fwzone1,
            command=('dnsforwardzone_show', [fwzone1], {}),
            expected={
                'value': fwzone1_dnsname,
                'summary': None,
                'result': {
                    'dn': fwzone1_dn,
                    'idnsname': [fwzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'none'],
                },
            },
        ),


        dict(
            desc='Enable already enabled forward zone %r' % fwzone1,
            command=('dnsforwardzone_enable', [fwzone1], {}),
            expected={
                'value': fwzone1_dnsname,
                'summary': u'Enabled DNS forward zone "%s"' % fwzone1,
                'result': True,
            },
        ),


        dict(
            desc='Try to enable non-existent forward zone',
            command=('dnsforwardzone_enable', [nonexistent_fwzone], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS forward zone not found' % nonexistent_fwzone
                )
        ),

    ]


@pytest.mark.tier1
class test_forward_master_zones_mutual_exlusion(Declarative):
    # https://fedorahosted.org/freeipa/ticket/4750

    @classmethod
    def setup_class(cls):
        super(test_forward_master_zones_mutual_exlusion, cls).setup_class()

        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()

        if not have_ldap2:
            raise nose.SkipTest('server plugin not available')

        try:
            api.Command['dnszone_add'](zone1, idnssoarname=zone1_rname,)
            api.Command['dnszone_del'](zone1)
        except errors.NotFound:
            raise nose.SkipTest('DNS is not configured')
        except errors.DuplicateEntry:
            pass


    cleanup_commands = [
        ('dnszone_del', [zone1, zone_findtest_master], {'continue': True}),
        ('dnsforwardzone_del', [fwzone1, zone_findtest_forward],
            {'continue': True}),
        ('permission_del', [fwzone1_permission, ], {'force': True}),
    ]

    tests = [
        dict(
            desc='Create zone %r' % zone1,
            command=(
                'dnszone_add', [zone1], {
                    'idnssoarname': zone1_rname,
                }
            ),
            expected={
                'value': zone1_absolute_dnsname,
                'summary': None,
                'result': {
                    'dn': zone1_dn,
                    'idnsname': [zone1_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': lambda x: True,  # don't care in this test
                    'nsrecord': lambda x: True,  # don't care in this test
                    'idnssoarname': lambda x: True,  # don't care in this test
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': lambda x: True,  # don't care in this test
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(
            desc='Create forward zone %r without forwarders with "none" policy' % fwzone1,
            command=(
                'dnsforwardzone_add', [fwzone1], {'idnsforwardpolicy': u'none'}
            ),
            expected={
                'value': fwzone1_dnsname,
                'summary': None,
                'result': {
                    'dn': fwzone1_dn,
                    'idnsname': [fwzone1_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'none'],
                    'objectclass': objectclasses.dnsforwardzone,
                },
            },
        ),


        dict(
            desc='Try to create duplicate zone which is already forward zone %r' % fwzone1,
            command=(
                'dnszone_add', [fwzone1], {
                    'idnssoarname': zone1_rname,
                }
            ),
            expected=errors.DuplicateEntry(
                message=u'Only one zone type is allowed per zone name'),
        ),


        dict(
            desc='Try to create duplicate forward zone which is already master zone %r' % zone1,
            command=(
                'dnsforwardzone_add', [zone1], {
                    'idnsforwardpolicy': u'none',
                }
            ),
            expected=errors.DuplicateEntry(
                message=u'Only one zone type is allowed per zone name'),
        ),


        dict(
            desc='Try to modify forward zone %r using dnszone-mod' % fwzone1,
            command=(
                'dnszone_mod', [fwzone1], {
                    'idnssoarname': zone1_rname,
                }
            ),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % fwzone1),
        ),


        dict(
            desc='Try to modify master zone %r using dnsforwardzone-mod' % zone1,
            command=(
                'dnsforwardzone_mod', [zone1], {
                    'idnsforwardpolicy': u'none',
                }
            ),
            expected=errors.NotFound(
                reason=u'%s: DNS forward zone not found' % zone1_absolute),
        ),


        dict(
            desc='Try to delete forward zone %r using dnszone-del' % fwzone1,
            command=('dnszone_del', [fwzone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % fwzone1),
        ),


        dict(
            desc='Try to delete master zone %r using dnsforwardzone-del' % zone1,
            command=('dnsforwardzone_del', [zone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS forward zone not found' % zone1_absolute),
        ),


        dict(
            desc='Try to retrieve forward zone %r using dnszone-show' % fwzone1,
            command=('dnszone_show', [fwzone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % fwzone1),
        ),


        dict(
            desc='Try to retrieve master zone %r using dnsforwardzone-show' % zone1,
            command=('dnsforwardzone_show', [zone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS forward zone not found' % zone1_absolute),
        ),


        dict(
            desc='Try to add per-zone permission for forward zone %r using dnszone-add-permission' % fwzone1,
            command=('dnszone_add_permission', [fwzone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % fwzone1),
        ),


        dict(
            desc='Try to add per-zone permission for master zone %r using dnsforwardzone-add-permission' % zone1,
            command=('dnsforwardzone_add_permission', [zone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS forward zone not found' % zone1_absolute),
        ),

        dict(
            desc='Try to remove per-zone permission for forward zone %r using dnszone-remove-permission' % fwzone1,
            command=('dnszone_remove_permission', [fwzone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % fwzone1),
        ),


        dict(
            desc='Try to remove per-zone permission for master zone %r using dnsforwardzone-remove-permission' % zone1,
            command=('dnsforwardzone_remove_permission', [zone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS forward zone not found' % zone1_absolute),
        ),


        dict(
            desc='Try to disable forward zone %r using dnszone-disable' % fwzone1,
            command=('dnszone_disable', [fwzone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % fwzone1),
        ),


        dict(
            desc='Try to disable zone %r using dnsforwardzone-disable' % zone1,
            command=('dnsforwardzone_disable', [zone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS forward zone not found' % zone1_absolute),
        ),


        dict(
            desc='Try to enable forward zone %r using dnszone-disable' % fwzone1,
            command=('dnszone_enable', [fwzone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % fwzone1),
        ),


        dict(
            desc='Try to enable zone %r using dnsforwardzone-disable' % zone1,
            command=('dnsforwardzone_enable', [zone1], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS forward zone not found' % zone1_absolute),
        ),


        dict(
            desc='Create zone %r' % zone_findtest_master,
            command=(
                'dnszone_add', [zone_findtest_master], {
                    'idnssoarname': zone_findtest_master_rname,
                }
            ),
            expected={
                'value': zone_findtest_master_dnsname,
                'summary': None,
                'result': {
                    'dn': zone_findtest_master_dn,
                    'idnsname': [zone_findtest_master_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': lambda x: True,  # don't care in this test
                    'nsrecord': lambda x: True,  # don't care in this test
                    'idnssoarname': lambda x: True,  # don't care in this test
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': lambda x: True,  # don't care in this test
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),


        dict(
            desc='Create forward zone %r' % zone_findtest_forward,
            command=(
                'dnsforwardzone_add', [zone_findtest_forward],
                 {'idnsforwarders': [forwarder1]}
            ),
            expected={
                'value': zone_findtest_forward_dnsname,
                'summary': None,
                'messages': lambda x: True,  # fake forwarders - ignore message
                'result': {
                    'dn': zone_findtest_forward_dn,
                    'idnsname': [zone_findtest_forward_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'first'],
                    'idnsforwarders': [forwarder1],
                    'objectclass': objectclasses.dnsforwardzone,
                },
            },
        ),


        dict(
            desc='dnsforwardzone-find should return only forward zones',
            command=('dnsforwardzone_find', [zone_findtest], {}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [{
                    'dn': zone_findtest_forward_dn,
                    'idnsname': [zone_findtest_forward_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'first'],
                    'idnsforwarders': [forwarder1],
                }],
            },
        ),


        dict(
            desc='dnszone-find should return only master zones',
            command=('dnszone_find', [zone_findtest], {}),
            expected={
                'summary': None,
                'count': 1,
                'truncated': False,
                'result': [{
                    'dn': zone_findtest_master_dn,
                    'idnsname': [zone_findtest_master_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'nsrecord': lambda x: True,  # don't care in this test
                    'idnssoamname': lambda x: True,  # don't care in this test
                    'idnssoarname': lambda x: True,  # don't care in this test
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                }],
            },
        ),


        dict(
            desc='Try to add A record to forward zone %r in zone %r' % (name1, fwzone1),
            command=('dnsrecord_add', [fwzone1, name1], {'arecord': arec3}),
            expected=errors.ValidationError(
                        name='dnszoneidnsname',
                        error=(u'only master zones can contain records')
                    ),
        ),


        dict(
            desc='Try to retrieve record %r in forward zone %r' % (name1, fwzone1),
            command=('dnsrecord_show', [fwzone1, name1], {}),
            expected=errors.ValidationError(
                        name='dnszoneidnsname',
                        error=(u'only master zones can contain records')
                    ),
        ),


        dict(
            desc='Try to delete record %r in forward zone %r' % (name1, fwzone1),
            command=('dnsrecord_del', [fwzone1, name1], {'del_all': True}),
            expected=errors.ValidationError(
                        name='dnszoneidnsname',
                        error=(u'only master zones can contain records')
                    ),
        ),


        dict(
            desc='Try to modify record in forward zone %r' % fwzone1,
            command=('dnsrecord_mod',
                [fwzone1, name1],
                {'aaaarecord': u'f001:baad::1'}),
            expected=errors.ValidationError(
                        name='dnszoneidnsname',
                        error=(u'only master zones can contain records')
                    ),
        ),

        dict(
            desc='Try to search for all records in forward zone %r' % fwzone1,
            command=('dnsrecord_find', [fwzone1], {}),
            expected=errors.ValidationError(
                        name='dnszoneidnsname',
                        error=(u'only master zones can contain records')
                    ),
        ),

    ]


@pytest.mark.tier1
class test_forwardzone_delegation_warnings(Declarative):

    @classmethod
    def setup_class(cls):
        super(test_forwardzone_delegation_warnings, cls).setup_class()

        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()

        if not have_ldap2:
            raise nose.SkipTest('server plugin not available')

        try:
            api.Command['dnszone_add'](zone1, idnssoarname=zone1_rname,)
            api.Command['dnszone_del'](zone1)
        except errors.NotFound:
            raise nose.SkipTest('DNS is not configured')
        except errors.DuplicateEntry:
            pass


    cleanup_commands = [
        ('dnsforwardzone_del', [zone1_sub_fw, zone1_sub2_fw],
            {'continue': True}),
        ('dnszone_del', [zone1, zone1_sub],
            {'continue': True}),
    ]

    tests = [

        dict(
            desc='Create forward zone %r without forwarders with "none" '
                 'policy' % zone1_sub_fw,
            command=(
                'dnsforwardzone_add', [zone1_sub_fw],
                {'idnsforwardpolicy': u'none'}
            ),
            expected={
                'value': zone1_sub_fw_dnsname,
                'summary': None,
                'result': {
                    'dn': zone1_sub_fw_dn,
                    'idnsname': [zone1_sub_fw_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'none'],
                    'objectclass': objectclasses.dnsforwardzone,
                },
            },
        ),


        dict(
            desc='Create zone %r (expected warning for %r)' % (zone1,
                                                               zone1_sub_fw),
            command=(
                'dnszone_add', [zone1_absolute], {}
            ),
            expected={
                'value': zone1_absolute_dnsname,
                'summary': None,
                'result': {
                    'dn': zone1_dn,
                    'idnsname': [zone1_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': lambda x: True,  # don't care in this test
                    'nsrecord': lambda x: True,  # don't care in this test
                    'idnssoarname': lambda x: True,  # don't care in this test
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': lambda x: True,  # don't care in this test
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
                'messages': (
                    {'message': u'forward zone "fw.sub.dnszone.test." is not '
                                 u'effective because of missing proper NS '
                                 u'delegation in authoritative zone '
                                 u'"dnszone.test.". Please add NS record '
                                 u'"fw.sub" to parent zone "dnszone.test.".',
                     'code': 13008,
                     'type': u'warning',
                     'name': u'ForwardzoneIsNotEffectiveWarning',
                     'data': {
                        'authzone': zone1_absolute,
                        'fwzone': zone1_sub_fw,
                        'ns_rec': zone1_sub_fw[:-len(zone1_absolute) - 1]
                     }},
                ),
            },
        ),


        dict(
            desc='Create zone %r (expected warning for %r)' % (zone1_sub,
                                                               zone1_sub_fw),
            command=(
                'dnszone_add', [zone1_sub], {}
            ),
            expected={
                'value': zone1_sub_dnsname,
                'summary': None,
                'result': {
                    'dn': zone1_sub_dn,
                    'idnsname': [zone1_sub_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': lambda x: True,  # don't care in this test
                    'nsrecord': lambda x: True,  # don't care in this test
                    'idnssoarname': lambda x: True,  # don't care in this test
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': lambda x: True,  # don't care in this test
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
                'messages': (
                    {'message': u'forward zone "fw.sub.dnszone.test." is not '
                                u'effective because of missing proper NS '
                                u'delegation in authoritative zone '
                                u'"sub.dnszone.test.". Please add NS record '
                                u'"fw" to parent zone "sub.dnszone.test.".',
                     'code': 13008,
                     'type': u'warning',
                     'name': u'ForwardzoneIsNotEffectiveWarning',
                     'data': {
                        'authzone': zone1_sub,
                        'fwzone': zone1_sub_fw,
                        'ns_rec': zone1_sub_fw[:-len(zone1_sub) - 1]
                     }},
                ),
            },
        ),


        dict(
            desc='Disable zone %r (expected warning for %r)' % (zone1_sub,
                                                                zone1_sub_fw),
            command=(
                'dnszone_disable', [zone1_sub], {}
            ),
            expected={
                'value': zone1_sub_dnsname,
                'summary': u'Disabled DNS zone "%s"' % zone1_sub,
                'result': True,
                'messages': (
                    {'message': u'forward zone "fw.sub.dnszone.test." is not '
                                u'effective because of missing proper NS '
                                u'delegation in authoritative zone '
                                u'"dnszone.test.". Please add NS record '
                                u'"fw.sub" to parent zone "dnszone.test.".',
                     'code': 13008,
                     'type': u'warning',
                     'name': u'ForwardzoneIsNotEffectiveWarning',
                     'data': {
                        'authzone': zone1_absolute,
                        'fwzone': zone1_sub_fw,
                        'ns_rec': zone1_sub_fw[:-len(zone1_absolute) - 1]
                     }},
                ),
            },
        ),


        dict(
            desc='Enable zone %r (expected warning for %r)' % (zone1_sub,
                                                               zone1_sub_fw),
            command=(
                'dnszone_enable', [zone1_sub], {}
            ),
            expected={
                'value': zone1_sub_dnsname,
                'summary': u'Enabled DNS zone "%s"' % zone1_sub,
                'result': True,
                'messages': (
                    {'message': u'forward zone "fw.sub.dnszone.test." is not '
                                u'effective because of missing proper NS '
                                u'delegation in authoritative zone '
                                u'"sub.dnszone.test.". Please add NS record '
                                u'"fw" to parent zone "sub.dnszone.test.".',
                     'code': 13008,
                     'type': u'warning',
                     'name': u'ForwardzoneIsNotEffectiveWarning',
                     'data': {
                        'authzone': zone1_sub,
                        'fwzone': zone1_sub_fw,
                        'ns_rec': zone1_sub_fw[:-len(zone1_sub) - 1]
                     }},
                ),
            },
        ),


        dict(
            desc='Disable forward zone %r' % (zone1_sub_fw),
            command=(
                'dnsforwardzone_disable', [zone1_sub_fw], {}
            ),
            expected={
                'value': zone1_sub_fw_dnsname,
                'summary': u'Disabled DNS forward zone "%s"' % zone1_sub_fw,
                'result': True,
            },
        ),


        dict(
            desc='Enable forward zone %r (expected warning for %r)' % (
                zone1_sub_fw, zone1_sub_fw),
            command=(
                'dnsforwardzone_enable', [zone1_sub_fw], {}
            ),
            expected={
                'value': zone1_sub_fw_dnsname,
                'summary': u'Enabled DNS forward zone "%s"' % zone1_sub_fw,
                'result': True,
                'messages': (
                    {'message': u'forward zone "fw.sub.dnszone.test." is not '
                                u'effective because of missing proper NS '
                                u'delegation in authoritative zone '
                                u'"sub.dnszone.test.". Please add NS record '
                                u'"fw" to parent zone "sub.dnszone.test.".',
                     'code': 13008,
                     'type': u'warning',
                     'name': u'ForwardzoneIsNotEffectiveWarning',
                     'data': {
                        'authzone': zone1_sub,
                        'fwzone': zone1_sub_fw,
                        'ns_rec': zone1_sub_fw[:-len(zone1_sub) - 1]
                     }},
                ),
            },
        ),


        dict(
            desc='Delegate zone %r from zone %r using NS record' % (
                zone1_sub_fw, zone1_sub),
            command=('dnsrecord_add', [zone1_sub, u'fw'],
                     {'nsrecord': self_server_ns}),
            expected={
                'value': DNSName(u'fw'),
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': DN(('idnsname', u'fw'), zone1_sub_dn),
                    'idnsname': [DNSName(u'fw')],
                    'nsrecord': [self_server_ns],
                },
            },
        ),


        dict(
            desc='Disable zone %r (expected warning for %r)' % (zone1_sub,
                                                                zone1_sub_fw),
            command=(
                'dnszone_disable', [zone1_sub], {}
            ),
            expected={
                'value': zone1_sub_dnsname,
                'summary': u'Disabled DNS zone "%s"' % zone1_sub,
                'result': True,
                'messages': (
                    {'message': u'forward zone "fw.sub.dnszone.test." is not '
                                u'effective because of missing proper NS '
                                u'delegation in authoritative zone '
                                u'"dnszone.test.". Please add NS record '
                                u'"fw.sub" to parent zone "dnszone.test.".',
                     'code': 13008,
                     'type': u'warning',
                     'name': u'ForwardzoneIsNotEffectiveWarning',
                     'data': {
                        'authzone': zone1_absolute,
                        'fwzone': zone1_sub_fw,
                        'ns_rec': zone1_sub_fw[:-len(zone1_absolute) - 1]
                     }},
                ),
            },
        ),


        dict(
            desc='Enable zone %r' % (zone1_sub),
            command=(
                'dnszone_enable', [zone1_sub], {}
            ),
            expected={
                'value': zone1_sub_dnsname,
                'summary': u'Enabled DNS zone "%s"' % zone1_sub,
                'result': True,
            },
        ),


        dict(
            desc='Delete NS record which delegates zone %r from zone %r '
                 '(expected warning for %r)' % (zone1_sub_fw,
                                                zone1_sub, zone1_sub_fw),
            command=('dnsrecord_del', [zone1_sub, u'fw'],
                     {'del_all': True}),
            expected={
                'value': [DNSName(u'fw')],
                'summary': u'Deleted record "fw"',
                'result': {
                    'failed': [],
                },
                'messages': (
                    {'message': u'forward zone "fw.sub.dnszone.test." is not '
                                u'effective because of missing proper NS '
                                u'delegation in authoritative zone '
                                u'"sub.dnszone.test.". Please add NS record '
                                u'"fw" to parent zone "sub.dnszone.test.".',
                     'code': 13008,
                     'type': u'warning',
                     'name': u'ForwardzoneIsNotEffectiveWarning',
                     'data': {
                        'authzone': zone1_sub,
                        'fwzone': zone1_sub_fw,
                        'ns_rec': zone1_sub_fw[:-len(zone1_sub) - 1]
                     }},
                ),
            },
        ),


        dict(
            desc='Create forward zone %r without forwarders with "none" '
                 'policy (expected warning)' % zone1_sub2_fw,
            command=(
                'dnsforwardzone_add', [zone1_sub2_fw],
                {'idnsforwardpolicy': u'none'}
            ),
            expected={
                'value': zone1_sub2_fw_dnsname,
                'summary': None,
                'result': {
                    'dn': zone1_sub2_fw_dn,
                    'idnsname': [zone1_sub2_fw_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnsforwardpolicy': [u'none'],
                    'objectclass': objectclasses.dnsforwardzone,
                },
                'messages': (
                    {'message': u'forward zone "fw.sub2.sub.dnszone.test." '
                                u'is not effective because of missing proper '
                                u'NS delegation in authoritative zone '
                                u'"sub.dnszone.test.". Please add NS record '
                                u'"fw.sub2" to parent zone '
                                u'"sub.dnszone.test.".',
                     'code': 13008,
                     'type': u'warning',
                     'name': u'ForwardzoneIsNotEffectiveWarning',
                     'data': {
                        'authzone': zone1_sub,
                        'fwzone': zone1_sub2_fw,
                        'ns_rec': zone1_sub2_fw[:-len(zone1_sub) - 1]
                     }},
                ),
            },
        ),


        dict(
            desc='Delegate zone %r from zone %r using NS record' % (
                zone1_sub2_fw, zone1_sub),
            command=('dnsrecord_add', [zone1_sub, u'fw.sub2'],
                     {'nsrecord': self_server_ns}),
            expected={
                'value': DNSName(u'fw.sub2'),
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': DN(('idnsname', u'fw.sub2'), zone1_sub_dn),
                    'idnsname': [DNSName(u'fw.sub2')],
                    'nsrecord': [self_server_ns],
                },
            },
        ),


        dict(
            desc='Disable forward zone %r' % (zone1_sub2_fw),
            command=(
                'dnsforwardzone_disable', [zone1_sub2_fw], {}
            ),
            expected={
                'value': zone1_sub2_fw_dnsname,
                'summary': u'Disabled DNS forward zone "%s"' % zone1_sub2_fw,
                'result': True,
            },
        ),


        dict(
            desc='Enable forward zone %r' % (zone1_sub2_fw),
            command=(
                'dnsforwardzone_enable', [zone1_sub2_fw], {}
            ),
            expected={
                'value': zone1_sub2_fw_dnsname,
                'summary': u'Enabled DNS forward zone "%s"' % zone1_sub2_fw,
                'result': True,
            },
        ),


        dict(
            desc='Delete zone %r (expected warning for %r, %r)' % (
                zone1_sub, zone1_sub_fw, zone1_sub2_fw),
            command=('dnszone_del', [zone1_sub], {}),
            expected={
                'value': [zone1_sub_dnsname],
                'summary': u'Deleted DNS zone "%s"' % zone1_sub,
                'result': {'failed': []},
                'messages': (
                    {'message': u'forward zone "fw.sub.dnszone.test." is not '
                                u'effective because of missing proper NS '
                                u'delegation in authoritative zone '
                                u'"dnszone.test.". Please add NS record '
                                u'"fw.sub" to parent zone "dnszone.test.".',
                     'code': 13008,
                     'type': u'warning',
                     'name': u'ForwardzoneIsNotEffectiveWarning',
                     'data': {
                        'authzone': zone1_absolute,
                        'fwzone': zone1_sub_fw,
                        'ns_rec': zone1_sub_fw[:-len(zone1_absolute) - 1]
                     }},
                    {'message': u'forward zone "fw.sub2.sub.dnszone.test." '
                                 u'is not effective because of missing proper '
                                 u'NS delegation in authoritative zone '
                                 u'"dnszone.test.". Please add NS record '
                                 u'"fw.sub2.sub" to parent zone '
                                 u'"dnszone.test.".',
                     'code': 13008,
                     'type': u'warning',
                     'name': u'ForwardzoneIsNotEffectiveWarning',
                     'data': {
                        'authzone': zone1_absolute,
                        'fwzone': zone1_sub2_fw,
                        'ns_rec': zone1_sub2_fw[:-len(zone1_absolute) - 1]
                     }}
                ),
            },
        ),


        dict(
            desc='Delegate zone %r from zone %r using NS record' % (
                zone1_sub2_fw, zone1),
            command=('dnsrecord_add', [zone1, u'fw.sub2.sub'],
                     {'nsrecord': self_server_ns}),
            expected={
                'value': DNSName(u'fw.sub2.sub'),
                'summary': None,
                'result': {
                    'objectclass': objectclasses.dnsrecord,
                    'dn': DN(('idnsname', u'fw.sub2.sub'), zone1_dn),
                    'idnsname': [DNSName(u'fw.sub2.sub')],
                    'nsrecord': [self_server_ns],
                },
            },
        ),


        dict(
            desc='Delete (using dnsrecord-mod) NS record which delegates '
                 'zone %r from zone %r (expected warning for %r)' % (
                zone1_sub2_fw, zone1, zone1_sub2_fw),
            command=('dnsrecord_mod', [zone1, u'fw.sub2.sub'],
                     {'nsrecord': None}),
            expected={
                'value': DNSName(u'fw.sub2.sub'),
                'summary': u'Deleted record "fw.sub2.sub"',
                'result': {
                    'failed': [],
                },
                'messages': (
                    {'message': u'forward zone "fw.sub2.sub.dnszone.test." is '
                                u'not effective because of missing proper NS '
                                u'delegation in authoritative zone '
                                u'"dnszone.test.". Please add NS record '
                                u'"fw.sub2.sub" to parent zone '
                                u'"dnszone.test.".',
                     'code': 13008,
                     'type': u'warning',
                     'name': u'ForwardzoneIsNotEffectiveWarning',
                     'data': {
                        'authzone': zone1_absolute,
                        'fwzone': zone1_sub2_fw,
                        'ns_rec': zone1_sub2_fw[:-len(zone1_absolute) - 1]
                     }},
                ),
            },
        ),

    ]


# https://fedorahosted.org/freeipa/ticket/4746
# http://www.freeipa.org/page/V4/DNS:_Automatic_Zone_NS/SOA_Record_Maintenance
@pytest.mark.tier1
class test_dns_soa(Declarative):

    @classmethod
    def setup_class(cls):
        super(test_dns_soa, cls).setup_class()

        if not api.Backend.rpcclient.isconnected():
            api.Backend.rpcclient.connect()

        if not have_ldap2:
            raise nose.SkipTest('server plugin not available')

        if get_nameservers_error is not None:
            raise nose.SkipTest('unable to get list of nameservers (%s)' %
                                get_nameservers_error)
        try:
            api.Command['dnszone_add'](zone1,
                                       idnssoarname=zone1_rname,)
            api.Command['dnszone_del'](zone1)
        except errors.NotFound:
            raise nose.SkipTest('DNS is not configured')
        except errors.DuplicateEntry:
            pass

    cleanup_commands = [
        ('dnszone_del', [zone6, zone6b], {'continue': True}),
    ]

    tests = [

        dict(
            desc='Try to retrieve non-existent zone %r' % zone6,
            command=('dnszone_show', [zone6], {}),
            expected=errors.NotFound(
                reason=u'%s: DNS zone not found' % zone6_absolute),
            ),

        dict(
            desc='Create zone %r' % zone6b,
            command=(
                'dnszone_add', [zone6b], {
                    'idnssoarname': zone6b_rname,
                }
            ),
            expected={
                'value': zone6b_absolute_dnsname,
                'summary': None,
                'result': {
                    'dn': zone6b_absolute_dn,
                    'idnsname': [zone6b_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone6b_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-self * A; '
                                         u'grant %(realm)s krb5-self * AAAA; '
                                         u'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),

        dict(
            desc='Add A record to %r in zone %r' % (zone6b_ns_arec, zone6b),
            command=('dnsrecord_add',
                     [zone6b, zone6b_ns],
                     {'arecord': zone6b_ip}),
            expected={
                'value': zone6b_ns_dnsname,
                'summary': None,
                'result': {
                    'dn': zone6b_absolute_arec_dn,
                    'idnsname': [zone6b_ns_arec_dnsname],
                    'arecord': [zone6b_ip],
                    'objectclass': objectclasses.dnsrecord,
                },
            },
        ),

        dict(
            desc='Adding a zone - %r - just with zone name' % zone6,
            command=('dnszone_add', [zone6], {}),
            expected={
                'value': zone6_absolute_dnsname,
                'summary': None,
                'result': {
                    'dn': zone6_absolute_dn,
                    'idnsname': [zone6_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone6_rname_default_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-self * A; '
                                         u'grant %(realm)s krb5-self * AAAA; '
                                         u'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),

        dict(
            desc='Updating a zone - %r - with relative '
                 'admin\'s e-mail' %
                 zone6,
            command=(
                'dnszone_mod', [zone6], {
                    'idnssoarname': zone6_rname_relative_dnsname,
                }
            ),
            expected={
                'value': zone6_absolute_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [zone6_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone6_rname_relative_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
            },
        ),

        dict(
            desc='Updating a zone - %r - with absolute '
                 'admin\'s e-mail' %
                 zone6,
            command=(
                'dnszone_mod', [zone6], {
                    'idnssoarname': zone6_rname_absolute_dnsname,
                }
            ),
            expected={
                'value': zone6_absolute_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [zone6_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone6_rname_absolute_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
            },
        ),

        dict(
            desc='Updating a zone - %r - with default admin\'s e-mail' % zone6,
            command=(
                'dnszone_mod', [zone6], {
                    'idnssoarname': zone6_rname_default_dnsname,
                }
            ),
            expected={
                'value': zone6_absolute_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [zone6_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone6_rname_default_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
            },
        ),

        dict(
            desc='Updating a zone - %r - with name-server absolute' % zone6,
            command=(
                'dnszone_mod', [zone6], {
                    'idnssoamname': zone6b_ns,
                }
            ),
            expected={
                'value': zone6_absolute_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [zone6_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [zone6b_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone6b_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
                'messages': [{
                    'message': u"Semantic of setting Authoritative nameserver "
                               u"was changed. "
                               u"It is used only for setting the SOA MNAME "
                               u"attribute.\n"
                               u"NS record(s) can be edited in zone "
                               u"apex - '@'. ",
                    'code': 13005,
                    'type': u'warning',
                    'name': u'OptionSemanticChangedWarning',
                    'data': {
                        'current_behavior': u"It is used only for setting the "
                                            u"SOA MNAME attribute.",
                        'hint': u"NS record(s) can be edited in zone apex - "
                                u"'@'. ",
                        'label': u"setting Authoritative nameserver",
                    },
                }],
            },
        ),

        dict(
            desc='Add A record to %r in zone %r' % (zone6_ns, zone6),
            command=('dnsrecord_add',
                     [zone6, zone6_ns],
                     {'arecord': zone6b_ip}),
            expected={
                'value': zone6_ns_dnsname,
                'summary': None,
                'result': {
                    'dn': zone6_absolute_arec_dn,
                    'idnsname': [zone6_ns_arec_dnsname],
                    'arecord': [zone6b_ip],
                    'objectclass': objectclasses.dnsrecord,
                },
            },
        ),

        dict(
            desc='Updating a zone - %r - with name-server relative' % zone6,
            command=(
                'dnszone_mod', [zone6], {
                    'idnssoamname': zone6_ns_relative,
                }
            ),
            expected={
                'value': zone6_absolute_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [zone6_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [zone6_ns_arec_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone6_rname_default_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
                'messages': [{
                    'message': u"Semantic of setting Authoritative nameserver "
                               u"was changed. "
                               u"It is used only for setting the SOA MNAME "
                               u"attribute.\n"
                               u"NS record(s) can be edited in zone "
                               u"apex - '@'. ",
                    'code': 13005,
                    'type': u'warning',
                    'name': u'OptionSemanticChangedWarning',
                    'data': {
                        'current_behavior': u"It is used only for setting the "
                                            u"SOA MNAME attribute.",
                        'hint': u"NS record(s) can be edited in zone apex - "
                                u"'@'. ",
                        'label': u"setting Authoritative nameserver",
                    },
                }],
            },
        ),

        dict(
            desc='Updating a zone - %r - with unresolvable name-server '
                 'absolute with --force' %
                 zone6,
            command=(
                'dnszone_mod', [zone6], {
                    'idnssoamname': zone6_unresolvable_ns,
                    'force': True,
                }
            ),
            expected={
                'value': zone6_absolute_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [zone6_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [zone6_unresolvable_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone6_rname_default_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
                'messages': [{
                    'message': u"Semantic of setting Authoritative nameserver "
                               u"was changed. "
                               u"It is used only for setting the SOA MNAME "
                               u"attribute.\n"
                               u"NS record(s) can be edited in zone "
                               u"apex - '@'. ",
                    'code': 13005,
                    'type': u'warning',
                    'name': u'OptionSemanticChangedWarning',
                    'data': {
                        'current_behavior': u"It is used only for setting the "
                                            u"SOA MNAME attribute.",
                        'hint': u"NS record(s) can be edited in zone apex - "
                                u"'@'. ",
                        'label': u"setting Authoritative nameserver",
                    },
                }],
            },
        ),

        dict(
            desc='Updating a zone - %r - with unresolvable name-server '
                 'relative with --force' %
                 zone6,
            command=(
                'dnszone_mod', [zone6], {
                    'idnssoamname': zone6_unresolvable_ns_relative,
                    'force': True,
                }
            ),
            expected={
                'value': zone6_absolute_dnsname,
                'summary': None,
                'result': {
                    'idnsname': [zone6_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [zone6_unresolvable_ns_relative_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone6_rname_default_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                },
                'messages': [{
                    'message': u"Semantic of setting Authoritative nameserver "
                               u"was changed. "
                               u"It is used only for setting the SOA MNAME "
                               u"attribute.\n"
                               u"NS record(s) can be edited in zone "
                               u"apex - '@'. ",
                    'code': 13005,
                    'type': u'warning',
                    'name': u'OptionSemanticChangedWarning',
                    'data': {
                        'current_behavior': u"It is used only for setting the "
                                            u"SOA MNAME attribute.",
                        'hint': u"NS record(s) can be edited in zone apex - "
                                u"'@'. ",
                        'label': u"setting Authoritative nameserver",
                    },
                }],
            },
        ),

        dict(
            desc='Updating a zone - %r - with invalid s e-mail - %r' %
                 (zone6, zone6_rname_invalid_dnsname),
            command=(
                'dnszone_mod', [zone6], {
                    'idnssoarname': zone6_rname_invalid_dnsname,
                }),
            expected=errors.ConversionError(
                name='admin_email',
                error=u'empty DNS label'),
        ),

        dict(
            desc='Updating a zone - %r - with invalid name-server - %r' %
                 (zone6, zone6_ns_invalid_dnsname),
            command=(
                'dnszone_mod', [zone6], {
                    'idnssoamname': zone6_ns_invalid_dnsname,
                }),
            expected=errors.ConversionError(
                name='name_server',
                error=u'empty DNS label'),
        ),

        dict(
            desc='Updating a zone - %r - with unresolvable name-server - %r' %
                 (zone6, zone6_unresolvable_ns),
            command=(
                'dnszone_mod', [zone6], {
                    'idnssoamname': zone6_unresolvable_ns,
                }),
            expected=errors.NotFound(
                reason=u"Nameserver '%s' does not have a corresponding "
                       u"A/AAAA record" %
                       zone6_unresolvable_ns_dnsname,),
        ),

        dict(
            desc='Updating a zone - %r - with unresolvable relative '
                 'name-server - %r' %
                 (zone6, zone6_unresolvable_ns_relative),
            command=(
                'dnszone_mod', [zone6], {
                    'idnssoamname': zone6_unresolvable_ns_relative,
                }),
            expected=errors.NotFound(
                reason=u"Nameserver '%s' does not have a corresponding "
                       u"A/AAAA record" %
                       zone6_unresolvable_ns_dnsname,),
        ),

        dict(
            desc='Updating a zone - %r - with empty name-server - %r' %
                 (zone6, zone6_unresolvable_ns_relative),
            command=(
                'dnszone_mod', [zone6], {
                    'idnssoamname': "",
                }),
            expected=errors.ValidationError(name='name_server',
                                            error=u'is required'),
        ),

        dict(
            desc='Deleting a zone - %r' % zone6,
            command=('dnszone_del', [zone6], {}),
            expected={
                'value': [zone6_absolute_dnsname],
                'summary': u'Deleted DNS zone "%s"' % zone6_absolute,
                'result': {'failed': []},
            },
        ),

        dict(
            desc='Adding a zone - %r - with relative admin\'s e-mail' % zone6,
            command=(
                'dnszone_add', [zone6], {
                    'idnssoarname': zone6_rname_relative_dnsname,
                }
            ),
            expected={
                'value': zone6_absolute_dnsname,
                'summary': None,
                'result': {
                    'dn': zone6_absolute_dn,
                    'idnsname': [zone6_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone6_rname_relative_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-self * A; '
                                         u'grant %(realm)s krb5-self * AAAA; '
                                         u'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),
        dict(
            desc='Deleting a zone - %r' % zone6,
            command=('dnszone_del', [zone6], {}),
            expected={
                'value': [zone6_absolute_dnsname],
                'summary': u'Deleted DNS zone "%s"' % zone6_absolute,
                'result': {'failed': []},
            },
        ),

        dict(
            desc='Adding a zone - %r - with absolute admin\'s e-mail' % zone6,
            command=(
                'dnszone_add', [zone6], {
                    'idnssoarname': zone6_rname_absolute_dnsname,
                }
            ),
            expected={
                'value': zone6_absolute_dnsname,
                'summary': None,
                'result': {
                    'dn': zone6_absolute_dn,
                    'idnsname': [zone6_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [self_server_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone6_rname_absolute_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-self * A; '
                                         u'grant %(realm)s krb5-self * AAAA; '
                                         u'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
            },
        ),
        dict(
            desc='Deleting a zone - %r' % zone6,
            command=('dnszone_del', [zone6], {}),
            expected={
                'value': [zone6_absolute_dnsname],
                'summary': u'Deleted DNS zone "%s"' % zone6_absolute,
                'result': {'failed': []},
            },
        ),

        dict(
            desc='Adding a zone - %r - with name-server %r' %
                 (zone6, zone6_ns_dnsname),
            command=(
                'dnszone_add', [zone6], {
                    'idnssoamname': zone6b_ns,
                }),
            expected={
                'value': zone6_absolute_dnsname,
                'summary': None,
                'result': {
                    'dn': zone6_absolute_dn,
                    'idnsname': [zone6_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [zone6b_ns_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone6b_rname_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-self * A; '
                                         u'grant %(realm)s krb5-self * AAAA; '
                                         u'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
                'messages': [{
                    'message': u"Semantic of setting Authoritative nameserver "
                               u"was changed. "
                               u"It is used only for setting the SOA MNAME "
                               u"attribute.\n"
                               u"NS record(s) can be edited in zone "
                               u"apex - '@'. ",
                    'code': 13005,
                    'type': u'warning',
                    'name': u'OptionSemanticChangedWarning',
                    'data': {
                        'current_behavior': u"It is used only for setting the "
                                            u"SOA MNAME attribute.",
                        'hint': u"NS record(s) can be edited in zone apex - "
                                u"'@'. ",
                        'label': u"setting Authoritative nameserver",
                    },
                }], },
        ),
        dict(
            desc='Deleting a zone - %r' % zone6,
            command=('dnszone_del', [zone6], {}),
            expected={
                'value': [zone6_absolute_dnsname],
                'summary': u'Deleted DNS zone "%s"' % zone6_absolute,
                'result': {'failed': []},
            },
        ),

        dict(
            desc='Adding a zone - %r - with unresolvable name-server '
                 'relative with --force' %
                 zone6,
            command=(
                'dnszone_add', [zone6], {
                    'idnssoamname': zone6_unresolvable_ns_relative,
                    'force': True,
                }
            ),
            expected={
                'value': zone6_absolute_dnsname,
                'summary': None,
                'result': {
                    'dn': zone6_absolute_dn,
                    'idnsname': [zone6_absolute_dnsname],
                    'idnszoneactive': [u'TRUE'],
                    'idnssoamname': [zone6_unresolvable_ns_relative_dnsname],
                    'nsrecord': nameservers,
                    'idnssoarname': [zone6_rname_default_dnsname],
                    'idnssoaserial': [fuzzy_digits],
                    'idnssoarefresh': [fuzzy_digits],
                    'idnssoaretry': [fuzzy_digits],
                    'idnssoaexpire': [fuzzy_digits],
                    'idnssoaminimum': [fuzzy_digits],
                    'idnsallowdynupdate': [u'FALSE'],
                    'idnsupdatepolicy': [u'grant %(realm)s krb5-self * A; '
                                         u'grant %(realm)s krb5-self * AAAA; '
                                         u'grant %(realm)s krb5-self * SSHFP;'
                                         % dict(realm=api.env.realm)],
                    'idnsallowtransfer': [u'none;'],
                    'idnsallowquery': [u'any;'],
                    'objectclass': objectclasses.dnszone,
                },
                'messages': [{
                    'message': u"Semantic of setting Authoritative nameserver "
                               u"was changed. "
                               u"It is used only for setting the SOA MNAME "
                               u"attribute.\n"
                               u"NS record(s) can be edited in zone "
                               u"apex - '@'. ",
                    'code': 13005,
                    'type': u'warning',
                    'name': u'OptionSemanticChangedWarning',
                    'data': {
                        'current_behavior': u"It is used only for setting the "
                                            u"SOA MNAME attribute.",
                        'hint': u"NS record(s) can be edited in zone apex - "
                                u"'@'. ",
                        'label': u"setting Authoritative nameserver",
                    },
                }],
            },
        ),
        dict(
            desc='Deleting a zone - %r' % zone6,
            command=('dnszone_del', [zone6], {}),
            expected={
                'value': [zone6_absolute_dnsname],
                'summary': u'Deleted DNS zone "%s"' % zone6_absolute,
                'result': {'failed': []},
            },
        ),


        dict(
            desc='Adding zone with invalid zone name - %r' % zone6_invalid,
            command=('dnszone_add', [zone6_invalid], {}),
            expected=errors.ConversionError(
                name='name',
                error=u'empty DNS label'
            ),
        ),

        dict(
            desc='Adding a zone - %r - with invalid s e-mail - %r' %
                 (zone6, zone6_rname_invalid_dnsname),
            command=(
                'dnszone_add', [zone6], {
                    'idnssoarname': zone6_rname_invalid_dnsname,
                }),
            expected=errors.ConversionError(
                name='admin_email',
                error=u'empty DNS label'),
        ),

        dict(
            desc='Adding a zone - %r - with invalid name-server - %r' %
                 (zone6, zone6_ns_invalid_dnsname),
            command=(
                'dnszone_add', [zone6], {
                    'idnssoamname': zone6_ns_invalid_dnsname,
                }),
            expected=errors.ConversionError(
                name='name_server',
                error=u'empty DNS label'),
        ),

        dict(
            desc='Adding a zone - %r - with unresolvable name-server - %r' %
                 (zone6, zone6_unresolvable_ns),
            command=(
                'dnszone_add', [zone6], {
                    'idnssoamname': zone6_unresolvable_ns,
                }),
            expected=errors.NotFound(
                reason=u"Nameserver '%s' does not have a corresponding "
                       u"A/AAAA record" %
                       zone6_unresolvable_ns_dnsname,),
        ),

        dict(
            desc='Adding a zone - %r - with unresolvable '
                 'relative name-server - %r' %
                 (zone6,
                  zone6_unresolvable_ns_relative),
            command=(
                'dnszone_add', [zone6], {
                    'idnssoamname': zone6_unresolvable_ns_relative,
                }),
            expected=errors.NotFound(
                reason=u"Nameserver '%s' does not have a corresponding "
                       u"A/AAAA record" %
                       zone6_unresolvable_ns_dnsname,),
        ),
    ]


@pytest.mark.tier1
class test_dns_type_uri(test_dns):
    """Test behavior specific for URI RR type."""

    @classmethod
    def setup_class(cls):
        super(test_dns_type_uri, cls).setup_class()
        try:
            api.Command['dnszone_add'](zone1, idnssoarname=zone1_rname)
        except errors.DuplicateEntry:
            pass

    cleanup_commands = [
        ('dnszone_del', [zone1], {'continue': True}),
    ]

    uri_priority = 1
    uri_weight = 2
    uri_target = 'http://example.com/'
    uri_raw_value = u'{0} {1} "{2}"'.format(
        uri_priority, uri_weight, uri_target)
    tests = [
        dict(
            desc='Create URI record under %s zone %r' % (name1_dnsname, zone1),
            command=('dnsrecord_add', [zone1, name1_dnsname],
                     {'urirecord': uri_raw_value}),
            expected={
                'value': name1_dnsname,
                'summary': None,
                'result': {
                    'dn': name1_dn,
                    'idnsname': [name1_dnsname],
                    'objectclass': objectclasses.dnsrecord,
                    'urirecord': [uri_raw_value],
                },
            },
        ),
        dict(
            desc='URI record is case sensitive on delete (one record)',
            command=('dnsrecord_del', [zone1, name1_dnsname],
                     {'urirecord': uri_raw_value.upper()}),
            expected=errors.AttrValueNotFound(attr='URI record',
                                              value=uri_raw_value.upper()),
        ),
        dict(
            desc='URI record is case sensitive on add',
            command=('dnsrecord_add', [zone1, name1_dnsname],
                     {'urirecord': uri_raw_value.upper()}),
            expected={
                'value': name1_dnsname,
                'summary': None,
                'result': {
                    'dn': name1_dn,
                    'idnsname': [name1_dnsname],
                    'objectclass': objectclasses.dnsrecord,
                    'urirecord': [uri_raw_value, uri_raw_value.upper()],
                },
            },
        ),
        dict(
            desc='URI record is case sensitive on delete (two records)',
            command=('dnsrecord_del', [zone1, name1_dnsname],
                     {'urirecord': [uri_raw_value, uri_raw_value.upper()]}),
            expected={
                'value': [name1_dnsname],
                'summary': u'Deleted record "%s"' % name1_dnsname,
                'result': {'failed': []},
            },
        ),
        dict(
            desc='URI record normalization does not double "" around target',
            command=('dnsrecord_add', [zone1, name1_dnsname],
                     {'uri_part_target': u'"{0}"'.format(uri_target),
                      'uri_part_priority': uri_priority,
                      'uri_part_weight': uri_weight}),
            expected={
                'value': name1_dnsname,
                'summary': None,
                'result': {
                    'dn': name1_dn,
                    'idnsname': [name1_dnsname],
                    'objectclass': objectclasses.dnsrecord,
                    'urirecord': [uri_raw_value],
                },
            },
        ),
    ]
