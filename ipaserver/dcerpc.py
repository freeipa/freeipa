# Authors:
#     Alexander Bokovoy <abokovoy@redhat.com>
#
# Copyright (C) 2011-2016  Red Hat
# see file 'COPYING' for use and warranty information
#
# Portions (C) Andrew Tridgell, Andrew Bartlett
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

# Make sure we only run this module at the server where samba4-python
# package is installed to avoid issues with unavailable modules

from __future__ import absolute_import

import logging
import re
import time

from ipalib import api, _
from ipalib import errors
from ipapython import ipautil
from ipapython.dn import DN
from ipapython.dnsutil import query_srv
from ipapython.ipaldap import ldap_initialize
from ipaserver.install import installutils
from ipaserver.dcerpc_common import (TRUST_BIDIRECTIONAL,
                                     TRUST_JOIN_EXTERNAL,
                                     trust_type_string)

from ipalib.util import normalize_name

import os
import struct
import random

from samba import param
from samba import credentials
from samba.dcerpc import security, lsa, drsblobs, nbt, netlogon
from samba.ndr import ndr_pack, ndr_print
from samba import net
from samba import arcfour_encrypt
import samba

import ldap as _ldap
from ipapython import ipaldap
from ipapython.dnsutil import DNSName
from dns.exception import DNSException
import pysss_nss_idmap
import pysss
import six
from ipaplatform.paths import paths

from ldap.filter import escape_filter_chars
from time import sleep

try:
    from ldap.controls import RequestControl as LDAPControl
except ImportError:
    from ldap.controls import LDAPControl

if six.PY3:
    unicode = str
    long = int

__doc__ = _("""
Classes to manage trust joins using DCE-RPC calls

The code in this module relies heavily on samba4-python package
and Samba4 python bindings.
""")

logger = logging.getLogger(__name__)


def is_sid_valid(sid):
    try:
        security.dom_sid(sid)
    except TypeError:
        return False
    else:
        return True


access_denied_error = errors.ACIError(
                          info=_('CIFS server denied your credentials'))
dcerpc_error_codes = {
    -1073741823:
        errors.RemoteRetrieveError(
            reason=_('communication with CIFS server was unsuccessful')),
    -1073741790: access_denied_error,
    -1073741715: access_denied_error,
    -1073741614: access_denied_error,
    -1073741603:
        errors.ValidationError(
            name=_('AD domain controller'),
            error=_('unsupported functional level')),
    -1073741811:  # NT_STATUS_INVALID_PARAMETER
        errors.RemoteRetrieveError(
            reason=_('AD domain controller complains about communication '
                     'sequence. It may mean unsynchronized time on both '
                     'sides, for example')),
    -1073741776:  # NT_STATUS_INVALID_PARAMETER_MIX,
                  # we simply will skip the binding
        access_denied_error,
    -1073741772:  # NT_STATUS_OBJECT_NAME_NOT_FOUND
        errors.NotFound(
            reason=_('Cannot find specified domain or server name')),
}

dcerpc_error_messages = {
    "NT_STATUS_OBJECT_NAME_NOT_FOUND":
        errors.NotFound(
            reason=_('Cannot find specified domain or server name')),
    "The object name is not found.":
        errors.NotFound(
            reason=_('Cannot find specified domain or server name')),
    "WERR_NO_LOGON_SERVERS":
        errors.RemoteRetrieveError(
            reason=_('AD DC was unable to reach any IPA domain controller. '
                     'Most likely it is a DNS or firewall issue')),
    # This is a very long key, don't change it
    "There are currently no logon servers available to "
    "service the logon request.":
        errors.RemoteRetrieveError(
            reason=_('AD DC was unable to reach any IPA domain controller. '
                     'Most likely it is a DNS or firewall issue')),
    "NT_STATUS_INVALID_PARAMETER_MIX":
        errors.RequirementError(
            name=_('At least the domain or IP address should be specified')),
}

pysss_type_key_translation_dict = {
    pysss_nss_idmap.ID_USER: 'user',
    pysss_nss_idmap.ID_GROUP: 'group',
    # Used for users with magic private groups
    pysss_nss_idmap.ID_BOTH: 'both',
}


class TrustTopologyConflictSolved(Exception):
    """
    Internal trust error: raised when previously detected
    trust topology conflict is automatically solved.

    No separate errno is assigned as this error should
    not be visible outside the dcerpc.py code.
    """
    pass


def assess_dcerpc_error(error):
    """
    Takes error returned by Samba bindings and converts it into
    an IPA error class.
    """
    if isinstance(error, RuntimeError):
        error_tuple = error.args
    else:
        error_tuple = error
    if len(error_tuple) != 2:
        raise RuntimeError("Unable to parse error: {err!r}".format(err=error))

    num, message = error_tuple
    if num and num in dcerpc_error_codes:
        return dcerpc_error_codes[num]
    if message and message in dcerpc_error_messages:
        return dcerpc_error_messages[message]
    reason = _('CIFS server communication error: code "%(num)s", '
               'message "%(message)s" (both may be "None")') % \
        dict(num=num, message=message)
    return errors.RemoteRetrieveError(reason=reason)


class ExtendedDNControl(LDAPControl):
    def __init__(self):
        LDAPControl.__init__(
            self,
            controlType="1.2.840.113556.1.4.529",
            criticality=False,
            encodedControlValue=b'0\x03\x02\x01\x01'
        )


class DomainValidator(object):
    ATTR_FLATNAME = 'ipantflatname'
    ATTR_SID = 'ipantsecurityidentifier'
    ATTR_TRUSTED_SID = 'ipanttrusteddomainsid'
    ATTR_TRUST_PARTNER = 'ipanttrustpartner'
    ATTR_TRUST_AUTHOUT = 'ipanttrustauthoutgoing'

    def __init__(self, api):
        self.api = api
        self.ldap = self.api.Backend.ldap2
        self.domain = None
        self.flatname = None
        self.dn = None
        self.sid = None
        self._domains = None
        self._info = dict()
        self._creds = None
        self._admin_creds = None
        self._parm = None

    def is_configured(self):
        cn_trust_local = DN(('cn', self.api.env.domain),
                            self.api.env.container_cifsdomains,
                            self.api.env.basedn)
        try:
            entry_attrs = self.ldap.get_entry(cn_trust_local,
                                              [self.ATTR_FLATNAME,
                                               self.ATTR_SID])
            self.flatname = entry_attrs[self.ATTR_FLATNAME][0]
            self.sid = entry_attrs[self.ATTR_SID][0]
            self.dn = entry_attrs.dn
            self.domain = self.api.env.domain
        except errors.NotFound:
            return False
        return True

    def get_trusted_domains(self):
        """
        Returns case-insensitive dict of trusted domain tuples
        (flatname, sid, trust_auth_outgoing), keyed by domain name.
        """
        cn_trust = DN(('cn', 'ad'), self.api.env.container_trusts,
                      self.api.env.basedn)

        try:
            search_kw = {'objectClass': 'ipaNTTrustedDomain'}
            filter = self.ldap.make_filter(search_kw,
                                           rules=self.ldap.MATCH_ALL)
            entries, _truncated = self.ldap.find_entries(
                filter=filter,
                base_dn=cn_trust,
                attrs_list=[self.ATTR_TRUSTED_SID,
                            self.ATTR_FLATNAME,
                            self.ATTR_TRUST_PARTNER]
                )

            # We need to use case-insensitive dictionary since we use
            # domain names as keys and those are generally case-insensitive
            result = ipautil.CIDict()

            for e in entries:
                try:
                    t_partner = e.single_value.get(self.ATTR_TRUST_PARTNER)
                    fname_norm = e.single_value.get(self.ATTR_FLATNAME).lower()
                    trusted_sid = e.single_value.get(self.ATTR_TRUSTED_SID)
                except KeyError as exc:
                    # Some piece of trusted domain info in LDAP is missing
                    # Skip the domain, but leave log entry for investigation
                    logger.warning("Trusted domain '%s' entry misses an "
                                   "attribute: %s", e.dn, exc)
                    continue

                result[t_partner] = (fname_norm,
                                     security.dom_sid(trusted_sid))
            return result
        except errors.NotFound as exc:
            return []

    def set_trusted_domains(self):
        # At this point we have SID_NT_AUTHORITY family SID and really need to
        # check it against prefixes of domain SIDs we trust to
        if not self._domains:
            self._domains = self.get_trusted_domains()
        if len(self._domains) == 0:
            # Our domain is configured but no trusted domains are configured
            # This means we can't check the correctness of a trusted
            # domain SIDs
            raise errors.ValidationError(name='sid',
                                         error=_('no trusted domain '
                                                 'is configured'))

    def get_domain_by_sid(self, sid, exact_match=False):
        if not self.domain:
            # our domain is not configured or self.is_configured() never run
            # reject SIDs as we can't check correctness of them
            raise errors.ValidationError(name='sid',
                                         error=_('domain is not configured'))

        # Parse sid string to see if it is really in a SID format
        try:
            test_sid = security.dom_sid(sid)
        except TypeError:
            raise errors.ValidationError(name='sid',
                                         error=_('SID is not valid'))

        # At this point we have SID_NT_AUTHORITY family SID and really need to
        # check it against prefixes of domain SIDs we trust to
        self.set_trusted_domains()

        # We have non-zero list of trusted domains and have to go through
        # them one by one and check their sids as prefixes / exact match
        # depending on the value of exact_match flag
        if exact_match:
            # check exact match of sids
            for domain in self._domains:
                if sid == str(self._domains[domain][1]):
                    return domain

            raise errors.NotFound(reason=_("SID does not match exactly"
                                           "with any trusted domain's SID"))
        else:
            # check as prefixes
            test_sid_subauths = test_sid.sub_auths
            for domain in self._domains:
                domsid = self._domains[domain][1]
                sub_auths = domsid.sub_auths
                num_auths = min(test_sid.num_auths, domsid.num_auths)
                if test_sid_subauths[:num_auths] == sub_auths[:num_auths]:
                    return domain
            raise errors.NotFound(reason=_('SID does not match any '
                                           'trusted domain'))

    def is_trusted_sid_valid(self, sid):
        try:
            self.get_domain_by_sid(sid)
        except (errors.ValidationError, errors.NotFound):
            return False
        else:
            return True

    def is_trusted_domain_sid_valid(self, sid):
        try:
            self.get_domain_by_sid(sid, exact_match=True)
        except (errors.ValidationError, errors.NotFound):
            return False
        else:
            return True

    def get_sid_from_domain_name(self, name):
        """Returns binary representation of SID for the trusted domain name
           or None if name is not in the list of trusted domains."""

        domains = self.get_trusted_domains()
        if name in domains:
            return domains[name][1]
        else:
            return None

    def get_trusted_domain_objects(self, domain=None, flatname=None, filter="",
                                   attrs=None, scope=_ldap.SCOPE_SUBTREE,
                                   basedn=None):
        """
        Search for LDAP objects in a trusted domain specified either by
        `domain' or `flatname'. The actual LDAP search is specified by
        `filter', `attrs', `scope' and `basedn'. When `basedn' is empty,
        database root DN is used.
        """
        assert domain is not None or flatname is not None
        """Returns SID for the trusted domain object (user or group only)"""
        if not self.domain:
            # our domain is not configured or self.is_configured() never run
            raise errors.ValidationError(name=_('Trust setup'),
                                         error=_('Our domain is '
                                                 'not configured'))
        if not self._domains:
            self._domains = self.get_trusted_domains()
        if len(self._domains) == 0:
            # Our domain is configured but no trusted domains are configured
            raise errors.ValidationError(name=_('Trust setup'),
                                         error=_('No trusted domain is '
                                                 'not configured'))

        entries = None
        if domain is not None:
            if domain not in self._domains:
                raise errors.ValidationError(name=_('trusted domain object'),
                                             error=_('domain is not trusted'))
            # Now we have a name to check against our list of trusted domains
            entries = self.search_in_dc(domain, filter, attrs, scope, basedn)
        elif flatname is not None:
            # Flatname was specified, traverse through the list of trusted
            # domains first to find the proper one
            found_flatname = False
            for domain in self._domains:
                if self._domains[domain][0] == flatname:
                    found_flatname = True
                    entries = self.search_in_dc(domain, filter,
                                                attrs, scope, basedn)
                    if entries:
                        break
            if not found_flatname:
                raise errors.ValidationError(name=_('trusted domain object'),
                                             error=_('no trusted domain '
                                                     'matched the specified '
                                                     'flat name'))
        if not entries:
            raise errors.NotFound(reason=_('trusted domain object not found'))

        return entries

    def get_trusted_domain_object_sid(self, object_name,
                                      fallback_to_ldap=True):
        result = pysss_nss_idmap.getsidbyname(object_name)
        if object_name in result and \
           (pysss_nss_idmap.SID_KEY in result[object_name]):
            object_sid = result[object_name][pysss_nss_idmap.SID_KEY]
            return object_sid

        # If fallback to AD DC LDAP is not allowed, bail out
        if not fallback_to_ldap:
            raise errors.ValidationError(name=_('trusted domain object'),
                                         error=_('SSSD was unable to resolve '
                                                 'the object to a valid SID'))

        # Else, we are going to contact AD DC LDAP
        components = normalize_name(object_name)
        if not ('domain' in components or 'flatname' in components):
            # No domain or realm specified, ambiguous search
            raise errors.ValidationError(name=_('trusted domain object'),
                                         error=_('Ambiguous search, user '
                                                 'domain was not specified'))

        attrs = ['objectSid']
        filter = '(&(sAMAccountName=%(name)s)' \
                 '(|(objectClass=user)(objectClass=group)))' \
                 % dict(name=components['name'])
        scope = _ldap.SCOPE_SUBTREE
        entries = self.get_trusted_domain_objects(components.get('domain'),
                                                  components.get('flatname'),
                                                  filter, attrs, scope)

        if len(entries) > 1:
            # Treat non-unique entries as invalid
            raise errors.ValidationError(name=_('trusted domain object'),
                                         error=_('Trusted domain did not '
                                                 'return a unique object'))
        sid = self.__sid_to_str(entries[0]['objectSid'][0])
        try:
            test_sid = security.dom_sid(sid)
            return unicode(test_sid)
        except TypeError:
            raise errors.ValidationError(name=_('trusted domain object'),
                                         error=_('Trusted domain did not '
                                                 'return a valid SID for '
                                                 'the object'))

    def get_trusted_domain_object_type(self, name_or_sid):
        """
        Return the type of the object corresponding to the given name in
        the trusted domain, which is either 'user', 'group' or 'both'.
        The 'both' types is used for users with magic private groups.
        """

        object_type = None

        if is_sid_valid(name_or_sid):
            result = pysss_nss_idmap.getnamebysid(name_or_sid)
        else:
            result = pysss_nss_idmap.getsidbyname(name_or_sid)

        if name_or_sid in result:
            object_type = result[name_or_sid].get(pysss_nss_idmap.TYPE_KEY)

        # Do the translation to hide pysss_nss_idmap constants
        # from higher-level code
        return pysss_type_key_translation_dict.get(object_type)

    def get_trusted_domain_object_from_sid(self, sid):
        logger.debug("Converting SID to object name: %s", sid)

        # Check if the given SID is valid
        if not self.is_trusted_sid_valid(sid):
            raise errors.ValidationError(name='sid', error='SID is not valid')

        # Use pysss_nss_idmap to obtain the name
        result = pysss_nss_idmap.getnamebysid(sid).get(sid)

        valid_types = (pysss_nss_idmap.ID_USER,
                       pysss_nss_idmap.ID_GROUP,
                       pysss_nss_idmap.ID_BOTH)

        if result:
            if result.get(pysss_nss_idmap.TYPE_KEY) in valid_types:
                return result.get(pysss_nss_idmap.NAME_KEY)

        # If unsuccessful, search AD DC LDAP
        logger.debug("Searching AD DC LDAP")

        escaped_sid = escape_filter_chars(
            security.dom_sid(sid).__ndr_pack__(),
            2  # 2 means every character needs to be escaped
        )

        attrs = ['sAMAccountName']
        filter = (r'(&(objectSid=%(sid)s)'
                  '(|(objectClass=user)(objectClass=group)))'
                  % dict(sid=escaped_sid))  # sid in binary
        domain = self.get_domain_by_sid(sid)

        entries = self.get_trusted_domain_objects(domain=domain,
                                                  filter=filter,
                                                  attrs=attrs)

        if len(entries) > 1:
            # Treat non-unique entries as invalid
            raise errors.ValidationError(name=_('trusted domain object'),
                                         error=_('Trusted domain did not '
                                                 'return a unique object'))

        object_name = (
            "%s@%s" % (entries[0].single_value['sAMAccountName'].lower(),
                       domain.lower())
            )

        return unicode(object_name)

    def __get_trusted_domain_user_and_groups(self, object_name):
        """
        Returns a tuple with user SID and a list of SIDs of all groups he is
        a member of.

        LIMITATIONS:
            - only Trusted Admins group members can use this function as it
              uses secret for IPA-Trusted domain link
            - List of group SIDs does not contain group memberships outside
              of the trusted domain
        """
        components = normalize_name(object_name)
        domain = components.get('domain')
        flatname = components.get('flatname')
        name = components.get('name')

        is_valid_sid = is_sid_valid(object_name)
        if is_valid_sid:
            # Find a trusted domain for the SID
            domain = self.get_domain_by_sid(object_name)
            # Now search a trusted domain for a user with this SID
            attrs = ['cn']
            filter = '(&(objectClass=user)(objectSid=%(sid)s))' \
                % dict(sid=object_name)
            try:
                entries = self.get_trusted_domain_objects(domain=domain,
                                                          filter=filter,
                                                          attrs=attrs,
                                                          scope=_ldap.SCOPE_SUBTREE)
            except errors.NotFound:
                raise errors.NotFound(reason=_('trusted domain user not found'))
            user_dn = entries[0].dn
        elif domain or flatname:
            attrs = ['cn']
            filter = '(&(sAMAccountName=%(name)s)(objectClass=user))' \
                     % dict(name=name)
            try:
                entries = self.get_trusted_domain_objects(domain,
                                                          flatname, filter, attrs,
                                                          _ldap.SCOPE_SUBTREE)
            except errors.NotFound:
                raise errors.NotFound(reason=_('trusted domain user not found'))
            user_dn = entries[0].dn
        else:
            # No domain or realm specified, ambiguous search
            raise errors.ValidationError(name=_('trusted domain object'),
                                         error=_('Ambiguous search, '
                                                 'user domain was not specified'))

        # Get SIDs of user object and it's groups
        # tokenGroups attribute must be read with a scope BASE for a known user
        # distinguished name to avoid search error
        attrs = ['objectSID', 'tokenGroups']
        filter = "(objectClass=user)"
        entries = self.get_trusted_domain_objects(domain,
                                                  flatname, filter, attrs,
                                                  _ldap.SCOPE_BASE, user_dn)
        object_sid = self.__sid_to_str(entries[0]['objectSid'][0])
        group_sids = [self.__sid_to_str(sid)
                      for sid in entries[0]['tokenGroups']]
        return (object_sid, group_sids)

    def get_trusted_domain_user_and_groups(self, object_name):
        """
        Returns a tuple with user SID and a list of SIDs of all groups he is
        a member of.

        First attempts to perform SID lookup via SSSD and in case of failure
        resorts back to checking trusted domain's AD DC LDAP directly.

        LIMITATIONS:
            - only Trusted Admins group members can use this function as it
              uses secret for IPA-Trusted domain link if SSSD lookup failed
            - List of group SIDs does not contain group memberships outside
              of the trusted domain
        """
        group_sids = None
        group_list = None
        object_sid = None
        is_valid_sid = is_sid_valid(object_name)
        if is_valid_sid:
            object_sid = object_name
            result = pysss_nss_idmap.getnamebysid(object_name)
            if object_name in result and \
               (pysss_nss_idmap.NAME_KEY in result[object_name]):
                group_list = pysss.getgrouplist(
                                 result[object_name][pysss_nss_idmap.NAME_KEY])
        else:
            result = pysss_nss_idmap.getsidbyname(object_name)
            if object_name in result and \
               (pysss_nss_idmap.SID_KEY in result[object_name]):
                object_sid = result[object_name][pysss_nss_idmap.SID_KEY]
                group_list = pysss.getgrouplist(object_name)

        if not group_list:
            return self.__get_trusted_domain_user_and_groups(object_name)

        group_sids = pysss_nss_idmap.getsidbyname(group_list)
        return (
                object_sid,
                [el[1][pysss_nss_idmap.SID_KEY] for el in group_sids.items()]
               )

    def __sid_to_str(self, sid):
        """
        Converts binary SID to string representation
        Returns unicode string
        """
        sid_rev_num = ord(sid[0])
        number_sub_id = ord(sid[1])
        ia = struct.unpack('!Q', '\x00\x00'+sid[2:8])[0]
        subs = [
            struct.unpack('<I', sid[8+4*i:12+4*i])[0]
            for i in range(number_sub_id)
        ]
        return u'S-%d-%d-%s' % (sid_rev_num, ia,
                                '-'.join([str(s) for s in subs]),)

    def kinit_as_administrator(self, domain):
        """
        Initializes ccache with http service credentials.

        Applies session code defaults for ccache directory and naming prefix.
        Session code uses kinit_+<pid>, we use
        kinit_+<TD>+<domain netbios name> so there is no clash.

        Returns tuple (ccache path, principal) where (None, None) signifes an
        error on ccache initialization
        """

        if self._admin_creds is None:
            return (None, None)

        domain_suffix = domain.replace('.', '-')

        ccache_name = "kinit_TDA%s" % (domain_suffix)
        ccache_path = os.path.join(paths.IPA_CCACHES, ccache_name)

        (principal, password) = self._admin_creds.split('%', 1)

        # Destroy the contents of the ccache
        logger.debug('Destroying the contents of the separate ccache')

        ipautil.run(
            [paths.KDESTROY, '-A', '-c', ccache_path],
            env={'KRB5CCNAME': ccache_path},
            raiseonerr=False)

        # Destroy the contents of the ccache
        logger.debug('Running kinit with credentials of AD administrator')

        result = ipautil.run(
            [paths.KINIT, principal],
            env={'KRB5CCNAME': ccache_path},
            stdin=password,
            raiseonerr=False)

        if result.returncode == 0:
            return (ccache_path, principal)
        else:
            return (None, None)

    def search_in_dc(self, domain, filter, attrs, scope, basedn=None,
                     quiet=False):
        """
        Perform LDAP search in a trusted domain `domain' Domain Controller.
        Returns resulting entries or None.
        """

        entries = None

        info = self.__retrieve_trusted_domain_gc_list(domain)

        if not info:
            raise errors.ValidationError(
                name=_('Trust setup'),
                error=_('Cannot retrieve trusted domain GC list'))

        for (host, port) in info['gc']:
            entries = self.__search_in_dc(info, host, port, filter, attrs,
                                          scope, basedn=basedn,
                                          quiet=quiet)
            if entries:
                break

        return entries

    def __search_in_dc(self, info, host, port, filter, attrs, scope,
                       basedn=None, quiet=False):
        """
        Actual search in AD LDAP server, using SASL GSSAPI authentication
        Returns LDAP result or None.
        """

        ccache_name = None

        if self._admin_creds:
            (ccache_name,
             _principal) = self.kinit_as_administrator(info['dns_domain'])

        if ccache_name:
            with ipautil.private_ccache(path=ccache_name):
                entries = None

                try:
                    ldap_uri = ipaldap.get_ldap_uri(host)
                    conn = ipaldap.LDAPClient(
                        ldap_uri,
                        no_schema=True,
                        decode_attrs=False
                    )
                    conn.gssapi_bind()

                    if basedn is None:
                        # Use domain root base DN
                        basedn = ipautil.realm_to_suffix(info['dns_domain'])

                    entries = conn.get_entries(basedn, scope, filter, attrs)
                except Exception as e:
                    msg = "Search on AD DC {host}:{port} failed with: {err}"\
                          .format(host=host, port=str(port), err=str(e))
                    if quiet:
                        logger.debug('%s', msg)
                    else:
                        logger.warning('%s', msg)

                return entries
        return None

    def __retrieve_trusted_domain_gc_list(self, domain):
        """
        Retrieves domain information and preferred GC list
        Returns dictionary with following keys
             name       -- NetBIOS name of the trusted domain
             dns_domain -- DNS name of the trusted domain
             gc         -- array of tuples (server, port) for Global Catalog
        """
        if domain in self._info:
            return self._info[domain]

        if not self._creds:
            self._parm = param.LoadParm()
            self._parm.load(
                os.path.join(paths.USR_SHARE_IPA_DIR, "smb.conf.empty"))
            self._parm.set('netbios name', self.flatname)
            self._creds = credentials.Credentials()
            self._creds.set_kerberos_state(credentials.MUST_USE_KERBEROS)
            self._creds.guess(self._parm)
            self._creds.set_workstation(self.flatname)

        netrc = net.Net(creds=self._creds, lp=self._parm)
        finddc_error = None
        result = None
        flags = nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_GC | nbt.NBT_SERVER_CLOSEST
        try:
            result = netrc.finddc(domain=domain, flags=flags)
        except RuntimeError as e:
            try:
                # If search of closest GC failed, attempt to find any one
                flags = nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_GC
                result = netrc.finddc(domain=domain, flags=flags)
            except RuntimeError as e:
                finddc_error = e

        if not self._domains:
            self._domains = self.get_trusted_domains()

        info = dict()
        servers = []

        if result:
            info['name'] = unicode(result.domain_name)
            info['dns_domain'] = unicode(result.dns_domain)
            servers = [(unicode(result.pdc_dns_name), 3268)]
        else:
            info['name'] = self._domains[domain]
            info['dns_domain'] = domain
            # Retrieve GC servers list
            gc_name = '_gc._tcp.%s.' % info['dns_domain']

            try:
                answers = query_srv(gc_name)
            except DNSException as e:
                answers = []

            for answer in answers:
                server = str(answer.target).rstrip(".")
                servers.append((server, answer.port))

        info['gc'] = servers

        # Both methods should not fail at the same time
        if finddc_error and len(info['gc']) == 0:
            raise assess_dcerpc_error(finddc_error)

        self._info[domain] = info
        return info


def string_to_array(what):
    if six.PY3 and isinstance(what, bytes):
        return [v for v in what]
    return [ord(v) for v in what]


class TrustDomainInstance(object):

    def __init__(self, hostname, creds=None):
        self.parm = param.LoadParm()
        self.parm.load(os.path.join(paths.USR_SHARE_IPA_DIR, "smb.conf.empty"))
        if len(hostname) > 0:
            self.parm.set('netbios name', hostname)
        self.creds = creds
        self.hostname = hostname
        self.info = {}
        self._pipe = None
        self._policy_handle = None
        self.read_only = False
        self.ftinfo_records = None
        self.validation_attempts = 0

    def __gen_lsa_connection(self, binding):
        if self.creds is None:
            raise errors.RequirementError(name=_('CIFS credentials object'))
        try:
            result = lsa.lsarpc(binding, self.parm, self.creds)
            return result
        except RuntimeError as e:
            raise assess_dcerpc_error(e)

    def init_lsa_pipe(self, remote_host):
        """
        Try to initialize connection to the LSA pipe at remote host.
        This method tries consequently all possible transport options
        and selects one that works. See __gen_lsa_bindings() for details.

        The actual result may depend on details of existing credentials.
        For example, using signing causes NO_SESSION_KEY with Win2K8 and
        using kerberos against Samba with signing does not work.
        """
        # short-cut: if LSA pipe is initialized, skip completely
        if self._pipe:
            return

        attempts = 0
        session_attempts = 0
        bindings = self.__gen_lsa_bindings(remote_host)
        for binding in bindings:
            try:
                self._pipe = self.__gen_lsa_connection(binding)
                if self._pipe and self._pipe.session_key:
                    break
            except errors.ACIError:
                attempts = attempts + 1
            except RuntimeError:
                # When session key is not available, we just skip this binding
                session_attempts = session_attempts + 1

        if self._pipe is None and \
           (attempts + session_attempts) == len(bindings):
            raise errors.ACIError(
                      info=_('CIFS server %(host)s denied your credentials')
                      % dict(host=remote_host))

        if self._pipe is None:
            raise errors.RemoteRetrieveError(
                    reason=_('Cannot establish LSA connection to %(host)s. '
                             'Is CIFS server running?') % dict(host=remote_host))
        self.binding = binding
        self.session_key = self._pipe.session_key

    def __gen_lsa_bindings(self, remote_host):
        """
        There are multiple transports to issue LSA calls. However, depending on
        a system in use they may be blocked by local operating system policies.
        Generate all we can use. init_lsa_pipe() will try them one by one until
        there is one working.

        We try NCACN_NP before NCACN_IP_TCP and use SMB2 before SMB1.
        """
        transports = (u'ncacn_np', u'ncacn_ip_tcp')
        options = (u'smb2,print', u'print')
        return [u'%s:%s[%s]' % (t, remote_host, o)
                for t in transports for o in options]

    def retrieve_anonymously(self, remote_host,
                             discover_srv=False, search_pdc=False):
        """
        When retrieving DC information anonymously, we can't get SID of the domain
        """
        netrc = net.Net(creds=self.creds, lp=self.parm)
        flags = nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS | nbt.NBT_SERVER_WRITABLE
        if search_pdc:
            flags = flags | nbt.NBT_SERVER_PDC
        try:
            if discover_srv:
                result = netrc.finddc(domain=remote_host, flags=flags)
            else:
                result = netrc.finddc(address=remote_host, flags=flags)
        except RuntimeError as e:
            raise assess_dcerpc_error(e)

        if not result:
            return False
        self.info['name'] = unicode(result.domain_name)
        self.info['dns_domain'] = unicode(result.dns_domain)
        self.info['dns_forest'] = unicode(result.forest)
        self.info['guid'] = unicode(result.domain_uuid)
        self.info['dc'] = unicode(result.pdc_dns_name)
        self.info['is_pdc'] = (result.server_type & nbt.NBT_SERVER_PDC) != 0

        # Netlogon response doesn't contain SID of the domain.
        # We need to do rootDSE search with LDAP_SERVER_EXTENDED_DN_OID
        # control to reveal the SID
        ldap_uri = 'ldap://%s' % (result.pdc_dns_name)
        conn = ldap_initialize(ldap_uri)
        conn.set_option(_ldap.OPT_SERVER_CONTROLS, [ExtendedDNControl()])
        search_result = None
        try:
            _objtype, res = conn.search_s('', _ldap.SCOPE_BASE)[0]
            for o in res.keys():
                if isinstance(res[o], list):
                    t = res[o]
                    for z, v in enumerate(t):
                        if isinstance(v, bytes):
                            t[z] = v.decode('utf-8')
                elif isinstance(res[o], bytes):
                    res[o] = res[o].decode('utf-8')
            search_result = res['defaultNamingContext'][0]
            self.info['dns_hostname'] = res['dnsHostName'][0]
        except _ldap.LDAPError as e:
            logger.error(
                "LDAP error when connecting to %s: %s",
                unicode(result.pdc_name), str(e))
        except KeyError as e:
            logger.error("KeyError: %s, LDAP entry from %s "
                         "returned malformed. Your DNS might be "
                         "misconfigured.",
                         unicode(e),
                         unicode(result.pdc_name))

        if search_result:
            self.info['sid'] = self.parse_naming_context(search_result)
        return True

    def parse_naming_context(self, context):
        naming_ref = re.compile('.*<SID=(S-.*)>.*')
        return unicode(naming_ref.match(context).group(1))

    def retrieve(self, remote_host):
        self.init_lsa_pipe(remote_host)

        objectAttribute = lsa.ObjectAttribute()
        objectAttribute.sec_qos = lsa.QosInfo()
        try:
            self._policy_handle = \
                self._pipe.OpenPolicy2(u"", objectAttribute,
                                       security.SEC_FLAG_MAXIMUM_ALLOWED)
            result = self._pipe.QueryInfoPolicy2(self._policy_handle,
                                                 lsa.LSA_POLICY_INFO_DNS)
        except RuntimeError as e:
            raise assess_dcerpc_error(e)

        self.info['name'] = unicode(result.name.string)
        self.info['dns_domain'] = unicode(result.dns_domain.string)
        self.info['dns_forest'] = unicode(result.dns_forest.string)
        self.info['guid'] = unicode(result.domain_guid)
        self.info['sid'] = unicode(result.sid)
        self.info['dc'] = remote_host

        try:
            result = self._pipe.QueryInfoPolicy2(self._policy_handle,
                                                 lsa.LSA_POLICY_INFO_ROLE)
        except RuntimeError as e:
            raise assess_dcerpc_error(e)

        self.info['is_pdc'] = (result.role == lsa.LSA_ROLE_PRIMARY)

    def generate_auth(self, trustdom_secret):
        password_blob = string_to_array(trustdom_secret.encode('utf-16-le'))

        clear_value = drsblobs.AuthInfoClear()
        clear_value.size = len(password_blob)
        clear_value.password = password_blob

        clear_authinfo = drsblobs.AuthenticationInformation()
        clear_authinfo.LastUpdateTime = samba.unix2nttime(int(time.time()))
        clear_authinfo.AuthType = lsa.TRUST_AUTH_TYPE_CLEAR
        clear_authinfo.AuthInfo = clear_value

        authinfo_array = drsblobs.AuthenticationInformationArray()
        authinfo_array.count = 1
        authinfo_array.array = [clear_authinfo]

        outgoing = drsblobs.trustAuthInOutBlob()
        outgoing.count = 1
        outgoing.current = authinfo_array

        confounder = [3]*512
        for i in range(512):
            confounder[i] = random.randint(0, 255)

        trustpass = drsblobs.trustDomainPasswords()
        trustpass.confounder = confounder

        trustpass.outgoing = outgoing
        trustpass.incoming = outgoing

        trustpass_blob = ndr_pack(trustpass)

        encrypted_trustpass = arcfour_encrypt(self._pipe.session_key,
                                              trustpass_blob)

        auth_blob = lsa.DATA_BUF2()
        auth_blob.size = len(encrypted_trustpass)
        auth_blob.data = string_to_array(encrypted_trustpass)

        auth_info = lsa.TrustDomainInfoAuthInfoInternal()
        auth_info.auth_blob = auth_blob
        self.auth_info = auth_info

    def generate_ftinfo(self, another_domain):
        """
        Generates TrustDomainInfoFullInfo2Internal structure
        This structure allows to pass information about all domains associated
        with the another domain's realm.

        Only top level name and top level name exclusions are handled here.
        """
        if not another_domain.ftinfo_records:
            return None

        ftinfo_records = []
        info = lsa.ForestTrustInformation()

        for rec in another_domain.ftinfo_records:
            record = lsa.ForestTrustRecord()
            record.flags = 0
            record.time = rec['rec_time']
            record.type = rec['rec_type']
            record.forest_trust_data.string = rec['rec_name']
            ftinfo_records.append(record)

        info.count = len(ftinfo_records)
        info.entries = ftinfo_records
        return info

    def clear_ftinfo_conflict(self, another_domain, cinfo):
        """
        Attempt to clean up the forest trust collisions

        :param self: the forest we establish trust to
        :param another_domain: a forest that establishes trust to 'self'
        :param cinfo: lsa_ForestTrustCollisionInfo structure that contain
                      set of of lsa_ForestTrustCollisionRecord structures
        :raises: TrustTopologyConflictSolved, TrustTopologyConflictError

        This code tries to perform intelligent job of going
        over individual collisions and making exclusion entries
        for affected IPA namespaces.

        There are three possible conflict configurations:
          - conflict of DNS namespace (TLN conflict, LSA_TLN_DISABLED_CONFLICT)
          - conflict of SID namespace (LSA_SID_DISABLED_CONFLICT)
          - conflict of NetBIOS namespace (LSA_NB_DISABLED_CONFLICT)

        we only can handle TLN conflicts because (a) excluding SID namespace
        is not possible and (b) excluding NetBIOS namespace not possible.
        These two types of conflicts should result in trust-add CLI error

        These conflicts can come from external source (another forest) or
        from internal source (another domain in the same forest). We only
        can fix the problems with another forest.

        To resolve TLN conflict we need to do following:
          1. Retrieve forest trust information for the forest we conflict on
          2. Add an exclusion entry for IPA DNS namespace to it
          3. Set forest trust information for the forest we conflict on
          4. Re-try establishing trust to the original forest

        This all can only be done under privileges of Active Directory admin
        that can change forest trusts. If we cannot have those privileges,
        the work has to be done manually in the Windows UI for
        'Active Directory Domains and Trusts' by the administrator of the
        original forest.
        """

        # List of entries for unsolved conflicts
        result = []

        trust_timestamp = long(time.time()*1e7+116444736000000000)

        # Collision information contains entries for specific trusted domains
        # we collide with. Look into TLN collisions and add a TLN exclusion
        # entry to the specific domain trust.
        logger.error("Attempt to solve forest trust topology conflicts")
        for rec in cinfo.entries:
            if rec.type == lsa.LSA_FOREST_TRUST_COLLISION_TDO:
                dominfo = self._pipe.lsaRQueryForestTrustInformation(
                                 self._policy_handle,
                                 rec.name,
                                 lsa.LSA_FOREST_TRUST_DOMAIN_INFO)

                # Oops, we were unable to retrieve trust topology for this
                # trusted domain (forest).
                if not dominfo:
                    result.append(rec)
                    logger.error("Unable to resolve conflict for "
                                 "DNS domain %s in the forest %s "
                                 "for domain trust %s. Trust cannot "
                                 "be established unless this conflict "
                                 "is fixed manually.",
                                 another_domain.info['dns_domain'],
                                 self.info['dns_domain'],
                                 rec.name.string)
                    continue

                # Copy over the entries, extend with TLN exclusion
                entries = []
                is_our_record = False
                for e in dominfo.entries:
                    e1 = lsa.ForestTrustRecord()
                    e1.type = e.type
                    e1.flags = e.flags
                    e1.time = e.time
                    e1.forest_trust_data = e.forest_trust_data

                    # Search for a match in the topology of another domain
                    # if there is a match, we have to convert a record
                    # into a TLN exclusion to allow its routing to the
                    # another domain
                    for r in another_domain.ftinfo_records:
                        if r['rec_name'] == e.forest_trust_data.string:
                            is_our_record = True

                            # Convert e1 into an exclusion record
                            e1.type = lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX
                            e1.flags = 0
                            e1.time = trust_timestamp
                            break
                    entries.append(e1)

                # If no candidate for the exclusion entry was found
                # make sure it is the other domain itself, this covers
                # a most common case
                if not is_our_record:
                    # Create TLN exclusion record for the top level domain
                    record = lsa.ForestTrustRecord()
                    record.type = lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX
                    record.flags = 0
                    record.time = trust_timestamp
                    record.forest_trust_data.string = \
                        another_domain.info['dns_domain']
                    entries.append(record)

                fti = lsa.ForestTrustInformation()
                fti.count = len(entries)
                fti.entries = entries

                # Update the forest trust information now
                ldname = lsa.StringLarge()
                ldname.string = rec.name.string
                cninfo = self._pipe.lsaRSetForestTrustInformation(
                             self._policy_handle,
                             ldname,
                             lsa.LSA_FOREST_TRUST_DOMAIN_INFO,
                             fti, 0)
                if cninfo:
                    result.append(rec)
                    logger.error("When defining exception for DNS "
                                 "domain %s in forest %s for "
                                 "trusted forest %s, "
                                 "got collision info back:\n%s",
                                 another_domain.info['dns_domain'],
                                 self.info['dns_domain'],
                                 rec.name.string,
                                 ndr_print(cninfo))
            else:
                result.append(rec)
                logger.error("Unable to resolve conflict for "
                             "DNS domain %s in the forest %s "
                             "for in-forest domain %s. Trust cannot "
                             "be established unless this conflict "
                             "is fixed manually.",
                             another_domain.info['dns_domain'],
                             self.info['dns_domain'],
                             rec.name.string)

        if len(result) == 0:
            logger.error("Successfully solved all conflicts")
            raise TrustTopologyConflictSolved()

        # Otherwise, raise TrustTopologyConflictError() exception
        domains = [x.name.string for x in result]
        raise errors.TrustTopologyConflictError(
                              target=self.info['dns_domain'],
                              conflict=another_domain.info['dns_domain'],
                              domains=domains)



    def update_ftinfo(self, another_domain):
        """
        Updates forest trust information in this forest corresponding
        to the another domain's information.
        """
        if another_domain.ftinfo_records:
            ftinfo = self.generate_ftinfo(another_domain)
            # Set forest trust information -- we do it only against AD DC as
            # smbd already has the information about itself
            ldname = lsa.StringLarge()
            ldname.string = another_domain.info['dns_domain']
            ftlevel = lsa.LSA_FOREST_TRUST_DOMAIN_INFO
            # RSetForestTrustInformation returns collision information
            # for trust topology
            cinfo = self._pipe.lsaRSetForestTrustInformation(
                        self._policy_handle,
                        ldname,
                        ftlevel,
                        ftinfo, 0)
            if cinfo:
                logger.error("When setting forest trust information, "
                             "got collision info back:\n%s",
                             ndr_print(cinfo))
                self.clear_ftinfo_conflict(another_domain, cinfo)

    def establish_trust(self, another_domain, trustdom_secret,
                        trust_type='bidirectional', trust_external=False):
        """
        Establishes trust between our and another domain
        Input: another_domain -- instance of TrustDomainInstance,
                                 initialized with #retrieve call
               trustdom_secret -- shared secred used for the trust
        """
        if self.info['name'] == another_domain.info['name']:
            # Check that NetBIOS names do not clash
            raise errors.ValidationError(name=u'AD Trust Setup',
                                         error=_('the IPA server and the '
                                                 'remote domain cannot share '
                                                 'the same NetBIOS name: %s')
                                         % self.info['name'])

        self.generate_auth(trustdom_secret)

        info = lsa.TrustDomainInfoInfoEx()
        info.domain_name.string = another_domain.info['dns_domain']
        info.netbios_name.string = another_domain.info['name']
        info.sid = security.dom_sid(another_domain.info['sid'])
        info.trust_direction = lsa.LSA_TRUST_DIRECTION_INBOUND
        if trust_type == TRUST_BIDIRECTIONAL:
            info.trust_direction |= lsa.LSA_TRUST_DIRECTION_OUTBOUND
        info.trust_type = lsa.LSA_TRUST_TYPE_UPLEVEL
        info.trust_attributes = 0
        if trust_external:
            info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_NON_TRANSITIVE

        try:
            dname = lsa.String()
            dname.string = another_domain.info['dns_domain']
            res = self._pipe.QueryTrustedDomainInfoByName(
                self._policy_handle,
                dname,
                lsa.LSA_TRUSTED_DOMAIN_INFO_FULL_INFO
            )
            if res.info_ex.trust_type != lsa.LSA_TRUST_TYPE_UPLEVEL:
                msg = _('There is already a trust to {ipa_domain} with '
                        'unsupported type {trust_type}. Please remove '
                        'it manually on AD DC side.')
                ttype = trust_type_string(
                    res.info_ex.trust_type, res.info_ex.trust_attributes
                )
                err = msg.format(
                    ipa_domain=another_domain.info['dns_domain'],
                    trust_type=ttype)

                raise errors.ValidationError(
                    name=_('AD domain controller'),
                    error=err
                )

            self._pipe.DeleteTrustedDomain(self._policy_handle,
                                           res.info_ex.sid)
        except RuntimeError as e:
            # pylint: disable=unbalanced-tuple-unpacking
            num, _message = e.args
            # pylint: enable=unbalanced-tuple-unpacking
            # Ignore anything but access denied (NT_STATUS_ACCESS_DENIED)
            if num == -1073741790:
                raise access_denied_error

        try:
            trustdom_handle = self._pipe.CreateTrustedDomainEx2(
                                           self._policy_handle,
                                           info, self.auth_info,
                                           security.SEC_STD_DELETE)
        except RuntimeError as e:
            raise assess_dcerpc_error(e)

        # We should use proper trustdom handle in order to modify the
        # trust settings. Samba insists this has to be done with LSA
        # OpenTrustedDomain* calls, it is not enough to have a handle
        # returned by the CreateTrustedDomainEx2 call.
        trustdom_handle = self._pipe.OpenTrustedDomainByName(
                                         self._policy_handle,
                                         dname,
                                         security.SEC_FLAG_MAXIMUM_ALLOWED)
        try:
            infocls = lsa.TrustDomainInfoSupportedEncTypes()
            infocls.enc_types = security.KERB_ENCTYPE_RC4_HMAC_MD5
            infocls.enc_types |= security.KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96
            infocls.enc_types |= security.KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96
            self._pipe.SetInformationTrustedDomain(
                           trustdom_handle,
                           lsa.LSA_TRUSTED_DOMAIN_SUPPORTED_ENCRYPTION_TYPES,
                           infocls)
        except RuntimeError as e:
            # We can ignore the error here -- changing enctypes is for
            # improved security but the trust will work with default values as
            # well. In particular, the call may fail against Windows 2003
            # server as that one doesn't support AES encryption types
            pass

        if not trust_external:
            try:
                info = self._pipe.QueryTrustedDomainInfo(
                                      trustdom_handle,
                                      lsa.LSA_TRUSTED_DOMAIN_INFO_INFO_EX)
                info.trust_attributes |= lsa.LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE
                self._pipe.SetInformationTrustedDomain(
                                      trustdom_handle,
                                      lsa.LSA_TRUSTED_DOMAIN_INFO_INFO_EX, info)
            except RuntimeError as e:
                logger.error(
                      'unable to set trust transitivity status: %s', str(e))

        # Updating forest trust info may fail
        # If it failed due to topology conflict, it may be fixed automatically
        # update_ftinfo() will through exceptions in that case
        # Note that MS-LSAD 3.1.4.7.16 says:
        # -------------------------
        # The server MUST also make sure that the trust attributes associated
        # with the trusted domain object referenced by the TrustedDomainName
        # parameter has the TRUST_ATTRIBUTE_FOREST_TRANSITIVE set.
        # If the attribute is not present, the server MUST return
        # STATUS_INVALID_PARAMETER.
        # -------------------------
        # Thus, we must not update forest trust info for the external trust
        if self.info['is_pdc'] and not trust_external:
            self.update_ftinfo(another_domain)

    def verify_trust(self, another_domain):
        def retrieve_netlogon_info_2(logon_server, domain, function_code, data):
            try:
                netr_pipe = netlogon.netlogon(domain.binding,
                                              domain.parm, domain.creds)
                result = netr_pipe.netr_LogonControl2Ex(
                                           logon_server=logon_server,
                                           function_code=function_code,
                                           level=2,
                                           data=data)
                return result
            except RuntimeError as e:
                raise assess_dcerpc_error(e)

        result = retrieve_netlogon_info_2(None, self,
                                          netlogon.NETLOGON_CONTROL_TC_VERIFY,
                                          another_domain.info['dns_domain'])

        if result and result.flags and netlogon.NETLOGON_VERIFY_STATUS_RETURNED:
            if result.pdc_connection_status[0] != 0 and \
               result.tc_connection_status[0] != 0:
                if result.pdc_connection_status[1] == "WERR_ACCESS_DENIED":
                    # Most likely AD DC hit another IPA replica which
                    # yet has no trust secret replicated

                    # Sleep and repeat again
                    self.validation_attempts += 1
                    if self.validation_attempts < 10:
                        sleep(5)
                        return self.verify_trust(another_domain)

                    # If we get here, we already failed 10 times
                    srv_record_templates = (
                        '_ldap._tcp.%s',
                        '_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.%s'
                    )

                    srv_records = ', '.join(
                        [srv_record % api.env.domain
                         for srv_record in srv_record_templates]
                    )

                    error_message = _(
                        'IPA master denied trust validation requests from AD '
                        'DC %(count)d times. Most likely AD DC contacted a '
                        'replica that has no trust information replicated '
                        'yet. Additionally, please check that AD DNS is able '
                        'to resolve %(records)s SRV records to the correct '
                        'IPA server.') % dict(count=self.validation_attempts,
                                              records=srv_records)

                    raise errors.ACIError(info=error_message)

                raise assess_dcerpc_error(result.pdc_connection_status)

            return True

        return False


def fetch_domains(api, mydomain, trustdomain, creds=None, server=None):
    def communicate(td):
        td.init_lsa_pipe(td.info['dc'])
        netr_pipe = netlogon.netlogon(td.binding, td.parm, td.creds)
        # Older FreeIPA versions used netr_DsrEnumerateDomainTrusts call
        # but it doesn't provide information about non-domain UPNs associated
        # with the forest, thus we have to use netr_DsRGetForestTrustInformation
        domains = netr_pipe.netr_DsRGetForestTrustInformation(td.info['dc'], None, 0)
        return domains

    domains = None
    domain_validator = DomainValidator(api)
    configured = domain_validator.is_configured()
    if not configured:
        return None

    td = TrustDomainInstance('')
    td.parm.set('workgroup', mydomain)
    cr = credentials.Credentials()
    cr.set_kerberos_state(credentials.DONT_USE_KERBEROS)
    cr.guess(td.parm)
    cr.set_anonymous()
    cr.set_workstation(domain_validator.flatname)
    netrc = net.Net(creds=cr, lp=td.parm)
    try:
        if server:
            result = netrc.finddc(address=server,
                                  flags=nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS)
        else:
            result = netrc.finddc(domain=trustdomain,
                                  flags=nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS)
    except RuntimeError as e:
        raise assess_dcerpc_error(e)

    td.info['dc'] = unicode(result.pdc_dns_name)
    td.info['name'] = unicode(result.dns_domain)
    if type(creds) is bool:
        # Rely on existing Kerberos credentials in the environment
        td.creds = credentials.Credentials()
        td.creds.set_kerberos_state(credentials.MUST_USE_KERBEROS)
        td.creds.guess(td.parm)
        td.creds.set_workstation(domain_validator.flatname)
        domains = communicate(td)
    else:
        # Attempt to authenticate as HTTP/ipa.master and use cross-forest trust
        # or as passed-in user in case of a one-way trust
        domval = DomainValidator(api)
        ccache_name = None
        if creds:
            domval._admin_creds = creds
            ccache_name, _principal = domval.kinit_as_administrator(
                trustdomain)
        else:
            raise errors.ValidationError(name=_('Credentials'),
                                         error=_('Missing credentials for '
                                                 'cross-forest communication'))
        td.creds = credentials.Credentials()
        td.creds.set_kerberos_state(credentials.MUST_USE_KERBEROS)
        if ccache_name:
            with ipautil.private_ccache(path=ccache_name):
                td.creds.guess(td.parm)
                td.creds.set_workstation(domain_validator.flatname)
                domains = communicate(td)

    if domains is None:
        return None

    result = {'domains': {}, 'suffixes': {}}
    # netr_DsRGetForestTrustInformation returns two types of entries:
    # domain information  -- name, NetBIOS name, SID of the domain
    # top level name info -- a name suffix associated with the forest
    # We should ignore forest root name/name suffix as it is already part
    # of trust information for IPA purposes and only add what's inside the forest
    for t in domains.entries:
        if t.type == lsa.LSA_FOREST_TRUST_DOMAIN_INFO:
            tname = unicode(t.forest_trust_data.dns_domain_name.string)
            if tname == trustdomain:
                continue
            result['domains'][tname] = {
                'cn': tname,
                'ipantflatname': unicode(
                    t.forest_trust_data.netbios_domain_name.string),
                'ipanttrusteddomainsid': unicode(
                    t.forest_trust_data.domain_sid)
            }
        elif t.type == lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME:
            tname = unicode(t.forest_trust_data.string)
            if tname == trustdomain:
                continue

            result['suffixes'][tname] = {'cn': tname}
    return result


def retrieve_remote_domain(hostname, local_flatname,
                           realm, realm_server=None,
                           realm_admin=None, realm_passwd=None):
    def get_instance(local_flatname):
        # Fetch data from foreign domain using password only
        rd = TrustDomainInstance('')
        rd.parm.set('workgroup', local_flatname)
        rd.creds = credentials.Credentials()
        rd.creds.set_kerberos_state(credentials.DONT_USE_KERBEROS)
        rd.creds.guess(rd.parm)
        return rd

    rd = get_instance(local_flatname)
    rd.creds.set_anonymous()
    rd.creds.set_workstation(hostname)
    if realm_server is None:
        rd.retrieve_anonymously(realm, discover_srv=True, search_pdc=True)
    else:
        rd.retrieve_anonymously(realm_server,
                                discover_srv=False, search_pdc=True)
    rd.read_only = True
    if realm_admin and realm_passwd:
        if 'name' in rd.info:
            names = realm_admin.split('\\')
            if len(names) > 1:
                # realm admin is in DOMAIN\user format
                # strip DOMAIN part as we'll enforce the one discovered
                realm_admin = names[-1]
            auth_string = u"%s\%s%%%s" \
                          % (rd.info['name'], realm_admin, realm_passwd)
            td = get_instance(local_flatname)
            td.creds.parse_string(auth_string)
            td.creds.set_workstation(hostname)
            if realm_server is None:
                # we must have rd.info['dns_hostname'] then
                # as it is part of the anonymous discovery
                td.retrieve(rd.info['dns_hostname'])
            else:
                td.retrieve(realm_server)
            td.read_only = False
            return td

    # Otherwise, use anonymously obtained data
    return rd


class TrustDomainJoins(object):
    def __init__(self, api):
        self.api = api
        self.local_domain = None
        self.remote_domain = None
        self.__allow_behavior = 0

        domain_validator = DomainValidator(api)
        self.configured = domain_validator.is_configured()

        if self.configured:
            self.local_flatname = domain_validator.flatname
            self.local_dn = domain_validator.dn
            self.__populate_local_domain()

    def allow_behavior(self, *flags):
        for f in flags:
            self.__allow_behavior |= int(f)

    def __populate_local_domain(self):
        # Initialize local domain info using kerberos only
        ld = TrustDomainInstance(self.local_flatname)
        ld.creds = credentials.Credentials()
        ld.creds.set_kerberos_state(credentials.MUST_USE_KERBEROS)
        ld.creds.guess(ld.parm)
        ld.creds.set_workstation(ld.hostname)
        ld.retrieve(installutils.get_fqdn())
        self.local_domain = ld

    def populate_remote_domain(self, realm, realm_server=None,
                               realm_admin=None, realm_passwd=None):
        self.remote_domain = retrieve_remote_domain(
            self.local_domain.hostname,
            self.local_domain.info['name'],
            realm,
            realm_server=realm_server,
            realm_admin=realm_admin,
            realm_passwd=realm_passwd)

    def get_realmdomains(self):
        """
        Generate list of records for forest trust information about
        our realm domains. Note that the list generated currently
        includes only top level domains, no exclusion domains, and
        no TDO objects as we handle the latter in a separate way
        """
        if self.local_domain.read_only:
            return

        self.local_domain.ftinfo_records = []

        realm_domains = self.api.Command.realmdomains_show()['result']
        # Use realmdomains' modification timestamp
        # to judge records' last update time
        entry = self.api.Backend.ldap2.get_entry(
                    realm_domains['dn'], ['modifyTimestamp'])
        # Convert the timestamp to Windows 64-bit timestamp format
        trust_timestamp = long(
                time.mktime(
                     entry.single_value.get('modifytimestamp').timetuple()
                )*1e7+116444736000000000)

        forest = DNSName(self.local_domain.info['dns_forest'])
        # tforest is IPA forest. keep the line below for future checks
        # tforest = DNSName(self.remote_domain.info['dns_forest'])
        for dom in realm_domains['associateddomain']:
            d = DNSName(dom)

            # We should skip all DNS subdomains of our forest
            # because we are going to add *.<forest> TLN anyway
            if forest.is_superdomain(d) and forest != d:
                continue

            # We also should skip single label TLDs as they
            # cannot be added as TLNs
            if len(d.labels) == 1:
                continue

            ftinfo = dict()
            ftinfo['rec_name'] = dom
            ftinfo['rec_time'] = trust_timestamp
            ftinfo['rec_type'] = lsa.LSA_FOREST_TRUST_TOP_LEVEL_NAME
            self.local_domain.ftinfo_records.append(ftinfo)

    def join_ad_full_credentials(self, realm, realm_server, realm_admin,
                                 realm_passwd, trust_type):
        if not self.configured:
            return None

        if not(isinstance(self.remote_domain, TrustDomainInstance)):
            self.populate_remote_domain(
                realm,
                realm_server,
                realm_admin,
                realm_passwd
            )

        trust_external = bool(self.__allow_behavior & TRUST_JOIN_EXTERNAL)
        if self.remote_domain.info['dns_domain'] != \
           self.remote_domain.info['dns_forest']:
            if not trust_external:
                raise errors.NotAForestRootError(
                          forest=self.remote_domain.info['dns_forest'],
                          domain=self.remote_domain.info['dns_domain'])

        if not self.remote_domain.read_only:
            trustdom_pass = samba.generate_random_password(128, 128)
            self.get_realmdomains()

            # Establishing trust may throw an exception for topology
            # conflict. If it was solved, re-establish the trust again
            # Otherwise let the CLI to display a message about the conflict
            try:
                self.remote_domain.establish_trust(self.local_domain,
                                                   trustdom_pass,
                                                   trust_type, trust_external)
            except TrustTopologyConflictSolved:
                # we solved topology conflict, retry again
                self.remote_domain.establish_trust(self.local_domain,
                                                   trustdom_pass,
                                                   trust_type, trust_external)

            # For local domain we don't set topology information
            self.local_domain.establish_trust(self.remote_domain,
                                              trustdom_pass,
                                              trust_type, trust_external)
            # if trust is inbound, we don't need to verify it because
            # AD DC will respond with WERR_NO_SUCH_DOMAIN --
            # it only does verification for outbound trusts.
            result = True
            if trust_type == TRUST_BIDIRECTIONAL:
                result = self.remote_domain.verify_trust(self.local_domain)
            return dict(
                        local=self.local_domain,
                        remote=self.remote_domain,
                        verified=result
                       )
        return None

    def join_ad_ipa_half(self, realm, realm_server, trustdom_passwd, trust_type):
        if not self.configured:
            return None

        if not(isinstance(self.remote_domain, TrustDomainInstance)):
            self.populate_remote_domain(realm, realm_server, realm_passwd=None)

        trust_external = bool(self.__allow_behavior & TRUST_JOIN_EXTERNAL)
        if self.remote_domain.info['dns_domain'] != \
           self.remote_domain.info['dns_forest']:
            if not trust_external:
                raise errors.NotAForestRootError(
                          forest=self.remote_domain.info['dns_forest'],
                          domain=self.remote_domain.info['dns_domain'])

        self.local_domain.establish_trust(self.remote_domain,
                                          trustdom_passwd,
                                          trust_type, trust_external)
        return {
            'local': self.local_domain,
            'remote': self.remote_domain,
            'verified': False,
        }
