# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007  Red Hat
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
#

from __future__ import absolute_import

import logging
import socket

import six

from dns import resolver, rdatatype
from dns.exception import DNSException
from ipalib import errors
from ipalib.util import validate_domain_name
from ipapython.dnsutil import query_srv

from ipaplatform.paths import paths
from ipapython.ipautil import valid_ip, realm_to_suffix
from ipapython.dn import DN

try:
    import ldap  # pylint: disable=unused-import
except ImportError:
    ipaldap = None
else:
    from ipapython import ipaldap

logger = logging.getLogger(__name__)

SUCCESS = 0
NOT_FQDN = -1
NO_LDAP_SERVER = -2
REALM_NOT_FOUND = -3
NOT_IPA_SERVER = -4
NO_ACCESS_TO_LDAP = -5
NO_TLS_LDAP = -6
PYTHON_LDAP_NOT_INSTALLED = -7
BAD_HOST_CONFIG = -10
UNKNOWN_ERROR = -15

IPA_BASEDN_INFO = 'ipa v2.0'

error_names = {
    SUCCESS: 'Success',
    NOT_FQDN: 'NOT_FQDN',
    NO_LDAP_SERVER: 'NO_LDAP_SERVER',
    REALM_NOT_FOUND: 'REALM_NOT_FOUND',
    NOT_IPA_SERVER: 'NOT_IPA_SERVER',
    NO_ACCESS_TO_LDAP: 'NO_ACCESS_TO_LDAP',
    NO_TLS_LDAP: 'NO_TLS_LDAP',
    PYTHON_LDAP_NOT_INSTALLED: 'PYTHON_LDAP_NOT_INSTALLED',
    BAD_HOST_CONFIG: 'BAD_HOST_CONFIG',
    UNKNOWN_ERROR: 'UNKNOWN_ERROR',
}


def get_ipa_basedn(conn):
    """
    Get base DN of IPA suffix in given LDAP server.

    None is returned if the suffix is not found

    :param conn: Bound LDAPClient that will be used for searching
    """
    entry = conn.get_entry(
        DN(), attrs_list=['defaultnamingcontext', 'namingcontexts'])

    contexts = [c.decode('utf-8') for c in entry.raw['namingcontexts']]
    if 'defaultnamingcontext' in entry:
        # If there is a defaultNamingContext examine that one first
        [default] = entry.raw['defaultnamingcontext']
        default = default.decode('utf-8')
        if default in contexts:
            contexts.remove(default)
        contexts.insert(0, default)
    for context in contexts:
        logger.debug("Check if naming context '%s' is for IPA", context)
        try:
            [entry] = conn.get_entries(
                DN(context), conn.SCOPE_BASE, "(info=IPA*)")
        except errors.NotFound:
            logger.debug("LDAP server did not return info attribute to "
                         "check for IPA version")
            continue
        [info] = entry.raw['info']
        info = info.decode('utf-8').lower()
        if info != IPA_BASEDN_INFO:
            logger.debug(
                "Detected IPA server version (%s) did not match the "
                "client (%s)", info, IPA_BASEDN_INFO)
            continue
        logger.debug("Naming context '%s' is a valid IPA context", context)
        return DN(context)

    return None


class IPADiscovery:

    def __init__(self):
        self.realm = None
        self.domain = None
        self.server = None
        self.servers = []
        self.basedn = None

        self.realm_source = None
        self.domain_source = None
        self.server_source = None
        self.basedn_source = None

    def __get_resolver_domains(self):
        """Read /etc/resolv.conf and return all domains

        Returns a list of (domain, info) pairs. The info contains a reason
         why the domain is returned.
        """
        domains = []
        domain = None
        try:
            with open(paths.RESOLV_CONF, 'r') as f:
                lines = f.readlines()

            for line in lines:
                if line.lower().startswith('domain'):
                    domain = (line.split()[-1],
                              'local domain from /etc/resolv.conf')
                elif line.lower().startswith('search'):
                    domains.extend(
                        (d, 'search domain from /etc/resolv.conf')
                        for d in line.split()[1:]
                    )
        except Exception:
            pass
        if domain:
            domains = [domain] + domains
        return domains

    def getServerName(self):
        return self.server

    def getDomainName(self):
        return self.domain

    def getRealmName(self):
        return self.realm

    def getKDCName(self):
        return self.kdc

    def getBaseDN(self):
        return self.basedn

    def check_domain(self, domain, tried, reason):
        """
        Given a domain search it for SRV records, breaking it down to search
        all subdomains too.

        Returns a tuple (servers, domain) or (None,None) if a SRV record
        isn't found. servers is a list of servers found. domain is a string.

        :param tried: A set of domains that were tried already
        :param reason: Reason this domain is searched (included in the log)
        """
        servers = None
        logger.debug('Start searching for LDAP SRV record in "%s" (%s) '
                     'and its sub-domains', domain, reason)
        while not servers:
            if domain in tried:
                logger.debug("Already searched %s; skipping", domain)
                break
            tried.add(domain)

            servers = self.ipadns_search_srv(domain, '_ldap._tcp', 389,
                                             break_on_first=False)
            if servers:
                return (servers, domain)
            else:
                p = domain.find(".")
                if p == -1:
                    # no ldap server found and last component of the domain
                    # already tested
                    return None, None
                domain = domain[p + 1:]
        return None, None

    def search(self, domain="", servers="", realm=None, hostname=None,
               ca_cert_path=None):
        """
        Use DNS discovery to identify valid IPA servers.

        servers may contain an optional list of servers which will be used
        instead of discovering available LDAP SRV records.

        Returns a constant representing the overall search result.
        """
        logger.debug("[IPA Discovery]")
        logger.debug(
            'Starting IPA discovery with domain=%s, servers=%s, hostname=%s',
            domain, servers, hostname)

        self.server = None
        autodiscovered = False

        if not servers:
            if not domain:  # domain not provided do full DNS discovery
                # get the local host name
                if not hostname:
                    hostname = socket.getfqdn()
                    logger.debug('Hostname: %s', hostname)
                if not hostname:
                    return BAD_HOST_CONFIG

                if valid_ip(hostname):
                    return NOT_FQDN

                # first, check for an LDAP server for the local domain
                p = hostname.find(".")
                if p == -1:  # no domain name
                    return NOT_FQDN
                domain = hostname[p + 1:]

                # Get the list of domains from /etc/resolv.conf, we'll search
                # them all. We search the domain of our hostname first though.
                # This is to avoid the situation where domain isn't set in
                # /etc/resolv.conf and the search list has the hostname domain
                # not first. We could end up with the wrong SRV record.
                domains = self.__get_resolver_domains()
                domains = [(domain, 'domain of the hostname')] + domains
                tried = set()
                for domain, reason in domains:
                    # Domain name should not be single-label
                    try:
                        validate_domain_name(domain)
                    except ValueError as e:
                        logger.debug("Skipping invalid domain '%s' (%s)",
                                     domain, e)
                        continue
                    servers, domain = self.check_domain(domain, tried, reason)
                    if servers:
                        autodiscovered = True
                        self.domain = domain
                        self.server_source = self.domain_source = (
                            'Discovered LDAP SRV records from %s (%s)' %
                            (domain, reason))
                        break
                if not self.domain:  # no ldap server found
                    logger.debug('No LDAP server found')
                    return NO_LDAP_SERVER
            else:
                logger.debug("Search for LDAP SRV record in %s", domain)
                servers = self.ipadns_search_srv(domain, '_ldap._tcp', 389,
                                                 break_on_first=False)
                if servers:
                    autodiscovered = True
                    self.domain = domain
                    self.server_source = self.domain_source = (
                        'Discovered LDAP SRV records from %s' % domain)
                else:
                    self.server = None
                    logger.debug('No LDAP server found')
                    return NO_LDAP_SERVER

        else:

            logger.debug("Server and domain forced")
            self.domain = domain
            self.domain_source = self.server_source = 'Forced'

        # search for kerberos
        logger.debug("[Kerberos realm search]")
        if realm:
            logger.debug("Kerberos realm forced")
            self.realm = realm
            self.realm_source = 'Forced'
        else:
            realm = self.ipadnssearchkrbrealm()
            self.realm = realm
            self.realm_source = (
                'Discovered Kerberos DNS records from %s' % self.domain)

        if not servers and not realm:
            return REALM_NOT_FOUND

        if autodiscovered:
            self.kdc = self.ipadnssearchkrbkdc()
            self.kdc_source = (
                'Discovered Kerberos DNS records from %s' % self.domain)
        else:
            self.kdc = ', '.join(servers)
            self.kdc_source = "Kerberos DNS record discovery bypassed"

        # We may have received multiple servers corresponding to the domain
        # Iterate through all of those to check if it is IPA LDAP server
        ldapret = [NOT_IPA_SERVER]
        ldapaccess = True
        logger.debug("[LDAP server check]")
        valid_servers = []
        for server in servers:
            logger.debug('Verifying that %s (realm %s) is an IPA server',
                         server, self.realm)
            # check ldap now
            ldapret = self.ipacheckldap(
                server, self.realm, ca_cert_path=ca_cert_path
            )

            if ldapret[0] == SUCCESS:
                # Make sure that realm is not single-label
                try:
                    validate_domain_name(ldapret[2], entity='realm')
                except ValueError as e:
                    logger.debug("Skipping invalid realm '%s' (%s)",
                                 ldapret[2], e)
                    ldapret = [NOT_IPA_SERVER]
                else:
                    self.server = ldapret[1]
                    self.realm = ldapret[2]
                    self.server_source = self.realm_source = (
                        'Discovered from LDAP DNS records in %s' % self.server)
                    valid_servers.append(server)
                    # verified, we actually talked to the remote server and it
                    # is definetely an IPA server
                    if autodiscovered:
                        # No need to keep verifying servers if we discovered
                        # them via DNS
                        break
            elif ldapret[0] in (NO_ACCESS_TO_LDAP, NO_TLS_LDAP,
                                PYTHON_LDAP_NOT_INSTALLED):
                ldapaccess = False
                valid_servers.append(server)
                # we may set verified_servers below, we don't have it yet
                if autodiscovered:
                    # No need to keep verifying servers if we discovered them
                    # via DNS
                    break
            elif ldapret[0] == NOT_IPA_SERVER:
                logger.warning(
                    'Skip %s: not an IPA server', server)
            elif ldapret[0] == NO_LDAP_SERVER:
                logger.warning(
                    'Skip %s: LDAP server is not responding, unable to '
                    'verify if this is an IPA server', server)
            else:
                logger.warning(
                    'Skip %s: cannot verify if this is an IPA server', server)

        # If one of LDAP servers checked rejects access (maybe anonymous
        # bind is disabled), assume realm and basedn generated off domain.
        # Note that in case ldapret[0] == 0 and ldapaccess == False (one of
        # servers didn't provide access but another one succeeded), self.realm
        # will be set already to a proper value above, self.basdn will be
        # initialized during the LDAP check itself and we'll skip these two
        # checks.
        if not ldapaccess and self.realm is None:
            # Assume realm is the same as domain.upper()
            self.realm = self.domain.upper()
            self.realm_source = 'Assumed same as domain'
            logger.debug(
                "Assuming realm is the same as domain: %s", self.realm)

        if not ldapaccess and self.basedn is None:
            # Generate suffix from realm
            self.basedn = realm_to_suffix(self.realm)
            self.basedn_source = 'Generated from Kerberos realm'
            logger.debug("Generated basedn from realm: %s", self.basedn)

        logger.debug(
            "Discovery result: %s; server=%s, domain=%s, kdc=%s, basedn=%s",
            error_names.get(ldapret[0], ldapret[0]),
            self.server, self.domain, self.kdc, self.basedn)

        logger.debug("Validated servers: %s", ','.join(valid_servers))
        self.servers = valid_servers

        # If we have any servers left then override the last return value
        # to indicate success.
        if valid_servers:
            self.server = servers[0]
            ldapret[0] = SUCCESS

        return ldapret[0]

    def ipacheckldap(self, thost, trealm, ca_cert_path=None):
        """
        Given a host and kerberos realm verify that it is an IPA LDAP
        server hosting the realm.

        Returns a list [errno, host, realm] or an empty list on error.
        Errno is an error number:
            0 means all ok
            negative number means something went wrong
        """
        if ipaldap is None:
            return [PYTHON_LDAP_NOT_INSTALLED]

        lrealms = []

        # now verify the server is really an IPA server
        try:
            ldap_uri = ipaldap.get_ldap_uri(thost)
            start_tls = False
            if ca_cert_path:
                start_tls = True
            logger.debug("Init LDAP connection to: %s", ldap_uri)
            lh = ipaldap.LDAPClient(
                ldap_uri, cacert=ca_cert_path, start_tls=start_tls,
                no_schema=True, decode_attrs=False)
            try:
                lh.simple_bind(DN(), '')

                # get IPA base DN
                logger.debug("Search LDAP server for IPA base DN")
                basedn = get_ipa_basedn(lh)
            except errors.ACIError:
                logger.debug("LDAP Error: Anonymous access not allowed")
                return [NO_ACCESS_TO_LDAP]
            except errors.DatabaseError as err:
                logger.error("Error checking LDAP: %s", err.strerror)
                # We should only get UNWILLING_TO_PERFORM if the remote LDAP
                # server has minssf > 0 and we have attempted a non-TLS conn.
                if ca_cert_path is None:
                    logger.debug(
                        "Cannot connect to LDAP server. Check that minssf is "
                        "not enabled")
                    return [NO_TLS_LDAP]
                else:
                    return [UNKNOWN_ERROR]

            if basedn is None:
                logger.debug("The server is not an IPA server")
                return [NOT_IPA_SERVER]

            self.basedn = basedn
            self.basedn_source = 'From IPA server %s' % lh.ldap_uri

            # search and return known realms
            logger.debug(
                "Search for (objectClass=krbRealmContainer) in %s (sub)",
                self.basedn)
            try:
                lret = lh.get_entries(
                    DN(('cn', 'kerberos'), self.basedn),
                    lh.SCOPE_SUBTREE, "(objectClass=krbRealmContainer)")
            except errors.NotFound:
                # something very wrong
                return [REALM_NOT_FOUND]

            for lres in lret:
                logger.debug("Found: %s", lres.dn)
                [cn] = lres.raw['cn']
                if six.PY3:
                    cn = cn.decode('utf-8')
                lrealms.append(cn)

            if trealm:
                for r in lrealms:
                    if trealm == r:
                        return [SUCCESS, thost, trealm]
                # must match or something is very wrong
                logger.debug("Realm %s does not match any realm in LDAP "
                             "database", trealm)
                return [REALM_NOT_FOUND]
            else:
                if len(lrealms) != 1:
                    # which one? we can't attach to a multi-realm server
                    # without DNS working
                    logger.debug(
                        "Multiple realms found, cannot decide which realm "
                        "is the correct realm without working DNS")
                    return [REALM_NOT_FOUND]
                else:
                    return [SUCCESS, thost, lrealms[0]]

            # we shouldn't get here
            assert False, "Unknown error in ipadiscovery"

        except errors.DatabaseTimeout:
            logger.debug("LDAP Error: timeout")
            return [NO_LDAP_SERVER]
        except errors.NetworkError as err:
            logger.debug("LDAP Error: %s", err.strerror)
            return [NO_LDAP_SERVER]
        except errors.ACIError:
            logger.debug("LDAP Error: Anonymous access not allowed")
            return [NO_ACCESS_TO_LDAP]
        except errors.DatabaseError as err:
            logger.debug("Error checking LDAP: %s", err.strerror)
            return [UNKNOWN_ERROR]
        except Exception as err:
            logger.debug("Error checking LDAP: %s", err)

            return [UNKNOWN_ERROR]

    def ipadns_search_srv(self, domain, srv_record_name, default_port,
                          break_on_first=True):
        """
        Search for SRV records in given domain. When no record is found,
        en empty list is returned

        :param domain: Search domain name
        :param srv_record_name: SRV record name, e.g. "_ldap._tcp"
        :param default_port: When default_port is not None, it is being
                    checked with the port in SRV record and if they don't
                    match, the port from SRV record is appended to
                    found hostname in this format: "hostname:port"
        :param break_on_first: break on the first find and return just one
                    entry
        """
        servers = []
        qname = '%s.%s' % (srv_record_name, domain)

        logger.debug("Search DNS for SRV record of %s", qname)

        try:
            answers = query_srv(qname)
        except DNSException as e:
            logger.debug("DNS record not found: %s", e.__class__.__name__)
            answers = []

        for answer in answers:
            logger.debug("DNS record found: %s", answer)
            server = str(answer.target).rstrip(".")
            if not server:
                logger.debug("Cannot parse the hostname from SRV record: %s",
                             answer)
                continue
            if default_port is not None and answer.port != default_port:
                server = "%s:%s" % (server, str(answer.port))
            servers.append(server)
            if break_on_first:
                break

        return servers

    def ipadnssearchkrbrealm(self, domain=None):
        """
        :param domain: Domain to be searched in
        :returns: string of a realm found in a TXT record
                  None if no realm was found
        """
        if not domain:
            domain = self.domain
        # now, check for a Kerberos realm the local host or domain is in
        qname = "_kerberos." + domain

        logger.debug("Search DNS for TXT record of %s", qname)

        try:
            answers = resolver.query(qname, rdatatype.TXT)
        except DNSException as e:
            logger.debug("DNS record not found: %s", e.__class__.__name__)
            answers = []

        realm = None
        for answer in answers:
            logger.debug("DNS record found: %s", answer)
            if answer.strings:
                try:
                    realm = answer.strings[0].decode('utf-8')
                except UnicodeDecodeError as e:
                    logger.debug(
                        'A TXT record cannot be decoded as UTF-8: %s', e)
                    continue
                if realm:
                    # Make sure that the realm is not single-label
                    try:
                        validate_domain_name(realm, entity='realm')
                    except ValueError as e:
                        logger.debug("Skipping invalid realm '%s' (%s)",
                                     realm, e)
                        continue
                    return realm
        return None

    def ipadnssearchkrbkdc(self, domain=None):
        if not domain:
            domain = self.domain

        kdc = self.ipadns_search_srv(domain, '_kerberos._udp', 88,
                                     break_on_first=False)

        if kdc:
            kdc = ','.join(kdc)
        else:
            logger.debug("SRV record for KDC not found! Domain: %s", domain)
            kdc = None

        return kdc
