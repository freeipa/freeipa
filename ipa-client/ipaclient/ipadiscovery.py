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

import socket
import os
from ipapython.ipa_log_manager import *
import tempfile
import ldap
from ldap import LDAPError
from dns import resolver, rdatatype
from dns.exception import DNSException

from ipapython.ipautil import run, CalledProcessError, valid_ip, get_ipa_basedn, \
                              realm_to_suffix, format_netloc
from ipapython.dn import DN

NOT_FQDN = -1
NO_LDAP_SERVER = -2
REALM_NOT_FOUND = -3
NOT_IPA_SERVER = -4
NO_ACCESS_TO_LDAP = -5
BAD_HOST_CONFIG = -10
UNKNOWN_ERROR = -15

error_names = {
    0: 'Success',
    NOT_FQDN: 'NOT_FQDN',
    NO_LDAP_SERVER: 'NO_LDAP_SERVER',
    REALM_NOT_FOUND: 'REALM_NOT_FOUND',
    NOT_IPA_SERVER: 'NOT_IPA_SERVER',
    NO_ACCESS_TO_LDAP: 'NO_ACCESS_TO_LDAP',
    BAD_HOST_CONFIG: 'BAD_HOST_CONFIG',
    UNKNOWN_ERROR: 'UNKNOWN_ERROR',
}

class IPADiscovery(object):

    def __init__(self):
        self.realm = None
        self.domain = None
        self.server = None
        self.basedn = None

        self.realm_source = None
        self.domain_source = None
        self.server_source = None
        self.basedn_source = None

    def __get_resolver_domains(self):
        """
        Read /etc/resolv.conf and return all the domains found in domain and
        search.

        Returns a list of (domain, info) pairs. The info contains a reason why
        the domain is returned.
        """
        domains = []
        domain = None
        try:
            fp = open('/etc/resolv.conf', 'r')
            lines = fp.readlines()
            fp.close()

            for line in lines:
                if line.lower().startswith('domain'):
                    domain = (line.split()[-1],
                        'local domain from /etc/resolv.conf')
                elif line.lower().startswith('search'):
                    domains += [(d, 'search domain from /etc/resolv.conf') for
                        d in line.split()[1:]]
        except:
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

        Returns a tuple (server, domain) or (None,None) if a SRV record
        isn't found.

        :param tried: A set of domains that were tried already
        :param reason: Reason this domain is searched (included in the log)
        """
        server = None
        root_logger.debug('Start searching for LDAP SRV record in "%s" (%s) ' +
                          'and its sub-domains', domain, reason)
        while not server:
            if domain in tried:
                root_logger.debug("Already searched %s; skipping", domain)
                break
            tried.add(domain)

            server = self.ipadns_search_srv(domain, '_ldap._tcp', 389)
            if server:
                return (server[0], domain)
            else:
                p = domain.find(".")
                if p == -1: #no ldap server found and last component of the domain already tested
                    return (None, None)
                domain = domain[p+1:]
        return (None, None)

    def search(self, domain = "", server = "", hostname=None):
        root_logger.debug("[IPA Discovery]")
        root_logger.debug(
            'Starting IPA discovery with domain=%s, server=%s, hostname=%s',
            domain, server, hostname)

        if type(server) in (list, tuple):
            server = server[0]

        if not server:

            if not domain: #domain not provided do full DNS discovery

                # get the local host name
                if not hostname:
                    hostname = socket.getfqdn()
                    root_logger.debug('Hostname: %s', hostname)
                if not hostname:
                    return BAD_HOST_CONFIG

                if valid_ip(hostname):
                    return NOT_FQDN

                # first, check for an LDAP server for the local domain
                p = hostname.find(".")
                if p == -1: #no domain name
                    return NOT_FQDN
                domain = hostname[p+1:]

                # Get the list of domains from /etc/resolv.conf, we'll search
                # them all. We search the domain of our hostname first though.
                # This is to avoid the situation where domain isn't set in
                # /etc/resolv.conf and the search list has the hostname domain
                # not first. We could end up with the wrong SRV record.
                domains = self.__get_resolver_domains()
                domains = [(domain, 'domain of the hostname')] + domains
                tried = set()
                for domain, reason in domains:
                    server, domain = self.check_domain(domain, tried, reason)
                    if server:
                        self.server = server
                        self.domain = domain
                        self.server_source = self.domain_source = (
                            'Discovered LDAP SRV records from %s (%s)' %
                                (domain, reason))
                        break
                if not self.domain: #no ldap server found
                    root_logger.debug('No LDAP server found')
                    return NO_LDAP_SERVER
            else:
                root_logger.debug("Search for LDAP SRV record in %s", domain)
                server = self.ipadns_search_srv(domain, '_ldap._tcp', 389)
                if server:
                    self.server = server[0]
                    self.domain = domain
                    self.server_source = self.domain_source = (
                        'Discovered LDAP SRV records from %s' % domain)
                else:
                    self.server = None
                    root_logger.debug('No LDAP server found')
                    return NO_LDAP_SERVER

        else:

            root_logger.debug("Server and domain forced")
            self.domain = domain
            self.server = server
            self.domain_source = self.server_source = 'Forced'

        #search for kerberos
        root_logger.debug("[Kerberos realm search]")
        krb_realm, kdc = self.ipadnssearchkrb(self.domain)
        if not server and not krb_realm:
            return REALM_NOT_FOUND

        self.realm = krb_realm
        self.kdc = kdc
        self.realm_source = self.kdc_source = (
            'Discovered Kerberos DNS records from %s' % self.domain)

        root_logger.debug("[LDAP server check]")
        root_logger.debug('Verifying that %s (realm %s) is an IPA server',
            self.server, self.realm)
        # We may have received multiple servers corresponding to the domain
        # Iterate through all of those to check if it is IPA LDAP server
        ldapret = [NOT_IPA_SERVER]
        ldapaccess = True
        if self.server:
            # check ldap now
            ldapret = self.ipacheckldap(self.server, self.realm)

            if ldapret[0] == 0:
                self.server = ldapret[1]
                self.realm = ldapret[2]
                self.server_source = self.realm_source = (
                    'Discovered from LDAP DNS records in %s' % self.server)
            elif ldapret[0] == NO_ACCESS_TO_LDAP:
                ldapaccess = False

        # If one of LDAP servers checked rejects access (maybe anonymous
        # bind is disabled), assume realm and basedn generated off domain.
        # Note that in case ldapret[0] == 0 and ldapaccess == False (one of
        # servers didn't provide access but another one succeeded), self.realm
        # will be set already to a proper value above, self.basdn will be
        # initialized during the LDAP check itself and we'll skip these two checks.
        if not ldapaccess and self.realm is None:
            # Assume realm is the same as domain.upper()
            self.realm = self.domain.upper()
            self.realm_source = 'Assumed same as domain'
            root_logger.debug(
                "Assuming realm is the same as domain: %s", self.realm)

        if not ldapaccess and self.basedn is None:
            # Generate suffix from realm
            self.basedn = realm_to_suffix(self.realm)
            self.basedn_source = 'Generated from Kerberos realm'
            root_logger.debug("Generated basedn from realm: %s" % self.basedn)

        root_logger.debug(
            "Discovery result: %s; server=%s, domain=%s, kdc=%s, basedn=%s",
            error_names.get(ldapret[0], ldapret[0]),
            self.server, self.domain, self.kdc, self.basedn)

        return ldapret[0]

    def ipacheckldap(self, thost, trealm):
        """
        Given a host and kerberos realm verify that it is an IPA LDAP
        server hosting the realm. The connection is an SSL connection
        so the remote IPA CA cert must be available at
        http://HOST/ipa/config/ca.crt

        Returns a list [errno, host, realm] or an empty list on error.
        Errno is an error number:
            0 means all ok
            1 means we could not check the info in LDAP (may happend when
                anonymous binds are disabled)
            2 means the server is certainly not an IPA server
        """

        lrealms = []

        i = 0

        # Get the CA certificate
        try:
            # Create TempDir
            temp_ca_dir = tempfile.mkdtemp()
        except OSError, e:
            raise RuntimeError("Creating temporary directory failed: %s" % str(e))

        try:
            run(["/usr/bin/wget", "-O", "%s/ca.crt" % temp_ca_dir, "-T", "15", "-t", "2",
                 "http://%s/ipa/config/ca.crt" % format_netloc(thost)])
        except CalledProcessError, e:
            root_logger.error('Retrieving CA from %s failed', thost)
            root_logger.debug('Retrieving CA from %s failed: %s', thost, str(e))
            return [NOT_IPA_SERVER]

        #now verify the server is really an IPA server
        try:
            ldap_url = "ldap://" + format_netloc(thost, 389)
            root_logger.debug("Init LDAP connection with: %s", ldap_url)
            lh = ldap.initialize(ldap_url)
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, True)
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, "%s/ca.crt" % temp_ca_dir)
            lh.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
            lh.set_option(ldap.OPT_X_TLS_DEMAND, True)
            lh.start_tls_s()
            lh.simple_bind_s("","")

            # get IPA base DN
            root_logger.debug("Search LDAP server for IPA base DN")
            basedn = get_ipa_basedn(lh)

            if basedn is None:
                root_logger.debug("The server is not an IPA server")
                return [NOT_IPA_SERVER]

            self.basedn = basedn
            self.basedn_source = 'From IPA server %s' % ldap_url

            #search and return known realms
            root_logger.debug(
                "Search for (objectClass=krbRealmContainer) in %s (sub)",
                self.basedn)
            lret = lh.search_s(str(DN(('cn', 'kerberos'), self.basedn)), ldap.SCOPE_SUBTREE, "(objectClass=krbRealmContainer)")
            if not lret:
                #something very wrong
                return [REALM_NOT_FOUND]

            for lres in lret:
                root_logger.debug("Found: %s", lres[0])
                for lattr in lres[1]:
                    if lattr.lower() == "cn":
                        lrealms.append(lres[1][lattr][0])


            if trealm:
                for r in lrealms:
                    if trealm == r:
                        return [0, thost, trealm]
                # must match or something is very wrong
                return [REALM_NOT_FOUND]
            else:
                if len(lrealms) != 1:
                    #which one? we can't attach to a multi-realm server without DNS working
                    return [REALM_NOT_FOUND]
                else:
                    return [0, thost, lrealms[0]]

            #we shouldn't get here
            return [UNKNOWN_ERROR]

        except LDAPError, err:
            if isinstance(err, ldap.TIMEOUT):
                root_logger.error("LDAP Error: timeout")
                return [NO_LDAP_SERVER]

            if isinstance(err, ldap.INAPPROPRIATE_AUTH):
                root_logger.debug("LDAP Error: Anonymous acces not allowed")
                return [NO_ACCESS_TO_LDAP]

            root_logger.error("LDAP Error: %s: %s" %
               (err.args[0]['desc'], err.args[0].get('info', '')))
            return [UNKNOWN_ERROR]

        finally:
            os.remove("%s/ca.crt" % temp_ca_dir)
            os.rmdir(temp_ca_dir)


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

        root_logger.debug("Search DNS for SRV record of %s", qname)

        try:
            answers = resolver.query(qname, rdatatype.SRV)
        except DNSException, e:
            root_logger.debug("DNS record not found: %s", e.__class__.__name__)
            answers = []

        for answer in answers:
            root_logger.debug("DNS record found: %s", answer)
            server = str(answer.target).rstrip(".")
            if not server:
                root_logger.debug("Cannot parse the hostname from SRV record: %s", answer)
                continue
            if default_port is not None and answer.port != default_port:
                server = "%s:%s" % (server, str(answer.port))
            servers.append(server)
            if break_on_first:
                break

        return servers

    def ipadnssearchkrb(self, tdomain):
        realm = None
        kdc = None
        # now, check for a Kerberos realm the local host or domain is in
        qname = "_kerberos." + tdomain

        root_logger.debug("Search DNS for TXT record of %s", qname)

        try:
            answers = resolver.query(qname, rdatatype.TXT)
        except DNSException, e:
            root_logger.debug("DNS record not found: %s", e.__class__.__name__)
            answers = []

        for answer in answers:
            root_logger.debug("DNS record found: %s", answer)
            if answer.strings:
                realm = answer.strings[0]
                if realm:
                    break

        if realm:
            # now fetch server information for the realm
            domain = realm.lower()

            kdc = self.ipadns_search_srv(domain, '_kerberos._udp', 88,
                    break_on_first=False)

            if not kdc:
                root_logger.debug("SRV record for KDC not found! Realm: %s, SRV record: %s" % (realm, qname))
                kdc = None
            kdc = ','.join(kdc)

        return realm, kdc
