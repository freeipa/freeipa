#! /usr/bin/python -E
# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 or later
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import socket
import logging
import dnsclient
import ldap
from ldap import LDAPError
 
class IPADiscovery:

    def __init__(self):
        self.realm = None
        self.domain = None
        self.server = None
        self.basedn = None

    def getServerName(self):
        return str(self.server)

    def getDomainName(self):
        return str(self.domain)

    def getRealmName(self):
        return str(self.realm)

    def getBaseDN(self):
        return str(self.basedn)

    def search(self, domain = "", server = ""):
        hostname = ""
        qname = ""
        results = []
        result = []
        krbret = []
        ldapret = []
    
        if not server:

            if not domain: #domain not provided do full DNS discovery
            
                # get the local host name
                hostname = socket.getfqdn()
                if not hostname:
                    return -10 #bad host configuration
    
                # first, check for an LDAP server for the local domain
                p = hostname.find(".")
                if p == -1: #no domain name
                    return -1
                domain = hostname[p+1:]
    
                while not self.server:
                    logging.debug("[ipadnssearchldap("+domain+")]")
                    self.server = self.ipadnssearchldap(domain)
                    if self.server:
                        self.domain = domain
                    else:
                        p = domain.find(".")
                        if p == -1: #no ldap server found and last component of the domain already tested
                            return -1
                        domain = domain[p+1:]
            else:
                logging.debug("[ipadnssearchldap]")
                self.server = self.ipadnssearchldap(domain)
                if self.server:
                    self.domain = domain
                else:
                    return -2 #no ldap server found
    
    
            #search for kerberos TODO: move this after ipacheckldap()
            logging.debug("[ipadnssearchkrb]")
            krbret = self.ipadnssearchkrb(self.domain)
            if not krbret:
                return -3 #no krb server found
    
            self.realm = krbret[0]
    
        else: #server forced on us, this means DNS doesn't work :/
    
            self.domain = domain
            self.server = server
    
        logging.debug("[ipacheckldap]")
        # check ldap now
        ldapret = self.ipacheckldap(self.server, self.realm);
    
        if not ldapret:
            return -4 # not an IPA server (or broken config)
    
        self.server = ldapret[0]
        self.realm = ldapret[1]
    
        return 0

    def ipacheckldap(self, thost, trealm):
    
        lret = []
        lres = []
        lattr = ""
        linfo = ""
        lrealms = []
    
        i = 0
    
        #now verify the server is really an IPA server
        try:
            logging.debug("Init ldap with: ldap://"+thost+":389")
            lh = ldap.initialize("ldap://"+thost+":389")
            lh.simple_bind_s("","")
    
            logging.debug("Search rootdse")
            lret = lh.search_s("", ldap.SCOPE_BASE, "(objectClass=*)")
            for lattr in lret[0][1]:
                if lattr.lower() == "namingcontexts":
                    self.basedn = lret[0][1][lattr][0]
    
            logging.debug("Search for (info=*) in "+self.basedn+"(base)")
            lret = lh.search_s(self.basedn, ldap.SCOPE_BASE, "(info=IPA*)")
            if not lret:
                return []
            logging.debug("Found: "+str(lret))
    
            for lattr in lret[0][1]:
                if lattr.lower() == "info":
                    linfo = lret[0][1][lattr][0].lower()
                    break
    
            if not linfo:
                return []
    
            #search and return known realms
            logging.debug("Search for (objectClass=krbRealmContainer) in "+self.basedn+"(sub)")
            lret = lh.search_s("cn=kerberos,"+self.basedn, ldap.SCOPE_SUBTREE, "(objectClass=krbRealmContainer)")
            if not lret:
                #something very wrong
                return []
            logging.debug("Found: "+str(lret))
    
            for lres in lret:
                for lattr in lres[1]:
                    if lattr.lower() == "cn":
                        lrealms.append(lres[1][lattr][0])
    
    
            if trealm:
                for r in lrealms:
                    if trealm == r:
                        return [thost, trealm]
                # must match or something is very wrong
                return []
            else:
                if len(lrealms) != 1:
                    #which one? we can't attach to a multi-realm server without DNS working
                    return []
                else:
                    return [thost, lrealms[0]]
    
            #we shouldn't get here
            return []
    
        except LDAPError, err:
            #no good
            logging.error("Ldap Error: "+str(err))
            return []

    
    def ipadnssearchldap(self, tdomain):
        servers = ""
        rserver = ""
    
        qname = "_ldap._tcp."+tdomain
        # terminate the name
        if not qname.endswith("."):
            qname += "."
        results = dnsclient.query(qname, dnsclient.DNS_C_IN, dnsclient.DNS_T_SRV)
    
        for result in results:
            if result.dns_type == dnsclient.DNS_T_SRV:
                rserver = result.rdata.server.rstrip(".")
                if result.rdata.port and result.rdata.port != 389:
                    rserver += ":" + str(result.rdata.port)
                if servers:
                    servers += "," + rserver
                else:
                    servers = rserver
                break
    
        return servers
    
    def ipadnssearchkrb(self, tdomain):
        realm = ""
        kdc = ""
        # now, check for a Kerberos realm the local host or domain is in
        qname = "_kerberos." + tdomain
        # terminate the name
        if not qname.endswith("."):
            qname += "."
        results = dnsclient.query(qname, dnsclient.DNS_C_IN, dnsclient.DNS_T_TXT)
    
        for result in results:
            if result.dns_type == dnsclient.DNS_T_TXT:
                realm = result.rdata.data
                if realm:
                    break
    
        if realm:
            # now fetch server information for the realm
            qname = "_kerberos._udp." + tdomain
            # terminate the name
            if not qname.endswith("."):
                qname += "."
            results = dnsclient.query(qname, dnsclient.DNS_C_IN, dnsclient.DNS_T_SRV)
            for result in results:
                if result.dns_type == dnsclient.DNS_T_SRV:
                    qname = result.rdata.server.rstrip(".")
                    if result.rdata.port and result.rdata.port != 88:
                        qname += ":" + str(result.rdata.port)
                    if kdc:
                        kdc += "," + qname
                    else:
                        kdc = qname

        return [realm, kdc]
