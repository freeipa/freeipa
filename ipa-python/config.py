# Authors: Karl MacMillan <kmacmill@redhat.com>
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
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

import ConfigParser
from optparse import OptionParser

import krbV
import socket
import ipa.dnsclient
import re

class IPAConfigError(Exception):
    def __init__(self, msg=''):
        self.msg = msg
        Exception.__init__(self, msg)

    def __repr__(self):
        return self.msg

    __str__ = __repr__

class IPAConfig:
    def __init__(self):
        self.default_realm = None
        self.default_server = []
        self.default_domain = None

    def get_realm(self):
        if self.default_realm:
            return self.default_realm
        else:
            raise IPAConfigError("no default realm")

    def get_server(self):
        if len(self.default_server):
            return self.default_server
        else:
            raise IPAConfigError("no default server")

    def get_domain(self):
        if self.default_domain:
            return self.default_domain
        else:
            raise IPAConfigError("no default domain")

# Global library config
config = IPAConfig()

def __parse_config():
    p = ConfigParser.SafeConfigParser()
    p.read("/etc/ipa/ipa.conf")

    try:
        if not config.default_realm:
            config.default_realm = p.get("defaults", "realm")
        if not len(config.default_server):
            s = p.get("defaults", "server")
            config.default_server = re.sub("\s+", "", s).split(',')
        if not config.default_domain:
            config.default_domain = p.get("defaults", "domain")
    except:
        pass

def __discover_config():
    try:
        if not config.default_realm:
            krbctx = krbV.default_context()
            config.default_realm = krbctx.default_realm
            if not config.default_realm:
                return False

        if not config.default_domain:
            #try once with REALM -> domain
            dom_name = config.default_realm.lower()
            name = "_ldap._tcp."+dom_name+"."
            rs = ipa.dnsclient.query(name, ipa.dnsclient.DNS_C_IN, ipa.dnsclient.DNS_T_SRV)
            rl = len(rs)
            if rl == 0:
                #try cycling on domain components of FQDN
                dom_name = socket.getfqdn()
            while rl == 0:
                tok = dom_name.find(".")
                if tok == -1:
                     return False
                dom_name = dom_name[tok+1:]
                name = "_ldap._tcp." + dom_name + "."
                rs = ipa.dnsclient.query(name, ipa.dnsclient.DNS_C_IN, ipa.dnsclient.DNS_T_SRV)
                rl = len(rs)

            config.default_domain = dom_name

        if rl == 0:
             name = "_ldap._tcp."+config.default_domain+"."
             rs = ipa.dnsclient.query(name, ipa.dnsclient.DNS_C_IN, ipa.dnsclient.DNS_T_SRV)

        for r in rs:
            if r.dns_type == ipa.dnsclient.DNS_T_SRV:
                rsrv = r.rdata.server.rstrip(".")
                config.default_server.append(rsrv)

    except:
        pass

def usage():
    return """  --realm\tset the IPA realm
  --server\tset the IPA server
  --domain\tset the IPA dns domain
"""

def __parse_args(args):
    # Can't use option parser because it doesn't easily leave
    # unknown arguments - creating our own seems simpler.
    #
    # should make this more robust and handle --realm=foo syntax
    out_args = []
    i = 0
    while i < len(args):
        if args[i] == "--realm":
            if i == len(args) - 1:
                raise IPAConfigError("missing argument to --realm")
            config.default_realm = args[i + 1]
            i = i + 2
            continue
        if args[i] == "--server":
            if i == len(args) - 1:
                raise IPAConfigError("missing argument to --server")
            config.default_server.append(args[i + 1])
            i = i + 2
            continue
        if args[i] == "--domain":
            if i == len(args) - 1:
                raise IPAConfigError("missing argument to --domain")
            config.default_domain = args[i + 1]
            i = i + 2
            continue
        out_args.append(args[i])
        i = i + 1

    return out_args


def init_config(args=None):
    out_args = None
    if args:
        out_args = __parse_args(args)

    __parse_config()
    __discover_config()

    if not config.default_realm:
        raise IPAConfigError("IPA realm not found in DNS, in the config file (/etc/ipa/ipa.conf) or on the command line.")
    if not config.default_server:
        raise IPAConfigError("IPA server not found in DNS, in the config file (/etc/ipa/ipa.conf) or on the command line.")
    if not config.default_domain:
        raise IPAConfigError("IPA domain not found in the config file (/etc/ipa/ipa.conf) or on the command line.")

    if out_args:
        return out_args
