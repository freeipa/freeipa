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

    def get_realm(self):
        if self.default_realm:
            return self.default_realm
        else:
            raise IPAConfigError("no default realm")

    def get_server(self):
        if self.default_server:
            return self.default_server
        else:
            raise IPAConfigError("no default server")

# Global library config
config = IPAConfig()

def __parse_config():
    p = ConfigParser.SafeConfigParser()
    p.read("/etc/ipa/ipa.conf")

    try:
        if not config.default_realm:
            config.default_realm = p.get("defaults", "realm")
        if not config.default_server:
            s = p.get("defaults", "server")
            config.default_server = re.sub("\s+", "", s).split(',')
    except:
        pass

def __discover_config():
    try:
        if not config.default_realm:
            krbctx = krbV.default_context()
            config.default_realm = krbctx.default_realm
            if not config.default_realm:
                return False

        if not config.default_server:
            #try once with REALM -> domain
            name = "_ldap._tcp."+config.default_realm+"."
            rs = ipa.dnsclient.query(name, ipa.dnsclient.DNS_C_IN, ipa.dnsclient.DNS_T_SRV)
            rl = len(rs)

            #try cycling on domain components of FQDN
            if rl == 0:
                name = socket.getfqdn()
            while rl == 0:
                tok = name.find(".")
                if tok == -1:
                    return False
                name = name[tok+1:]
                q = "_ldap._tcp." + name + "."
                rs = ipa.dnsclient.query(q, ipa.dnsclient.DNS_C_IN, ipa.dnsclient.DNS_T_SRV)
                rl = len(rs)

            for r in rs:
                if r.dns_type == ipa.dnsclient.DNS_T_SRV:
                    rsrv = r.rdata.server.rstrip(".")
                    config.default_server.append(rsrv)

        if config.default_server:
            return True
        else:
            return False
    except:
        return False

def usage():
    return """  --realm\tset the IPA realm
  --server\tset the IPA server
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
            config.default_server = args[i + 1]
            i = i + 2
            continue
        out_args.append(args[i])
        i = i + 1
        
    return out_args
                      

def init_config(args=None):
    out_args = None
    if args:
        out_args = __parse_args(args)

    __discover_config()
    __parse_config()

    if not config.default_realm:
        raise IPAConfigError("realm not found, nor specified in config file or on command line")
    if not config.default_server:
        raise IPAConfigError("server not found, nor specified in config file or on command line")

    if out_args:
        return out_args
