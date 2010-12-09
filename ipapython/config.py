# Authors: Karl MacMillan <kmacmill@redhat.com>
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

import ConfigParser
from optparse import Option, Values, OptionParser, IndentedHelpFormatter

import socket
import ipapython.dnsclient
import re
import urlparse

class IPAConfigError(Exception):
    def __init__(self, msg=''):
        self.msg = msg
        Exception.__init__(self, msg)

    def __repr__(self):
        return self.msg

    __str__ = __repr__

class IPAFormatter(IndentedHelpFormatter):
    """Our own optparse formatter that indents multiple lined usage string."""
    def format_usage(self, usage):
        usage_string = "Usage:"
        spacing = " " * len(usage_string)
        lines = usage.split("\n")
        ret = "%s %s\n" % (usage_string, lines[0])
        for line in lines[1:]:
            ret += "%s %s\n" % (spacing, line)
        return ret

class IPAOption(Option):
    """
    optparse.Option subclass with support of options labeled as
    security-sensitive such as passwords.
    """
    ATTRS = Option.ATTRS + ["sensitive"]

class IPAOptionParser(OptionParser):
    """
    optparse.OptionParser subclass that uses IPAOption by default
    for storing options.
    """
    def __init__(self,
                 usage=None,
                 option_list=None,
                 option_class=IPAOption,
                 version=None,
                 conflict_handler="error",
                 description=None,
                 formatter=None,
                 add_help_option=True,
                 prog=None):
        OptionParser.__init__(self, usage, option_list, option_class,
                              version, conflict_handler, description,
                              formatter, add_help_option, prog)

    def get_safe_opts(self, opts):
        """
        Returns all options except those with sensitive=True in the same
        fashion as parse_args would
        """
        all_opts_dict = dict([ (o.dest, o) for o in self._get_all_options() if hasattr(o, 'sensitive') ])
        safe_opts_dict = {}

        for option, value in opts.__dict__.iteritems():
            if all_opts_dict[option].sensitive != True:
                safe_opts_dict[option] = value

        return Values(safe_opts_dict)

def verify_args(parser, args, needed_args = None):
    """Verify that we have all positional arguments we need, if not, exit."""
    if needed_args:
        needed_list = needed_args.split(" ")
    else:
        needed_list = []
    len_need = len(needed_list)
    len_have = len(args)
    if len_have > len_need:
        parser.error("too many arguments")
    elif len_have < len_need:
        parser.error("no %s specified" % needed_list[len_have])

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

def __parse_config(discover_server = True):
    p = ConfigParser.SafeConfigParser()
    p.read("/etc/ipa/default.conf")

    try:
        if not config.default_realm:
            config.default_realm = p.get("global", "realm")
    except:
        pass
    if discover_server:
        try:
            s = p.get("global", "xmlrpc_uri")
            server = urlparse.urlsplit(s)
            config.default_server.extend(server.netloc)
        except:
            pass
    try:
        if not config.default_domain:
            config.default_domain = p.get("global", "domain")
    except:
        pass

def __discover_config(discover_server = True):
    rl = 0
    try:
        if not config.default_realm:
            try:
                # only import krbV when we need it
                import krbV
                krbctx = krbV.default_context()
                config.default_realm = krbctx.default_realm
            except ImportError:
                pass
            if not config.default_realm:
                return False

        if not config.default_domain:
            #try once with REALM -> domain
            dom_name = config.default_realm.lower()
            name = "_ldap._tcp."+dom_name+"."
            rs = ipapython.dnsclient.query(name, ipapython.dnsclient.DNS_C_IN, ipapython.dnsclient.DNS_T_SRV)
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
                rs = ipapython.dnsclient.query(name, ipapython.dnsclient.DNS_C_IN, ipapython.dnsclient.DNS_T_SRV)
                rl = len(rs)

            config.default_domain = dom_name

        if discover_server:
            if rl == 0:
                name = "_ldap._tcp."+config.default_domain+"."
                rs = ipapython.dnsclient.query(name, ipapython.dnsclient.DNS_C_IN, ipapython.dnsclient.DNS_T_SRV)

            for r in rs:
                if r.dns_type == ipapython.dnsclient.DNS_T_SRV:
                    rsrv = r.rdata.server.rstrip(".")
                    config.default_server.append(rsrv)

    except:
        pass

def add_standard_options(parser):
    parser.add_option("--realm", dest="realm", help="Override default IPA realm")
    parser.add_option("--server", dest="server", help="Override default IPA server")
    parser.add_option("--domain", dest="domain", help="Override default IPA DNS domain")

def init_config(options=None):
    if options:
        config.default_realm = options.realm
        config.default_domain = options.domain
        if options.server:
            config.default_server.extend(options.server.split(","))

    if len(config.default_server):
        discover_server = False
    else:
        discover_server = True
    __parse_config(discover_server)
    __discover_config(discover_server)

    # make sure the server list only contains unique items
    new_server = []
    for server in config.default_server:
        if server not in new_server:
            new_server.append(server)
    config.default_server = new_server

    if not config.default_realm:
        raise IPAConfigError("IPA realm not found in DNS, in the config file (/etc/ipa/default.conf) or on the command line.")
    if not config.default_server:
        raise IPAConfigError("IPA server not found in DNS, in the config file (/etc/ipa/default.conf) or on the command line.")
    if not config.default_domain:
        raise IPAConfigError("IPA domain not found in the config file (/etc/ipa/default.conf) or on the command line.")
