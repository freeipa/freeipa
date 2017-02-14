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

# pylint: disable=deprecated-module
from optparse import (
    Option, Values, OptionParser, IndentedHelpFormatter, OptionValueError)
# pylint: enable=deprecated-module
from copy import copy
import socket

from dns import resolver, rdatatype
from dns.exception import DNSException
import dns.name
# pylint: disable=import-error
from six.moves.configparser import SafeConfigParser
from six.moves.urllib.parse import urlsplit
# pylint: enable=import-error

from ipapython.dn import DN

try:
    # pylint: disable=ipa-forbidden-import
    from ipaplatform.paths import paths
    # pylint: enable=ipa-forbidden-import
except ImportError:
    IPA_DEFAULT_CONF = '/etc/ipa/default.conf'
else:
    IPA_DEFAULT_CONF = paths.IPA_DEFAULT_CONF


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

def check_ip_option(option, opt, value):
    from ipapython.ipautil import CheckedIPAddress

    ip_local = option.ip_local is True
    ip_netmask = option.ip_netmask is True
    try:
        return CheckedIPAddress(value, parse_netmask=ip_netmask, match_local=ip_local)
    except Exception as e:
        raise OptionValueError("option %s: invalid IP address %s: %s" % (opt, value, e))

def check_dn_option(option, opt, value):
    try:
        return DN(value)
    except Exception as e:
        raise OptionValueError("option %s: invalid DN: %s" % (opt, e))

class IPAOption(Option):
    """
    optparse.Option subclass with support of options labeled as
    security-sensitive such as passwords.
    """
    ATTRS = Option.ATTRS + ["sensitive", "ip_local", "ip_netmask"]
    TYPES = Option.TYPES + ("ip", "dn")
    TYPE_CHECKER = copy(Option.TYPE_CHECKER)
    TYPE_CHECKER["ip"] = check_ip_option
    TYPE_CHECKER["dn"] = check_dn_option

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

        for option, value in opts.__dict__.items():
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


class IPAConfig(object):
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
    p = SafeConfigParser()
    p.read(IPA_DEFAULT_CONF)

    try:
        if not config.default_realm:
            config.default_realm = p.get("global", "realm")
    except Exception:
        pass
    if discover_server:
        try:
            s = p.get("global", "xmlrpc_uri")
            server = urlsplit(s)
            config.default_server.append(server.netloc)
        except Exception:
            pass
    try:
        if not config.default_domain:
            config.default_domain = p.get("global", "domain")
    except Exception:
        pass

def __discover_config(discover_server = True):
    servers = []
    try:
        if not config.default_domain:
            # try once with REALM -> domain
            domain = str(config.default_realm).lower()
            name = "_ldap._tcp." + domain

            try:
                servers = resolver.query(name, rdatatype.SRV)
            except DNSException:
                # try cycling on domain components of FQDN
                try:
                    domain = dns.name.from_text(socket.getfqdn())
                except DNSException:
                    return False

                while True:
                    domain = domain.parent()

                    if str(domain) == '.':
                        return False
                    name = "_ldap._tcp.%s" % domain
                    try:
                        servers = resolver.query(name, rdatatype.SRV)
                        break
                    except DNSException:
                        pass

            config.default_domain = str(domain).rstrip(".")

        if discover_server:
            if not servers:
                name = "_ldap._tcp.%s." % config.default_domain
                try:
                    servers = resolver.query(name, rdatatype.SRV)
                except DNSException:
                    pass

            for server in servers:
                hostname = str(server.target).rstrip(".")
                config.default_server.append(hostname)

    except Exception:
        pass

def add_standard_options(parser):
    parser.add_option("--realm", dest="realm", help="Override default IPA realm")
    parser.add_option("--server", dest="server",
                      help="Override default FQDN of IPA server")
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
