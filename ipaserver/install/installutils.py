# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import socket
import errno
import getpass
import os
import re
import fileinput
import sys
import struct
import fcntl
import netaddr
import time
import tempfile
import shutil
from ConfigParser import SafeConfigParser, NoOptionError
import traceback
import textwrap

from dns import resolver, rdatatype
from dns.exception import DNSException
import ldap

from ipapython import ipautil, sysrestore, admintool
from ipapython.admintool import ScriptError
from ipapython.ipa_log_manager import *
from ipalib.util import validate_hostname
from ipapython import config
from ipalib import errors
from ipapython.dn import DN

# Used to determine install status
IPA_MODULES = [
    'httpd', 'kadmin', 'dirsrv', 'pki-cad', 'pki-tomcatd', 'pkids', 'install',
    'krb5kdc', 'ntpd', 'named', 'ipa_memcached']

class BadHostError(Exception):
    pass

class HostLookupError(BadHostError):
    pass

class HostForwardLookupError(HostLookupError):
    pass

class HostReverseLookupError(HostLookupError):
    pass

class HostnameLocalhost(HostLookupError):
    pass

class ReplicaConfig:
    def __init__(self):
        self.realm_name = ""
        self.domain_name = ""
        self.master_host_name = ""
        self.dirman_password = ""
        self.host_name = ""
        self.dir = ""
        self.subject_base = None
        self.setup_ca = False
        self.version = 0

    subject_base = ipautil.dn_attribute_property('_subject_base')

def get_fqdn():
    fqdn = ""
    try:
        fqdn = socket.getfqdn()
    except:
        try:
            fqdn = socket.gethostname()
        except:
            fqdn = ""
    return fqdn

def verify_fqdn(host_name, no_host_dns=False, local_hostname=True):
    """
    Run fqdn checks for given host:
        - test hostname format
        - test that hostname is fully qualified
        - test forward and reverse hostname DNS lookup

    Raises `BadHostError` or derived Exceptions if there is an error

    :param host_name: The host name to verify.
    :param no_host_dns: If true, skip DNS resolution tests of the host name.
    :param local_hostname: If true, run additional checks for local hostnames
    """
    if len(host_name.split(".")) < 2 or host_name == "localhost.localdomain":
        raise BadHostError("Invalid hostname '%s', must be fully-qualified." % host_name)

    if host_name != host_name.lower():
        raise BadHostError("Invalid hostname '%s', must be lower-case." % host_name)

    if ipautil.valid_ip(host_name):
        raise BadHostError("IP address not allowed as a hostname")

    try:
        # make sure that the host name meets the requirements in ipalib
        validate_hostname(host_name)
    except ValueError, e:
        raise BadHostError("Invalid hostname '%s', %s" % (host_name, unicode(e)))

    if local_hostname:
        try:
            root_logger.debug('Check if %s is a primary hostname for localhost', host_name)
            ex_name = socket.gethostbyaddr(host_name)
            root_logger.debug('Primary hostname for localhost: %s', ex_name[0])
            if host_name != ex_name[0]:
                raise HostLookupError("The host name %s does not match the primary host name %s. "\
                        "Please check /etc/hosts or DNS name resolution" % (host_name, ex_name[0]))
        except socket.gaierror:
            pass

    if no_host_dns:
        print "Warning: skipping DNS resolution of host", host_name
        return

    try:
        root_logger.debug('Search DNS for %s', host_name)
        hostaddr = socket.getaddrinfo(host_name, None)
    except Exception, e:
        root_logger.debug('Search failed: %s', e)
        raise HostForwardLookupError("Unable to resolve host name, check /etc/hosts or DNS name resolution")

    if len(hostaddr) == 0:
        raise HostForwardLookupError("Unable to resolve host name, check /etc/hosts or DNS name resolution")

    # Verify this is NOT a CNAME
    try:
        root_logger.debug('Check if %s is not a CNAME', host_name)
        resolver.query(host_name, rdatatype.CNAME)
        raise HostReverseLookupError("The IPA Server Hostname cannot be a CNAME, only A and AAAA names are allowed.")
    except DNSException:
        pass

    # list of verified addresses to prevent multiple searches for the same address
    verified = set()
    for a in hostaddr:
        address = a[4][0]
        if address in verified:
            continue
        if address == '127.0.0.1' or address == '::1':
            raise HostForwardLookupError("The IPA Server hostname must not resolve to localhost (%s). A routable IP address must be used. Check /etc/hosts to see if %s is an alias for %s" % (address, host_name, address))
        try:
            root_logger.debug('Check reverse address of %s', address)
            revname = socket.gethostbyaddr(address)[0]
        except Exception, e:
            root_logger.debug('Check failed: %s', e)
            raise HostReverseLookupError("Unable to resolve the reverse ip address, check /etc/hosts or DNS name resolution")
        root_logger.debug('Found reverse name: %s', revname)
        if revname != host_name:
            raise HostReverseLookupError("The host name %s does not match the reverse lookup %s" % (host_name, revname))
        verified.add(address)

def record_in_hosts(ip, host_name=None, file="/etc/hosts"):
    """
    Search record in /etc/hosts - static table lookup for hostnames

    In case of match, returns a tuple of ip address and a list of
    hostname aliases
    When no record is matched, None is returned

    :param ip: IP address
    :param host_name: Optional hostname to search
    :param file: Optional path to the lookup table
    """
    hosts = open(file, 'r').readlines()
    for line in hosts:
        line = line.rstrip('\n')
        fields = line.partition('#')[0].split()
        if len(fields) == 0:
            continue

        try:
            hosts_ip = fields[0]
            names = fields[1:]

            if hosts_ip != ip:
                continue
            if host_name is not None:
                if host_name in names:
                    return (hosts_ip, names)
                else:
                    return None
            return (hosts_ip, names)
        except IndexError:
            print "Warning: Erroneous line '%s' in %s" % (line, file)
            continue

    return None

def add_record_to_hosts(ip, host_name, file="/etc/hosts"):
    hosts_fd = open(file, 'r+')
    hosts_fd.seek(0, 2)
    hosts_fd.write(ip+'\t'+host_name+' '+host_name.split('.')[0]+'\n')
    hosts_fd.close()

def read_ip_address(host_name, fstore):
    while True:
        ip = ipautil.user_input("Please provide the IP address to be used for this host name", allow_empty = False)
        try:
            ip_parsed = ipautil.CheckedIPAddress(ip, match_local=True)
        except Exception, e:
            print "Error: Invalid IP Address %s: %s" % (ip, e)
            continue
        else:
            break

    return ip_parsed

def read_dns_forwarders():
    addrs = []
    if ipautil.user_input("Do you want to configure DNS forwarders?", True):
        print "Enter the IP address of DNS forwarder to use, or press Enter to finish."

        while True:
            ip = ipautil.user_input("Enter IP address for a DNS forwarder",
                                    allow_empty=True)
            if not ip:
                break
            try:
                ip_parsed = ipautil.CheckedIPAddress(ip, parse_netmask=False)
            except Exception, e:
                print "Error: Invalid IP Address %s: %s" % (ip, e)
                print "DNS forwarder %s not added" % ip
                continue

            print "DNS forwarder %s added" % ip
            addrs.append(str(ip_parsed))

    if not addrs:
        print "No DNS forwarders configured"

    return addrs

def get_password(prompt):
    if os.isatty(sys.stdin.fileno()):
        return getpass.getpass(prompt)
    else:
        return sys.stdin.readline().rstrip()

def _read_password_default_validator(password):
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")

def read_password(user, confirm=True, validate=True, retry=True, validator=_read_password_default_validator):
    correct = False
    pwd = None
    try:
        while not correct:
            if not retry:
                correct = True
            pwd = get_password(user + " password: ")
            if not pwd:
                continue
            if validate:
                try:
                    validator(pwd)
                except ValueError, e:
                    print str(e)
                    pwd = None
                    continue
            if not confirm:
                correct = True
                continue
            pwd_confirm = get_password("Password (confirm): ")
            if pwd != pwd_confirm:
                print "Password mismatch!"
                print ""
                pwd = None
            else:
                correct = True
    except EOFError:
        return None
    print ""
    return pwd

def update_file(filename, orig, subst):
    if os.path.exists(filename):
        st = os.stat(filename)
        pattern = "%s" % re.escape(orig)
        p = re.compile(pattern)
        for line in fileinput.input(filename, inplace=1):
            if not p.search(line):
                sys.stdout.write(line)
            else:
                sys.stdout.write(p.sub(subst, line))
        fileinput.close()
        os.chown(filename, st.st_uid, st.st_gid) # reset perms
        return 0
    else:
        print "File %s doesn't exist." % filename
        return 1

def set_directive(filename, directive, value, quotes=True, separator=' '):
    """Set a name/value pair directive in a configuration file.

       A value of None means to drop the directive.

       This has only been tested with nss.conf
    """
    valueset = False
    st = os.stat(filename)
    fd = open(filename)
    newfile = []
    for line in fd:
        if directive in line:
            valueset = True
            if value is not None:
                if quotes:
                    newfile.append('%s%s"%s"\n' % (directive, separator, value))
                else:
                    newfile.append('%s%s%s\n' % (directive, separator, value))
        else:
            newfile.append(line)
    fd.close()
    if not valueset:
        if value is not None:
            if quotes:
                newfile.append('%s%s"%s"\n' % (directive, separator, value))
            else:
                newfile.append('%s%s%s\n' % (directive, separator, value))

    fd = open(filename, "w")
    fd.write("".join(newfile))
    fd.close()
    os.chown(filename, st.st_uid, st.st_gid) # reset perms

def get_directive(filename, directive, separator=' '):
    """
    A rather inefficient way to get a configuration directive.
    """
    fd = open(filename, "r")
    for line in fd:
        if directive in line:
            line = line.strip()
            result = line.split(separator, 1)[1]
            result = result.strip('"')
            result = result.strip(' ')
            fd.close()
            return result
    fd.close()
    return None

def kadmin(command):
    ipautil.run(["kadmin.local", "-q", command,
                                 "-x", "ipa-setup-override-restrictions"])

def kadmin_addprinc(principal):
    kadmin("addprinc -randkey " + principal)

def kadmin_modprinc(principal, options):
    kadmin("modprinc " + options + " " + principal)

def create_keytab(path, principal):
    try:
        if ipautil.file_exists(path):
            os.remove(path)
    except os.error:
        root_logger.critical("Failed to remove %s." % path)

    kadmin("ktadd -k " + path + " " + principal)

def resolve_host(host_name):
    try:
        addrinfos = socket.getaddrinfo(host_name, None,
                                       socket.AF_UNSPEC, socket.SOCK_STREAM)

        ip_list = []

        for ai in addrinfos:
            ip = ai[4][0]
            if ip == "127.0.0.1" or ip == "::1":
                raise HostnameLocalhost("The hostname resolves to the localhost address")

            ip_list.append(ip)

        return ip_list
    except socket.error:
        return []

def get_host_name(no_host_dns):
    """
    Get the current FQDN from the socket and verify that it is valid.

    no_host_dns is a boolean that determines whether we enforce that the
    hostname is resolvable.

    Will raise a RuntimeError on error, returns hostname on success
    """
    hostname = get_fqdn()
    verify_fqdn(hostname, no_host_dns)
    return hostname

def get_server_ip_address(host_name, fstore, unattended, options):
    # Check we have a public IP that is associated with the hostname
    try:
        hostaddr = resolve_host(host_name)
    except HostnameLocalhost:
        print >> sys.stderr, "The hostname resolves to the localhost address (127.0.0.1/::1)"
        print >> sys.stderr, "Please change your /etc/hosts file so that the hostname"
        print >> sys.stderr, "resolves to the ip address of your network interface."
        print >> sys.stderr, "The KDC service does not listen on localhost"
        print >> sys.stderr, ""
        print >> sys.stderr, "Please fix your /etc/hosts file and restart the setup program"
        sys.exit(1)

    ip_add_to_hosts = False

    if len(hostaddr) > 1:
        print >> sys.stderr, "The server hostname resolves to more than one address:"
        for addr in hostaddr:
            print >> sys.stderr, "  %s" % addr

        if options.ip_address:
            if str(options.ip_address) not in hostaddr:
                print >> sys.stderr, "Address passed in --ip-address did not match any resolved"
                print >> sys.stderr, "address!"
                sys.exit(1)
            print "Selected IP address:", str(options.ip_address)
            ip = options.ip_address
        else:
            if unattended:
                print >> sys.stderr, "Please use --ip-address option to specify the address"
                sys.exit(1)
            else:
                ip = read_ip_address(host_name, fstore)
    elif len(hostaddr) == 1:
        try:
            ip = ipautil.CheckedIPAddress(hostaddr[0], match_local=True)
        except ValueError, e:
            sys.exit("Invalid IP Address %s for %s: %s" % (hostaddr[0], host_name, unicode(e)))
    else:
        # hostname is not resolvable
        ip = options.ip_address
        ip_add_to_hosts = True

    if ip is None:
        print "Unable to resolve IP address for host name"
        if unattended:
            sys.exit(1)

    if options.ip_address:
        if options.ip_address != ip and not options.setup_dns:
            print >>sys.stderr, "Error: the hostname resolves to an IP address that is different"
            print >>sys.stderr, "from the one provided on the command line.  Please fix your DNS"
            print >>sys.stderr, "or /etc/hosts file and restart the installation."
            sys.exit(1)

        ip = options.ip_address

    if ip is None:
        ip = read_ip_address(host_name, fstore)
        root_logger.debug("read ip_address: %s\n" % str(ip))

    ip_address = str(ip)

    # check /etc/hosts sanity, add a record when needed
    hosts_record = record_in_hosts(ip_address)

    if hosts_record is None:
        if ip_add_to_hosts:
            print "Adding ["+ip_address+" "+host_name+"] to your /etc/hosts file"
            fstore.backup_file("/etc/hosts")
            add_record_to_hosts(ip_address, host_name)
    else:
        primary_host = hosts_record[1][0]
        if primary_host != host_name:
            print >>sys.stderr, "Error: there is already a record in /etc/hosts for IP address %s:" \
                    % ip_address
            print >>sys.stderr, hosts_record[0], " ".join(hosts_record[1])
            print >>sys.stderr, "Chosen hostname %s does not match configured canonical hostname %s" \
                    % (host_name, primary_host)
            print >>sys.stderr, "Please fix your /etc/hosts file and restart the installation."
            sys.exit(1)

    return ip

def expand_replica_info(filename, password):
    """
    Decrypt and expand a replica installation file into a temporary
    location. The caller is responsible to remove this directory.
    """
    top_dir = tempfile.mkdtemp("ipa")
    tarfile = top_dir+"/files.tar"
    dir = top_dir + "/realm_info"
    ipautil.decrypt_file(filename, tarfile, password, top_dir)
    ipautil.run(["tar", "xf", tarfile, "-C", top_dir])
    os.remove(tarfile)

    return top_dir, dir

def read_replica_info(dir, rconfig):
    """
    Read the contents of a replica installation file.

    rconfig is a ReplicaConfig object
    """
    filename = dir + "/realm_info"
    fd = open(filename)
    config = SafeConfigParser()
    config.readfp(fd)

    rconfig.realm_name = config.get("realm", "realm_name")
    rconfig.master_host_name = config.get("realm", "master_host_name")
    rconfig.domain_name = config.get("realm", "domain_name")
    rconfig.host_name = config.get("realm", "destination_host")
    rconfig.subject_base = config.get("realm", "subject_base")
    try:
        rconfig.version = int(config.get("realm", "version"))
    except NoOptionError:
        pass

def check_server_configuration():
    """
    Check if IPA server is configured on the system.

    This is done by checking if there are system restore (uninstall) files
    present on the system. Note that this check can only be run with root
    privileges.

    When IPA is not configured, this function raises a RuntimeError exception.
    Most convenient use case for the function is in install tools that require
    configured IPA for its function.
    """
    server_fstore = sysrestore.FileStore('/var/lib/ipa/sysrestore')
    if not server_fstore.has_files():
        raise RuntimeError("IPA is not configured on this system.")

def remove_file(filename):
    """
    Remove a file and log any exceptions raised.
    """
    try:
        if os.path.exists(filename):
            os.unlink(filename)
    except Exception, e:
        root_logger.error('Error removing %s: %s' % (filename, str(e)))

def rmtree(path):
    """
    Remove a directory structure and log any exceptions raised.
    """
    try:
        if os.path.exists(path):
            shutil.rmtree(path)
    except Exception, e:
        root_logger.error('Error removing %s: %s' % (path, str(e)))

def is_ipa_configured():
    """
    Using the state and index install files determine if IPA is already
    configured.
    """
    installed = False

    sstore = sysrestore.StateFile('/var/lib/ipa/sysrestore')
    fstore = sysrestore.FileStore('/var/lib/ipa/sysrestore')

    for module in IPA_MODULES:
        if sstore.has_state(module):
            root_logger.debug('%s is configured' % module)
            installed = True
        else:
            root_logger.debug('%s is not configured' % module)

    if fstore.has_files():
        root_logger.debug('filestore has files')
        installed = True
    else:
        root_logger.debug('filestore is tracking no files')

    return installed


def run_script(main_function, operation_name, log_file_name=None,
        fail_message=None):
    """Run the given function as a command-line utility

    This function:

    - Runs the given function
    - Formats any errors
    - Exits with the appropriate code

    :param main_function: Function to call
    :param log_file_name: Name of the log file (displayed on unexpected errors)
    :param operation_name: Name of the script
    :param fail_message: Optional message displayed on failure
    """

    root_logger.info('Starting script: %s', operation_name)
    try:
        try:
            return_value = main_function()
        except BaseException, e:
            if isinstance(e, SystemExit) and (e.code is None or e.code == 0):
                # Not an error after all
                root_logger.info('The %s command was successful',
                    operation_name)
            else:
                # Log at the INFO level, which is not output to the console
                # (unless in debug/verbose mode), but is written to a logfile
                # if one is open.
                tb = sys.exc_info()[2]
                root_logger.info('\n'.join(traceback.format_tb(tb)))
                root_logger.info('The %s command failed, exception: %s: %s',
                    operation_name, type(e).__name__, e)
                exception = e
                if fail_message and not isinstance(e, SystemExit):
                    print fail_message
                raise
        else:
            if return_value:
                root_logger.info('The %s command failed, return value %s',
                    operation_name, return_value)
            else:
                root_logger.info('The %s command was successful',
                    operation_name)
            sys.exit(return_value)

    except BaseException, error:
        message, exitcode = handle_error(error, log_file_name)
        if message:
            print >> sys.stderr, message
        sys.exit(exitcode)


def handle_error(error, log_file_name=None):
    """Handle specific errors. Returns a message and return code"""

    if isinstance(error, SystemExit):
        if isinstance(error.code, int):
            return None, error.code
        elif error.code is None:
            return None, 0
        else:
            return str(error), 1
    if isinstance(error, RuntimeError):
        return str(error), 1
    if isinstance(error, KeyboardInterrupt):
        return "Cancelled.", 1

    if isinstance(error, admintool.ScriptError):
        return error.msg, error.rval

    if isinstance(error, socket.error):
        return error, 1

    if isinstance(error, ldap.INVALID_CREDENTIALS):
        return "Invalid password", 1
    if isinstance(error, ldap.INSUFFICIENT_ACCESS):
        return "Insufficient access", 1
    if isinstance(error, ldap.LOCAL_ERROR):
        return error.args[0]['info'], 1
    if isinstance(error, ldap.SERVER_DOWN):
        return error.args[0]['desc'], 1
    if isinstance(error, ldap.LDAPError):
        return 'LDAP error: %s\n%s' % (
            type(error).__name__, error.args[0]['info']), 1

    if isinstance(error, config.IPAConfigError):
        message = "An IPA server to update cannot be found. Has one been configured yet?"
        message += "\nThe error was: %s" % error
        return message, 1
    if isinstance(error, errors.LDAPError):
        return "An error occurred while performing operations: %s" % error, 1

    if isinstance(error, HostnameLocalhost):
        message = textwrap.dedent("""
            The hostname resolves to the localhost address (127.0.0.1/::1)
            Please change your /etc/hosts file so that the hostname
            resolves to the ip address of your network interface.

            Please fix your /etc/hosts file and restart the setup program
            """).strip()
        return message, 1

    if log_file_name:
        message = "Unexpected error - see %s for details:" % log_file_name
    else:
        message = "Unexpected error"
    message += '\n%s: %s' % (type(error).__name__, error)
    return message, 1
