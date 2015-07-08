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

from __future__ import absolute_import

import socket
import getpass
import os
import re
import fileinput
import sys
import tempfile
import shutil
from ConfigParser import SafeConfigParser, NoOptionError
import traceback
import textwrap
from contextlib import contextmanager

from dns import resolver, rdatatype
from dns.exception import DNSException
import ldap
from nss.error import NSPRError

import ipaplatform

from ipapython import ipautil, sysrestore, admintool, dogtag, version
from ipapython.admintool import ScriptError
from ipapython.ipa_log_manager import root_logger, log_mgr
from ipalib.util import validate_hostname
from ipapython import config
from ipalib import errors, x509
from ipapython.dn import DN
from ipaserver.install import certs, service, sysupgrade
from ipaplatform import services
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks

# Used to determine install status
IPA_MODULES = [
    'httpd', 'kadmin', 'dirsrv', 'pki-cad', 'pki-tomcatd', 'install',
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


class UpgradeVersionError(Exception):
    pass


class UpgradePlatformError(UpgradeVersionError):
    pass


class UpgradeDataOlderVersionError(UpgradeVersionError):
    pass


class UpgradeDataNewerVersionError(UpgradeVersionError):
    pass


class UpgradeMissingVersionError(UpgradeVersionError):
    pass


class ReplicaConfig:
    def __init__(self, top_dir=None):
        self.realm_name = ""
        self.domain_name = ""
        self.master_host_name = ""
        self.dirman_password = ""
        self.host_name = ""
        self.dir = ""
        self.subject_base = None
        self.setup_ca = False
        self.version = 0
        self.top_dir = top_dir

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
        except socket.error, e:
            root_logger.debug('socket.gethostbyaddr() error: %d: %s' % (e.errno, e.strerror))

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
            raise HostReverseLookupError(
                "Unable to resolve the IP address %s to a host name, "
                "check /etc/hosts and DNS name resolution" % address)
        root_logger.debug('Found reverse name: %s', revname)
        if revname != host_name:
            raise HostReverseLookupError(
                "The host name %s does not match the value %s obtained "
                "by reverse lookup on IP address %s"
                % (host_name, revname, address))
        verified.add(address)


def record_in_hosts(ip, host_name=None, conf_file=paths.HOSTS):
    """
    Search record in /etc/hosts - static table lookup for hostnames

    In case of match, returns a tuple of ip address and a list of
    hostname aliases
    When no record is matched, None is returned

    :param ip: IP address
    :param host_name: Optional hostname to search
    :param conf_file: Optional path to the lookup table
    """
    hosts = open(conf_file, 'r').readlines()
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
            print "Warning: Erroneous line '%s' in %s" % (line, conf_file)
            continue

    return None

def add_record_to_hosts(ip, host_name, conf_file=paths.HOSTS):
    hosts_fd = open(conf_file, 'r+')
    hosts_fd.seek(0, 2)
    hosts_fd.write(ip+'\t'+host_name+' '+host_name.split('.')[0]+'\n')
    hosts_fd.close()

# TODO: Remove when removing usage from ipa-adtrust-install
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

def read_ip_addresses(host_name, fstore):
    ips = []
    print "Enter the IP address to use, or press Enter to finish."
    while True:
        ip = ipautil.user_input("Please provide the IP address to be used for this host name", allow_empty = True)
        if not ip:
            break
        try:
            ip_parsed = ipautil.CheckedIPAddress(ip, match_local=True)
        except Exception, e:
            print "Error: Invalid IP Address %s: %s" % (ip, e)
            continue
        ips.append(ip_parsed)

    return ips


def read_dns_forwarders():
    addrs = []
    if ipautil.user_input("Do you want to configure DNS forwarders?", True):
        while True:
            ip = ipautil.user_input("Enter an IP address for a DNS forwarder, "
                                    "or press Enter to skip", allow_empty=True)
            if not ip:
                break
            try:
                ip_parsed = ipautil.CheckedIPAddress(ip, parse_netmask=False)
            except Exception, e:
                print "Error: Invalid IP Address %s: %s" % (ip, e)
                print "DNS forwarder %s not added." % ip
                continue

            print "DNS forwarder %s added. You may add another." % ip
            addrs.append(str(ip_parsed))

    if not addrs:
        print "No DNS forwarders configured"

    return addrs

def get_password(prompt):
    if os.isatty(sys.stdin.fileno()):
        return getpass.getpass(prompt)
    else:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        line = sys.stdin.readline()
        if not line:
            raise EOFError()
        return line.rstrip()


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
    finally:
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
        if line.lstrip().startswith(directive):
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
        if line.lstrip().startswith(directive):
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

def get_server_ip_address(host_name, fstore, unattended, setup_dns, ip_addresses):
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

    ips = []
    if len(hostaddr):
        for ha in hostaddr:
            try:
                ips.append(ipautil.CheckedIPAddress(ha, match_local=True))
            except ValueError, e:
                root_logger.warning("Invalid IP address %s for %s: %s", ha, host_name, unicode(e))

    if not ips and not ip_addresses:
        if not unattended:
            ip_addresses = read_ip_addresses(host_name, fstore)

    if ip_addresses:
        if setup_dns:
            ips = ip_addresses
        else:
            # all specified addresses was resolved for this host
            if set(ip_addresses) <= set(ips):
                ips = ip_addresses
            else:
                print >>sys.stderr, "Error: the hostname resolves to IP address(es) that are different"
                print >>sys.stderr, "from those provided on the command line.  Please fix your DNS"
                print >>sys.stderr, "or /etc/hosts file and restart the installation."
                print >>sys.stderr, "Provided but not resolved address(es): %s" % \
                                    ", ".join(str(ip) for ip in (set(ip_addresses) - set(ips)))
                sys.exit(1)
        ip_add_to_hosts = True

    if not ips:
        print >> sys.stderr, "No usable IP address provided nor resolved."
        sys.exit(1)

    for ip_address in ips:
        # check /etc/hosts sanity, add a record when needed
        hosts_record = record_in_hosts(str(ip_address))

        if hosts_record is None:
            if ip_add_to_hosts or setup_dns:
                print "Adding ["+str(ip_address)+" "+host_name+"] to your /etc/hosts file"
                fstore.backup_file(paths.HOSTS)
                add_record_to_hosts(str(ip_address), host_name)
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

    return ips

def expand_replica_info(filename, password):
    """
    Decrypt and expand a replica installation file into a temporary
    location. The caller is responsible to remove this directory.
    """
    top_dir = tempfile.mkdtemp("ipa")
    tarfile = top_dir+"/files.tar"
    dir_path = top_dir + "/realm_info"
    ipautil.decrypt_file(filename, tarfile, password, top_dir)
    ipautil.run(["tar", "xf", tarfile, "-C", top_dir])
    os.remove(tarfile)

    return top_dir, dir_path

def read_replica_info(dir_path, rconfig):
    """
    Read the contents of a replica installation file.

    rconfig is a ReplicaConfig object
    """
    filename = dir_path + "/realm_info"
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

def read_replica_info_dogtag_port(config_dir):
    portfile = config_dir + "/dogtag_directory_port.txt"
    default_port = dogtag.Dogtag9Constants.DS_PORT
    if not ipautil.file_exists(portfile):
        dogtag_master_ds_port = default_port
    else:
        with open(portfile) as fd:
            try:
                dogtag_master_ds_port = int(fd.read())
            except (ValueError, IOError), e:
                root_logger.debug('Cannot parse dogtag DS port: %s', e)
                root_logger.debug('Default to %d', default_port)
                dogtag_master_ds_port = default_port

    return dogtag_master_ds_port


def create_replica_config(dirman_password, filename, options):
    top_dir = None
    try:
        top_dir, dir = expand_replica_info(filename, dirman_password)
    except Exception, e:
        root_logger.error("Failed to decrypt or open the replica file.")
        print "ERROR: Failed to decrypt or open the replica file."
        print "Verify you entered the correct Directory Manager password."
        sys.exit(1)
    config = ReplicaConfig(top_dir)
    read_replica_info(dir, config)
    root_logger.debug(
        'Installing replica file with version %d (0 means no version in prepared file).',
        config.version)
    if config.version and config.version > version.NUM_VERSION:
        root_logger.error(
            'A replica file from a newer release (%d) cannot be installed on an older version (%d)',
            config.version, version.NUM_VERSION)
        sys.exit(1)
    config.dirman_password = dirman_password
    try:
        host = get_host_name(options.no_host_dns)
    except BadHostError, e:
        root_logger.error(str(e))
        sys.exit(1)
    if config.host_name != host:
        try:
            print "This replica was created for '%s' but this machine is named '%s'" % (config.host_name, host)
            if not ipautil.user_input("This may cause problems. Continue?", False):
                root_logger.debug(
                    "Replica was created for %s but machine is named %s  "
                    "User chose to exit",
                    config.host_name, host)
                sys.exit(0)
            config.host_name = host
            print ""
        except KeyboardInterrupt:
            root_logger.debug("Keyboard Interrupt")
            sys.exit(0)
    config.dir = dir
    config.ca_ds_port = read_replica_info_dogtag_port(config.dir)
    return config


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
    server_fstore = sysrestore.FileStore(paths.SYSRESTORE)
    if not server_fstore.has_files():
        raise RuntimeError("IPA is not configured on this system.")


def remove_file(filename):
    """
    Remove a file and log any exceptions raised.
    """
    try:
        if os.path.lexists(filename):
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

    sstore = sysrestore.StateFile(paths.SYSRESTORE)
    fstore = sysrestore.FileStore(paths.SYSRESTORE)

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
                # Log at the DEBUG level, which is not output to the console
                # (unless in debug/verbose mode), but is written to a logfile
                # if one is open.
                tb = sys.exc_info()[2]
                root_logger.debug('\n'.join(traceback.format_tb(tb)))
                root_logger.debug('The %s command failed, exception: %s: %s',
                                  operation_name, type(e).__name__, e)
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

    if isinstance(error, errors.ACIError):
        return error.message, 1
    if isinstance(error, ldap.INVALID_CREDENTIALS):
        return "Invalid password", 1
    if isinstance(error, ldap.INSUFFICIENT_ACCESS):
        return "Insufficient access", 1
    if isinstance(error, ldap.LOCAL_ERROR):
        return error.args[0].get('info', ''), 1
    if isinstance(error, ldap.SERVER_DOWN):
        return error.args[0]['desc'], 1
    if isinstance(error, ldap.LDAPError):
        message = 'LDAP error: %s\n%s\n%s' % (
            type(error).__name__,
            error.args[0]['desc'].strip(),
            error.args[0].get('info', '').strip()
        )
        return message, 1

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


def load_pkcs12(cert_files, key_password, key_nickname, ca_cert_files,
                host_name):
    """
    Load and verify server certificate and private key from multiple files

    The files are accepted in PEM and DER certificate, PKCS#7 certificate
    chain, PKCS#8 and raw private key and PKCS#12 formats.

    :param cert_files: Names of server certificate and private key files to
        import
    :param key_password: Password to decrypt private keys
    :param key_nickname: Nickname of the private key to import from PKCS#12
        files
    :param ca_cert_files: Names of CA certificate files to import
    :param host_name: Host name of the server
    :returns: Temporary PKCS#12 file with the server certificate, private key
        and CA certificate chain, password to unlock the PKCS#12 file and
        the CA certificate of the CA that issued the server certificate
    """
    with certs.NSSDatabase() as nssdb:
        db_password = ipautil.ipa_generate_password()
        db_pwdfile = ipautil.write_tmp_file(db_password)
        nssdb.create_db(db_pwdfile.name)

        try:
            nssdb.import_files(cert_files, db_pwdfile.name,
                               True, key_password, key_nickname)
        except RuntimeError as e:
            raise ScriptError(str(e))

        if ca_cert_files:
            try:
                nssdb.import_files(ca_cert_files, db_pwdfile.name)
            except RuntimeError as e:
                raise ScriptError(str(e))

        for nickname, trust_flags in nssdb.list_certs():
            if 'u' in trust_flags:
                key_nickname = nickname
                continue
            nssdb.trust_root_cert(nickname)

        # Check we have the whole cert chain & the CA is in it
        trust_chain = list(reversed(nssdb.get_trust_chain(key_nickname)))
        ca_cert = None
        for nickname in trust_chain[1:]:
            cert = nssdb.get_cert(nickname)
            if ca_cert is None:
                ca_cert = cert

            nss_cert = x509.load_certificate(cert, x509.DER)
            subject = DN(str(nss_cert.subject))
            issuer = DN(str(nss_cert.issuer))
            del nss_cert

            if subject == issuer:
                break
        else:
            raise ScriptError(
                "The full certificate chain is not present in %s" %
                (", ".join(cert_files)))

        for nickname in trust_chain[1:]:
            try:
                nssdb.verify_ca_cert_validity(nickname)
            except ValueError, e:
                raise ScriptError(
                    "CA certificate %s in %s is not valid: %s" %
                    (subject, ", ".join(cert_files), e))

        # Check server validity
        try:
            nssdb.verify_server_cert_validity(key_nickname, host_name)
        except ValueError as e:
            raise ScriptError(
                "The server certificate in %s is not valid: %s" %
                (", ".join(cert_files), e))

        out_file = tempfile.NamedTemporaryFile()
        out_password = ipautil.ipa_generate_password()
        out_pwdfile = ipautil.write_tmp_file(out_password)
        args = [
            paths.PK12UTIL,
            '-o', out_file.name,
            '-n', key_nickname,
            '-d', nssdb.secdir,
            '-k', db_pwdfile.name,
            '-w', out_pwdfile.name,
        ]
        ipautil.run(args)

    return out_file, out_password, ca_cert


@contextmanager
def stopped_service(service, instance_name=""):
    """
    Ensure that the specified service is stopped while the commands within
    this context are executed.

    Service is started at the end of the execution.
    """

    if instance_name:
        log_instance_name = "@{instance}".format(instance=instance_name)
    else:
        log_instance_name = ""

    root_logger.debug('Ensuring that service %s%s is not running while '
                      'the next set of commands is being executed.', service,
                      log_instance_name)

    service_obj = services.service(service)

    # Figure out if the service is running, if not, yield
    if not service_obj.is_running(instance_name):
        root_logger.debug('Service %s%s is not running, continue.', service,
                          log_instance_name)
        yield
    else:
        # Stop the service, do the required stuff and start it again
        root_logger.debug('Stopping %s%s.', service, log_instance_name)
        service_obj.stop(instance_name)
        try:
            yield
        finally:
            root_logger.debug('Starting %s%s.', service, log_instance_name)
            service_obj.start(instance_name)


def check_entropy():
    """
    Checks if the system has enough entropy, if not, displays warning message
    """
    try:
        with open(paths.ENTROPY_AVAIL, 'r') as efname:
            if int(efname.read()) < 200:
                emsg = 'WARNING: Your system is running out of entropy, ' \
                        'you may experience long delays'
                service.print_msg(emsg)
                root_logger.debug(emsg)
    except IOError as e:
        root_logger.debug(
            "Could not open %s: %s", paths.ENTROPY_AVAIL, e)
    except ValueError as e:
        root_logger.debug("Invalid value in %s %s", paths.ENTROPY_AVAIL, e)

def load_external_cert(files, subject_base):
    """
    Load and verify external CA certificate chain from multiple files.

    The files are accepted in PEM and DER certificate and PKCS#7 certificate
    chain formats.

    :param files: Names of files to import
    :param subject_base: Subject name base for IPA certificates
    :returns: Temporary file with the IPA CA certificate and temporary file
        with the external CA certificate chain
    """
    with certs.NSSDatabase() as nssdb:
        db_password = ipautil.ipa_generate_password()
        db_pwdfile = ipautil.write_tmp_file(db_password)
        nssdb.create_db(db_pwdfile.name)

        try:
            nssdb.import_files(files, db_pwdfile.name)
        except RuntimeError as e:
            raise ScriptError(str(e))

        ca_subject = DN(('CN', 'Certificate Authority'), subject_base)
        ca_nickname = None
        cache = {}
        for nickname, trust_flags in nssdb.list_certs():
            cert = nssdb.get_cert(nickname, pem=True)

            nss_cert = x509.load_certificate(cert)
            subject = DN(str(nss_cert.subject))
            issuer = DN(str(nss_cert.issuer))
            del nss_cert

            cache[nickname] = (cert, subject, issuer)
            if subject == ca_subject:
                ca_nickname = nickname
            nssdb.trust_root_cert(nickname)

        if ca_nickname is None:
            raise ScriptError(
                "IPA CA certificate not found in %s" % (", ".join(files)))

        trust_chain = reversed(nssdb.get_trust_chain(ca_nickname))
        ca_cert_chain = []
        for nickname in trust_chain:
            cert, subject, issuer = cache[nickname]
            ca_cert_chain.append(cert)
            if subject == issuer:
                break
        else:
            raise ScriptError(
                "CA certificate chain in %s is incomplete" %
                (", ".join(files)))

        for nickname in trust_chain:
            try:
                nssdb.verify_ca_cert_validity(nickname)
            except ValueError, e:
                raise ScriptError(
                    "CA certificate %s in %s is not valid: %s" %
                    (subject, ", ".join(files), e))

    cert_file = tempfile.NamedTemporaryFile()
    cert_file.write(ca_cert_chain[0] + '\n')
    cert_file.flush()

    ca_file = tempfile.NamedTemporaryFile()
    ca_file.write('\n'.join(ca_cert_chain[1:]) + '\n')
    ca_file.flush()

    return cert_file, ca_file


def store_version():
    """Store current data version and platform. This is required for check if
    upgrade is required.
    """
    sysupgrade.set_upgrade_state('ipa', 'data_version',
                                 version.VENDOR_VERSION)
    sysupgrade.set_upgrade_state('ipa', 'platform', ipaplatform.NAME)


def check_version():
    """
    :raise UpgradePlatformError: if platform is not the same
    :raise UpgradeDataOlderVersionError: if data needs to be upgraded
    :raise UpgradeDataNewerVersionError: older version of IPA was detected than data
    :raise UpgradeMissingVersionError: if platform or version is missing
    """
    platform = sysupgrade.get_upgrade_state('ipa', 'platform')
    if platform is not None:
        if platform != ipaplatform.NAME:
            raise UpgradePlatformError(
                "platform mismatch (expected '%s', current '%s')" % (
                platform, ipaplatform.NAME)
            )
    else:
        raise UpgradeMissingVersionError("no platform stored")

    data_version = sysupgrade.get_upgrade_state('ipa', 'data_version')
    if data_version is not None:
        parsed_data_ver = tasks.parse_ipa_version(data_version)
        parsed_ipa_ver = tasks.parse_ipa_version(version.VENDOR_VERSION)
        if parsed_data_ver < parsed_ipa_ver:
            raise UpgradeDataOlderVersionError(
                "data needs to be upgraded (expected version '%s', current "
                "version '%s')" % (version.VENDOR_VERSION, data_version)
            )
        elif parsed_data_ver > parsed_ipa_ver:
            raise UpgradeDataNewerVersionError(
                "data are in newer version than IPA (data version '%s', IPA "
                "version '%s')" % (data_version, version.VENDOR_VERSION)
            )
    else:
        raise UpgradeMissingVersionError("no data_version stored")

def realm_to_serverid(realm_name):
    return "-".join(realm_name.split("."))

def enable_and_start_oddjobd(sstore):
    oddjobd = services.service('oddjobd')
    sstore.backup_state('oddjobd', 'running', oddjobd.is_running())
    sstore.backup_state('oddjobd', 'enabled', oddjobd.is_enabled())

    try:
        oddjobd.enable()
        oddjobd.start()
    except Exception as e:
        root_logger.critical("Unable to start oddjobd: {0}".format(str(e)))
