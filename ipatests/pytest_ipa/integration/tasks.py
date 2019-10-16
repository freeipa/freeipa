# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2013  Red Hat
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

"""Common tasks for FreeIPA integration tests"""

from __future__ import absolute_import

import logging
import os
from io import StringIO
import textwrap
import re
import collections
import itertools
import tempfile
import time
from pipes import quote
import configparser
from contextlib import contextmanager

import dns
from ldif import LDIFWriter
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from ipapython import certdb
from ipapython import ipautil
from ipaplatform.paths import paths
from ipaplatform.services import knownservices
from ipapython.dn import DN
from ipalib import errors
from ipalib.util import get_reverse_zone_default, verify_host_resolvable
from ipalib.constants import (
    DEFAULT_CONFIG, DOMAIN_SUFFIX_NAME, DOMAIN_LEVEL_0,
    MIN_DOMAIN_LEVEL, MAX_DOMAIN_LEVEL
)

from ipatests.create_external_ca import ExternalCA
from .env_config import env_to_script
from .host import Host
from .firewall import Firewall

logger = logging.getLogger(__name__)


def setup_server_logs_collecting(host):
    """
    This function setup logs to be collected on host. We should collect all
    possible logs that may be helpful to debug IPA server
    """
    # dirsrv logs
    inst = host.domain.realm.replace('.', '-')
    host.collect_log(paths.SLAPD_INSTANCE_ERROR_LOG_TEMPLATE % inst)
    host.collect_log(paths.SLAPD_INSTANCE_ACCESS_LOG_TEMPLATE % inst)

    # IPA install logs
    host.collect_log(paths.IPASERVER_INSTALL_LOG)
    host.collect_log(paths.IPASERVER_UNINSTALL_LOG)
    host.collect_log(paths.IPACLIENT_INSTALL_LOG)
    host.collect_log(paths.IPACLIENT_UNINSTALL_LOG)
    host.collect_log(paths.IPAREPLICA_INSTALL_LOG)
    host.collect_log(paths.IPAREPLICA_CONNCHECK_LOG)
    host.collect_log(paths.IPAREPLICA_CA_INSTALL_LOG)
    host.collect_log(paths.IPASERVER_KRA_INSTALL_LOG)
    host.collect_log(paths.IPA_CUSTODIA_AUDIT_LOG)

    # IPA uninstall logs
    host.collect_log(paths.IPACLIENT_UNINSTALL_LOG)

    # IPA backup and restore logs
    host.collect_log(paths.IPARESTORE_LOG)
    host.collect_log(paths.IPABACKUP_LOG)

    # kerberos related logs
    host.collect_log(paths.KADMIND_LOG)
    host.collect_log(paths.KRB5KDC_LOG)

    # httpd logs
    host.collect_log(paths.VAR_LOG_HTTPD_ERROR)

    # dogtag logs
    host.collect_log(os.path.join(paths.VAR_LOG_PKI_DIR))

    # selinux logs
    host.collect_log(paths.VAR_LOG_AUDIT)

    # SSSD debugging must be set after client is installed (function
    # setup_sssd_debugging)


def collect_logs(func):
    def wrapper(*args):
        try:
            func(*args)
        finally:
            if hasattr(args[0], 'master'):
                setup_server_logs_collecting(args[0].master)
            if hasattr(args[0], 'replicas') and args[0].replicas:
                for replica in args[0].replicas:
                    setup_server_logs_collecting(replica)
            if hasattr(args[0], 'clients') and args[0].clients:
                for client in args[0].clients:
                    setup_server_logs_collecting(client)
    return wrapper


def check_arguments_are(slice, instanceof):
    """
    :param: slice - tuple of integers denoting the beginning and the end
    of argument list to be checked
    :param: instanceof - name of the class the checked arguments should be
    instances of
    Example: @check_arguments_are((1, 3), int) will check that the second
    and third arguments are integers
    """
    def wrapper(func):
        def wrapped(*args, **kwargs):
            for i in args[slice[0]:slice[1]]:
                assert isinstance(i, instanceof), "Wrong type: %s: %s" % (i, type(i))
            return func(*args, **kwargs)
        return wrapped
    return wrapper

def prepare_reverse_zone(host, ip):
    zone = get_reverse_zone_default(ip)
    result = host.run_command(["ipa",
                      "dnszone-add",
                      zone], raiseonerr=False)
    if result.returncode > 0:
        logger.warning("%s", result.stderr_text)
    return zone, result.returncode

def prepare_host(host):
    if isinstance(host, Host):
        env_filename = os.path.join(host.config.test_dir, 'env.sh')

        # First we try to run simple echo command to test the connection
        host.run_command(['true'], set_env=False)

        host.collect_log(env_filename)
        try:
            host.transport.mkdir_recursive(host.config.test_dir)
        except IOError:
            # The folder already exists
            pass
        host.put_file_contents(env_filename, env_to_script(host.to_env()))


def rpcbind_kadmin_workaround(host):
    """Restart rpcbind in case it blocks 749/TCP, 464/UDP, or 464/TCP

    See https://pagure.io/freeipa/issue/7769
    See https://bugzilla.redhat.com/show_bug.cgi?id=1592883
    """
    cmd = [
        'ss',
        '--all',  # listening and non-listening sockets
        '--tcp', '--udp',  # only TCP and UDP sockets
        '--numeric',  # don't resolve host and service names
        '--processes',  # show processes
    ]
    # run once to list all ports for debugging
    host.run_command(cmd)
    # check for blocked kadmin port
    cmd.extend((
        '-o', 'state', 'all',  # ports in any state, not just listening
        '( sport = :749 or dport = :749 or sport = :464 or dport = :464 )'
    ))
    for _i in range(5):
        result = host.run_command(cmd)
        if 'rpcbind' in result.stdout_text:
            logger.error("rpcbind blocks 749, restarting")
            host.run_command(['systemctl', 'restart', 'rpcbind.service'])
            time.sleep(2)
        else:
            break


def apply_common_fixes(host):
    prepare_host(host)
    fix_hostname(host)
    rpcbind_kadmin_workaround(host)


def allow_sync_ptr(host):
    kinit_admin(host)
    host.run_command(["ipa", "dnsconfig-mod", "--allow-sync-ptr=true"],
                     raiseonerr=False)


def backup_file(host, filename):
    if host.transport.file_exists(filename):
        backupname = os.path.join(host.config.test_dir, 'file_backup',
                                  filename.lstrip('/'))
        host.transport.mkdir_recursive(os.path.dirname(backupname))
        host.run_command(['cp', '-af', filename, backupname])
        return True
    else:
        rmname = os.path.join(host.config.test_dir, 'file_remove')
        host.run_command('echo %s >> %s' % (
            ipautil.shell_quote(filename),
            ipautil.shell_quote(rmname)))
        host.transport.mkdir_recursive(os.path.dirname(rmname))
        return False


def fix_hostname(host):
    backup_file(host, paths.ETC_HOSTNAME)
    host.put_file_contents(paths.ETC_HOSTNAME, host.hostname + '\n')
    host.run_command(['hostname', host.hostname])

    backupname = os.path.join(host.config.test_dir, 'backup_hostname')
    host.run_command('hostname > %s' % ipautil.shell_quote(backupname))


def host_service_active(host, service):
    res = host.run_command(['systemctl', 'is-active', '--quiet', service],
                           raiseonerr=False)

    return res.returncode == 0

def fix_apache_semaphores(master):
    systemd_available = master.transport.file_exists(paths.SYSTEMCTL)

    if systemd_available:
        master.run_command(['systemctl', 'stop', 'httpd'], raiseonerr=False)
    else:
        master.run_command([paths.SBIN_SERVICE, 'httpd', 'stop'],
                           raiseonerr=False)

    master.run_command('for line in `ipcs -s | grep apache | cut -d " " -f 2`; '
                       'do ipcrm -s $line; done', raiseonerr=False)


def unapply_fixes(host):
    restore_files(host)
    restore_hostname(host)
    # Clean ccache to prevent issues like 5741
    host.run_command(['kdestroy', '-A'], raiseonerr=False)

    # Clean up the test directory
    host.run_command(['rm', '-rvf', host.config.test_dir])


def restore_files(host):
    backupname = os.path.join(host.config.test_dir, 'file_backup')
    rmname = os.path.join(host.config.test_dir, 'file_remove')

    # Prepare command for restoring context of the backed-up files
    sed_remove_backupdir = 's/%s//g' % backupname.replace('/', r'\/')
    restorecon_command = (
        "find %s | "
        "sed '%s' | "
        "sed '/^$/d' | "
        "xargs -d '\n' "
        "/sbin/restorecon -v" % (backupname, sed_remove_backupdir))

    # Prepare command for actual restoring of the backed up files
    copyfiles_command = 'if [ -d %(dir)s/ ]; then cp -arvf %(dir)s/* /; fi' % {
        'dir': ipautil.shell_quote(backupname)}

    # Run both commands in one session. For more information, see:
    # https://fedorahosted.org/freeipa/ticket/4133
    host.run_command('%s ; (%s ||:)' % (copyfiles_command, restorecon_command))

    # Remove all the files that did not exist and were 'backed up'
    host.run_command(['xargs', '-d', r'\n', '-a', rmname, 'rm', '-vf'],
                     raiseonerr=False)
    host.run_command(['rm', '-rvf', backupname, rmname], raiseonerr=False)


def restore_hostname(host):
    backupname = os.path.join(host.config.test_dir, 'backup_hostname')
    try:
        hostname = host.get_file_contents(backupname, encoding='utf-8')
    except IOError:
        logger.debug('No hostname backed up on %s', host.hostname)
    else:
        host.run_command(['hostname', hostname.strip()])
        host.run_command(['rm', backupname])


def enable_replication_debugging(host, log_level=0):
    logger.info('Set LDAP debug level')
    logging_ldif = textwrap.dedent("""
        dn: cn=config
        changetype: modify
        replace: nsslapd-errorlog-level
        nsslapd-errorlog-level: {log_level}
        """.format(log_level=log_level))
    ldapmodify_dm(host, logging_ldif)

def set_default_ttl_for_ipa_dns_zone(host, raiseonerr=True):
    args = [
        'ipa', 'dnszone-mod', host.domain.name,
        '--default-ttl', '1',
        '--ttl', '1'
    ]
    result = host.run_command(args, raiseonerr=raiseonerr, stdin_text=None)
    if result.returncode != 0:
        logger.info('Failed to set TTL and default TTL for DNS zone %s to 1',
                    host.domain.name)


def install_master(host, setup_dns=True, setup_kra=False, setup_adtrust=False,
                   extra_args=(), domain_level=None, unattended=True,
                   external_ca=False, stdin_text=None, raiseonerr=True):
    if domain_level is None:
        domain_level = host.config.domain_level
    check_domain_level(domain_level)
    setup_server_logs_collecting(host)
    apply_common_fixes(host)
    fix_apache_semaphores(host)
    fw = Firewall(host)
    fw_services = ["freeipa-ldap", "freeipa-ldaps"]

    args = [
        'ipa-server-install',
        '-n', host.domain.name,
        '-r', host.domain.realm,
        '-p', host.config.dirman_password,
        '-a', host.config.admin_password,
        "--domain-level=%i" % domain_level,
    ]
    if unattended:
        args.append('-U')

    if setup_dns:
        args.extend([
            '--setup-dns',
            '--forwarder', host.config.dns_forwarder,
            '--auto-reverse'
        ])
        fw_services.append("dns")
    if setup_kra:
        args.append('--setup-kra')
    if setup_adtrust:
        args.append('--setup-adtrust')
        fw_services.append("freeipa-trust")
    if external_ca:
        args.append('--external-ca')

    args.extend(extra_args)
    result = host.run_command(args, raiseonerr=raiseonerr,
                              stdin_text=stdin_text)
    if result.returncode == 0:
        fw.enable_services(fw_services)
    if result.returncode == 0 and not external_ca:
        # external CA step 1 doesn't have DS and KDC fully configured, yet
        enable_replication_debugging(host)
        setup_sssd_debugging(host)
        kinit_admin(host)
        if setup_dns:
            # fixup DNS zone default TTL for IPA DNS zone
            # For tests we should not wait too long
            set_default_ttl_for_ipa_dns_zone(host, raiseonerr=raiseonerr)
    return result


def check_domain_level(domain_level):
    if domain_level < MIN_DOMAIN_LEVEL:
        pytest.fail(
            "Domain level {} not supported, min level is {}.".format(
                domain_level, MIN_DOMAIN_LEVEL)
        )
    if domain_level > MAX_DOMAIN_LEVEL:
        pytest.fail(
            "Domain level {} not supported, max level is {}.".format(
                domain_level, MAX_DOMAIN_LEVEL)
        )


def domainlevel(host):
    """
    Dynamically determines the domainlevel on master. Needed for scenarios
    when domainlevel is changed during the test execution.

    Sometimes the master is even not installed. Please refer to ca-less
    tests, where we call tasks.uninstall_master after every test while a lot
    of them make sure that the server installation fails. Therefore we need
    to not raise on failures here.
    """
    kinit_admin(host, raiseonerr=False)
    result = host.run_command(['ipa', 'domainlevel-get'], raiseonerr=False)
    level = MIN_DOMAIN_LEVEL
    domlevel_re = re.compile(r'.*(\d)')
    if result.returncode == 0:
        # "domainlevel-get" command doesn't exist on ipa versions prior to 4.3
        level = int(domlevel_re.findall(result.stdout_text)[0])
    check_domain_level(level)
    return level


def master_authoritative_for_client_domain(master, client):
    zone = ".".join(client.hostname.split('.')[1:])
    result = master.run_command(["ipa", "dnszone-show", zone],
                                raiseonerr=False)
    return result.returncode == 0


def config_host_resolvconf_with_master_data(master, host):
    """
    Configure host /etc/resolv.conf to use master as DNS server
    """
    content = ('search {domain}\nnameserver {master_ip}'
               .format(domain=master.domain.name, master_ip=master.ip))
    host.put_file_contents(paths.RESOLV_CONF, content)


def install_replica(master, replica, setup_ca=True, setup_dns=False,
                    setup_kra=False, setup_adtrust=False, extra_args=(),
                    domain_level=None, unattended=True, stdin_text=None,
                    raiseonerr=True, promote=True):
    """
    This task installs client and then promote it to the replica
    """
    replica_args = list(extra_args)  # needed for client's ntp options
    if domain_level is None:
        domain_level = domainlevel(master)
    check_domain_level(domain_level)
    apply_common_fixes(replica)
    setup_server_logs_collecting(replica)
    allow_sync_ptr(master)
    fw = Firewall(replica)
    fw_services = ["freeipa-ldap", "freeipa-ldaps"]
    # Otherwise ipa-client-install would not create a PTR
    # and replica installation would fail
    args = ['ipa-replica-install',
            '--admin-password', replica.config.admin_password]

    if promote:  # while promoting we use directory manager password
        args.extend(['--password', replica.config.dirman_password])
        # install client on a replica machine and then promote it to replica
        # to configure ntp options we have to pass them to client installation
        # because promotion does not support NTP options
        ntp_args = [arg for arg in replica_args if "-ntp" in arg]

        for ntp_arg in ntp_args:
            replica_args.remove(ntp_arg)

        install_client(master, replica, extra_args=ntp_args)
    else:
        # for one step installation of replica we need authorized user
        # to enroll a replica and master server to contact
        args.extend(['--principal', replica.config.admin_name,
                     '--server', master.hostname])

    if unattended:
        args.append('-U')
    if setup_ca:
        args.append('--setup-ca')
    if setup_kra:
        assert setup_ca, "CA must be installed on replica with KRA"
        args.append('--setup-kra')
    if setup_dns:
        args.extend([
            '--setup-dns',
            '--forwarder', replica.config.dns_forwarder
        ])
        fw_services.append("dns")
    if setup_adtrust:
        args.append('--setup-adtrust')
        fw_services.append("freeipa-trust")
    if master_authoritative_for_client_domain(master, replica):
        args.extend(['--ip-address', replica.ip])

    args.extend(replica_args)  # append extra arguments to installation

    fix_apache_semaphores(replica)
    args.extend(['--realm', replica.domain.realm,
                 '--domain', replica.domain.name])
    fw.enable_services(fw_services)

    result = replica.run_command(args, raiseonerr=raiseonerr,
                                 stdin_text=stdin_text)
    if result.returncode == 0:
        enable_replication_debugging(replica)
        setup_sssd_debugging(replica)
        kinit_admin(replica)
    else:
        fw.disable_services(fw_services)
    return result


def install_client(master, client, extra_args=[], user=None,
                   password=None, unattended=True, stdin_text=None):
    client.collect_log(paths.IPACLIENT_INSTALL_LOG)

    apply_common_fixes(client)
    allow_sync_ptr(master)
    # Now, for the situations where a client resides in a different subnet from
    # master, we need to explicitly tell master to create a reverse zone for
    # the client and enable dynamic updates for this zone.
    zone, error = prepare_reverse_zone(master, client.ip)
    if not error:
        master.run_command(["ipa", "dnszone-mod", zone,
                            "--dynamic-update=TRUE"])
    if user is None:
        user = client.config.admin_name
    if password is None:
        password = client.config.admin_password

    args = [
        'ipa-client-install',
        '--domain', client.domain.name,
        '--realm', client.domain.realm,
        '-p', user,
        '-w', password,
        '--server', master.hostname
    ]

    if unattended:
        args.append('-U')

    args.extend(extra_args)

    result = client.run_command(args, stdin_text=stdin_text)

    setup_sssd_debugging(client)
    kinit_admin(client)

    return result


def install_adtrust(host):
    """
    Runs ipa-adtrust-install on the client and generates SIDs for the entries.
    Configures the compat tree for the legacy clients.
    """

    setup_server_logs_collecting(host)

    kinit_admin(host)
    host.run_command(['ipa-adtrust-install', '-U',
                      '--enable-compat',
                      '--netbios-name', host.netbios,
                      '-a', host.config.admin_password,
                      '--add-sids'])

    Firewall(host).enable_service("freeipa-trust")

    # Restart named because it lost connection to dirsrv
    # (Directory server restarts during the ipa-adtrust-install)
    host.run_command(['systemctl', 'restart',
                      knownservices.named.systemd_name])

    # Check that named is running and has loaded the information from LDAP
    dig_command = ['dig', 'SRV', '+short', '@localhost',
                   '_ldap._tcp.%s' % host.domain.name]
    dig_output = '0 100 389 %s.' % host.hostname
    dig_test = lambda x: re.search(re.escape(dig_output), x)

    run_repeatedly(host, dig_command, test=dig_test)


def disable_dnssec_validation(host):
    backup_file(host, paths.NAMED_CONF)
    named_conf = host.get_file_contents(paths.NAMED_CONF)
    named_conf = re.sub(br'dnssec-validation\s*yes;', b'dnssec-validation no;',
                        named_conf)
    host.put_file_contents(paths.NAMED_CONF, named_conf)
    restart_named(host)


def restore_dnssec_validation(host):
    restore_files(host)
    restart_named(host)


def is_subdomain(subdomain, domain):
    subdomain_unpacked = subdomain.split('.')
    domain_unpacked = domain.split('.')

    subdomain_unpacked.reverse()
    domain_unpacked.reverse()

    subdomain = False

    if len(subdomain_unpacked) > len(domain_unpacked):
        subdomain = True

        for subdomain_segment, domain_segment in zip(subdomain_unpacked,
                                                     domain_unpacked):
            subdomain = subdomain and subdomain_segment == domain_segment

    return subdomain


def configure_dns_for_trust(master, *ad_hosts):
    """
    This configures DNS on IPA master according to the relationship of the
    IPA's and AD's domains.
    """

    kinit_admin(master)
    dnssec_disabled = False
    for ad in ad_hosts:
        if is_subdomain(ad.domain.name, master.domain.name):
            master.run_command(['ipa', 'dnsrecord-add', master.domain.name,
                                '%s.%s' % (ad.shortname, ad.netbios),
                                '--a-ip-address', ad.ip])

            master.run_command(['ipa', 'dnsrecord-add', master.domain.name,
                                ad.netbios,
                                '--ns-hostname',
                                '%s.%s' % (ad.shortname, ad.netbios)])

            master.run_command(['ipa', 'dnszone-mod', master.domain.name,
                                '--allow-transfer', ad.ip])
        else:
            if not dnssec_disabled:
                disable_dnssec_validation(master)
                dnssec_disabled = True
            master.run_command(['ipa', 'dnsforwardzone-add', ad.domain.name,
                                '--forwarder', ad.ip,
                                '--forward-policy', 'only',
                                ])


def unconfigure_dns_for_trust(master, *ad_hosts):
    """
    This undoes changes made by configure_dns_for_trust
    """
    kinit_admin(master)
    dnssec_needs_restore = False
    for ad in ad_hosts:
        if is_subdomain(ad.domain.name, master.domain.name):
            master.run_command(['ipa', 'dnsrecord-del', master.domain.name,
                                '%s.%s' % (ad.shortname, ad.netbios),
                                '--a-rec', ad.ip])
            master.run_command(['ipa', 'dnsrecord-del', master.domain.name,
                                ad.netbios,
                                '--ns-rec',
                                '%s.%s' % (ad.shortname, ad.netbios)])
        else:
            master.run_command(['ipa', 'dnsforwardzone-del', ad.domain.name])
            dnssec_needs_restore = True
    if dnssec_needs_restore:
        restore_dnssec_validation(master)


def configure_windows_dns_for_trust(ad, master):
    ad.run_command(['dnscmd', '/zoneadd', master.domain.name,
                    '/Forwarder', master.ip])


def unconfigure_windows_dns_for_trust(ad, master):
    ad.run_command(['dnscmd', '/zonedelete', master.domain.name, '/f'])


def establish_trust_with_ad(master, ad_domain, extra_args=(),
                            shared_secret=None):
    """
    Establishes trust with Active Directory. Trust type is detected depending
    on the presence of SfU (Services for Unix) support on the AD.

    Use extra arguments to pass extra arguments to the trust-add command, such
    as --range-type="ipa-ad-trust" to enforce a particular range type.
    """

    # Force KDC to reload MS-PAC info by trying to get TGT for HTTP
    extra_args = list(extra_args)
    master.run_command(['kinit', '-kt', paths.HTTP_KEYTAB,
                        'HTTP/%s' % master.hostname])
    master.run_command(['systemctl', 'restart', 'krb5kdc.service'])
    master.run_command(['kdestroy', '-A'])

    kinit_admin(master)
    master.run_command(['klist'])
    master.run_command(['smbcontrol', 'all', 'debug', '100'])

    if shared_secret:
        extra_args += ['--trust-secret']
        stdin_text = shared_secret
    else:
        extra_args += ['--admin', 'Administrator', '--password']
        stdin_text = master.config.ad_admin_password
    run_repeatedly(
        master, ['ipa', 'trust-add', '--type', 'ad', ad_domain] + extra_args,
        stdin_text=stdin_text)
    master.run_command(['smbcontrol', 'all', 'debug', '1'])
    clear_sssd_cache(master)
    master.run_command(['systemctl', 'restart', 'krb5kdc.service'])
    time.sleep(60)


def remove_trust_with_ad(master, ad_domain):
    """
    Removes trust with Active Directory. Also removes the associated ID range.
    """

    kinit_admin(master)

    # Remove the trust
    master.run_command(['ipa', 'trust-del', ad_domain])

    # Remove the range
    range_name = ad_domain.upper() + '_id_range'
    master.run_command(['ipa', 'idrange-del', range_name])

    remove_trust_info_from_ad(master, ad_domain)


def remove_trust_info_from_ad(master, ad_domain):
    # Remove record about trust from AD
    master.run_command(['rpcclient', ad_domain,
                        '-U\\Administrator%{}'.format(
                            master.config.ad_admin_password),
                        '-c', 'deletetrustdom {}'.format(master.domain.name)],
                       raiseonerr=False)


def configure_auth_to_local_rule(master, ad):
    """
    Configures auth_to_local rule in /etc/krb5.conf
    """

    section_identifier = " %s = {" % master.domain.realm
    line1 = ("  auth_to_local = RULE:[1:$1@$0](^.*@%s$)s/@%s/@%s/"
             % (ad.domain.realm, ad.domain.realm, ad.domain.name))
    line2 = "  auth_to_local = DEFAULT"

    krb5_conf_content = master.get_file_contents(paths.KRB5_CONF)
    krb5_lines = [line.rstrip() for line in krb5_conf_content.split('\n')]
    realm_section_index = krb5_lines.index(section_identifier)

    krb5_lines.insert(realm_section_index + 1, line1)
    krb5_lines.insert(realm_section_index + 2, line2)

    krb5_conf_new_content = '\n'.join(krb5_lines)
    master.put_file_contents(paths.KRB5_CONF, krb5_conf_new_content)

    master.run_command(['systemctl', 'restart', 'sssd'])


def setup_sssd_debugging(host):
    """
    Sets debug level to 7 in each section of sssd.conf file.
    """

    # Set debug level in each section of sssd.conf file to 7
    # First, remove any previous occurences
    host.run_command(['sed', '-i',
                      '/debug_level = 7/d',
                      paths.SSSD_CONF],
                     raiseonerr=False)

    # Add the debug directive to each section
    host.run_command(['sed', '-i',
                      r'/\[*\]/ a\debug_level = 7',
                      paths.SSSD_CONF],
                     raiseonerr=False)

    host.collect_log(os.path.join(paths.VAR_LOG_SSSD_DIR))

    # Clear the cache and restart SSSD
    clear_sssd_cache(host)


def modify_sssd_conf(host, domain, mod_dict, provider='ipa',
                     provider_subtype=None):
    """
    modify options in a single domain section of host's sssd.conf
    :param host: multihost.Host object
    :param domain: domain section name to modify
    :param mod_dict: dictionary of options which will be passed to
        SSSDDomain.set_option(). To remove an option specify its value as
        None
    :param provider: provider backend to set. Defaults to ipa
    :param provider_subtype: backend subtype (e.g. id or sudo), will be added
        to the domain config if not present
    """
    from SSSDConfig import SSSDConfig
    fd, temp_config_file = tempfile.mkstemp()
    os.close(fd)
    try:
        current_config = host.transport.get_file_contents(paths.SSSD_CONF)

        with open(temp_config_file, 'wb') as f:
            f.write(current_config)

        sssd_config = SSSDConfig()
        sssd_config.import_config(temp_config_file)
        sssd_domain = sssd_config.get_domain(domain)

        if provider_subtype is not None:
            sssd_domain.add_provider(provider, provider_subtype)

        for m in mod_dict:
            sssd_domain.set_option(m, mod_dict[m])

        sssd_config.save_domain(sssd_domain)

        new_config = sssd_config.dump(sssd_config.opts).encode('utf-8')
        host.transport.put_file_contents(paths.SSSD_CONF, new_config)
    finally:
        try:
            os.remove(temp_config_file)
        except OSError:
            pass


def clear_sssd_cache(host):
    """
    Clears SSSD cache by removing the cache files. Restarts SSSD.
    """

    systemd_available = host.transport.file_exists(paths.SYSTEMCTL)

    if systemd_available:
        host.run_command(['systemctl', 'stop', 'sssd'])
    else:
        host.run_command([paths.SBIN_SERVICE, 'sssd', 'stop'])

    host.run_command("find /var/lib/sss/db -name '*.ldb' | "
                     "xargs rm -fv")
    host.run_command(['rm', '-fv', paths.SSSD_MC_GROUP])
    host.run_command(['rm', '-fv', paths.SSSD_MC_PASSWD])

    if systemd_available:
        host.run_command(['systemctl', 'start', 'sssd'])
    else:
        host.run_command([paths.SBIN_SERVICE, 'sssd', 'start'])

    # To avoid false negatives due to SSSD not responding yet
    time.sleep(10)


def sync_time(host, server):
    """
    Syncs the time with the remote server. Please note that this function
    leaves chronyd stopped.
    """

    host.run_command(['systemctl', 'stop', 'chronyd'])
    host.run_command(['chronyd', '-q',
                      "server {srv} iburst maxdelay 1000".format(
                          srv=server.hostname),
                      'pidfile /tmp/chronyd.pid', 'bindcmdaddress /',
                      'maxdistance 1000', 'maxjitter 1000'])


def connect_replica(master, replica, domain_level=None,
                    database=DOMAIN_SUFFIX_NAME):
    if domain_level is None:
        domain_level = master.config.domain_level
    check_domain_level(domain_level)
    if domain_level == DOMAIN_LEVEL_0:
        if database == DOMAIN_SUFFIX_NAME:
            cmd = 'ipa-replica-manage'
        else:
            cmd = 'ipa-csreplica-manage'
        replica.run_command([cmd, 'connect', master.hostname])
    else:
        kinit_admin(master)
        master.run_command(["ipa", "topologysegment-add", database,
                            "%s-to-%s" % (master.hostname, replica.hostname),
                            "--leftnode=%s" % master.hostname,
                            "--rightnode=%s" % replica.hostname
                            ])


def disconnect_replica(master, replica, domain_level=None,
                       database=DOMAIN_SUFFIX_NAME):
    if domain_level is None:
        domain_level = master.config.domain_level
    check_domain_level(domain_level)
    if domain_level == DOMAIN_LEVEL_0:
        if database == DOMAIN_SUFFIX_NAME:
            cmd = 'ipa-replica-manage'
        else:
            cmd = 'ipa-csreplica-manage'
        replica.run_command([cmd, 'disconnect', master.hostname])
    else:
        kinit_admin(master)
        master.run_command(["ipa", "topologysegment-del", database,
                            "%s-to-%s" % (master.hostname, replica.hostname),
                            "--continue"
                            ])


def kinit_admin(host, raiseonerr=True):
    return host.run_command(['kinit', 'admin'], raiseonerr=raiseonerr,
                            stdin_text=host.config.admin_password)


def uninstall_master(host, ignore_topology_disconnect=True,
                     ignore_last_of_role=True, clean=True, verbose=False):
    host.collect_log(paths.IPASERVER_UNINSTALL_LOG)
    uninstall_cmd = ['ipa-server-install', '--uninstall', '-U']

    host_domain_level = domainlevel(host)

    if ignore_topology_disconnect and host_domain_level != DOMAIN_LEVEL_0:
        uninstall_cmd.append('--ignore-topology-disconnect')

    if ignore_last_of_role and host_domain_level != DOMAIN_LEVEL_0:
        uninstall_cmd.append('--ignore-last-of-role')

    if verbose and host_domain_level != DOMAIN_LEVEL_0:
        uninstall_cmd.append('-v')

    result = host.run_command(uninstall_cmd)
    assert "Traceback" not in result.stdout_text
    if clean:
        Firewall(host).disable_services(["freeipa-ldap", "freeipa-ldaps",
                                         "freeipa-trust", "dns"])

    host.run_command(['pkidestroy', '-s', 'CA', '-i', 'pki-tomcat'],
                     raiseonerr=False)
    host.run_command(['rm', '-rf',
                      paths.TOMCAT_TOPLEVEL_DIR,
                      paths.SYSCONFIG_PKI_TOMCAT,
                      paths.SYSCONFIG_PKI_TOMCAT_PKI_TOMCAT_DIR,
                      paths.VAR_LIB_PKI_TOMCAT_DIR,
                      paths.PKI_TOMCAT,
                      paths.IPA_RENEWAL_LOCK,
                      paths.REPLICA_INFO_GPG_TEMPLATE % host.hostname],
                     raiseonerr=False)
    host.run_command("find /var/lib/sss/keytabs -name '*.keytab' | "
                     "xargs rm -fv", raiseonerr=False)
    host.run_command("find /run/ipa -name 'krb5*' | xargs rm -fv",
                     raiseonerr=False)
    if clean:
        unapply_fixes(host)


def uninstall_client(host):
    host.collect_log(paths.IPACLIENT_UNINSTALL_LOG)

    host.run_command(['ipa-client-install', '--uninstall', '-U'],
                     raiseonerr=False)
    unapply_fixes(host)


@check_arguments_are((0, 2), Host)
def clean_replication_agreement(master, replica, cleanup=False,
                                raiseonerr=True):
    """
    Performs `ipa-replica-manage del replica_hostname --force`.
    """
    args = ['ipa-replica-manage', 'del', replica.hostname, '--force']
    if cleanup:
        args.append('--cleanup')
    master.run_command(args, raiseonerr=raiseonerr)


@check_arguments_are((0, 3), Host)
def create_segment(master, leftnode, rightnode, suffix=DOMAIN_SUFFIX_NAME):
    """
    creates a topology segment. The first argument is a node to run the command
    :returns: a hash object containing segment's name, leftnode, rightnode
    information and an error string.
    """
    kinit_admin(master)
    lefthost = leftnode.hostname
    righthost = rightnode.hostname
    segment_name = "%s-to-%s" % (lefthost, righthost)
    result = master.run_command(["ipa", "topologysegment-add", suffix,
                                 segment_name,
                                 "--leftnode=%s" % lefthost,
                                 "--rightnode=%s" % righthost], raiseonerr=False)
    if result.returncode == 0:
        return {'leftnode': lefthost,
                'rightnode': righthost,
                'name': segment_name}, ""
    else:
        return {}, result.stderr_text


def destroy_segment(master, segment_name, suffix=DOMAIN_SUFFIX_NAME):
    """
    Destroys topology segment.
    :param master: reference to master object of class Host
    :param segment_name: name of the segment to be created
    """
    assert isinstance(master, Host), "master should be an instance of Host"
    kinit_admin(master)
    command = ["ipa",
               "topologysegment-del",
               suffix,
               segment_name]
    result = master.run_command(command, raiseonerr=False)
    return result.returncode, result.stderr_text


def get_topo(name_or_func):
    """Get a topology function by name

    A topology function receives a master and list of replicas, and yields
    (parent, child) pairs, where "child" should be installed from "parent"
    (or just connected if already installed)

    If a callable is given instead of name, it is returned directly
    """
    if callable(name_or_func):
        return name_or_func
    return topologies[name_or_func]


def _topo(name):
    """Decorator that registers a function in topologies under a given name"""
    def add_topo(func):
        topologies[name] = func
        return func
    return add_topo
topologies = collections.OrderedDict()


@_topo('star')
def star_topo(master, replicas):
    r"""All replicas are connected to the master

          Rn R1 R2
           \ | /
        R7-- M -- R3
           / | \
          R6 R5 R4
    """
    for replica in replicas:
        yield master, replica


@_topo('line')
def line_topo(master, replicas):
    r"""Line topology

          M
           \
           R1
            \
            R2
             \
             R3
              \
              ...
    """
    for replica in replicas:
        yield master, replica
        master = replica


@_topo('complete')
def complete_topo(master, replicas):
    r"""Each host connected to each other host

          M--R1
          |\/|
          |/\|
         R2-R3
    """
    for replica in replicas:
        yield master, replica
    for replica1, replica2 in itertools.combinations(replicas, 2):
        yield replica1, replica2


@_topo('tree')
def tree_topo(master, replicas):
    r"""Binary tree topology

             M
            / \
           /   \
          R1   R2
         /  \  / \
        R3 R4 R5 R6
       /
      R7 ...

    """
    replicas = list(replicas)

    def _masters():
        for host in [master] + replicas:
            yield host
            yield host

    for parent, child in zip(_masters(), replicas):
        yield parent, child


@_topo('tree2')
def tree2_topo(master, replicas):
    r"""First replica connected directly to master, the rest in a line

          M
         / \
        R1 R2
            \
            R3
             \
             R4
              \
              ...

    """
    if replicas:
        yield master, replicas[0]
    for replica in replicas[1:]:
        yield master, replica
        master = replica


@_topo('2-connected')
def two_connected_topo(master, replicas):
    r"""No replica has more than 4 agreements and at least two
        replicas must fail to disconnect the topology.

         .     .     .     .
         .     .     .     .
         .     .     .     .
     ... R --- R     R --- R ...
          \   / \   / \   /
           \ /   \ /   \ /
        ... R     R     R ...
             \   / \   /
              \ /   \ /
               M0 -- R2
               |     |
               |     |
               R1 -- R3
              . \   /  .
             .   \ /    .
            .     R      .
                 .  .
                .    .
               .      .
    """
    grow = []
    pool = [master] + replicas

    try:
        v0 = pool.pop(0)
        v1 = pool.pop(0)
        yield v0, v1

        v2 = pool.pop(0)
        yield v0, v2
        grow.append((v0, v2))

        v3 = pool.pop(0)
        yield v2, v3
        yield v1, v3
        grow.append((v1, v3))

        for (r, s) in grow:
            t = pool.pop(0)

            for (u, v) in [(r, t), (s, t)]:
                yield u, v
                w = pool.pop(0)
                yield u, w
                x = pool.pop(0)
                yield v, x
                yield w, x
                grow.append((w, x))

    except IndexError:
        return


@_topo('double-circle')
def double_circle_topo(master, replicas, site_size=6):
    r"""
                      R--R
                      |\/|
                      |/\|
                      R--R
                     /    \
                     M -- R
                    /|    |\
                   / |    | \
          R - R - R--|----|--R - R - R
          | X |   |  |    |  |   | X |
          R - R - R -|----|--R - R - R
                   \ |    | /
                    \|    |/
                     R -- R
                     \    /
                      R--R
                      |\/|
                      |/\|
                      R--R
    """
    # to provide redundancy there must be at least two replicas per site
    assert site_size >= 2
    # do not handle master other than the rest of the servers
    servers = [master] + replicas

    # split servers into sites
    it = [iter(servers)] * site_size
    sites = [(x[0], x[1], x[2:]) for x in zip(*it)]
    num_sites = len(sites)

    for i in range(num_sites):
        (a, b, _ignore) = sites[i]
        # create agreement inside the site
        yield a, b

        # create agreement to one server in two next sites
        for c, _d, _ignore in [sites[(i+n) % num_sites] for n in [1, 2]]:
            yield b, c

    if site_size > 2:
        # deploy servers inside the site
        for site in sites:
            site_servers = list(site[2])
            yield site[0], site_servers[0]
            for edge in complete_topo(site_servers[0], site_servers[1:]):
                yield edge
            yield site[1], site_servers[-1]


def install_topo(topo, master, replicas, clients, domain_level=None,
                 skip_master=False, setup_replica_cas=True,
                 setup_replica_kras=False, clients_extra_args=()):
    """Install IPA servers and clients in the given topology"""
    if setup_replica_kras and not setup_replica_cas:
        raise ValueError("Option 'setup_replica_kras' requires "
                         "'setup_replica_cas' set to True")
    replicas = list(replicas)
    installed = {master}
    if not skip_master:
        install_master(
            master,
            domain_level=domain_level,
            setup_kra=setup_replica_kras
        )

    add_a_records_for_hosts_in_master_domain(master)

    for parent, child in get_topo(topo)(master, replicas):
        if child in installed:
            logger.info('Connecting replica %s to %s', parent, child)
            connect_replica(parent, child)
        else:
            logger.info('Installing replica %s from %s', child, parent)
            install_replica(
                parent, child,
                setup_ca=setup_replica_cas,
                setup_kra=setup_replica_kras
            )
        installed.add(child)
    install_clients([master] + replicas, clients, clients_extra_args)


def install_clients(servers, clients, extra_args=()):
    """Install IPA clients, distributing them among the given servers"""
    izip = getattr(itertools, 'izip', zip)
    for server, client in izip(itertools.cycle(servers), clients):
        logger.info('Installing client %s on %s', server, client)
        install_client(server, client, extra_args)


def _entries_to_ldif(entries):
    """Format LDAP entries as LDIF"""
    io = StringIO()
    writer = LDIFWriter(io)
    for entry in entries:
        writer.unparse(str(entry.dn), dict(entry.raw))
    return io.getvalue()


def wait_for_replication(ldap, timeout=30,
                         target_status_re=r'^0 |^Error \(0\) ',
                         raise_on_timeout=False):
    """Wait for all replication agreements to reach desired state

    With defaults waits until updates on all replication agreements are
    done (or failed) and exits without exception
    :param ldap: LDAP client
        autenticated with necessary rights to read the mapping tree
    :param timeout: Maximum time to wait, in seconds
    :param target_status_re: Regexp of status to wait for
    :param raise_on_timeout: if True, raises AssertionError if status not
        reached in specified time

    Note that this waits for updates originating on this host, not those
    coming from other hosts.
    """
    logger.debug('Waiting for replication to finish')
    start = time.time()
    while True:
        status_attr = 'nsds5replicaLastUpdateStatus'
        progress_attr = 'nsds5replicaUpdateInProgress'
        entries = ldap.get_entries(
            DN(('cn', 'mapping tree'), ('cn', 'config')),
            filter='(objectclass=nsds5replicationagreement)',
            attrs_list=[status_attr, progress_attr])
        logger.debug('Replication agreements: \n%s', _entries_to_ldif(entries))
        statuses = [entry.single_value[status_attr] for entry in entries]
        wrong_statuses = [s for s in statuses
                          if not re.match(target_status_re, s)]
        if any(e.single_value[progress_attr] == 'TRUE' for e in entries):
            msg = 'Replication not finished'
            logger.debug(msg)
        elif wrong_statuses:
            msg = 'Unexpected replication status: %s' % wrong_statuses[0]
            logger.debug(msg)
        else:
            logger.debug('Replication finished')
            return
        if time.time() - start > timeout:
            logger.error('Giving up wait for replication to finish')
            if raise_on_timeout:
                raise AssertionError(msg)
            break
        time.sleep(1)


def wait_for_cleanallruv_tasks(ldap, timeout=30):
    """Wait until cleanallruv tasks are finished
    """
    logger.debug('Waiting for cleanallruv tasks to finish')
    success_status = 'Successfully cleaned rid'
    for i in range(timeout):
        status_attr = 'nstaskstatus'
        try:
            entries = ldap.get_entries(
                DN(('cn', 'cleanallruv'), ('cn', 'tasks'), ('cn', 'config')),
                scope=ldap.SCOPE_ONELEVEL,
                attrs_list=[status_attr])
        except errors.EmptyResult:
            logger.debug("No cleanallruv tasks")
            break
        # Check status
        if all(
            e.single_value[status_attr].startswith(success_status)
            for e in entries
        ):
            logger.debug("All cleanallruv tasks finished successfully")
            break
        logger.debug("cleanallruv task in progress, (waited %s/%ss)",
                     i, timeout)
        time.sleep(1)
    else:
        logger.error('Giving up waiting for cleanallruv to finish')
        for e in entries:
            stat_str = e.single_value[status_attr]
            if not stat_str.startswith(success_status):
                logger.debug('%s status: %s', e.dn, stat_str)


def add_a_records_for_hosts_in_master_domain(master):
    for host in master.domain.hosts:
        # We don't need to take care of the zone creation since it is master
        # domain
        try:
            verify_host_resolvable(host.hostname)
            logger.debug("The host (%s) is resolvable.", host.hostname)
        except errors.DNSNotARecordError:
            logger.debug("Hostname (%s) does not have A/AAAA record. Adding "
                         "new one.",
                         host.hostname)
            add_a_record(master, host)


def add_a_record(master, host):
    # Find out if the record is already there
    cmd = master.run_command(['ipa',
                              'dnsrecord-show',
                              master.domain.name,
                              host.hostname + "."],
                             raiseonerr=False)

    # If not, add it
    if cmd.returncode != 0:
        master.run_command(['ipa',
                            'dnsrecord-add',
                            master.domain.name,
                            host.hostname + ".",
                            '--a-rec', host.ip])


def resolve_record(nameserver, query, rtype="SOA", retry=True, timeout=100):
    """Resolve DNS record
    :retry: if resolution failed try again until timeout is reached
    :timeout: max period of time while method will try to resolve query
     (requires retry=True)
    """
    res = dns.resolver.Resolver()
    res.nameservers = [nameserver]
    res.lifetime = 10  # wait max 10 seconds for reply

    wait_until = time.time() + timeout

    while time.time() < wait_until:
        try:
            ans = res.query(query, rtype)
            return ans
        except dns.exception.DNSException:
            if not retry:
                raise
        time.sleep(1)


def ipa_backup(master):
    result = master.run_command(["ipa-backup"])
    path_re = re.compile("^Backed up to (?P<backup>.*)$", re.MULTILINE)
    matched = path_re.search(result.stdout_text + result.stderr_text)
    return matched.group("backup")


def ipa_restore(master, backup_path):
    master.run_command(["ipa-restore", "-U",
                        "-p", master.config.dirman_password,
                        backup_path])


def install_kra(host, domain_level=None, first_instance=False, raiseonerr=True):
    if domain_level is None:
        domain_level = domainlevel(host)
    check_domain_level(domain_level)
    command = ["ipa-kra-install", "-U", "-p", host.config.dirman_password]
    try:
        result = host.run_command(command, raiseonerr=raiseonerr)
    finally:
        setup_server_logs_collecting(host)
    return result


def install_ca(host, domain_level=None, first_instance=False,
               external_ca=False, cert_files=None, raiseonerr=True):
    if domain_level is None:
        domain_level = domainlevel(host)
    check_domain_level(domain_level)
    command = ["ipa-ca-install", "-U", "-p", host.config.dirman_password,
               "-P", 'admin', "-w", host.config.admin_password]
    # First step of ipa-ca-install --external-ca
    if external_ca:
        command.append('--external-ca')
    # Continue with ipa-ca-install --external-ca
    if cert_files:
        for fname in cert_files:
            command.extend(['--external-cert-file', fname])
    try:
        result = host.run_command(command, raiseonerr=raiseonerr)
    finally:
        setup_server_logs_collecting(host)
    return result


def install_dns(host, raiseonerr=True, extra_args=()):
    args = [
        "ipa-dns-install",
        "--forwarder", host.config.dns_forwarder,
        "-U",
    ]
    args.extend(extra_args)
    ret = host.run_command(args, raiseonerr=raiseonerr)
    Firewall(host).enable_service("dns")
    return ret


def uninstall_replica(master, replica):
    master.run_command(["ipa-replica-manage", "del", "--force",
                        "-p", master.config.dirman_password,
                        replica.hostname], raiseonerr=False)
    uninstall_master(replica)


def replicas_cleanup(func):
    """
    replicas_cleanup decorator, applied to any test method in integration tests
    uninstalls all replicas in the topology leaving only master
    configured
    """
    def wrapped(*args):
        func(*args)
        for host in args[0].replicas:
            uninstall_replica(args[0].master, host)
            uninstall_client(host)
            result = args[0].master.run_command(
                ["ipa", "host-del", "--updatedns", host.hostname],
                raiseonerr=False)
            # Workaround for 5627
            if "host not found" in result.stderr_text:
                args[0].master.run_command(["ipa",
                                            "host-del",
                                            host.hostname], raiseonerr=False)
    return wrapped


def run_server_del(host, server_to_delete, force=False,
                   ignore_topology_disconnect=False,
                   ignore_last_of_role=False):
    kinit_admin(host)
    args = ['ipa', 'server-del', server_to_delete]
    if force:
        args.append('--force')
    if ignore_topology_disconnect:
        args.append('--ignore-topology-disconnect')
    if ignore_last_of_role:
        args.append('--ignore-last-of-role')

    return host.run_command(args, raiseonerr=False)


def run_certutil(host, args, reqdir, dbtype=None,
                 stdin=None, raiseonerr=True):
    dbdir = reqdir if dbtype is None else '{}:{}'.format(dbtype, reqdir)
    new_args = [paths.CERTUTIL, '-d', dbdir]
    new_args.extend(args)
    return host.run_command(new_args, raiseonerr=raiseonerr,
                            stdin_text=stdin)


def certutil_certs_keys(host, reqdir, pwd_file, token_name=None):
    """Run certutils and get mappings of cert and key files
    """
    base_args = ['-f', pwd_file]
    if token_name is not None:
        base_args.extend(['-h', token_name])
    cert_args = base_args + ['-L']
    key_args = base_args + ['-K']

    result = run_certutil(host, cert_args, reqdir)
    certs = {}
    for line in result.stdout_text.splitlines():
        mo = certdb.CERT_RE.match(line)
        if mo:
            certs[mo.group('nick')] = mo.group('flags')

    result = run_certutil(host, key_args, reqdir)
    assert 'orphan' not in result.stdout_text
    keys = {}
    for line in result.stdout_text.splitlines():
        mo = certdb.KEY_RE.match(line)
        if mo:
            keys[mo.group('nick')] = mo.group('keyid')
    return certs, keys


def certutil_fetch_cert(host, reqdir, pwd_file, nickname, token_name=None):
    """Run certutil and retrieve a cert as cryptography.x509 object
    """
    args = ['-f', pwd_file, '-L', '-a', '-n']
    if token_name is not None:
        args.extend([
            '{}:{}'.format(token_name, nickname),
            '-h', token_name
        ])
    else:
        args.append(nickname)
    result = run_certutil(host, args, reqdir)
    return x509.load_pem_x509_certificate(
        result.stdout_bytes, default_backend()
    )


def upload_temp_contents(host, contents, encoding='utf-8'):
    """Upload contents to a temporary file

    :param host: Remote host instance
    :param contents: file content (str, bytes)
    :param encoding: file encoding
    :return: Temporary file name
    """
    result = host.run_command(['mktemp'])
    tmpname = result.stdout_text.strip()
    host.put_file_contents(tmpname, contents, encoding=encoding)
    return tmpname


def assert_error(result, pattern, returncode=None):
    """
    Assert that ``result`` command failed and its stderr contains ``pattern``.
    ``pattern`` may be a ``str`` or a ``re.Pattern`` (regular expression).

    """
    if isinstance(pattern, re.Pattern):
        assert pattern.search(result.stderr_text), \
            f"pattern {pattern} not found in stderr {result.stderr_text!r}"
    else:
        assert pattern in result.stderr_text, \
            f"substring {pattern!r} not found in stderr {result.stderr_text!r}"

    if returncode is not None:
        assert result.returncode == returncode
    else:
        assert result.returncode > 0


def restart_named(*args):
    time.sleep(20)  # give a time to DNSSEC daemons to provide keys for named
    for host in args:
        host.run_command(['systemctl', 'restart',
                          knownservices.named.systemd_name])
    time.sleep(20)  # give a time to named to be ready (zone loading)


def run_repeatedly(host, command, assert_zero_rc=True, test=None,
                timeout=30, **kwargs):
    """
    Runs command on host repeatedly until it's finished successfully (returns
    0 exit code and its stdout passes the test function).

    Returns True if the command was executed succesfully, False otherwise.

    This method accepts additional kwargs and passes these arguments
    to the actual run_command method.
    """

    time_waited = 0
    time_step = 2

    # Check that the test is a function
    if test:
        assert callable(test)

    while(time_waited <= timeout):
        result = host.run_command(command, raiseonerr=False, **kwargs)

        return_code_ok = not assert_zero_rc or (result.returncode == 0)
        test_ok = not test or test(result.stdout_text)

        if return_code_ok and test_ok:
            # Command successful
            return True
        else:
            # Command not successful
            time.sleep(time_step)
            time_waited += time_step

    raise AssertionError("Command: {cmd} repeatedly failed {times} times, "
                         "exceeding the timeout of {timeout} seconds."
                         .format(cmd=' '.join(command),
                                 times=timeout // time_step,
                                 timeout=timeout))


def get_host_ip_with_hostmask(host):
    """Detects the IP of the host including the hostmask

    Returns None if the IP could not be detected.
    """
    ip = host.ip
    result = host.run_command(['ip', 'addr'])
    full_ip_regex = r'(?P<full_ip>%s/\d{1,2}) ' % re.escape(ip)
    match = re.search(full_ip_regex, result.stdout_text)

    if match:
        return match.group('full_ip')
    else:
        return None


def ldappasswd_user_change(user, oldpw, newpw, master):
    container_user = dict(DEFAULT_CONFIG)['container_user']
    basedn = master.domain.basedn

    userdn = "uid={},{},{}".format(user, container_user, basedn)
    master_ldap_uri = "ldap://{}".format(master.hostname)

    args = [paths.LDAPPASSWD, '-D', userdn, '-w', oldpw, '-a', oldpw,
            '-s', newpw, '-x', '-ZZ', '-H', master_ldap_uri]
    master.run_command(args)


def ldappasswd_sysaccount_change(user, oldpw, newpw, master):
    container_sysaccounts = dict(DEFAULT_CONFIG)['container_sysaccounts']
    basedn = master.domain.basedn

    userdn = "uid={},{},{}".format(user, container_sysaccounts, basedn)
    master_ldap_uri = "ldap://{}".format(master.hostname)

    args = [paths.LDAPPASSWD, '-D', userdn, '-w', oldpw, '-a', oldpw,
            '-s', newpw, '-x', '-ZZ', '-H', master_ldap_uri]
    master.run_command(args)


def add_dns_zone(master, zone, skip_overlap_check=False,
                 dynamic_update=False, add_a_record_hosts=None):
    """
    Add DNS zone if it is not already added.
    """

    result = master.run_command(
        ['ipa', 'dnszone-show', zone], raiseonerr=False)

    if result.returncode != 0:
        command = ['ipa', 'dnszone-add', zone]
        if skip_overlap_check:
            command.append('--skip-overlap-check')
        if dynamic_update:
            command.append('--dynamic-update=True')

        master.run_command(command)

        if add_a_record_hosts:
            for host in add_a_record_hosts:
                master.run_command(['ipa', 'dnsrecord-add', zone,
                                    host.hostname + ".", '--a-rec', host.ip])
    else:
        logger.debug('Zone %s already added.', zone)


def sign_ca_and_transport(host, csr_name, root_ca_name, ipa_ca_name,
                          root_ca_path_length=None, ipa_ca_path_length=1,
                          key_size=None, root_ca_extensions=()):
    """
    Sign ipa csr and save signed CA together with root CA back to the host.
    Returns root CA and IPA CA paths on the host.
    """

    test_dir = host.config.test_dir

    # Get IPA CSR as bytes
    ipa_csr = host.get_file_contents(csr_name)

    external_ca = ExternalCA(key_size=key_size)
    # Create root CA
    root_ca = external_ca.create_ca(
        path_length=root_ca_path_length,
        extensions=root_ca_extensions,
    )
    # Sign CSR
    ipa_ca = external_ca.sign_csr(ipa_csr, path_length=ipa_ca_path_length)

    root_ca_fname = os.path.join(test_dir, root_ca_name)
    ipa_ca_fname = os.path.join(test_dir, ipa_ca_name)

    # Transport certificates (string > file) to master
    host.put_file_contents(root_ca_fname, root_ca)
    host.put_file_contents(ipa_ca_fname, ipa_ca)

    return root_ca_fname, ipa_ca_fname


def generate_ssh_keypair():
    """
    Create SSH keypair for key authentication testing
    """
    key = rsa.generate_private_key(backend=default_backend(),
                                   public_exponent=65537,
                                   key_size=2048)

    public_key = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        # paramiko does not support PKCS#8 format, yet.
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    private_key_str = pem.decode('utf-8')
    public_key_str = public_key.decode('utf-8')

    return (private_key_str, public_key_str)


def strip_cert_header(pem):
    """
    Remove the header and footer from a certificate.
    """
    regexp = (
        r"^-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----"
    )
    s = re.search(regexp, pem, re.MULTILINE | re.DOTALL)
    if s is not None:
        return s.group(1)
    else:
        return pem


def user_add(host, login, first='test', last='user', extra_args=(),
             password=None):
    cmd = [
        "ipa", "user-add", login,
        "--first", first,
        "--last", last
    ]
    if password is not None:
        cmd.append('--password')
        stdin_text = '{0}\n{0}\n'.format(password)
    else:
        stdin_text = None
    cmd.extend(extra_args)
    return host.run_command(cmd, stdin_text=stdin_text)


def group_add(host, groupname, extra_args=()):
    cmd = [
        "ipa", "group-add", groupname,
    ]
    cmd.extend(extra_args)
    return host.run_command(cmd)


def ldapmodify_dm(host, ldif_text, **kwargs):
    """Run ldapmodify as Directory Manager

    :param host: host object
    :param ldif_text: ldif string
    :param kwargs: additional keyword arguments to run_command()
    :return: result object
    """
    # no hard-coded hostname, let ldapmodify pick up the host from ldap.conf.
    args = [
        'ldapmodify',
        '-x',
        '-D', str(host.config.dirman_dn),  # pylint: disable=no-member
        '-w', host.config.dirman_password
    ]
    return host.run_command(args, stdin_text=ldif_text, **kwargs)


def ldapsearch_dm(host, base, ldap_args, scope='sub', **kwargs):
    """Run ldapsearch as Directory Manager

    :param host: host object
    :param base: Base DN
    :param ldap_args: additional arguments to ldapsearch (filter, attributes)
    :param scope: search scope (base, sub, one)
    :param kwargs: additional keyword arguments to run_command()
    :return: result object
    """
    args = [
        'ldapsearch',
        '-x', '-ZZ',
        '-h', host.hostname,
        '-p', '389',
        '-D', str(host.config.dirman_dn),  # pylint: disable=no-member
        '-w', host.config.dirman_password,
        '-s', scope,
        '-b', base,
        '-o', 'ldif-wrap=no',
        '-LLL',
    ]
    args.extend(ldap_args)
    return host.run_command(args, **kwargs)


def create_temp_file(host, directory=None, create_file=True):
    """Creates temproray file using mktemp."""
    cmd = ['mktemp']
    if create_file is False:
        cmd += ['--dry-run']
    if directory is not None:
        cmd += ['-p', directory]
    return host.run_command(cmd).stdout_text.strip()


def create_active_user(host, login, password, first='test', last='user',
                       extra_args=()):
    """Create user and do login to set password"""
    temp_password = 'Secret456789'
    kinit_admin(host)
    user_add(host, login, first=first, last=last, extra_args=extra_args,
             password=temp_password)
    host.run_command(
        ['kinit', login],
        stdin_text='{0}\n{1}\n{1}\n'.format(temp_password, password))
    kdestroy_all(host)


def kdestroy_all(host):
    return host.run_command(['kdestroy', '-A'])


def run_command_as_user(host, user, command, *args, **kwargs):
    """Run command on remote host using 'su -l'

    Arguments are similar to Host.run_command
    """
    if not isinstance(command, str):
        command = ' '.join(quote(s) for s in command)
    cwd = kwargs.pop('cwd', None)
    if cwd is not None:
        command = 'cd {}; {}'.format(quote(cwd), command)
    command = ['su', '-l', user, '-c', command]
    return host.run_command(command, *args, **kwargs)


def kinit_as_user(host, user, password):
    host.run_command(['kinit', user], stdin_text=password + '\n')


class FileBackup:
    """Create file backup and do restore on remote host

    Examples:

        config_backup = FileBackup(host, '/etc/some.conf')
        ... modify the file and do the test ...
        config_backup.restore()

    Use as a context manager:

        with FileBackup(host, '/etc/some.conf'):
            ... modify the file and do the test ...

    """

    def __init__(self, host, filename):
        """Create file backup."""
        self._host = host
        self._filename = filename
        self._backup = create_temp_file(host)
        host.run_command(['cp', '--preserve=all', filename, self._backup])

    def restore(self):
        """Restore file. Can be called multiple times."""
        self._host.run_command(['mv', self._backup, self._filename])

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.restore()


@contextmanager
def remote_ini_file(host, filename):
    """Context manager for editing an ini file on a remote host.

    It provides RawConfigParser object which is automatically serialized and
    uploaded to remote host upon exit from the context.

    If exception is raised inside the context then the ini file is NOT updated
    on remote host.

    Example:

        with remote_ini_file(master, '/etc/some.conf') as some_conf:
            some_conf.set('main', 'timeout', 10)


    """
    data = host.get_file_contents(filename, encoding='utf-8')
    ini_file = configparser.RawConfigParser()
    ini_file.read_string(data)
    yield ini_file
    data = StringIO()
    ini_file.write(data)
    host.put_file_contents(filename, data.getvalue())


def is_selinux_enabled(host):
    res = host.run_command('selinuxenabled', ok_returncode=(0, 1))
    return res.returncode == 0


def get_logsize(host, logfile):
    """ get current logsize"""
    logsize = len(host.get_file_contents(logfile))
    return logsize
