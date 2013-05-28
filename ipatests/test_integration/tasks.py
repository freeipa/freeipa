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

import os
import textwrap

from ipapython.ipa_log_manager import log_mgr

log = log_mgr.get_logger(__name__)


def enable_replication_debugging(host):
    log.info('Enable LDAP replication logging')
    logging_ldif = textwrap.dedent("""
        dn: cn=config
        changetype: modify
        replace: nsslapd-errorlog-level
        nsslapd-errorlog-level: 8192
        """)
    host.run_command(['ldapmodify', '-x',
                      '-D', str(host.config.dirman_dn),
                      '-w', host.config.dirman_password],
                     stdin_text=logging_ldif)


def install_master(host, collect_log=None):
    if collect_log:
        collect_log(host, '/var/log/ipaserver-install.log')
        collect_log(host, '/var/log/ipaclient-install.log')
        inst = host.domain.realm.replace('.', '-')
        collect_log(host, '/var/log/dirsrv/slapd-%s/errors' % inst)
        collect_log(host, '/var/log/dirsrv/slapd-%s/access' % inst)

    host.run_command(['ipa-server-install', '-U',
                      '-r', host.domain.name,
                      '-p', host.config.dirman_password,
                      '-a', host.config.admin_password,
                      '--setup-dns',
                      '--forwarder', host.config.dns_forwarder])

    enable_replication_debugging(host)


def install_replica(master, replica, collect_log=None):
    if collect_log:
        collect_log(replica, '/var/log/ipareplica-install.log')
        collect_log(replica, '/var/log/ipareplica-conncheck.log')

    master.run_command(['ipa-replica-prepare',
                        '-p', replica.config.dirman_password,
                        '--ip-address', replica.ip,
                        replica.hostname])
    replica_bundle = master.get_file_contents(
        '/var/lib/ipa/replica-info-%s.gpg' % replica.hostname)
    replica_filename = os.path.join(replica.config.test_dir,
                                    'replica-info.gpg')
    replica.put_file_contents(replica_filename, replica_bundle)
    replica.run_command(['ipa-replica-install', '-U',
                         '-p', replica.config.dirman_password,
                         '-w', replica.config.admin_password,
                         '--ip-address', replica.ip,
                         replica_filename])

    enable_replication_debugging(replica)


def connect_replica(master, replica=None):
    if replica is None:
        args = [replica.hostname, master.hostname]
    else:
        args = [master.hostname]
    replica.run_command(['ipa-replica-manage', 'connect'] + args)
