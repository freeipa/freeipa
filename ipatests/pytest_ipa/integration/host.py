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

"""Host class for integration testing"""
import base64
import ipaddress
import re
import subprocess
import tempfile

import ldap
import pytest_multihost.host

from ipaplatform.paths import paths
from ipapython import ipaldap

from .fips import is_fips_enabled
from .transport import IPAOpenSSHTransport
from .resolver import resolver

FIPS_NOISE_RE = re.compile(br"FIPS mode initialized\r?\n?")


class LDAPClientWithoutCertCheck(ipaldap.LDAPClient):
    """Adds an option to disable certificate check for TLS connection

    To disable certificate validity check create client with added option
    no_certificate_check:
    client = LDAPClientWithoutCertCheck(..., no_certificate_check=True)
    """
    def __init__(self, *args, **kwargs):
        self._no_certificate_check = kwargs.pop(
            'no_certificate_check', False)
        super(LDAPClientWithoutCertCheck, self).__init__(*args, **kwargs)

    def _connect(self):
        if (self._start_tls and self.protocol == 'ldap' and
                self._no_certificate_check):
            with self.error_handler():
                conn = ipaldap.ldap_initialize(
                    self.ldap_uri, cacertfile=self._cacert)
                conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT,
                                ldap.OPT_X_TLS_NEVER)
                conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
                conn.start_tls_s()
                return conn
        else:
            return super(LDAPClientWithoutCertCheck, self)._connect()


class Host(pytest_multihost.host.Host):
    """Representation of a remote IPA host"""

    transport_class = IPAOpenSSHTransport

    def __init__(self, domain, hostname, role, ip=None,
                 external_hostname=None, username=None, password=None,
                 test_dir=None, host_type=None):
        super().__init__(
            domain, hostname, role, ip=ip,
            external_hostname=external_hostname, username=username,
            password=password, test_dir=test_dir, host_type=host_type
        )
        self._fips_mode = None
        self._userspace_fips = False
        self.resolver = resolver(self)

    @property
    def is_fips_mode(self):
        """Check and cache if a system is in FIPS mode
        """
        if self._fips_mode is None:
            self._fips_mode = is_fips_enabled(self)
        return self._fips_mode

    @staticmethod
    def _make_host(domain, hostname, role, ip, external_hostname):
        # We need to determine the type of the host, this depends on the domain
        # type, as we assume all Unix machines are in the Unix domain and
        # all Windows machine in a AD domain

        if domain.type == 'AD':
            cls = WinHost
        else:
            cls = Host

        return cls(
            domain,
            hostname,
            role,
            ip=ip,
            external_hostname=external_hostname
        )

    def ldap_connect(self):
        """Return an LDAPClient authenticated to this host as directory manager
        """
        self.log.info('Connecting to LDAP at %s', self.external_hostname)
        # get IPA CA cert to establish a secure connection
        cacert = self.get_file_contents(paths.IPA_CA_CRT)
        with tempfile.NamedTemporaryFile() as f:
            f.write(cacert)
            f.flush()

            hostnames_mismatch = self.hostname != self.external_hostname
            conn = LDAPClientWithoutCertCheck.from_hostname_secure(
                self.external_hostname,
                cacert=f.name,
                no_certificate_check=hostnames_mismatch)
            binddn = self.config.dirman_dn
            self.log.info('LDAP bind as %s', binddn)
            conn.simple_bind(binddn, self.config.dirman_password)

            # The CA cert file  has been loaded into the SSL_CTX and is no
            # longer required.

        return conn

    @classmethod
    def from_env(cls, env, domain, hostname, role, index, domain_index):
        from ipatests.pytest_ipa.integration.env_config import host_from_env
        return host_from_env(env, domain, hostname, role, index, domain_index)

    def to_env(self, **kwargs):
        from ipatests.pytest_ipa.integration.env_config import host_to_env
        return host_to_env(self, **kwargs)

    def run_command(self, argv, set_env=True, stdin_text=None,
                    log_stdout=True, raiseonerr=True,
                    cwd=None, bg=False, encoding='utf-8', ok_returncode=0):
        """Wrapper around run_command to log stderr on raiseonerr=True

        :param ok_returncode: return code considered to be correct,
                              you can pass an integer or sequence of integers
        """
        result = super().run_command(
            argv, set_env=set_env, stdin_text=stdin_text,
            log_stdout=log_stdout, raiseonerr=False, cwd=cwd, bg=bg,
            encoding=encoding
        )
        # in FIPS mode SSH may print noise to stderr, remove the string
        # "FIPS mode initialized" + optional newline.
        result.stderr_bytes = FIPS_NOISE_RE.sub(b'', result.stderr_bytes)
        try:
            result_ok = result.returncode in ok_returncode
        except TypeError:
            result_ok = result.returncode == ok_returncode
        if not result_ok and raiseonerr:
            result.log.error('stderr: %s', result.stderr_text)
            raise subprocess.CalledProcessError(
                result.returncode, argv,
                result.stdout_text, result.stderr_text
            )
        else:
            return result

    def spawn_expect(self, argv, default_timeout=10, encoding='utf-8',
                     extra_ssh_options=None):
        """Run command on remote host using IpaTestExpect"""
        return self.transport.spawn_expect(argv, default_timeout, encoding,
                                           extra_ssh_options)


class WinHost(pytest_multihost.host.WinHost):
    """
    Representation of a remote Windows host.

    Active Directory operations that the tests need are methods of the AD
    host classes, so that a test does not care whether the AD domain
    controller is Windows (PowerShell, dnscmd) or Samba (samba-tool);
    SambaADHost has the same interface.
    """
    transport_class = IPAOpenSSHTransport
    ad_flavor = 'windows'

    def powershell(self, command, **kwargs):
        """Run a PowerShell command, quietly and without the IPA env"""
        kwargs.setdefault('set_env', False)
        return self.run_command(
            ['powershell', '-c',
             '$ProgressPreference = "SilentlyContinue"; ' + command],
            **kwargs)

    def dns_forwarder_add(self, zone, forwarder):
        """Make the AD DNS server forward queries for zone to forwarder"""
        self.run_command(['dnscmd', '/zoneadd', zone, '/Forwarder',
                          forwarder])

    def dns_forwarder_del(self, zone):
        self.run_command(['dnscmd', '/zonedelete', zone, '/f'])

    def group_add_member(self, group, user):
        self.powershell('Add-ADGroupMember -Identity "{}" -Members "{}"'
                        .format(group, user))

    def group_has_member(self, group, user):
        result = self.powershell(
            'Get-ADGroupMember -Identity "{}" | '
            'Where-Object {{$_.SamAccountName -eq "{}"}}'.format(group, user),
            raiseonerr=False)
        # the filter leaves only the user; still look for the name, so that
        # a listing of other members is never taken for a membership
        return re.search(r'(?im)^\s*SamAccountName\s*:\s*{}\s*$'.format(
            re.escape(user)), result.stdout_text) is not None

    def upn_suffix_add(self, suffix):
        self.powershell('Set-ADForest -Identity {} -UPNSuffixes @{{add="{}"}}'
                        .format(self.domain.name, suffix))

    def upn_suffix_del(self, suffix):
        self.powershell(
            'Set-ADForest -Identity {} -UPNSuffixes @{{Remove="{}"}}'
            .format(self.domain.name, suffix))

    def upn_suffixes(self):
        result = self.powershell(
            '(Get-ADForest -Identity {}).UPNSuffixes'.format(self.domain.name))
        return result.stdout_text.split()

    def user_set_upn(self, user, upn):
        self.powershell('Set-Aduser -UserPrincipalName {} -Identity {}'
                        .format(upn, user))

    def password_min_age_set(self, days, **kwargs):
        """Set the domain's minimum password age, in days"""
        self.powershell(
            'Set-ADDefaultDomainPasswordPolicy -Identity "{}" '
            '-MinPasswordAge {}.00:00:00'.format(self.domain.name, days),
            **kwargs)

    def user_reset_password(self, user, password, **kwargs):
        self.powershell(
            'Set-ADAccountPassword -Identity "{}" -Reset -NewPassword '
            '(ConvertTo-SecureString "{}" -AsPlainText -Force)'
            .format(user, password), **kwargs)

    def trust_local_side_create(self, remote_domain, secret,
                                external=False):
        """Create this side of an inbound forest trust with a shared secret

        `external` is for Samba, whose trust object has a type of its own;
        the Windows call below makes the same trust for both."""
        self.powershell(
            '[System.DirectoryServices.ActiveDirectory.Forest]'
            '::getCurrentForest()'
            '.CreateLocalSideOfTrustRelationship("{}", 1, "{}")'
            .format(remote_domain, secret))

    def trust_local_side_delete(self, remote_domain):
        self.powershell(
            '[System.DirectoryServices.ActiveDirectory.Forest]'
            '::getCurrentForest()'
            '.DeleteLocalSideOfTrustRelationship("{}")'.format(remote_domain))


# smb.conf of a Samba DC has one global `dns forwarder`. _FORWARDER_ADD keeps
# the value it replaces in a comment, once; _FORWARDER_DEL puts it back. The
# address is $1, never part of the script text; awk edits the file so that
# no value is read as a sed expression.
_SMB_CONF = '/etc/samba/smb.conf'
_FORWARDER_ADD = r'''
f=%(conf)s
grep -q '^# ipatests-forwarder: ' "$f" || {
    orig=$(sed -n -E \
        's/^[[:space:]]*dns forwarder[[:space:]]*=[[:space:]]*//p' \
        "$f" | head -n 1)
    awk -v o="${orig:-none}" '
        {print}
        /^\[global\]/ && !d {print "# ipatests-forwarder: " o; d=1}
    ' "$f" > "$f.new" && cat "$f.new" > "$f" && rm -f "$f.new"
}
if grep -qE '^[[:space:]]*dns forwarder[[:space:]]*=' "$f"; then
    awk -v v="$1" '
        /^[[:space:]]*dns forwarder[[:space:]]*=/ {
            print "\tdns forwarder = " v; next }
        {print}
    ' "$f" > "$f.new"
else
    awk -v v="$1" '
        {print}
        /^\[global\]/ && !d {print "\tdns forwarder = " v; d=1}
    ' "$f" > "$f.new"
fi &&
cat "$f.new" > "$f" && rm -f "$f.new" && systemctl restart samba
''' % {'conf': _SMB_CONF}
_FORWARDER_DEL = r'''
f=%(conf)s
orig=$(sed -n 's/^# ipatests-forwarder: //p' "$f" | head -n 1)
[ -n "$orig" ] || exit 0
awk -v o="$orig" '
    /^# ipatests-forwarder: / {next}
    /^[[:space:]]*dns forwarder[[:space:]]*=/ {
        if (o != "none") print "\tdns forwarder = " o
        next }
    {print}
' "$f" > "$f.new" &&
cat "$f.new" > "$f" && rm -f "$f.new" && systemctl restart samba
''' % {'conf': _SMB_CONF}


def _ldif_line(attr, value):
    """`attr: value` of an LDIF file, the value base64-encoded: it may hold
    anything but a line break, which would start another attribute"""
    if '\n' in value or '\r' in value:
        raise ValueError('{}: no line breaks in an LDIF value'.format(attr))
    return '{}:: {}\n'.format(attr, base64.b64encode(
        value.encode('utf-8')).decode('ascii'))


def _ldif_values(text, attr):
    """The values of `attr` in LDIF output, plain or base64"""
    values = []
    for line in text.splitlines():
        if line.startswith(attr + ':: '):
            values.append(base64.b64decode(
                line[len(attr) + 3:]).decode('utf-8'))
        elif line.startswith(attr + ': '):
            values.append(line[len(attr) + 2:].strip())
    return values


class SambaADHost(Host):
    """A Samba AD domain controller, driven with samba-tool and ldb tools.

    It has the interface of WinHost. What Samba cannot do is documented at
    the method: its internal DNS server has one global forwarder, not one
    per zone.
    """
    ad_flavor = 'samba'
    sam_ldb = '/var/lib/samba/private/sam.ldb'

    def run_command(self, argv, set_env=False, **kwargs):
        # a Samba DC has no IPA test environment (env.sh) to source
        return super().run_command(argv, set_env=set_env, **kwargs)

    @property
    def _basedn(self):
        return ','.join('DC=' + p for p in self.domain.name.split('.'))

    def _ldb(self, tool, *args, **kwargs):
        return self.run_command([tool, '-H', self.sam_ldb, *args], **kwargs)

    def _user_dn(self, user):
        result = self._ldb('ldbsearch', '-b', self._basedn,
                           '(sAMAccountName={})'.format(user), 'dn')
        dns = _ldif_values(result.stdout_text, 'dn')
        if not dns:
            raise ValueError('no user {} in {}'.format(
                user, self.domain.name))
        return dns[0]

    def dns_forwarder_add(self, zone, forwarder):
        """Forward to the forwarder: for every name not in this domain.

        The internal DNS server of Samba knows one forwarder, not one per
        zone, so the zone is not used. The value that was there is kept in
        a comment of smb.conf, once, for dns_forwarder_del(). The address
        is checked and passed as an argument, not put into the script.
        """
        ipaddress.ip_address(forwarder)
        self.run_command(['sh', '-c', _FORWARDER_ADD, 'sh', forwarder])

    def dns_forwarder_del(self, zone):
        self.run_command(['sh', '-c', _FORWARDER_DEL, 'sh'])

    def group_add_member(self, group, user):
        self.run_command(['samba-tool', 'group', 'addmembers', group, user])

    def group_has_member(self, group, user):
        result = self.run_command(
            ['samba-tool', 'group', 'listmembers', group], raiseonerr=False)
        return user.lower() in [
            m.strip().lower() for m in result.stdout_text.splitlines()]

    def _upn_suffixes_ldif(self, op, suffix):
        return ('dn: CN=Partitions,CN=Configuration,{}\n'
                'changetype: modify\n{}: uPNSuffixes\n{}'.format(
                    self._basedn, op, _ldif_line('uPNSuffixes', suffix)))

    def upn_suffix_add(self, suffix):
        self._ldb('ldbmodify', stdin_text=self._upn_suffixes_ldif(
            'add', suffix))

    def upn_suffix_del(self, suffix):
        self._ldb('ldbmodify', stdin_text=self._upn_suffixes_ldif(
            'delete', suffix))

    def upn_suffixes(self):
        result = self._ldb(
            'ldbsearch', '-b',
            'CN=Partitions,CN=Configuration,' + self._basedn,
            '-s', 'base', 'uPNSuffixes')
        return _ldif_values(result.stdout_text, 'uPNSuffixes')

    def user_set_upn(self, user, upn):
        upn_line = _ldif_line('userPrincipalName', upn)
        dn_line = _ldif_line('dn', self._user_dn(user))
        self._ldb('ldbmodify', stdin_text=''.join([
            dn_line, 'changetype: modify\nreplace: userPrincipalName\n',
            upn_line]))

    def password_min_age_set(self, days, **kwargs):
        self.run_command(['samba-tool', 'domain', 'passwordsettings', 'set',
                          '--min-pwd-age={}'.format(days)], **kwargs)

    def user_reset_password(self, user, password, **kwargs):
        # the new password is read from the terminal prompt (here: stdin),
        # not given in the arguments of a process that others can list
        self.run_command(['samba-tool', 'user', 'setpassword', user],
                         stdin_text='{0}\n{0}\n'.format(password), **kwargs)

    def trust_local_side_create(self, remote_domain, secret,
                                external=False):
        """Create this side of an incoming trust with a shared secret.

        The type has to be the one of the IPA side: `external` for
        `ipa trust-add --external=True`, else a forest trust. IPA cannot
        read the domain of a forest trust that it asked to be external.

        Unlike the .Net call used on Windows, samba-tool reads the remote
        domain from its DC: it needs the address and an administrator of
        the IPA domain. The last step, forest trust information of the
        remote domain, fails until the remote side of the trust exists, so
        the exit status is not used: the trust object is checked.

        The passwords go in on stdin: the administrator's one through the
        PASSWD variable that samba-tool reads, the trust secret at its
        prompts. Neither is an argument of a process.
        """
        remote = next(d for d in self.config.domains
                      if d.name == remote_domain)
        netbios = remote_domain.split('.')[0].upper()
        self.run_command(
            ['sh', '-c', 'IFS= read -r PASSWD && export PASSWD && exec "$@"',
             'sh', 'samba-tool', 'domain', 'trust', 'create', remote_domain,
             '--type={}'.format('external' if external else 'forest'),
             '--direction=incoming',
             '--create-location=local',
             '--ipaddress={}'.format(remote.master.ip),
             '-U', '{}\\{}'.format(netbios, self.config.admin_name)],
            stdin_text='{pw}\n{s}\n{s}\n'.format(
                pw=self.config.admin_password, s=secret),
            raiseonerr=False)
        trusts = self.run_command(['samba-tool', 'domain', 'trust', 'list'])
        names = [n.lower() for n in re.findall(r'Name\[([^\]]+)\]',
                                               trusts.stdout_text)]
        assert remote_domain.lower() in names, (
            'samba-tool did not create the trust to ' + remote_domain)

    def trust_local_side_delete(self, remote_domain):
        self.run_command(['samba-tool', 'domain', 'trust', 'delete',
                          remote_domain, '--delete-location=local'])
