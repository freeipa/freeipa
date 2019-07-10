#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

import glob

from ipaplatform.paths import paths

from ipatests.test_integration.base import IntegrationTest

AUTHORIZATION_FILE = '/var/lib/pki/pki-tomcat/ca/conf/flatfile.txt'
CERTMONGER_CONFIG = '/etc/sysconfig/certmonger'


def enable_SCEP(host):
    """Enable SCEP in Certificate Authority's CS.cfg
    by setting ca.scep.enable=true
    """
    content = host.get_file_contents(paths.CA_CS_CFG_PATH,
                                     encoding='utf-8')
    new_lines = []
    input_line = "auths.instance.flatFileAuth.deferOnFailure=false"
    for line in content.split('\n'):
        if line.startswith('auths.instance.flatFileAuth.deferOnFailure'):
            new_lines.append(input_line)
        elif line.startswith('ca.scep.enable'):
            new_lines.append("ca.scep.enable=true")
        else:
            new_lines.append(line)
    host.put_file_contents(paths.CA_CS_CFG_PATH, '\n'.join(new_lines))


def add_local_ip_to_authfile(host):
    """Add the local IP to the authorization file,
    /var/lib/pki/pki-tomcat/ca/conf/flatfile.txt
    """
    content = host.get_file_contents(AUTHORIZATION_FILE,
                                     encoding='utf-8')
    new_lines = []
    for line in content.split('\n'):
        if line.startswith('#UID:'):
            new_lines.append("UID:%s" % host.ip)
        elif line.startswith("#PWD:"):
            new_lines.append("PWD:1234")
        else:
            new_lines.append(line)
    host.put_file_contents(AUTHORIZATION_FILE, '\n'.join(new_lines))


def edit_certmonger_config(host):
    """Increase certmonger debug output by setting
    OPTS=-d 3 in /etc/sysconfig/certmonger
    """
    content = host.get_file_contents(CERTMONGER_CONFIG,
                                     encoding='utf-8')
    new_lines = []
    for line in content.split('\n'):
        if line.startswith('OPTS='):
            new_lines.append("OPTS=-d 3")
        else:
            new_lines.append(line)
    host.put_file_contents(CERTMONGER_CONFIG, '\n'.join(new_lines))


def set_scep_cipher(host):
    """hard code the default SCEP cipher to DES3 since there
    is no CLI to do this by adding scep_cipher=DES3
    """
    input_file = None
    cmd_output = host.run_command([
        'find', '/var/lib/certmonger/cas', '-type', 'f'
    ])
    for infile in cmd_output.stdout_text:
        with open(infile) as lines:
            for line in lines:
                if 'scep' in line:
                    input_file = infile
    content = host.get_file_contents(input_file, encoding='utf-8')
    content = '\n'.join([content, 'scep_cipher=DES3'])
    print(content)
    host.put_file_contents(input_file, content)


class TestInsecureCryptoSCEP(IntegrationTest):
    """This test checks that certmonger does not support
    insecure cryptography for SCEP enrollment
    """
    topology = 'star'

    def test_insecurecrypto_forscep(self):
        """Test to check that certmonger does not support
        insecure cryptography for SCEP enrollment

        Steps:
        1. enable SCEP in CA's CS.cfg
        2. Add the local IP to the authorization file
        3. Increase certmonger debug output
        4. Add the SCEP CA to certmonger
        5. Hard code the default SCEP cipher to DES3
           since there is no CLI to do this
        6. Try a request making changes to certmonger
        7.
        8.
        """
        # Stop CA
        self.master.run_command([
            'systemctl', 'stop', 'pki-tomcatd@pki-tomcat.service'
        ])
        # enable SCEP
        enable_SCEP(self.master)
        # Start CA
        self.master.run_command([
            'systemctl', 'start', 'pki-tomcatd@pki-tomcat.service'
        ])
        # Add local IP to authorization file
        add_local_ip_to_authfile(self.master)
        # Restart CA
        self.master.run_command([
            'systemctl', 'restart', 'pki-tomcatd@pki-tomcat.service'
        ])
        # increase certmonger debug output
        edit_certmonger_config(self.master)
        # restart certmonger
        self.master.run_command([
            'systemctl', 'restart', 'certmonger'
        ])
        # Add the SCEP CA to certmonger
        url_to_hit = 'http://%s:8080/ca/cgi-bin/pkiclient.exe' \
                     % self.master.hostname
        cmd_output = self.master.run_command([
            'getcert', 'add-scep-ca', '-c', 'scep', '-u',
            url_to_hit, '-I', paths.IPA_CA_CRT
        ])
        assert 'New CA "scep" added.' in cmd_output.stdout_text
        # stop certmonger
        self.master.run_command([
            'systemctl', 'stop', 'certmonger'
        ])
        # hard code the default SCEP cipher to DES3 since there
        # is no CLI to do this
        set_scep_cipher(self.master)
        # stop certmonger
        self.master.run_command([
            'systemctl', 'start', 'certmonger'
        ])
        # try a request making changes to certmonger
        cmd_output = self.master.run_command([
            'getcert', 'request', '-c', 'scep', '-k',
            '/etc/pki/tls/private/scep.key', '-f',
            '/etc/pki/tls/certs/scep.crt',
            '-g', '2048', '-L', '1234'
        ])

        assert 'New signing request' in cmd_output.stdout_text

        cmd_output = self.master.run_command([
            'getcert', 'list', '-f', '/etc/pki/tls/certs/scep.crt'
        ])
        assert_str = 'ca-error: Error reading request, expected PKCS7 data.'

        assert assert_str in cmd_output.stdout_text
        assert 'status: NEED_SCEP_DATA' in cmd_output.stdout_text
