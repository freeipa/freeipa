#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
"""Misc test for 'ipa' CLI regressions
"""
from __future__ import print_function

import re
from tempfile import NamedTemporaryFile
import textwrap
import time

from ipaplatform.paths import paths

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_plugins.integration import tasks


class TestIPACommand(IntegrationTest):
    """
    A lot of commands can be executed against a single IPA installation
    so provide a generic class to execute one-off commands that need to be
    tested without having to fire up a full server to run one command.
    """
    topology = 'line'

    def test_ldapmodify_password_issue7601(self):
        user = 'ipauser'
        original_passwd = 'Secret123'
        new_passwd = 'userPasswd123'
        new_passwd2 = 'mynewPwd123'
        master = self.master
        base_dn = str(master.domain.basedn)  # pylint: disable=no-member

        # Create a user with a password
        tasks.kinit_admin(master)
        add_password_stdin_text = "{pwd}\n{pwd}".format(pwd=original_passwd)
        master.run_command(['ipa', 'user-add', user,
                            '--first', user,
                            '--last', user,
                            '--password'],
                           stdin_text=add_password_stdin_text)
        # kinit as that user in order to modify the pwd
        user_kinit_stdin_text = "{old}\n%{new}\n%{new}\n".format(
            old=original_passwd,
            new=original_passwd)
        master.run_command(['kinit', user], stdin_text=user_kinit_stdin_text)
        # Retrieve krblastpwdchange and krbpasswordexpiration
        search_cmd = [
            'ldapsearch', '-x',
            '-D', 'cn=directory manager',
            '-w', master.config.dirman_password,
            '-s', 'base',
            '-b', 'uid={user},cn=users,cn=accounts,{base_dn}'.format(
                user=user, base_dn=base_dn),
            '-o', 'ldif-wrap=no',
            '-LLL',
            'krblastpwdchange',
            'krbpasswordexpiration']
        output = master.run_command(search_cmd).stdout_text.lower()

        # extract krblastpwdchange and krbpasswordexpiration
        krbchg_pattern = 'krblastpwdchange: (.+)\n'
        krbexp_pattern = 'krbpasswordexpiration: (.+)\n'
        krblastpwdchange = re.findall(krbchg_pattern, output)[0]
        krbexp = re.findall(krbexp_pattern, output)[0]

        # sleep 1 sec (krblastpwdchange and krbpasswordexpiration have at most
        # a 1s precision)
        time.sleep(1)
        # perform ldapmodify on userpassword as dir mgr
        mod = NamedTemporaryFile()
        ldif_file = mod.name
        entry_ldif = textwrap.dedent("""
            dn: uid={user},cn=users,cn=accounts,{base_dn}
            changetype: modify
            replace: userpassword
            userpassword: {new_passwd}
        """).format(
            user=user,
            base_dn=base_dn,
            new_passwd=new_passwd)
        master.put_file_contents(ldif_file, entry_ldif)
        arg = ['ldapmodify',
               '-h', master.hostname,
               '-p', '389', '-D',
               str(master.config.dirman_dn),   # pylint: disable=no-member
               '-w', master.config.dirman_password,
               '-f', ldif_file]
        master.run_command(arg)

        # Test new password with kinit
        master.run_command(['kinit', user], stdin_text=new_passwd)
        # Retrieve krblastpwdchange and krbpasswordexpiration
        output = master.run_command(search_cmd).stdout_text.lower()
        # extract krblastpwdchange and krbpasswordexpiration
        newkrblastpwdchange = re.findall(krbchg_pattern, output)[0]
        newkrbexp = re.findall(krbexp_pattern, output)[0]

        # both should have changed
        assert newkrblastpwdchange != krblastpwdchange
        assert newkrbexp != krbexp

        # Now test passwd modif with ldappasswd
        time.sleep(1)
        master.run_command([
            paths.LDAPPASSWD,
            '-D', str(master.config.dirman_dn),   # pylint: disable=no-member
            '-w', master.config.dirman_password,
            '-a', new_passwd,
            '-s', new_passwd2,
            '-x', '-ZZ',
            '-H', 'ldap://{hostname}'.format(hostname=master.hostname),
            'uid={user},cn=users,cn=accounts,{base_dn}'.format(
                user=user, base_dn=base_dn)]
        )
        # Test new password with kinit
        master.run_command(['kinit', user], stdin_text=new_passwd2)
        # Retrieve krblastpwdchange and krbpasswordexpiration
        output = master.run_command(search_cmd).stdout_text.lower()
        # extract krblastpwdchange and krbpasswordexpiration
        newkrblastpwdchange2 = re.findall(krbchg_pattern, output)[0]
        newkrbexp2 = re.findall(krbexp_pattern, output)[0]

        # both should have changed
        assert newkrblastpwdchange != newkrblastpwdchange2
        assert newkrbexp != newkrbexp2
