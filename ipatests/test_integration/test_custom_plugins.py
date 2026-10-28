#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#
"""Tests for custom plugins
"""
from __future__ import absolute_import

import logging
import os
import site

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

logger = logging.getLogger(__name__)


class TestCustomPlugin(IntegrationTest):
    """
    Tests for user-generated custom plugins
    """
    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

    def test_add_user_objectclass_with_custom_schema(self):
        """Test adding a custom userclass to new users

           Attributes should not be case-sensitive.

           Based heavily on the custom plugin and schema at
           https://github.com/Brandeis-CS-Systems/idm-unet-id-plugin
        """
        schema = (
            "dn: cn=schema\n"
            "attributeTypes: ( 2.16.840.1.113730.3.8.24.1.1 NAME 'customID' "
            "EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX "
            "1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'Testing' )\n"
            "objectClasses: ( 2.16.840.1.113730.3.8.24.2.1 NAME 'customUser' "
            "DESC 'custom user ID objectClass' AUXILIARY MAY ( customID ) "
            "X-ORIGIN 'Testing' )\n"
        )
        plugin = (
            "from ipalib.parameters import Str\n\n"
            "from ipaserver.plugins.user import user\n\n"
            "if 'customUser' not in user.possible_objectclasses:\n"
            "    user.possible_objectclasses.append('customUser')\n"
            "customuser_attributes = ['customID']\n"
            "user.default_attributes.extend(customuser_attributes)\n"
            "takes_params = (\n"
            "    Str('customid?',\n"
            "        cli_name='customid',\n"
            "        maxlength=64,\n"
            "        label='User custom uid'),\n"
            ")\n"
            "user.takes_params += takes_params\n"
        )

        tasks.kinit_admin(self.master)
        self.master.put_file_contents('/tmp/schema.ldif', schema)
        self.master.run_command(['ipa-ldap-updater', '-S', '/tmp/schema.ldif'])
        self.master.put_file_contents('/tmp/schema.ldif', schema)

        site_packages = site.getsitepackages()[-1]
        site_file = os.path.join(
            site_packages, "ipaserver", "plugins", "test.py"
        )

        self.master.put_file_contents(site_file, plugin)

        self.master.run_command(['ipactl', 'restart'])

        self.master.run_command([
            'ipa', 'config-mod',
            '--userobjectclasses', 'top',
            '--userobjectclasses', 'person',
            '--userobjectclasses', 'organizationalperson',
            '--userobjectclasses', 'inetorgperson',
            '--userobjectclasses', 'inetuser',
            '--userobjectclasses', 'posixaccount',
            '--userobjectclasses', 'krbprincipalaux',
            '--userobjectclasses', 'krbticketpolicyaux',
            '--userobjectclasses', 'ipaobject',
            '--userobjectclasses', 'ipasshuser',
            '--userobjectclasses', 'customuser',
        ])

        self.master.run_command(['rm', '-f', site_file])
