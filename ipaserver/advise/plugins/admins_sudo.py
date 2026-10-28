#
# Copyright (C) 2018 FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

from ipalib.plugable import Registry
from ipaserver.advise.base import Advice

register = Registry()


@register()
class enable_admins_sudo(Advice):
    """
    Configures HBAC and SUDO for members of the admins group
    """

    description = ("Instructions for enabling HBAC and unauthenticated "
                   "SUDO for members of the admins group.")

    def check_ccache_not_empty(self):
        self.log.comment('Check whether the credential cache is not empty')
        self.log.exit_on_failed_command(
            'klist',
            [
                "Credential cache is empty",
                'Use kinit as privileged user to obtain Kerberos credentials'
            ])

    def create_hbac_rule(self):
        self.log.comment('Create the HBAC rule for sudo')
        self.log.exit_on_failed_command(
            'err=$(ipa hbacrule-add --hostcat=all --desc "Allow admins '
            'to run sudo on all hosts" admins_sudo 2>&1)',
            ['Failed to add hbac rule: ${err}'])
        self.log.command('ipa hbacrule-add-user --groups=admins admins_sudo')
        self.log.command(
            'ipa hbacrule-add-service --hbacsvcs=sudo admins_sudo'
        )

    def create_sudo_rule(self):
        self.log.comment('Create the SUDO rule for the admins group')
        self.log.exit_on_failed_command(
            'err=$(ipa sudorule-add --desc "Allow admins to run any command '
            'on any host" --hostcat=all --cmdcat=all admins_all '
            '2>&1)',
            ['Failed to add sudo rule: ${err}'])
        self.log.command('ipa sudorule-add-user --groups=admins admins_all')

    def get_info(self):
        self.check_ccache_not_empty()
        with self.log.if_branch(
                'ipa hbacrule-show admins_sudo > /dev/null 2>&1'):
            self.log.command('echo HBAC rule admins_sudo already exists')
        with self.log.else_branch():
            self.create_hbac_rule()

        with self.log.if_branch(
                'ipa sudorule-show admins_all > /dev/null 2>&1'):
            self.log.command('echo SUDO rule admins_all already exists')
        with self.log.else_branch():
            self.create_sudo_rule()
