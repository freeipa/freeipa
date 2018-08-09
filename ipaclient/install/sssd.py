#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from ipalib.install import service
from ipalib.install.service import enroll_only
from ipapython.install.core import group, knob


@group
class SSSDInstallInterface(service.ServiceInstallInterface):
    description = "SSSD"

    fixed_primary = knob(
        None,
        description="Configure sssd to use fixed server as primary IPA server",
    )
    fixed_primary = enroll_only(fixed_primary)

    permit = knob(
        None,
        description="disable access rules by default, permit all access.",
    )
    permit = enroll_only(permit)

    enable_dns_updates = knob(
        None,
        description="Configures the machine to attempt dns updates when the "
                    "ip address changes.",
    )
    enable_dns_updates = enroll_only(enable_dns_updates)

    no_krb5_offline_passwords = knob(
        None,
        description="Configure SSSD not to store user password when the "
                    "server is offline",
    )
    no_krb5_offline_passwords = enroll_only(no_krb5_offline_passwords)

    preserve_sssd = knob(
        None,
        description="Preserve old SSSD configuration if possible",
    )
    preserve_sssd = enroll_only(preserve_sssd)

    no_sssd = False
