#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""FIPS testing helpers

Based on userspace FIPS mode by Ondrej Moris.

Userspace FIPS mode fakes a Kernel in FIPS enforcing mode. User space
programs behave like the Kernel was booted in FIPS enforcing mode. Kernel
space code still runs in standard mode.
"""
from ipaplatform.paths import paths


def is_fips_enabled(host):
    """Check if host has """
    result = host.run_command(
        ["cat", paths.PROC_FIPS_ENABLED], raiseonerr=False
    )
    if result.returncode == 1:
        # FIPS mode not available
        return None
    elif result.returncode == 0:
        return result.stdout_text.strip() == "1"
    else:
        raise RuntimeError(result.stderr_text)


def enable_crypto_subpolicy(host, subpolicy):
    result = host.run_command(["update-crypto-policies", "--show"])
    policy = result.stdout_text.strip() + ":" + subpolicy
    host.run_command(["update-crypto-policies", "--set", policy])
