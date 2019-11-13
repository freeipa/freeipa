#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""FIPS testing helpers

Based on userspace FIPS mode by Ondrej Moris.

Userspace FIPS mode fakes a Kernel in FIPS enforcing mode. User space
programs behave like the Kernel was booted in FIPS enforcing mode. Kernel
space code still runs in standard mode.
"""
import os
from ipaplatform.paths import paths

FIPS_OVERLAY_DIR = "/var/tmp/userspace-fips"
FIPS_OVERLAY = os.path.join(FIPS_OVERLAY_DIR, "fips_enabled")
SYSTEM_FIPS = "/etc/system-fips"


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


def enable_userspace_fips(host):
    # create /etc/system-fips
    host.put_file_contents(SYSTEM_FIPS, "# userspace fips\n")
    # fake Kernel FIPS mode with bind mount
    host.run_command(["mkdir", "-p", FIPS_OVERLAY_DIR])
    host.put_file_contents(FIPS_OVERLAY, "1\n")
    host.run_command(
        ["mount", "--bind", FIPS_OVERLAY, paths.PROC_FIPS_ENABLED]
    )
    # set crypto policy to FIPS mode
    host.run_command(["update-crypto-policies", "--show"])
    host.run_command(["update-crypto-policies", "--set", "FIPS"])
    # sanity check
    assert is_fips_enabled(host)
    result = host.run_command(
        ["openssl", "md5", "/dev/null"], raiseonerr=False
    )
    assert result.returncode == 1
    assert "EVP_DigestInit_ex:disabled for FIPS" in result.stderr_text


def disable_userspace_fips(host):
    host.run_command(["rm", "-f", SYSTEM_FIPS])
    host.run_command(["update-crypto-policies", "--set", "DEFAULT"])
    result = host.run_command(
        ["umount", paths.PROC_FIPS_ENABLED], raiseonerr=False
    )
    host.run_command(["rm", "-rf", FIPS_OVERLAY_DIR])
    if result.returncode != 0:
        raise RuntimeError(result.stderr_text)

    # sanity check
    assert not is_fips_enabled(host)
    host.run_command(["openssl", "md5", "/dev/null"])
