import re
import logging
import json

from ipatests.util import wait_for

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def run_powershell_script(host, script, raiseonerr=True, json_output=False):
    if json_output:
        script += '| ConvertTo-Json'
    result = host.run_command(
        ['powershell', '-c', script], raiseonerr=raiseonerr)
    if json_output:
        result.json = json.loads(result.stdout_text)
    return result


def create_temp_dir(host):
    path = run_powershell_script(
        host, 'New-TemporaryFile | Select-Object -Property "FullName"',
        json_output=True).json['FullName']
    run_powershell_script(host, f'Remove-Item "{path}"')
    run_powershell_script(host, f'mkdir "{path}"')
    return path


def reboot(host, timeout=600, test_cb=None):
    """Reboot Windows and wait until it has started.

    :param host: Host instance
    :param timeout: interval to wait for Windows to start before raising
           Exception
    :param test_cb: optional callback function to perform additional checks to
           verify Windows is fully operational.
    """
    def get_system_start_time():
        script = ('(Get-WmiObject -ClassName Win32_OperatingSystem)'
                  '.LastBootUpTime')
        start_time = run_powershell_script(host, script).stdout_text.strip()
        assert re.match(r'^\d+\.\d+\+000$', start_time)
        return start_time

    def windows_restarted():
        try:
            system_start_time = get_system_start_time()
        except Exception:
            logging.debug(
                'SSH connection failed, Windows is not fully loaded yet')
            return False
        return (system_start_time != initial_system_start_time
                and (test_cb is None or test_cb()))

    initial_system_start_time = get_system_start_time()
    host.run_command(['shutdown', '/r', '/t', '0'])

    if not wait_for(windows_restarted, timeout):
        raise Exception('Windows host failed to start up')


def backup_group_policies(host):
    backup_dir = create_temp_dir(host)
    run_powershell_script(host, f'Backup-GPO -All -Path "{backup_dir}"')
    return backup_dir


def restore_group_policies(host, backup_dir):
    run_powershell_script(host, f'Restore-GPO -All -Path "{backup_dir}"')
    run_powershell_script(host, f'Remove-Item -Recurse -Force "{backup_dir}"')


def set_group_policy(host, gpo_name, reg_key,
                     reg_value_name, reg_value_type, reg_value):
    """Configure registry-based group policy setting.

    :param host: Host object for Windows AD DC
    :param gpo_name: Common policies are "Default Domain Policy" and
           "Default Domain Controllers Policy"
    :param reg_key: Registry key starting from HKLM or HKCU
    :param reg_value_name: registry value name
    :param reg_value_type: registry value data type, one of
           String, ExpandString, Binary, DWord, MultiString, QWord
    :param reg_value: registry value data
    """
    if isinstance(reg_value, str):
        reg_value = f'"{reg_value}"'
    run_powershell_script(
        host, f'Set-GPRegistryValue '
              f'-Name "{gpo_name}" '
              f'-Key "{reg_key}" '
              f'-ValueName "{reg_value_name}" '
              f'-Type {reg_value_type} '
              f'-Value {reg_value}')


def get_registry_value(host, key, value_name):
    res = run_powershell_script(
        host,
        f'Get-ItemProperty -Path "Registry::{key}" '
        f'| Select-Object -Property "{value_name}"',
        json_output=True)
    return res.json[value_name]
