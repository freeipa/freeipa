#
# Copyright (C) 2017  FreeIPA Contributors.  See COPYING for license
#
from __future__ import absolute_import

import binascii
import os
import psutil
import re
import subprocess
import textwrap

import pytest

from unittest.mock import patch, mock_open

from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.admintool import ScriptError
from ipaserver.install import installutils
from ipaserver.install import ipa_backup
from ipaserver.install import ipa_restore


GPG_GENKEY = textwrap.dedent("""
%echo Generating a standard key
Key-Type: RSA
Key-Length: 2048
Name-Real: IPA Backup
Name-Comment: IPA Backup
Name-Email: root@example.com
Expire-Date: 0
Passphrase: {passphrase}
%commit
%echo done
""")


@pytest.fixture
def gpgkey(request, tempdir):
    passphrase = "Secret123"
    gnupghome = os.path.join(tempdir, "gnupg")
    os.makedirs(gnupghome, 0o700)
    # provide clean env for gpg test
    env = os.environ.copy()
    orig_gnupghome = env.get('GNUPGHOME')
    env['GNUPGHOME'] = gnupghome
    env['LC_ALL'] = 'C.UTF-8'
    env['LANGUAGE'] = 'C'
    devnull = open(os.devnull, 'w')

    # allow passing passphrases to agent
    with open(os.path.join(gnupghome, "gpg-agent.conf"), 'w') as f:
        f.write("verbose\n")
        f.write("allow-preset-passphrase\n")

    # daemonize agent (detach from the console and run in the background)
    subprocess.run(
        [paths.SYSTEMD_RUN, '--service-type=forking',
         '--setenv=GNUPGHOME={}'.format(gnupghome),
         '--setenv=LC_ALL=C.UTF-8',
         '--setenv=LANGUAGE=C',
         '--unit=gpg-agent', paths.GPG_AGENT, '--daemon', '--batch'],
        check=True,
        env=env,
    )

    def fin():
        subprocess.run(
            [paths.SYSTEMCTL, 'stop', 'gpg-agent'],
            check=True,
            env=env,
        )
        if orig_gnupghome is not None:
            os.environ['GNUPGHOME'] = orig_gnupghome
        else:
            os.environ.pop('GNUPGHOME', None)

    request.addfinalizer(fin)

    # create public / private key pair
    keygen = os.path.join(gnupghome, 'keygen')
    with open(keygen, 'w') as f:
        f.write(GPG_GENKEY.format(passphrase=passphrase))
    subprocess.check_call(
        [paths.GPG2, '--batch', '--gen-key', keygen],
        env=env, stdout=devnull, stderr=devnull
    )

    # get keygrip of private key
    out = subprocess.check_output(
        [paths.GPG2, "--list-secret-keys", "--with-keygrip"],
        env=env, stderr=subprocess.STDOUT
    )
    mo = re.search("Keygrip = ([A-Z0-9]{32,})", out.decode('utf-8'))
    if mo is None:
        raise ValueError(out.decode('utf-8'))
    keygrip = mo.group(1)

    # unlock private key
    cmd = "PRESET_PASSPHRASE {} -1 {}".format(
        keygrip,
        binascii.hexlify(passphrase.encode('utf-8')).decode('utf-8')
    )
    subprocess.check_call(
        [paths.GPG_CONNECT_AGENT, cmd, "/bye"],
        env=env, stdout=devnull, stderr=devnull
    )

    # set env for the rest of the progress
    os.environ['GNUPGHOME'] = gnupghome


def test_gpg_encrypt(tempdir):
    src = os.path.join(tempdir, "data.txt")
    encrypted = os.path.join(tempdir, "data.gpg")
    decrypted = os.path.join(tempdir, "data.out")
    passwd = 'Secret123'
    payload = 'Dummy text\n'

    with open(src, 'w') as f:
        f.write(payload)

    installutils.encrypt_file(src, encrypted, password=passwd)
    assert os.path.isfile(encrypted)

    installutils.decrypt_file(encrypted, decrypted, password=passwd)
    assert os.path.isfile(decrypted)
    with open(decrypted) as f:
        assert f.read() == payload

    with pytest.raises(ipautil.CalledProcessError):
        installutils.decrypt_file(encrypted, decrypted, password='invalid')


def test_gpg_asymmetric(tempdir, gpgkey):
    src = os.path.join(tempdir, "asymmetric.txt")
    encrypted = src + ".gpg"
    payload = 'Dummy text\n'

    with open(src, 'w') as f:
        f.write(payload)

    ipa_backup.encrypt_file(src, remove_original=True)
    assert os.path.isfile(encrypted)
    assert not os.path.exists(src)

    ipa_restore.decrypt_file(tempdir, encrypted)
    assert os.path.isfile(src)
    with open(src) as f:
        assert f.read() == payload


@pytest.mark.parametrize(
    "platform, expected",
    [
        ("fedora", "fedora"),
        ("fedora_container", "fedora"),
        ("fedora_containers", "fedora_containers"),
        ("fedoracontainer", "fedoracontainer"),
        ("rhel", "rhel"),
        ("rhel_container", "rhel"),
    ]
)
def test_get_current_platform(monkeypatch, platform, expected):
    monkeypatch.setattr(installutils.ipaplatform, "NAME", platform)
    assert installutils.get_current_platform() == expected


# The mock_exists in the following tests mocks that the cgroups
# files exist even in non-containers. The values are provided by
# mock_open_multi.


@patch('ipaserver.install.installutils.in_container')
@patch('os.path.exists')
def test_in_container_no_cgroup(mock_exists, mock_in_container):
    """
    In a container in a container without cgroups, can't detect RAM
    """
    mock_in_container.return_value = True
    mock_exists.side_effect = [False, False]
    with pytest.raises(ScriptError):
        installutils.check_available_memory(False)


def mock_open_multi(*contents):
    """Mock opening multiple files.

       For our purposes the first read is limit, second is usage.

       Note: this overrides *all* opens so if you use pdb then you will
             need to extend the list by 2.
    """
    mock_files = [
        mock_open(read_data=content).return_value for content in contents
    ]
    mock_multi = mock_open()
    mock_multi.side_effect = mock_files

    return mock_multi


RAM_OK = str(1800 * 1000 * 1000)
RAM_CA_USED = str(150 * 1000 * 1000)
RAM_MOSTLY_USED = str(1500 * 1000 * 1000)
RAM_NOT_OK = str(10 * 1000 * 1000)


@patch('ipaserver.install.installutils.in_container')
@patch('builtins.open', mock_open_multi(RAM_NOT_OK, "0"))
@patch('os.path.exists')
def test_in_container_insufficient_ram(mock_exists, mock_in_container):
    """In a container with insufficient RAM and zero used"""
    mock_in_container.return_value = True
    mock_exists.side_effect = [True, True]

    with pytest.raises(ScriptError):
        installutils.check_available_memory(True)


@patch('ipaserver.install.installutils.in_container')
@patch('builtins.open', mock_open_multi(RAM_OK, RAM_CA_USED))
@patch('os.path.exists')
def test_in_container_ram_ok_no_ca(mock_exists, mock_in_container):
    """In a container with just enough RAM to install w/o a CA"""
    mock_in_container.return_value = True
    mock_exists.side_effect = [True, True]

    installutils.check_available_memory(False)


@patch('ipaserver.install.installutils.in_container')
@patch('builtins.open', mock_open_multi(RAM_OK, RAM_MOSTLY_USED))
@patch('os.path.exists')
def test_in_container_insufficient_ram_with_ca(mock_exists, mock_in_container):
    """In a container and just miss the minimum RAM required"""
    mock_in_container.return_value = True
    mock_exists.side_effect = [True, True]

    with pytest.raises(ScriptError):
        installutils.check_available_memory(True)


@patch('ipaserver.install.installutils.in_container')
@patch('psutil.virtual_memory')
def test_not_container_insufficient_ram_with_ca(mock_psutil, mock_in_container):
    """Not a container and insufficient RAM"""
    mock_in_container.return_value = False
    fake_memory = psutil._pslinux.svmem
    fake_memory.available = int(RAM_NOT_OK)
    mock_psutil.return_value = fake_memory

    with pytest.raises(ScriptError):
        installutils.check_available_memory(True)


@patch('ipaserver.install.installutils.in_container')
@patch('psutil.virtual_memory')
def test_not_container_ram_ok(mock_psutil, mock_in_container):
    """Not a container and sufficient RAM"""
    mock_in_container.return_value = False
    fake_memory = psutil._pslinux.svmem
    fake_memory.available = int(RAM_OK)
    mock_psutil.return_value = fake_memory

    installutils.check_available_memory(True)
