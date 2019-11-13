#
# Copyright (C) 2017  FreeIPA Contributors.  See COPYING for license
#
from __future__ import absolute_import

import binascii
import os
import re
import subprocess
import textwrap

import pytest

from ipaplatform.paths import paths
from ipapython import ipautil
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
    subprocess.Popen(
        [paths.GPG_AGENT, '--batch', '--daemon'],
        env=env, stdout=devnull, stderr=devnull
    )

    def fin():
        if orig_gnupghome is not None:
            os.environ['GNUPGHOME'] = orig_gnupghome
        else:
            os.environ.pop('GNUPGHOME', None)
        subprocess.run(
            [paths.GPG_CONF, '--kill', 'all'],
            check=True,
            env=env,
        )

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
