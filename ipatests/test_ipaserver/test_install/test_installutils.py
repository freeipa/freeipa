#
# Copyright (C) 2017  FreeIPA Contributors.  See COPYING for license
#
from __future__ import absolute_import

import binascii
import os
import re
import subprocess
import shutil
import tempfile
import textwrap

import pytest

from ipaplatform.paths import paths
from ipapython import ipautil
from ipaserver.install import installutils
from ipaserver.install import ipa_backup
from ipaserver.install import ipa_restore

EXAMPLE_CONFIG = [
    'foo=1\n',
    'foobar=2\n',
]

WHITESPACE_CONFIG = [
    'foo 1\n',
    'foobar\t2\n',
]


@pytest.fixture
def tempdir(request):
    tempdir = tempfile.mkdtemp()

    def fin():
        shutil.rmtree(tempdir)

    request.addfinalizer(fin)
    return tempdir


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

    # run agent in background
    agent = subprocess.Popen(
        [paths.GPG_AGENT, '--batch', '--daemon'],
        env=env, stdout=devnull, stderr=devnull
    )

    def fin():
        if orig_gnupghome is not None:
            os.environ['GNUPGHOME'] = orig_gnupghome
        else:
            os.environ.pop('GNUPGHOME', None)
        agent.kill()
        agent.wait()

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


class test_set_directive_lines(object):
    def test_remove_directive(self):
        lines = installutils.set_directive_lines(
            False, '=', 'foo', None, EXAMPLE_CONFIG, comment="#")
        assert list(lines) == ['foobar=2\n']

    def test_add_directive(self):
        lines = installutils.set_directive_lines(
            False, '=', 'baz', '4', EXAMPLE_CONFIG, comment="#")
        assert list(lines) == ['foo=1\n', 'foobar=2\n', 'baz=4\n']

    def test_set_directive_does_not_clobber_suffix_key(self):
        lines = installutils.set_directive_lines(
            False, '=', 'foo', '3', EXAMPLE_CONFIG, comment="#")
        assert list(lines) == ['foo=3\n', 'foobar=2\n']


class test_set_directive_lines_whitespace(object):
    def test_remove_directive(self):
        lines = installutils.set_directive_lines(
            False, ' ', 'foo', None, WHITESPACE_CONFIG, comment="#")
        assert list(lines) == ['foobar\t2\n']

    def test_add_directive(self):
        lines = installutils.set_directive_lines(
            False, ' ', 'baz', '4', WHITESPACE_CONFIG, comment="#")
        assert list(lines) == ['foo 1\n', 'foobar\t2\n', 'baz 4\n']

    def test_set_directive_does_not_clobber_suffix_key(self):
        lines = installutils.set_directive_lines(
            False, ' ', 'foo', '3', WHITESPACE_CONFIG, comment="#")
        assert list(lines) == ['foo 3\n', 'foobar\t2\n']

    def test_set_directive_with_tab(self):
        lines = installutils.set_directive_lines(
            False, ' ', 'foobar', '6', WHITESPACE_CONFIG, comment="#")
        assert list(lines) == ['foo 1\n', 'foobar 6\n']


class test_set_directive(object):
    def test_set_directive(self):
        """Check that set_directive writes the new data and preserves mode."""
        fd, filename = tempfile.mkstemp()
        try:
            os.close(fd)
            stat_pre = os.stat(filename)

            with open(filename, 'w') as f:
                for line in EXAMPLE_CONFIG:
                    f.write(line)

            installutils.set_directive(filename, 'foo', '3', False, '=', "#")

            stat_post = os.stat(filename)
            with open(filename, 'r') as f:
                lines = list(f)

            assert lines == ['foo=3\n', 'foobar=2\n']
            assert stat_pre.st_mode == stat_post.st_mode
            assert stat_pre.st_uid == stat_post.st_uid
            assert stat_pre.st_gid == stat_post.st_gid

        finally:
            os.remove(filename)


class test_get_directive(object):
    def test_get_directive(self, tmpdir):
        configfile = tmpdir.join('config')
        configfile.write(''.join(EXAMPLE_CONFIG))

        assert '1' == installutils.get_directive(str(configfile),
                                                 'foo',
                                                 separator='=')
        assert '2' == installutils.get_directive(str(configfile),
                                                 'foobar',
                                                 separator='=')


class test_get_directive_whitespace(object):
    def test_get_directive(self, tmpdir):
        configfile = tmpdir.join('config')
        configfile.write(''.join(WHITESPACE_CONFIG))

        assert '1' == installutils.get_directive(str(configfile),
                                                 'foo')
        assert '2' == installutils.get_directive(str(configfile),
                                                 'foobar')


def test_directivesetter(tempdir):
    filename = os.path.join(tempdir, 'example.conf')
    with open(filename, 'w') as f:
        for line in EXAMPLE_CONFIG:
            f.write(line)

    ds = installutils.DirectiveSetter(filename)
    assert ds.lines is None
    with ds:
        assert ds.lines == EXAMPLE_CONFIG
        ds.set('foo', '3')  # quoted, space separated, doesn't change 'foo='
        ds.set('foobar', None, separator='=')  # remove
        ds.set('baz', '4', False, '=')  # add
        ds.setitems([
            ('list1', 'value1'),
            ('list2', 'value2'),
        ])
        ds.setitems({
            'dict1': 'value1',
            'dict2': 'value2',
        })

    with open(filename, 'r') as f:
        lines = list(f)

    assert lines == [
        'foo=1\n',
        'foo "3"\n',
        'baz=4\n',
        'list1 "value1"\n',
        'list2 "value2"\n',
        'dict1 "value1"\n',
        'dict2 "value2"\n',
    ]

    with installutils.DirectiveSetter(filename, True, '=') as ds:
        ds.set('foo', '4')  # doesn't change 'foo '

    with open(filename, 'r') as f:
        lines = list(f)

    assert lines == [
        'foo="4"\n',
        'foo "3"\n',
        'baz=4\n',
        'list1 "value1"\n',
        'list2 "value2"\n',
        'dict1 "value1"\n',
        'dict2 "value2"\n',

    ]


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
