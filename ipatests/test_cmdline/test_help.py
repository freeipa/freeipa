# Authors: Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2012  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
import os
from io import StringIO
import shutil
import errno

import six

from ipalib import api, errors
from ipaserver.plugins.user import user_add
import pytest

if six.PY3:
    unicode = str


pytestmark = pytest.mark.needs_ipaapi


@pytest.mark.tier0
class CLITestContext:
    """Context manager that replaces stdout & stderr, and catches SystemExit

    Whatever was printed to the streams is available in ``stdout`` and
    ``stderr`` attrributes once the with statement finishes.

    When exception is given, asserts that exception is raised. The exception
    will be available in the ``exception`` attribute.
    """
    def __init__(self, exception=None):
        self.exception = exception

    def __enter__(self):
        self.old_streams = sys.stdout, sys.stderr
        self.stdout_fileobj = sys.stdout = StringIO()
        self.stderr_fileobj = sys.stderr = StringIO()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        sys.stdout, sys.stderr = self.old_streams
        self.stdout = self.stdout_fileobj.getvalue()
        self.stderr = self.stderr_fileobj.getvalue()
        self.stdout_fileobj.close()
        self.stderr_fileobj.close()
        if self.exception:
            if not isinstance(exc_value, self.exception):
                return False
            self.exception = exc_value
            return True
        else:
            return None


def test_ipa_help():
    """Test that `ipa help` only writes to stdout"""
    with CLITestContext() as ctx:
        return_value = api.Backend.cli.run(['help'])
    assert return_value == 0
    assert ctx.stderr == ''


def test_ipa_help_without_cache():
    """Test `ipa help` without schema cache"""
    cache_dir = os.path.expanduser('~/.cache/ipa/schema/')
    backup_dir = os.path.expanduser('~/.cache/ipa/schema.bak/')
    shutil.rmtree(backup_dir, ignore_errors=True)
    if os.path.isdir(cache_dir):
        os.rename(cache_dir, backup_dir)
    try:
        with CLITestContext() as ctx:
            return_value = api.Backend.cli.run(['help'])
        assert return_value == 0
        assert ctx.stderr == ''
    finally:
        shutil.rmtree(cache_dir, ignore_errors=True)
        try:
            os.rename(backup_dir, cache_dir)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise


def test_ipa_without_arguments():
    """Test that `ipa` errors out, and prints the help to stderr"""
    with CLITestContext(exception=SystemExit) as ctx:
        api.Backend.cli.run([])
    assert ctx.exception.code == 2
    assert ctx.stdout == ''
    assert 'Error: Command not specified' in ctx.stderr

    with CLITestContext() as help_ctx:
        api.Backend.cli.run(['help'])
    assert help_ctx.stdout in ctx.stderr


def test_bare_topic():
    """Test that `ipa user` errors out, and prints the help to stderr

    This is because `user` is a topic, not a command, so `ipa user` doesn't
    match our usage string. The help should be accessed using `ipa help user`.
    """
    with CLITestContext(exception=errors.CommandError) as ctx:
        api.Backend.cli.run(['user'])
    assert ctx.exception.name == 'user'
    assert ctx.stdout == ''

    with CLITestContext() as help_ctx:
        return_value = api.Backend.cli.run(['help', 'user'])
    assert return_value == 0
    assert help_ctx.stdout in ctx.stderr


def test_command_help():
    """Test that `help user-add` & `user-add -h` are equivalent and contain doc
    """
    with CLITestContext() as help_ctx:
        return_value = api.Backend.cli.run(['help', 'user-add'])
    assert return_value == 0
    assert help_ctx.stderr == ''

    with CLITestContext(exception=SystemExit) as h_ctx:
        api.Backend.cli.run(['user-add', '-h'])
    assert h_ctx.exception.code == 0
    assert h_ctx.stderr == ''

    assert h_ctx.stdout == help_ctx.stdout
    assert unicode(user_add.doc) in help_ctx.stdout


def test_ambiguous_command_or_topic():
    """Test that `help ping` & `ping -h` are NOT equivalent

    One is a topic, the other is a command
    """
    with CLITestContext() as help_ctx:
        return_value = api.Backend.cli.run(['help', 'ping'])
    assert return_value == 0
    assert help_ctx.stderr == ''

    with CLITestContext(exception=SystemExit) as h_ctx:
        api.Backend.cli.run(['ping', '-h'])
    assert h_ctx.exception.code == 0
    assert h_ctx.stderr == ''

    assert h_ctx.stdout != help_ctx.stdout


def test_multiline_description():
    """Test that all of a multi-line command description appears in output
    """
    # This assumes trust_add has multiline doc. Ensure it is so.
    assert '\n\n' in unicode(api.Command.trust_add.doc).strip()

    with CLITestContext(exception=SystemExit) as help_ctx:
        api.Backend.cli.run(['trust-add', '-h'])

    assert unicode(api.Command.trust_add.doc).strip() in help_ctx.stdout


def test_bz1428690():
    """
    Test for BZ#1428690 - ipa-backup does not create log file at /var/log/
    :return: None
    :raises: AssertionError if the test fails
    """
    with CLITestContext(exception=SystemExit) as ctx:
        api.Backend.cli.run(['backup'])
    assert ctx.exception.code == 1
    assert ctx.stdout == ''
    assert 'not configured' in ctx.stderr
    assert '/var/log' not in ctx.stderr

