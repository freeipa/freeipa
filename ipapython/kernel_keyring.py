# Authors: Rob Crittenden <rcritten@redhat.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import absolute_import

import os
import six

from ipapython.ipautil import run
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks

# NOTE: Absolute path not required for keyctl since we reset the environment
#       in ipautil.run.

# Use the session keyring so the same user can have a different principal
# in different shells. This was explicitly chosen over @us because then
# it is not possible to use KRB5CCNAME to have a different user principal.
# The same session would always be used and the first principal would
# always win.
KEYRING = '@s'
KEYTYPE = 'user'


def dump_keys():
    """
    Dump all keys
    """
    result = run([paths.KEYCTL, 'list', KEYRING], raiseonerr=False,
                 capture_output=True)
    return result.output


def get_real_key(key):
    """
    One cannot request a key based on the description it was created with
    so find the one we're looking for.
    """
    assert isinstance(key, six.string_types)
    result = run([paths.KEYCTL, 'search', KEYRING, KEYTYPE, key],
                 raiseonerr=False, capture_output=True)
    if result.returncode:
        raise ValueError('key %s not found' % key)
    return result.raw_output.rstrip()


def get_persistent_key(key):
    assert isinstance(key, six.string_types)
    result = run([paths.KEYCTL, 'get_persistent', KEYRING, key],
                 raiseonerr=False, capture_output=True)
    if result.returncode:
        raise ValueError('persistent key %s not found' % key)
    return result.raw_output.rstrip()


def is_persistent_keyring_supported(check_container=True):
    """Returns True if the kernel persistent keyring is supported.

    If check_container is True and a containerized environment is detected,
    return False. There is no support for keyring namespace isolation yet.
    """
    if check_container and tasks.detect_container() is not None:
        return False
    uid = os.geteuid()
    try:
        get_persistent_key(str(uid))
    except ValueError:
        return False

    return True


def has_key(key):
    """
    Returns True/False whether the key exists in the keyring.
    """
    assert isinstance(key, six.string_types)
    try:
        get_real_key(key)
        return True
    except ValueError:
        return False


def read_key(key):
    """
    Read the keyring and return the value for key.

    Use pipe instead of print here to ensure we always get the raw data.
    """
    assert isinstance(key, six.string_types)
    real_key = get_real_key(key)
    result = run([paths.KEYCTL, 'pipe', real_key], raiseonerr=False,
                 capture_output=True)
    if result.returncode:
        raise ValueError('keyctl pipe failed: %s' % result.error_log)

    return result.raw_output


def update_key(key, value):
    """
    Update the keyring data. If they key doesn't exist it is created.
    """
    assert isinstance(key, six.string_types)
    assert isinstance(value, bytes)
    if has_key(key):
        real_key = get_real_key(key)
        result = run([paths.KEYCTL, 'pupdate', real_key], stdin=value,
                     raiseonerr=False)
        if result.returncode:
            raise ValueError('keyctl pupdate failed: %s' % result.error_log)
    else:
        add_key(key, value)


def add_key(key, value):
    """
    Add a key to the kernel keyring.
    """
    assert isinstance(key, six.string_types)
    assert isinstance(value, bytes)
    if has_key(key):
        raise ValueError('key %s already exists' % key)
    result = run([paths.KEYCTL, 'padd', KEYTYPE, key, KEYRING],
                 stdin=value, raiseonerr=False)
    if result.returncode:
        raise ValueError('keyctl padd failed: %s' % result.error_log)


def del_key(key):
    """
    Remove a key from the keyring
    """
    assert isinstance(key, six.string_types)
    real_key = get_real_key(key)
    result = run([paths.KEYCTL, 'unlink', real_key, KEYRING],
                 raiseonerr=False)
    if result.returncode:
        raise ValueError('keyctl unlink failed: %s' % result.error_log)
