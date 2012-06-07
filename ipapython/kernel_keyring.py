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

from ipapython.ipautil import run

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
    (stdout, stderr, rc) = run(['keyctl', 'list', KEYRING], raiseonerr=False)
    return stdout

def get_real_key(key):
    """
    One cannot request a key based on the description it was created with
    so find the one we're looking for.
    """
    (stdout, stderr, rc) = run(['keyctl', 'search', KEYRING, KEYTYPE, key], raiseonerr=False)
    if rc:
        raise ValueError('key %s not found' % key)
    return stdout.rstrip()

def has_key(key):
    """
    Returns True/False whether the key exists in the keyring.
    """
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
    real_key = get_real_key(key)
    (stdout, stderr, rc) = run(['keyctl', 'pipe', real_key], raiseonerr=False)
    if rc:
        raise ValueError('keyctl pipe failed: %s' % stderr)

    return stdout

def update_key(key, value):
    """
    Update the keyring data. If they key doesn't exist it is created.
    """
    if has_key(key):
        real_key = get_real_key(key)
        (stdout, stderr, rc) = run(['keyctl', 'pupdate', real_key], stdin=value, raiseonerr=False)
        if rc:
            raise ValueError('keyctl pupdate failed: %s' % stderr)
    else:
        add_key(key, value)

def add_key(key, value):
    """
    Add a key to the kernel keyring.
    """
    if has_key(key):
        raise ValueError('key %s already exists' % key)
    (stdout, stderr, rc) = run(['keyctl', 'padd', KEYTYPE, key, KEYRING], stdin=value, raiseonerr=False)
    if rc:
        raise ValueError('keyctl padd failed: %s' % stderr)

def del_key(key):
    """
    Remove a key from the keyring
    """
    real_key = get_real_key(key)
    (stdout, stderr, rc) = run(['keyctl', 'unlink', real_key, KEYRING], raiseonerr=False)
    if rc:
        raise ValueError('keyctl unlink failed: %s' % stderr)
