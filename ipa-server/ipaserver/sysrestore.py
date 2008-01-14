# Authors: Mark McLoughlin <markmc@redhat.com>
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 or later
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

#
# This module provides a very simple API which allows
# ipa-server-install --uninstall to restore certain
# parts of the system configuration to the way it was
# before ipa-server-install was first run
#

import os
import os.path
import errno
import shutil
import logging
import ConfigParser

from ipa import ipautil

SYSRESTORE_CACHE_PATH = "/var/cache/ipa/sysrestore"
SYSRESTORE_STATEFILE_PATH = "/var/cache/ipa/sysrestore.state"

def _mktree(basedir, reldir):
    """Create the tree of directories specified by @reldir
    under the directory @base.

    Caveats:
      - @basedir must exist
      - @reldir must not be absolute
      - @reldir must refer to a directory
    """
    (parentdir, subdir) = os.path.split(reldir)
    if parentdir:
        _mktree(basedir, parentdir)
    
    absdir = os.path.join(basedir, reldir)
    try:
        logging.debug("Creating directory '%s'", absdir)
        os.mkdir(absdir)
    except OSError, err:
        if err.errno != errno.EEXIST:
            raise err

def _rmtree(basedir, reldir):
    """Delete a tree of directories specified by @reldir
    under the directory @base, excluding the @base itself.
    Only empty directories will be deleted.

    Caveats:
      - @reldir must not be absolute
      - @reldir must refer to a directory
    """
    absdir = os.path.join(basedir, reldir)
    try:
        logging.debug("Deleting directory '%s'", absdir)
        os.rmdir(absdir)
    except OSError, err:
        if err.errno == errno.ENOTEMPTY:
            logging.debug("Directory '%s' not empty", absdir)
            return
        else:
            raise err

    (parentdir, subdir) = os.path.split(reldir)
    if parentdir:
        _rmtree(basedir, parentdir)
    
def backup_file(path):
    """Create a copy of the file at @path - so long as a copy
    does not already exist - which will be restored to its
    original location by restore_files().
    """
    logging.debug("Backing up system configuration file '%s'", path)
    
    if not os.path.isabs(path):
        raise ValueError("Absolute path required")

    if not os.path.isfile(path):
        logging.debug("  -> Not backing up - '%s' doesn't exist", path)
        return

    relpath = path[1:]

    backup_path = os.path.join(SYSRESTORE_CACHE_PATH, relpath)
    if os.path.exists(backup_path):
        logging.debug("  -> Not backing up - already have a copy of '%s'", path)
        return

    (reldir, file) = os.path.split(relpath)
    if reldir:
        _mktree(SYSRESTORE_CACHE_PATH, reldir)

    shutil.copy2(path, backup_path)

def restore_file(path):
    """Restore the copy of a file at @path to its original
    location and delete the copy.

    Returns #True if the file was restored, #False if there
    was no backup file to restore
    """
    logging.debug("Restoring system configuration file '%s'", path)

    if not os.path.isabs(path):
        raise ValueError("Absolute path required")

    relpath = path[1:]

    backup_path = os.path.join(SYSRESTORE_CACHE_PATH, relpath)
    if not os.path.exists(backup_path):
        logging.debug("  -> Not restoring - '%s' doesn't exist", backup_path)
        return False

    shutil.move(backup_path, path)

    ipautil.run(["/sbin/restorecon", path])
    
    (reldir, file) = os.path.split(relpath)
    if reldir:
        _rmtree(SYSRESTORE_CACHE_PATH, reldir)

    return True

class _StateFile:
    """A metadata file for recording system state which can
    be backed up and later restored. The format is something
    like:

    [httpd]
    running=True
    enabled=False
    """
                
    def __init__(self, path = SYSRESTORE_STATEFILE_PATH):
        """Create a _StateFile object, loading from @path.

        The dictionary @modules, a member of the returned object,
        is where the state can be modified. @modules is indexed
        using a module name to return another dictionary containing
        key/value pairs with the saved state of that module.

        The keys in these latter dictionaries are arbitrary strings
        and the values may either be strings or booleans.
        """
        self._path = path
        
        self.modules = {}
        
        self._load()

    def _load(self):
        """Load the modules from the file @_path. @modules will
        be an empty dictionary if the file doesn't exist.
        """
        logging.debug("Loading StateFile from '%s'", self._path)
        
        self.modules = {}

        p = ConfigParser.SafeConfigParser()
        p.read(self._path)

        for module in p.sections():
            self.modules[module] = {}
            for (key, value) in p.items(module):
                if value == str(True):
                    value = True
                elif value == str(False):
                    value = False
                self.modules[module][key] = value

    def save(self):
        """Save the modules to @_path. If @modules is an empty
        dict, then @_path should be removed.
        """
        logging.debug("Saving StateFile to '%s'", self._path)
        
        for module in self.modules.keys():
            if len(self.modules[module]) == 0:
                del self.modules[module]

        if len(self.modules) == 0:
            logging.debug("  -> no modules, removing file")
            if os.path.exists(self._path):
                os.remove(self._path)
            return

        p = ConfigParser.SafeConfigParser()

        for module in self.modules.keys():
            p.add_section(module)
            for (key, value) in self.modules[module].items():
                p.set(module, key, str(value))

        f = file(self._path, "w")
        p.write(f)
        f.close()

def backup_state(module, key, value):
    """Backup an item of system state from @module, identified
    by the string @key and with the value @value. @value may be
    a string or boolean.
    """
    if not (isinstance(value, str) or isinstance(value, bool)):
        raise ValueError("Only strings or booleans supported")

    state = _StateFile()
    
    if not state.modules.has_key(module):
        state.modules[module] = {}
       
    if not state.modules.has_key(key):
        state.modules[module][key] = value
    
    state.save()

def restore_state(module, key):
    """Return the value of an item of system state from @module,
    identified by the string @key, and remove it from the backed
    up system state.

    If the item doesn't exist, #None will be returned, otherwise
    the original string or boolean value is returned.
    """
    state = _StateFile()
    
    if not state.modules.has_key(module):
        return None
    
    if not state.modules[module].has_key(key):
        return None

    value = state.modules[module][key]
    del state.modules[module][key]

    state.save()

    return value
