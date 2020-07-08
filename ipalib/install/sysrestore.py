#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Facade for ipalib.sysrestore for backwards compatibility
"""

from ipalib import sysrestore as real_sysrestore

class FileStore(real_sysrestore.FileStore):
    def __init__(self, path=real_sysrestore.SYSRESTORE_PATH,
                 index_file=real_sysrestore.SYSRESTORE_INDEXFILE):
        super(FileStore, self).__init__(path, index_file)

class StateFile(real_sysrestore.StateFile):
    def __init__(self, path=real_sysrestore.SYSRESTORE_PATH,
                 state_file=real_sysrestore.SYSRESTORE_STATEFILE):
        super(StateFile, self).__init__(path, state_file)
