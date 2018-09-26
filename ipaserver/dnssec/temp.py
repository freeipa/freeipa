#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

import errno
import shutil
import tempfile


class TemporaryDirectory:
    def __init__(self, root):
        self.root = root

    def __enter__(self):
        self.name = tempfile.mkdtemp(dir=self.root)
        return self.name

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            shutil.rmtree(self.name)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
