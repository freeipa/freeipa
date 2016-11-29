#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

"""
ImportError ignoring import hook.
"""

from __future__ import absolute_import, print_function

import imp
import inspect
import os.path
import sys

# Load ipaplatform's meta importer before IgnoreImporter is registered as
# meta importer.
import ipaplatform.paths  # pylint: disable=unused-import


DIRNAME = os.path.dirname(os.path.abspath(__file__))


class FailedImport(object):
    def __init__(self, loader, name):
        self.__file__ = __file__
        self.__name__ = name
        self.__path__ = []
        self.__loader__ = loader
        self.__package__ = name

    def __repr__(self):
        return '<failed import {!r}>'.format(self.__name__)


class IgnoringImporter(object):
    def find_module(self, fullname, path=None):
        parentname, dot, name = fullname.rpartition('.')
        assert (not dot and path is None) or (dot and path is not None)

        # check if the module can be found
        try:
            file, _filename, _description = imp.find_module(name, path)
        except ImportError:
            pass
        else:
            if file is not None:
                file.close()
            # it can be found, do normal import
            return None

        # check if the parent module import failed
        if dot and isinstance(sys.modules[parentname], FailedImport):
            # it did fail, so this import will fail as well
            return self

        # find out from where are we importing
        if path is None:
            path = sys.path
        for pathname in path:
            pathname = os.path.abspath(pathname)
            if not pathname.startswith(DIRNAME):
                break
        else:
            # importing from our source tree, do normal import
            return None

        # find out into what .py file are we importing
        frame = inspect.currentframe().f_back
        filename = frame.f_code.co_filename
        if filename.startswith('<'):
            # not a file, do normal import
            return None
        filename = os.path.abspath(filename)
        if not filename.startswith(DIRNAME):
            # not a file in our source tree, do normal import
            return None

        return self

    def load_module(self, fullname):
        frame = inspect.currentframe().f_back
        print("{}: {}:{}: ignoring ImportError: No module named {}".format(
                sys.argv[0],
                os.path.relpath(frame.f_code.co_filename),
                frame.f_lineno,
                fullname))

        return sys.modules.setdefault(fullname, FailedImport(self, fullname))


sys.meta_path.insert(0, IgnoringImporter())
