#
# Copyright (C) 2017 FreeIPA Contributors see COPYING for license
#
"""Dummy package for FreeIPA

ipatests is not yet available as PyPI package.
"""

from os.path import abspath, dirname
import sys

if __name__ == '__main__':
    # include ../../ for ipasetup.py
    sys.path.append(dirname(dirname(dirname(abspath(__file__)))))
    from ipasetup import ipasetup  # noqa: E402

    ipasetup(
        name='ipaserver',
        doc = __doc__,
        packages=[
            "ipaserver",
        ],
        install_requires=[
            "ipaclient",
        ]
    )
