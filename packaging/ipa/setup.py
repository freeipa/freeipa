#
# Copyright (C) 2017 FreeIPA Contributors see COPYING for license
#
"""Dummy package for FreeIPA

Please install ipaclient instead.
"""

from os.path import abspath, dirname
import sys

if __name__ == '__main__':
    # include ../../ for ipasetup.py
    sys.path.append(dirname(dirname(dirname(abspath(__file__)))))
    from ipasetup import ipasetup  # noqa: E402

    ipasetup(
        name='ipa',
        doc = __doc__,
        install_requires=[
            "ipaclient",
        ]
    )
