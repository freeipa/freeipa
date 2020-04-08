#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#
"""Sphinx documentation plugins for IPA
"""
from os.path import abspath, dirname
import sys

if __name__ == "__main__":
    # include ../ for ipasetup.py
    sys.path.append(dirname(dirname(abspath(__file__))))
    from ipasetup import ipasetup  # noqa: E402

    ipasetup(
        name="ipasphinx",
        doc=__doc__,
        package_dir={"ipasphinx": ""},
        packages=["ipasphinx"],
        # m2r is not compatible with Sphinx 3.x yet
        install_requires=["ipaserver", "ipalib", "sphinx < 3.0", "m2r"],
    )
