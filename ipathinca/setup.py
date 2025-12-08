# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""FreeIPA platform

FreeIPA is a server for identity, policy, and audit.
"""
from os.path import abspath, dirname
import sys

if __name__ == "__main__":
    # include ../ for ipasetup.py
    sys.path.append(dirname(dirname(abspath(__file__))))
    from ipasetup import ipasetup  # noqa: E402

    ipasetup(
        name="ipathinca",
        doc=__doc__,
        package_dir={"ipathinca": ""},
        packages=[
            "ipathinca",
        ],
        install_requires=[
            "cryptography",
            "python-gunicorn",
            "python-flask",
        ],
        extras_require={
            "install": ["ipaplatform"],
            "ldap": ["python-ldap"],  # ipapython.ipaldap
        },
    )
