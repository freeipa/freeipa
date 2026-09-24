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
        name="ipacta",
        doc=__doc__,
        package_dir={"ipacta": ""},
        packages=[
            "ipacta",
            "ipacta.certificate",
            "ipacta.install",
            "ipacta.profile",
            "ipacta.rest_api",
            "ipacta.storage",
        ],
        install_requires=[
            "cryptography>=42.0",
            "python-gunicorn",
            "python-flask",
            "ipapython",  # ipautil.run, ipautil.fsdecode
            "ipalib",     # errors, constants — used unconditionally at import
            "ipaplatform",  # paths — used unconditionally at import
            "python-ldap",  # ipapython.ipaldap
            "cachetools",  # TTLCache for sub-CA and profile caches
        ],
    )
