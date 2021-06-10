# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
"""WSGI entry point for kdcproxy
"""
import os

from kdcproxy import application


def set_env():
    """Replace current env with new one"""
    # KDCPROXY_CONFIG is used by kdcproxy
    pass_vars = ["KDCPROXY_CONFIG", "LANG", "LC_ALL"]
    new_env = {}
    for var in pass_vars:
        try:
            new_env[var] = os.environ[var]
        except KeyError:
            pass

    new_env["PATH"] = "/usr/bin:/bin"
    os.environ.clear()
    os.environ.update(new_env)


set_env()
