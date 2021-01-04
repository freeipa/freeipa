#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#
"""WSGI server application
"""
import gc
import logging
import os
import sys

# Some dependencies like Dogtag's pki.client library and custodia use
# python-requsts to make HTTPS connection. python-requests prefers
# PyOpenSSL over Python's stdlib ssl module. PyOpenSSL is build on top
# of python-cryptography which trigger a execmem SELinux violation
# in the context of Apache HTTPD (httpd_execmem).
# When requests is imported, it always tries to import pyopenssl glue
# code from urllib3's contrib directory. The import of PyOpenSSL is
# enough to trigger the SELinux denial.
# Block any import of PyOpenSSL's SSL module by raising an ImportError
sys.modules["OpenSSL.SSL"] = None

from ipaplatform.paths import paths
from ipalib import api
from ipapython import ipaldap

logger = logging.getLogger(os.path.basename(__file__))


def populate_schema_cache(api=api):
    """populate schema cache in parent process

    LDAP server schema is available for anonymous binds.
    """
    conn = ipaldap.ldap_initialize(api.env.ldap_uri)
    try:
        ipaldap.schema_cache.get_schema(api.env.ldap_uri, conn)
    except Exception as e:
        logger.error("Failed to pre-populate LDAP schema cache: %s", e)
    finally:
        try:
            conn.unbind_s()
        except AttributeError:
            # SimpleLDAPObject has no attribute '_l'
            pass


def create_application():
    api.bootstrap(context="server", confdir=paths.ETC_IPA, log=None)

    try:
        api.finalize()
    except Exception as e:
        logger.error("Failed to start IPA: %s", e)
        raise

    # speed up first request to each worker by 200ms
    populate_schema_cache()

    # collect garbage and freeze all objects that are currently tracked by
    # cyclic garbage collector. We assume that vast majority of currently
    # loaded objects won't be removed in requests. This speeds up GC
    # collections and improve CoW memory handling.
    gc.collect()
    if hasattr(gc, "freeze"):
        # Python 3.7+
        gc.freeze()

    # This is the WSGI callable:
    def application(environ, start_response):
        if not environ["wsgi.multithread"]:
            return api.Backend.wsgi_dispatch(environ, start_response)
        else:
            logger.error(
                "IPA does not work with the threaded MPM, "
                "use the pre-fork MPM"
            )
            raise RuntimeError("threaded MPM detected")

    return application


if __name__ == "__main__":
    application = create_application()
