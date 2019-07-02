#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

'''
This Fedora base platform module exports platform related constants.
'''

# Fallback to default constant definitions
from __future__ import absolute_import

from ipaplatform.redhat.constants import RedHatConstantsNamespace
from ipaplatform.osinfo import osinfo

# Fedora 28 and earlier use /etc/sysconfig/nfs
# Fedora 30 and later use /etc/nfs.conf
# Fedora 29 has both
HAS_NFS_CONF = osinfo.version_number >= (30,)


class FedoraConstantsNamespace(RedHatConstantsNamespace):
    # Fedora allows installation of Python 2 and 3 mod_wsgi, but the modules
    # can't coexist. For Apache to load correct module.
    MOD_WSGI_PYTHON2 = "modules/mod_wsgi.so"
    MOD_WSGI_PYTHON3 = "modules/mod_wsgi_python3.so"

    if HAS_NFS_CONF:
        SECURE_NFS_VAR = None

constants = FedoraConstantsNamespace()
