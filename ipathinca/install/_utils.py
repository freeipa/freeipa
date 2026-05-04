# Copyright (C) 2025  FreeIPA Contributors see COPYING for license

"""Internal utilities shared across install sub-modules.

This module avoids circular imports: sub-modules (acme, kra, replica, …)
can import from here without pulling in ``ipathinca.install.__init__``, which
in turn imports those sub-modules.
"""

from __future__ import absolute_import

import logging
import os
import urllib.parse

from ipaplatform.paths import paths
from ipapython import ipautil

logger = logging.getLogger(__name__)


class _InstallLDAPMod:
    """Provides ``_ldap_mod`` for install-time LDAP operations.

    Uses SASL EXTERNAL over the local LDAPI socket (derived from
    ``self.realm``).  This matches what ``service.Service._ldap_mod`` does
    when running as root during installation, without requiring an import
    of ``ipaserver`` or ``ipalib.api``.

    Classes that mix this in must have ``self.realm`` set.
    """

    # Declared here so pylint knows the attribute exists; concrete __init__
    # must assign it (e.g. ``self.realm = config.realm``).
    realm: str

    def _ldap_mod(self, filename, sub_dict=None, raise_on_err=True):
        if not os.path.isabs(filename):
            path = os.path.join(paths.USR_SHARE_IPA_DIR, filename)
        else:
            path = filename

        fd = None
        if sub_dict is not None:
            txt = ipautil.template_file(path, sub_dict)
            fd = ipautil.write_tmp_file(txt)
            fd.flush()
            path = fd.name

        realm_name = self.realm.replace(".", "-")
        socket_path = f"/run/slapd-{realm_name}.socket"
        socket_url = "ldapi://" + urllib.parse.quote(socket_path, safe="")

        try:
            return ipautil.run(
                [
                    "ldapmodify",
                    "-c",
                    "-Y",
                    "EXTERNAL",
                    "-H",
                    socket_url,
                    "-f",
                    path,
                ],
                raiseonerr=raise_on_err,
            )
        finally:
            if fd is not None:
                fd.close()
