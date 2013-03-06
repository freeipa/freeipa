# Authors:
#   Alexander Bokovoy <abokovoy@redhat.com>
#
# Copyright (C) 2012  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from ipaserver.install.plugins import MIDDLE
from ipaserver.install.plugins.baseupdate import PostUpdate
from ipaserver.install.dsinstance import realm_to_serverid, config_dirname
from ipaserver.install import certs
from ipalib import api
from ipapython.dn import DN
import base64

class update_upload_cacrt(PostUpdate):
    """
    Upload public CA certificate to LDAP
    """
    order=MIDDLE

    def execute(self, **options):
        ldap = self.obj.backend
        (cdn, ipa_config) = ldap.get_ipa_config()
        subject_base = ipa_config.get('ipacertificatesubjectbase', [None])[0]
        dirname = config_dirname(realm_to_serverid(api.env.realm))
        certdb = certs.CertDB(api.env.realm, nssdir=dirname, subject_base=subject_base)

        dercert = certdb.get_cert_from_db(certdb.cacert_name, pem=False)

        updates = {}
        dn = DN(('cn', 'CACert'), ('cn', 'ipa'), ('cn','etc'), api.env.basedn)

        cacrt_entry = ['objectclass:nsContainer',
                       'objectclass:pkiCA',
                       'cn:CAcert',
                       'cACertificate;binary:%s' % dercert,
                      ]
        updates[dn] = {'dn': dn, 'default': cacrt_entry}

        return (False, True, [updates])

api.register(update_upload_cacrt)
