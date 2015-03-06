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
from ipaserver.install import certs
from ipalib import api, certstore
from ipapython import certdb
from ipapython.dn import DN

class update_upload_cacrt(PostUpdate):
    """
    Upload public CA certificate to LDAP
    """
    order=MIDDLE

    def execute(self, **options):
        db = certs.CertDB(self.api.env.realm)
        ca_cert = None

        ca_enabled = self.api.Command.ca_is_enabled()['result']
        if ca_enabled:
            ca_nickname = certdb.get_ca_nickname(self.api.env.realm)
        else:
            ca_nickname = None
            server_certs = db.find_server_certs()
            if server_certs:
                ca_chain = db.find_root_cert(server_certs[0][0])[:-1]
                if ca_chain:
                    ca_nickname = ca_chain[-1]

        updates = []

        for nickname, trust_flags in db.list_certs():
            if 'u' in trust_flags:
                continue
            if nickname == ca_nickname and ca_enabled:
                trust_flags = 'CT,C,C'
            cert = db.get_cert_from_db(nickname, pem=False)
            try:
                dn, entry = self._make_entry(cert, nickname, trust_flags)
            except Exception, e:
                self.log.warning("Failed to create entry for %s: %s",
                                 nickname, e)
                continue
            if nickname == ca_nickname:
                ca_cert = cert
                if ca_enabled:
                    entry.append('ipaConfigString:ipaCA')
                entry.append('ipaConfigString:compatCA')
            updates.append({'dn': dn, 'default': entry})

        if ca_cert:
            dn = DN(('cn', 'CACert'), ('cn', 'ipa'), ('cn','etc'),
                    self.api.env.basedn)
            entry = ['objectclass:nsContainer',
                     'objectclass:pkiCA',
                     'cn:CAcert',
                     'cACertificate;binary:%s' % ca_cert,
                    ]
            updates.append({'dn': dn, 'default': entry})

        return (False, True, updates)

    def _make_entry(self, cert, nickname, trust_flags):
        dn = DN(('cn', nickname), ('cn', 'certificates'), ('cn', 'ipa'),
                ('cn','etc'), self.api.env.basedn)

        entry = dict()
        trust, ca, eku = certstore.trust_flags_to_key_policy(trust_flags)
        certstore.init_ca_entry(entry, cert, nickname, trust, eku)
        entry = ['%s:%s' % (a, v) for a, vs in entry.iteritems() for v in vs]

        return dn, entry

api.register(update_upload_cacrt)
