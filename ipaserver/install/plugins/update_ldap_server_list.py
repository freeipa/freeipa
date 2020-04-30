#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from ipalib import Registry
from ipalib import Updater
from ipalib import errors
from ipapython.dn import DN

register = Registry()


@register()
class update_ldap_server_list(Updater):
    """
    Update defaultServerList, an option that helps Solaris
    clients discover LDAP server replicas.
    """
    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        dn = DN(('cn', 'default'), ('ou', 'profile'), self.api.env.basedn)
        try:
            entry = ldap.get_entry(dn)
            srvlist = entry.single_value.get('defaultServerList', '')
            srvlist = srvlist.split()
            if self.api.env.host not in srvlist:
                srvlist.append(self.api.env.host)
                attr = ' '.join(srvlist)
                entry['defaultServerList'] = attr
                ldap.update_entry(entry)
        except errors.NotFound:
            pass
        except ldap.TYPE_OR_VALUE_EXISTS:
            pass

        # no restart, no updates
        return False, ()
