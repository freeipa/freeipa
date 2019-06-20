#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import io
import os
from ipaserver.plugins.ldap2 import ldap2
from ipalib import api
from ipapython.dn import DN
import pytest


@pytest.mark.tier1
class TestTopologyPlugin:
    """
    Test Topology plugin from the DS point of view
    Testcase: http://www.freeipa.org/page/V4/Manage_replication_topology/
    Test_plan#Test_case:
    _Replication_Topology_is_listed_among_directory_server_plugins
    """
    pwfile = os.path.join(api.env.dot_ipa, ".dmpw")

    @pytest.fixture(autouse=True)
    def topologyplugin_setup(self, request):
        """
        setup for test
        """
        self.conn = None

        def fin():
            if self.conn and self.conn.isconnected():
                self.conn.disconnect()
        request.addfinalizer(fin)

    @pytest.mark.skipif(os.path.isfile(pwfile) is False,
                        reason="You did not provide a .dmpw file with the DM password")
    def test_topologyplugin(self):
        pluginattrs = {
            u'nsslapd-pluginPath': [u'libtopology'],
            u'nsslapd-pluginVendor': [u'freeipa'],
            u'cn': [u'IPA Topology Configuration'],
            u'nsslapd-plugin-depends-on-named':
                [u'Multimaster Replication Plugin', u'ldbm database'],
            u'nsslapd-topo-plugin-shared-replica-root': [u'dc=example,dc=com'],
            u'nsslapd-pluginVersion': [u'1.0'],
            u'nsslapd-topo-plugin-shared-config-base':
                [u'cn=ipa,cn=etc,dc=example,dc=com'],
            u'nsslapd-pluginDescription': [u'ipa-topology-plugin'],
            u'nsslapd-pluginEnabled': [u'on'],
            u'nsslapd-pluginId': [u'ipa-topology-plugin'],
            u'objectClass': [u'top', u'nsSlapdPlugin', u'extensibleObject'],
            u'nsslapd-topo-plugin-startup-delay': [u'20'],
            u'nsslapd-topo-plugin-shared-binddngroup':
                [u'cn=replication managers,cn=sysaccounts,cn=etc,dc=example,dc=com'],
            u'nsslapd-pluginType': [u'object'],
            u'nsslapd-pluginInitfunc': [u'ipa_topo_init']
        }
        variable_attrs = {u'nsslapd-topo-plugin-shared-replica-root',
                          u'nsslapd-topo-plugin-shared-config-base',
                          u'nsslapd-topo-plugin-shared-binddngroup'}

        # Now eliminate keys that have domain-dependent values.
        checkvalues = set(pluginattrs.keys()) - variable_attrs
        topoplugindn = DN(('cn', 'IPA Topology Configuration'),
                          ('cn', 'plugins'),
                          ('cn', 'config'))
        pwfile = os.path.join(api.env.dot_ipa, ".dmpw")
        with io.open(pwfile, "r") as f:
            dm_password = f.read().rstrip()
        self.conn = ldap2(api)
        self.conn.connect(bind_dn=DN(('cn', 'directory manager')),
                          bind_pw=dm_password)
        entry = self.conn.get_entry(topoplugindn)
        assert(set(entry.keys()) == set(pluginattrs.keys()))
        for i in checkvalues:
            assert(set(pluginattrs[i]) == set(entry[i]))
