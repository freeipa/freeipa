#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#
import pytest
import time
import textwrap
from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration.tasks import (
    clear_sssd_cache, kinit_admin, install_master, install_client,
    create_active_user, ldapsearch_dm
)


class TestAutomount(IntegrationTest):
    """
    Test Automount Functional
    """

    @classmethod
    def install(cls, mh):
        super(TestAutomount, cls).install(mh)
        install_master(cls.master, setup_dns=True)

    def test_automount_location_add_001(self):
        master = self.master
        kinit_admin(master)

        result = master.run_command(["ipa", "automountlocation-add", "pune"])
        assert 'Added automount location "pune"' in result.stdout_text
        assert "Location: pune" in result.stdout_text
        # Verify LDAP entries exist
        result = ldapsearch_dm(
            self.master,
            f"cn=pune,cn=automount,{master.domain.basedn}",
            ldap_args=[],
            scope="sub",
            raiseonerr=False
        )
        out = result.stdout_text
        assert f"dn: cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "dn: automountmapname=auto.master,cn=pune,cn=automount" in out
        assert "automountMapName: auto.master" in out
        assert "dn: automountmapname=auto.direct,cn=pune,cn=automount," in out
        assert "automountMapName: auto.direct" in out
        assert "automountInformation: auto.direct" in out
        assert "dn: description=/- auto.direct,automountmapname=auto.master,cn=pune" in out
        assert "automountKey: /-" in out
        assert "automountInformation: auto.direct" in out
        assert "description: /- auto.direct" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automount_location_add_002(self):
        master = self.master
        result = master.run_command(
            ["ipa", "automountlocation-add", "pune", "--all"]
        )
        assert 'Added automount location "pune"' in result.stdout_text
        assert f"dn: cn=pune,cn=automount,{master.domain.basedn}" in result.stdout_text
        assert "Location: pune" in result.stdout_text
        assert "objectclass: nscontainer, top" in result.stdout_text

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automount_location_add_003(self):
        master = self.master
        result = master.run_command(
            ["ipa", "automountlocation-add", "pune", "--all", "--raw"]
        )
        assert 'Added automount location "pune"' in result.stdout_text
        assert f"dn: cn=pune,cn=automount,{master.domain.basedn}" in result.stdout_text
        assert "cn: pune" in result.stdout_text
        assert "objectClass: nscontainer" in result.stdout_text
        assert "objectClass: top" in result.stdout_text

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automount_location_find_001(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command(["ipa", "automountlocation-find"])
        out = result.stdout_text
        assert "Location: default" in out
        assert "Location: pune" in out
        assert "Number of entries returned 2" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automount_location_find_002(self):
        master = self.master
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command(["ipa", "automountlocation-find", "pune"])
        out = result.stdout_text
        assert "Location: pune" in out
        assert "Number of entries returned 1" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automount_location_find_003(self):
        master = self.master
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command(
            ["ipa", "automountlocation-find", "--location=pune"]
        )
        out = result.stdout_text
        assert "Location: pune" in out
        assert "Number of entries returned 1" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automount_location_find_004(self):
        master = self.master
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command(
            ["ipa", "automountlocation-find", "--location=pune", "--all"]
        )
        out = result.stdout_text
        assert f"dn: cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "Location: pune" in out
        assert "objectclass: nscontainer, top" in out
        assert "Number of entries returned 1" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automount_location_find_005(self):
        master = self.master
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command(
            ["ipa", "automountlocation-find", "--location=pune", "--all", "--raw"]
        )
        out = result.stdout_text
        assert f"dn: cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "cn: pune" in out
        assert "objectClass: nscontainer" in out
        assert "objectClass: top" in out
        assert "Number of entries returned 1" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automount_location_find_006(self):
        master = self.master
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command(
            ["ipa", "automountlocation-find", "--location=pune", "--pkey-only"]
        )
        out = result.stdout_text
        assert "Location: pune" in out
        assert "Number of entries returned 1" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automount_location_show_001(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command(["ipa", "automountlocation-show", "pune"])
        assert "Location: pune" in result.stdout_text

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automount_location_show_002(self):
        master = self.master
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command(
            ["ipa", "automountlocation-show", "pune", "--all"]
        )
        out = result.stdout_text
        assert f"dn: cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "objectclass: nscontainer, top" in out
        assert "Location: pune" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automount_location_show_003(self):
        master = self.master
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command(
            ["ipa", "automountlocation-show", "pune", "--all", "--raw"]
        )
        out = result.stdout_text
        assert f"dn: cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "objectClass: nscontainer" in out
        assert "objectClass: top" in out
        assert "cn: pune" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automount_location_show_004(self):
        master = self.master
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command(
            ["ipa", "automountlocation-show", "pune", "--all", "--raw", "--rights"]
        )
        out = result.stdout_text
        assert f"dn: cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "cn: pune" in out
        assert "objectClass: nscontainer" in out
        assert "objectClass: top" in out
        assert "attributelevelrights:" in out
        assert "attributelevelrights: {'cn': 'rscwo', 'objectclass': 'rscwo', 'aci': 'rscwo', 'nsaccountlock': 'rscwo'}" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automountmap_add_001(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command(["ipa", "automountmap-add", "pune", "auto.pune"])
        out = result.stdout_text
        assert 'Added automount map "auto.pune"' in out
        assert "Map: auto.pune" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automountmap_add_002(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command(["ipa", "automountmap-add", "pune", "auto.pune", "--all"])
        out = result.stdout_text
        assert 'Added automount map "auto.pune"' in out
        assert "Map: auto.pune" in out
        assert "objectclass: automountmap, top" in out
        assert f"dn: automountmapname=auto.pune,cn=pune,cn=automount,{master.domain.basedn}" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automountmap_add_003(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command([
            "ipa", "automountmap-add", "pune", "auto.pune", "--all", "--raw"
        ])
        out = result.stdout_text
        assert 'Added automount map "auto.pune"' in out
        assert f"dn: automountmapname=auto.pune,cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "automountmapname: auto.pune" in out
        assert "objectClass: automountmap" in out
        assert "objectClass: top" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automountmap_add_004(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command([
            "ipa", "automountmap-add", "pune", "auto.pune", "--all", "--raw",
            "--desc='pune automount map'"
        ])
        out = result.stdout_text
        assert 'Added automount map "auto.pune"' in out
        assert f"dn: automountmapname=auto.pune,cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "automountmapname: auto.pune" in out
        assert "description: 'pune automount map'" in out
        assert "objectClass: automountmap" in out
        assert "objectClass: top" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automountmap_add_005(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command([
            "ipa", "automountmap-add-indirect", "pune", "punechild.map",
            "--mount=/usr/share/man"
        ])
        out = result.stdout_text
        assert 'Added automount map "punechild.map"' in out
        assert "Map: punechild.map" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automountmap_add_006(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "pune"])
        master.run_command(["ipa", "automountmap-add", "pune", "pune.map"])

        result = master.run_command([
            "ipa", "automountmap-add-indirect", "pune", "punechild.map",
            "--mount=usr/share/man", "--parentmap=pune.map"
        ])
        out = result.stdout_text
        assert 'Added automount map "punechild.map"' in out
        assert "Map: punechild.map" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automountmap_add_007(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "pune"])
        master.run_command(["ipa", "automountmap-add", "pune", "pune.map"])

        result = master.run_command([
            "ipa", "automountmap-add-indirect", "pune", "punechild.map",
            "--mount=usr/share/man", "--parentmap=pune.map", "--all"
        ])
        out = result.stdout_text
        assert f"dn: automountmapname=punechild.map,cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "Map: punechild.map" in out
        assert "objectclass: automountmap, top" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automountmap_add_008(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "-d", "automountlocation-add", "pune"])
        master.run_command(["ipa", "-d", "automountmap-add", "pune", "pune.map"])

        result = master.run_command([
            "ipa", "-d", "automountmap-add-indirect", "pune", "punechild.map",
            "--mount=usr/share/man", "--parentmap=pune.map", "--all", "--raw"
        ])
        out = result.stdout_text
        assert f"dn: automountmapname=punechild.map,cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "automountmapname: punechild.map" in out
        assert "objectClass: automountmap" in out
        assert "objectClass: top" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automountmap_find_001(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "pune"])
        master.run_command(["ipa", "automountmap-add", "pune", "pune.map"])
        master.run_command(["ipa", "automountmap-add", "pune", "pune2.map"])
        master.run_command(["ipa", "automountmap-add", "pune", "pune3.map"])

        result = master.run_command(["ipa", "automountmap-find", "pune"])
        out = result.stdout_text
        assert "5 automount maps matched" in out
        assert "Map: auto.direct" in out
        assert "Map: auto.master" in out
        assert "Map: pune.map" in out
        assert "Map: pune2.map" in out
        assert "Map: pune3.map" in out
        assert "Number of entries returned 5" in out

    def test_automountmap_find_002(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command([
            "ipa", "automountmap-find", "pune", "--map=pune.map"
        ])
        out = result.stdout_text
        assert "1 automount map matched" in out
        assert "Map: pune.map" in out
        assert "Number of entries returned 1" in out

    def test_automountmap_find_003(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command([
            "ipa", "automountmap-find", "pune", "--map=pune.map", "--all"
        ])
        out = result.stdout_text
        assert "1 automount map matched" in out
        assert f"dn: automountmapname=pune.map,cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "Map: pune.map" in out
        assert "objectclass: automountmap, top" in out
        assert "Number of entries returned 1" in out

    def test_automountmap_find_004(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command([
            "ipa", "automountmap-find", "pune", "--map=pune.map", "--all", "--raw"
        ])
        out = result.stdout_text
        assert "1 automount map matched" in out
        assert f"dn: automountmapname=pune.map,cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "automountmapname: pune.map" in out
        assert "objectClass: automountmap" in out
        assert "objectClass: top" in out
        assert "Number of entries returned 1" in out

    def test_automountmap_find_005(self):
        master = self.master
        kinit_admin(master)
        # size limit 2
        result = master.run_command([
            "ipa", "automountmap-find", "pune", "--all", "--raw", "--sizelimit=2"
        ])
        out = result.stdout_text
        assert "2 automount maps matched" in out
        assert f"dn: automountmapname=auto.direct,cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "automountmapname: auto.direct" in out
        assert "objectClass: automountmap" in out
        assert "objectClass: top" in out
        assert f"dn: automountmapname=auto.master,cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "automountmapname: auto.master" in out
        assert "objectClass: automountmap" in out
        assert "objectClass: top" in out
        assert "Number of entries returned 2" in out

        # size limit 3
        result = master.run_command([
            "ipa", "automountmap-find", "pune", "--all", "--raw", "--sizelimit=3"
        ])
        out = result.stdout_text
        assert "3 automount maps matched" in out
        assert f"dn: automountmapname=auto.direct,cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "automountmapname: auto.direct" in out
        assert "objectClass: automountmap" in out
        assert "objectClass: top" in out

        assert f"dn: automountmapname=auto.master,cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "automountmapname: auto.master" in out
        assert "objectClass: automountmap" in out
        assert "objectClass: top" in out

        assert f"dn: automountmapname=pune.map,cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "automountmapname: pune.map" in out
        assert "objectClass: automountmap" in out
        assert "objectClass: top" in out
        assert "Number of entries returned 3" in out

    def test_automountmap_find_006(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command([
            "ipa", "automountmap-find", "pune", "--map=pune.map", "--pkey-only"
        ])
        out = result.stdout_text
        assert "1 automount map matched" in out
        assert "Map: pune.map" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automountmap_show_001(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "pune"])
        master.run_command([
            "ipa", "automountmap-add", "pune", "pune.map",
            "--desc='map file for pune location'"
        ])

        result = master.run_command(["ipa", "automountmap-show", "pune", "pune.map"])
        out = result.stdout_text
        assert "Map: pune.map" in out
        assert "Description: 'map file for pune location'" in out

    def test_automountmap_show_002(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command([
            "ipa", "automountmap-show", "pune", "pune.map", "--all"
        ])
        out = result.stdout_text
        assert f"dn: automountmapname=pune.map,cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "Map: pune.map" in out
        assert "Description: 'map file for pune location'" in out
        assert "objectclass: automountmap, top" in out

    def test_automountmap_show_003(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command([
            "ipa", "automountmap-show", "pune", "pune.map", "--all", "--raw"
        ])
        out = result.stdout_text
        assert f"dn: automountmapname=pune.map,cn=pune,cn=automount,{master.domain.basedn}" in out
        assert "automountmapname: pune.map" in out
        assert "description: 'map file for pune location'" in out
        assert "objectClass: automountmap" in out
        assert "objectClass: top" in out

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_automountkey_add_001(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "baltimore"])
        master.run_command(["ipa", "automountmap-add", "baltimore", "auto.baltimore"])

        result = master.run_command([
            "ipa", "automountkey-add", "baltimore", "auto.master",
            "--key=/share", "--info=auto.share"
        ])
        # Verifying bug https://bugzilla.redhat.com/show_bug.cgi?id=725763
        assert 'Added automount key "/share"' in result.stdout_text
        assert "Key: /share" in result.stdout_text
        assert "Mount information: auto.share" in result.stdout_text

        # cleanup
        master.run_command(["ipa", "automountlocation-del", "baltimore"])

    def test_automountkey_add_002(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "baltimore"])
        master.run_command(["ipa", "automountmap-add", "baltimore", "auto.baltimore"])

        result = master.run_command([
            "ipa", "automountkey-add", "baltimore", "auto.master",
            "--key=/share", "--info=auto.share", "--all"
        ])

        assert 'Added automount key "/share"' in result.stdout_text
        assert f"dn: description=/share,automountmapname=auto.master,cn=baltimore,cn=automount,{master.domain.basedn}" in result.stdout_text
        assert "Key: /share" in result.stdout_text
        assert "objectclass: automount, top" in result.stdout_text
        assert "description: /share" in result.stdout_text
        assert "Mount information: auto.share" in result.stdout_text

        # cleanup
        master.run_command(["ipa", "automountlocation-del", "baltimore"])

    def test_automountkey_add_003(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "baltimore"])
        master.run_command(["ipa", "automountmap-add", "baltimore", "auto.baltimore"])

        result = master.run_command([
            "ipa", "automountkey-add", "baltimore", "auto.master",
            "--key=/share", "--info=auto.share", "--all", "--raw"
        ])

        assert 'Added automount key "/share"' in result.stdout_text
        assert f"dn: description=/share,automountmapname=auto.master,cn=baltimore,cn=automount,{master.domain.basedn}" in result.stdout_text
        assert "automountkey: /share" in result.stdout_text
        assert "objectClass: automount" in result.stdout_text
        assert "objectClass: top" in result.stdout_text
        assert "description: /share" in result.stdout_text
        assert "automountinformation: auto.share" in result.stdout_text

        # cleanup
        master.run_command(["ipa", "automountlocation-del", "baltimore"])

    def test_automountkey_mod_001(self):
        master = self.master
        kinit_admin(master)

        master.run_command([
            "ipa", "automountlocation-add", "baltimore"
        ])
        master.run_command([
            "ipa", "automountkey-add", "baltimore", "auto.master",
            "--key=/share", "--info=auto.share"
        ])
        result = master.run_command([
            "ipa", "automountkey-mod", "baltimore", "auto.master",
            "--key=/share", "--rename=/ipashare",
            "--info=auto.share", "--newinfo=auto.ipashare"
        ])
        out = result.stdout_text

        assert "Key: /share" not in out
        assert "Key: /ipashare" in out
        assert "Mount information: auto.ipashare" in out

        master.run_command(["ipa", "automountlocation-del", "baltimore"])

    def test_automountkey_mod_002(self):
        master = self.master
        kinit_admin(master)

        master.run_command(["ipa", "automountlocation-add", "baltimore"])
        master.run_command([
            "ipa", "automountkey-add", "baltimore", "auto.master",
            "--key=/share", "--info=auto.share"
        ])
        result = master.run_command([
            "ipa", "automountkey-mod", "baltimore", "auto.master",
            "--key=/share", "--rename=/ipashare",
            "--info=auto.share", "--newinfo=auto.ipashare", "--all"
        ])
        out = result.stdout_text

        assert "Key: /ipashare" in out
        assert "Mount information: auto.ipashare" in out
        assert "description: /ipashare" in out
        assert "objectclass: automount, top" in out
        master.run_command(["ipa", "automountlocation-del", "baltimore"])

    def test_automountkey_mod_003(self):
        master = self.master
        kinit_admin(master)

        master.run_command(["ipa", "automountlocation-add", "baltimore"])
        master.run_command([
            "ipa", "automountkey-add", "baltimore", "auto.master",
            "--key=/share", "--info=auto.share"
        ])
        result = master.run_command([
            "ipa", "automountkey-mod", "baltimore", "auto.master",
            "--key=/share", "--rename=/ipashare", "--info=auto.share",
            "--newinfo=auto.ipashare", "--all", "--raw"
        ])
        out = result.stdout_text

        assert "automountkey: /ipashare" in out
        assert "automountinformation: auto.ipashare" in out
        assert "description: /ipashare" in out
        assert "objectClass: automount" in out
        assert "objectClass: top" in out

        master.run_command(["ipa", "automountlocation-del", "baltimore"])

    def test_automountkey_mod_004(self):
        master = self.master
        kinit_admin(master)

        master.run_command(["ipa", "automountlocation-add", "baltimore"])
        master.run_command([
            "ipa", "automountkey-add", "baltimore", "auto.master",
            "--key=/share", "--info=auto.share"
        ])
        result = master.run_command([
            "ipa", "automountkey-mod", "baltimore", "auto.master",
            "--key=/share", "--rename=/ipashare", "--info=auto.share",
            "--newinfo=auto.ipashare", "--all", "--raw", "--rights"
        ])
        out = result.stdout_text

        assert "automountkey: /ipashare" in out
        assert "automountinformation: auto.ipashare" in out
        assert "attributelevelrights: {'automountkey': 'rscwo', 'automountinformation': 'rscwo', 'objectclass': 'rscwo', 'description': 'rscwo', 'aci': 'rscwo', 'nsaccountlock': 'rscwo'}" in out
        assert "description: /ipashare" in out
        assert "objectClass: automount" in out
        assert "objectClass: top" in out

        master.run_command(["ipa", "automountlocation-del", "baltimore"])

    def test_automountkey_find_001(self):
        master = self.master
        kinit_admin(master)

        master.run_command(["ipa", "automountlocation-add", "baltimore"])
        master.run_command([
            "ipa", "automountkey-add", "baltimore", "auto.master",
            "--key=/share", "--info=auto.share"
        ])
        result = master.run_command([
            "ipa", "automountkey-find", "baltimore", "auto.master"
        ])
        out = result.stdout_text

        assert "2 automount keys matched" in out
        assert "Key: /-" in out
        assert "Mount information: auto.direct" in out
        assert "Key: /share" in out
        assert "Mount information: auto.share" in out

    def test_automountkey_find_002(self):
        master = self.master
        kinit_admin(master)

        result = master.run_command([
            "ipa", "automountkey-find", "baltimore", "auto.master",
            "--all"
        ])
        out = result.stdout_text

        assert "2 automount keys matched" in out
        assert f"dn: description=/- auto.direct,automountmapname=auto.master,cn=baltimore,cn=automount,{master.domain.basedn}" in out
        assert "Key: /-" in out
        assert "Mount information: auto.direct" in out
        assert "description: /- auto.direct" in out
        assert "objectclass: automount, top" in out
        assert f"dn: description=/share,automountmapname=auto.master,cn=baltimore,cn=automount,{master.domain.basedn}" in out
        assert "Key: /share" in out
        assert "Mount information: auto.share" in out
        assert "description: /share" in out
        assert "objectclass: automount, top" in out
        assert "Number of entries returned 2" in out

    def test_automountkey_find_003(self):
        master = self.master
        kinit_admin(master)

        result = master.run_command([
            "ipa", "automountkey-find", "baltimore", "auto.master",
            "--all"
        ])
        out = result.stdout_text

        assert "2 automount keys matched" in out
        assert f"dn: description=/- auto.direct,automountmapname=auto.master,cn=baltimore,cn=automount,{master.domain.basedn}" in out
        assert "automountkey: /-" in out
        assert "automountinformation: auto.direct" in out
        assert "description: /- auto.direct" in out
        assert "objectClass: automount" in out
        assert "objectClass: top" in out
        assert f"dn: description=/share,automountmapname=auto.master,cn=baltimore,cn=automount,{master.domain.basedn}" in out
        assert "automountkey: /share" in out
        assert "automountinformation: auto.share" in out
        assert "description: /share" in out
        assert "objectClass: automount" in out
        assert "objectClass: top" in out

    def test_automountkey_find_004(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command([
            "ipa", "automountkey-find", "baltimore", "auto.master",
            "--all", "--sizelimit=1"
        ])
        out = result.stdout_text
        assert "1 automount key matched" in out
        assert (
            f"dn: description=/- auto.direct,automountmapname=auto.master,"
            f"cn=baltimore,cn=automount,{master.domain.basedn}" in out
        )
        assert "Key: /-" in out
        assert "Mount information: auto.direct" in out
        assert "description: /- auto.direct" in out
        assert "objectclass: automount, top" in out
        assert "Number of entries returned 1" in out

    def test_automountkey_find_005(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command([
            "ipa", "automountkey-find", "baltimore", "auto.master",
            "--all", "--key=/share"
        ])
        out = result.stdout_text
        assert "1 automount key matched" in out
        assert "Key: /share" in out
        assert "Mount information: auto.share" in out
        assert "Number of entries returned 1" in out

    def test_automountkey_find_006(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command([
            "ipa", "automountkey-find", "baltimore", "auto.master",
            "--all", "--info=auto.share"
        ])
        out = result.stdout_text
        assert "1 automount key matched" in out
        assert "Key: /share" in out
        assert "Mount information: auto.share" in out
        assert "Number of entries returned 1" in out

    def test_automountkey_show_001(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command([
            "ipa", "automountkey-show", "baltimore", "auto.master",
            "--key=/share"
        ])
        out = result.stdout_text
        assert "Key: /share" in out
        assert "Mount information: auto.share" in out

    def test_automountkey_show_002(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command([
            "ipa", "automountkey-show", "baltimore", "auto.master",
            "--key=/share", "--info=auto.share"
        ])
        out = result.stdout_text
        assert "Key: /share" in out
        assert "Mount information: auto.share" in out

    def test_automountkey_show_003(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command([
            "ipa", "automountkey-show", "baltimore", "auto.master",
            "--key=/share", "--info=auto.share", "--all"
        ])
        out = result.stdout_text
        assert (
            f"dn: description=/share,automountmapname=auto.master,"
            f"cn=baltimore,cn=automount,{master.domain.basedn}" in out
        )
        assert "Key: /share" in out
        assert "Mount information: auto.share" in out
        assert "description: /share" in out
        assert "objectclass: automount, top" in out

    def test_automountkey_show_004(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command([
            "ipa", "automountkey-show", "baltimore", "auto.master",
            "--key=/share", "--info=auto.share", "--all", "--raw"
        ])
        out = result.stdout_text
        assert (
            f"dn: description=/share,automountmapname=auto.master,"
            f"cn=baltimore,cn=automount,{master.domain.basedn}" in out
        )
        assert "automountkey: /share" in out
        assert "automountinformation: auto.share" in out
        assert "description: /share" in out
        assert "objectClass: automount" in out
        assert "objectClass: top" in out

    def test_automountkey_show_005(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command([
            "ipa", "automountkey-show", "baltimore", "auto.master",
            "--key=/share", "--info=auto.share", "--all", "--raw",
            "--rights"
        ])
        out = result.stdout_text
        assert (
            f"dn: description=/share,automountmapname=auto.master,"
            f"cn=baltimore,cn=automount,{master.domain.basedn}" in out
        )
        assert "automountkey: /share" in out
        assert "automountinformation: auto.share" in out
        assert (
            "attributelevelrights: {'automountkey': 'rscwo', "
            "'automountinformation': 'rscwo', 'objectclass': 'rscwo', "
            "'description': 'rscwo', 'aci': 'rscwo', "
            "'nsaccountlock': 'rscwo'}" in out
        )
        assert "description: /share" in out
        assert "objectClass: automount" in out
        assert "objectClass: top" in out

        master.run_command(["ipa", "automountlocation-del", "baltimore"])

    def test_automount_location_del_001(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "pune"])
        result = master.run_command(["ipa", "automountlocation-del", "pune"])
        assert 'Deleted automount location "pune"' in result.stdout_text

    def test_automount_location_del_002(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "pune"])
        master.run_command(["ipa", "automountlocation-del", "pune"])
        # Verify LDAP entries exist
        result = ldapsearch_dm(
            self.master,
            f"cn=pune,cn=automount,{master.domain.basedn}",
            ldap_args=[],
            scope="sub",
            raiseonerr=False
        )
        out = result.stdout_text
        assert f"dn: cn=pune,cn=automount,{master.domain.basedn}" not in out
        assert "automountMapName: auto.master" not in out
        assert "automountMapName: auto.direct" not in out
        assert "automountKey: /-" not in out
        assert "automountInformation: auto.direct" not in out

    def test_automountkey_del(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "baltimore"])
        master.run_command([
            "ipa", "automountkey-add", "baltimore", "auto.master",
            "--key=/share", "--info=-rw"
        ])
        result = master.run_command([
            "ipa", "automountkey-del", "baltimore", "auto.master",
            "--key=/share", "--info=-rw"
        ])
        assert 'Deleted automount key "/share"' in result.stdout_text

        result = master.run_command([
            "ipa", "automountkey-del", "baltimore", "auto.master",
            "--key=/share", "--info=-rw"
        ], raiseonerr=False)
        assert "ipa: ERROR: no matching entry found" in result.stderr_text

        master.run_command(["ipa", "automountlocation-del", "baltimore"])

    def test_automountmap_del(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "baltimore"])
        master.run_command(["ipa", "automountmap-add", "baltimore", "auto.map1"])
        master.run_command(["ipa", "automountmap-add", "baltimore", "auto.map2"])

        result = master.run_command([
            "ipa", "automountmap-del", "baltimore", "auto.map1"
        ])
        assert 'Deleted automount map "auto.map1"' in result.stdout_text

        result = master.run_command([
            "ipa", "automountmap-del", "baltimore", "auto.map1", "auto.map2"
        ], raiseonerr=False)
        assert "ipa: ERROR: auto.map1: automount map not found" in result.stderr_text

        result = master.run_command([
            "ipa", "automountmap-del", "baltimore",
            "auto.map1", "auto.map2", "--continue"
        ])
        out = result.stdout_text
        assert 'Deleted automount map "auto.map2"' in out
        assert "Failed to remove: auto.map1" in out

    def test_bz725433(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-del", "baltimore"],
                           raiseonerr=False)
        master.run_command(["ipa", "automountlocation-add", "baltimore"])
        master.run_command(["ipa", "automountmap-add", "baltimore", "auto.share"])
        master.run_command([
            "ipa", "automountkey-add", "baltimore", "auto.master",
            "--key=/share", "--info=auto.share"
        ])
        master.run_command([
            "ipa", "automountmap-add-indirect", "baltimore", "auto.share2",
            "--mount=/usr/share/man"
        ])
        master.run_command([
            "ipa", "automountmap-add-indirect", "baltimore", "auto.share3",
            "--mount=/usr/share/man"
        ], raiseonerr=False)

        result = master.run_command([
            "ldapsearch", "-LLL", "-x", "-h", "localhost",
            "-D", "cn=Directory Manager", "-w", "Secret123",
            "-b", master.domain.basedn,
            "(&(objectclass=automountmap)(automountMapName=auto.share3))"
        ], raiseonerr=False)
        assert "auto.share3" not in result.stdout_text

        master.run_command(["ipa", "automountlocation-del", "baltimore"])

    def test_bz726725(self):
        master = self.master
        kinit_admin(master)
        master.run_command(["ipa", "automountlocation-add", "pune"])

        result = master.run_command(
            ["ipa", "automountkey-add", "pune"], raiseonerr=False
        )
        assert "ipa: ERROR: 'automountmap' is required" in result.stderr_text

        result = master.run_command(
            ["ipa", "automountkey-del", "pune"], raiseonerr=False
        )
        assert "ipa: ERROR: 'automountmap' is required" in result.stderr_text

        result = master.run_command(
            ["ipa", "automountkey-mod", "pune"], raiseonerr=False
        )
        assert "ipa: ERROR: 'automountmap' is required" in result.stderr_text

        result = master.run_command(
            ["ipa", "automountkey-find", "pune"], raiseonerr=False
        )
        assert "ipa: ERROR: 'automountmap' is required" in result.stderr_text

        result = master.run_command(
            ["ipa", "automountkey-show", "pune"], raiseonerr=False
        )
        assert "ipa: ERROR: 'automountmap' is required" in result.stderr_text

        master.run_command(["ipa", "automountlocation-del", "pune"])

    def test_bz726722(self):
        master = self.master
        kinit_admin(master)

        result = master.run_command(["ipa", "automountmap-add"],
                                    raiseonerr=False)
        assert "ipa: ERROR: 'automountlocation' is required" in result.stderr_text

        result = master.run_command(["ipa", "automountkey-add"],
                                    raiseonerr=False)
        assert "ipa: ERROR: 'automountlocation' is required" in result.stderr_text

        result = master.run_command(["ipa", "automountmap-del"],
                                    raiseonerr=False)
        assert "ipa: ERROR: 'automountlocation' is required" in result.stderr_text

        result = master.run_command(["ipa", "automountkey-del"],
                                    raiseonerr=False)
        assert "ipa: ERROR: 'automountlocation' is required" in result.stderr_text


class TestAutomount_Functional(IntegrationTest):
    """
    Test Automount Functional
    """
    @classmethod
    def install(cls, mh):
        super(TestAutomount_Functional, cls).install(mh)
        install_master(cls.master, setup_dns=True)
        kinit_admin(cls.master)
        cls.user_password = "Secret123!"
        for i in range(1, 3):
            username = f"testuser{i}"
            create_active_user(
                cls.master,
                username,
                password=cls.user_password
            )
        # Setup /etc/sysconfig/autofs & /etc/autofs_ldap_auth.conf
        conf = textwrap.dedent(f"""\
        <?xml version="1.0" ?>
        <!--
        This file contains a single entry with multiple attributes tied to it.
        See autofs_ldap_auth.conf(5) for more information.
        -->
        <autofs_ldap_sasl_conf
            usetls="no"
            tlsrequired="no"
            authrequired="yes"
            authtype="GSSAPI"
            clientprinc="host/{cls.master.hostname}@{cls.master.domain.realm}"
        />
        """)
        cls.master.put_file_contents("/etc/autofs_ldap_auth.conf", conf)
        cls.master.run_command(["cat", "/etc/autofs_ldap_auth.conf"])

        conf = textwrap.dedent(f"""\
        TIMEOUT=60
        BROWSE_MODE="no"
        MOUNT_NFS_DEFAULT_PROTOCOL=4
        LOGGING="debug"
        LDAP_URI="ldap://{cls.master.hostname}"
        SEARCH_BASE="cn=loc1,cn=automount,{cls.master.domain.basedn}"
        MAP_OBJECT_CLASS="automountMap"
        ENTRY_OBJECT_CLASS="automount"
        MAP_ATTRIBUTE="automountMapName"
        ENTRY_ATTRIBUTE="automountKey"
        VALUE_ATTRIBUTE="automountInformation"
        AUTH_CONF_FILE="/etc/autofs_ldap_auth.conf"
        """)
        cls.master.put_file_contents("/etc/sysconfig/autofs", conf)
        cls.master.run_command(["cat", "/etc/sysconfig/autofs"])

        # setting up nfs and automount maps
        # /etc/exports
        exports_conf = textwrap.dedent("""\
        /ipashare       *(rw,fsid=0,insecure,no_root_squash,sync,anonuid=65534,anongid=65534)
        /share          *(rw,fsid=0,insecure,no_root_squash,sync,anonuid=65534,anongid=65534)
        """)
        cls.master.put_file_contents("/etc/exports", exports_conf)

        # /etc/auto.master
        auto_master_conf = textwrap.dedent("""\
        /-      /etc/auto.direct
        /ipashare       /etc/auto.loc1
        """)
        cls.master.put_file_contents("/etc/auto.master", auto_master_conf)

        # /etc/auto.direct
        auto_direct_conf = textwrap.dedent(f"""\
        /share  -rw,fsid=0,insecure,no_root_squash,sync,anonuid=65534,anongid=65534 {cls.master.hostname}:/usr/share/man
        """)
        cls.master.put_file_contents("/etc/auto.direct", auto_direct_conf)

        # /etc/auto.loc1
        auto_loc1_conf = textwrap.dedent(f"""\
        *       -rw,fsid=0,insecure,no_root_squash,sync,anonuid=65534,anongid=65534 {cls.master.hostname}:/tmp
        """)
        cls.master.put_file_contents("/etc/auto.loc1", auto_loc1_conf)

        cls.master.run_command(["mkdir", "/share", "/ipashare"])
        cls.master.run_command(
            ["sed", "-i", r"s/^automount:.*$/automount:  ldap nisplus sss/g", "/etc/nsswitch.conf"]
        )

        cls.master.run_command(["service", "nfs-server", "restart"])
        cls.master.run_command(["service", "autofs", "restart"])
        cls.master.run_command(["showmount", "-e", f"{cls.master.hostname}"])

    def test_001_automountlocation_add_func(self):
        master = self.master
        kinit_admin(self.master)
        # Add automount location
        master.run_command(["ipa", "automountlocation-add", "loc1"])

        # Verify LDAP entries exist
        result = ldapsearch_dm(
            self.master,
            f"cn=loc1,cn=automount,{master.domain.basedn}",
            ldap_args=[],
            scope="sub"
        )
        out = result.stdout_text
        assert f"dn: cn=loc1,cn=automount,{master.domain.basedn}" in out
        assert "objectClass: nscontainer" in out
        assert "cn: loc1" in out
        assert "objectClass: automountmap" in out
        assert "automountMapName: auto.master" in out
        assert "objectClass: automount" in out
        assert "automountInformation: auto.direct" in out
        assert "automountKey: /-" in out

        # Clean up
        master.run_command(["ipa", "automountlocation-del", "loc1"])

    def test_002_automountlocation_del_func(self):
        master = self.master
        kinit_admin(master)

        # Add location
        master.run_command(["ipa", "automountlocation-add", "loc1"])

        # Delete location
        master.run_command(["ipa", "automountlocation-del", "loc1"])

        # Verify LDAP entries exist
        result = ldapsearch_dm(
            self.master,
            f"cn=loc1,cn=automount,{master.domain.basedn}",
            ldap_args=[],
            scope="sub",
            raiseonerr=False
        )
        out = result.stdout_text
        assert f"dn: cn=loc1,cn=automount,{master.domain.basedn}" not in out
        assert "objectClass: nscontainer" not in out
        assert "cn: loc1" not in out
        assert "objectClass: automountmap" not in out
        assert "automountMapName: auto.master" not in out
        assert "objectClass: automount" not in out
        assert "automountInformation: auto.direct" not in out
        assert "automountKey: /-" not in out

    def test_003_automountlocation_import_func(self):
        master = self.master
        kinit_admin(master)

        # Add automount location
        master.run_command(["ipa", "automountlocation-add", "loc1"])

        # Import maps from /etc/auto.master
        result = master.run_command(
            ["ipa", "automountlocation-import", "loc1", "/etc/auto.master"],
            raiseonerr=True
        )
        out = result.stdout_text

        # Verify expected output strings
        assert "Imported maps:" in out
        assert "Added auto.loc1" in out
        assert "Imported keys:" in out
        assert "Added /ipashare to auto.master" in out
        assert "Added * to auto.loc1" in out
        assert "Added /share to auto.direct" in out

        # Verify ipa automountlocation-tofiles output
        result = master.run_command(
            ["ipa", "automountlocation-tofiles", "loc1"],
            raiseonerr=True
        )
        out = result.stdout_text
        assert "/etc/auto.master:" in out
        assert "/etc/auto.direct:" in out
        assert "/etc/auto.loc1:" in out
        assert "/ipashare" in out or "/etc/auto.loc1" in out
        assert "share" in out or "rw,fsid=0,insecure,no_root_squash,sync,anonuid=65534,anongid=65534" in out or f"{master.hostname}:/usr/share/man" in out
        assert "/etc/auto.loc1:" in out
        assert "*" in out or "rw,fsid=0,insecure,no_root_squash,sync,anonuid=65534,anongid=65534" in out or f"{master.hostname}:/tmp" in out

        # Verify LDAP entries exist
        ldap_bases = [
            f"cn=loc1,cn=automount,{master.domain.basedn}",
            f"automountmapname=auto.loc1,cn=loc1,cn=automount,{master.domain.basedn}",
            f"description=/share,automountmapname=auto.direct,cn=loc1,cn=automount,{master.domain.basedn}",
            f"description=/ipashare,automountmapname=auto.master,cn=loc1,cn=automount,{master.domain.basedn}",
            f"description=/- auto.direct,automountmapname=auto.master,cn=loc1,cn=automount,{master.domain.basedn}",
        ]
        for base in ldap_bases:
            result = ldapsearch_dm(
                master,
                base,
                ldap_args=[],
                scope="sub",
                raiseonerr=True
            )
            # all of these should exist after import
            assert result.returncode == 0

        # Cleanup
        result = master.run_command(["ipa", "automountlocation-del", "loc1"])
        assert "Deleted automount location \"loc1\"" in result.stdout_text
        master.run_command(["rm", "-f", "/etc/auto.master", "/etc/auto.direct", "/etc/auto.loc1"])

    def test_004_automountmap_add_func(self):
        master = self.master
        kinit_admin(master)
        # add location
        result = master.run_command(["ipa", "automountlocation-add", "loc1"])
        assert "Added automount location \"loc1\"" in result.stdout_text

        # add map
        result = master.run_command(["ipa", "automountmap-add", "loc1", "auto.loc1"])
        assert "Added automount map \"auto.loc1\"" in result.stdout_text
        # ldapsearch verify
        result = ldapsearch_dm(
            self.master,
            f"automountmapname=auto.loc1,cn=loc1,cn=automount,{master.domain.basedn}",
            ldap_args=[],
            scope="sub",
            raiseonerr=True
        )
        out = result.stdout_text
        assert "objectClass: automountmap" in out
        assert "automountMapName: auto.loc1" in out

        # cleanup location (this removes map too)
        result = master.run_command(["ipa", "automountlocation-del", "loc1"])
        assert "Deleted automount location \"loc1\"" in result.stdout_text

    def test_005_automountmap_del_func(self):
        master = self.master
        kinit_admin(master)
        # Add location
        result = master.run_command(["ipa", "automountlocation-add", "loc1"])
        assert "Added automount location \"loc1\"" in result.stdout_text

        # Add map
        result = master.run_command(["ipa", "automountmap-add", "loc1", "auto.loc1"])
        assert "Added automount map \"auto.loc1\"" in result.stdout_text

        # Verify map exists in LDAP
        result = ldapsearch_dm(
            self.master,
            f"automountmapname=auto.loc1,cn=loc1,cn=automount,{master.domain.basedn}",
            ldap_args=[],
            scope="sub",
            raiseonerr=True
        )
        out = result.stdout_text
        assert "objectClass: automountmap" in out
        assert "automountMapName: auto.loc1" in out

        # Delete location (removes map as well)
        result = master.run_command(["ipa", "automountlocation-del", "loc1"])
        assert "Deleted automount location \"loc1\"" in result.stdout_text

        # Verify map is gone (expect rc=32 → no such object)
        result = ldapsearch_dm(
            self.master,
            f"automountmapname=auto.loc1,cn=loc1,cn=automount,{master.domain.basedn}",
            ldap_args=[],
            scope="sub",
            raiseonerr=False
        )
        assert result.returncode == 32

    def test_006_automountmap_mod_func(self):
        master = self.master
        kinit_admin(master)
        result = master.run_command(["ipa", "automountlocation-add", "loc1"])
        assert "Added automount location \"loc1\"" in result.stdout_text

        result = master.run_command(["ipa", "automountmap-add", "loc1", "auto.loc1"])
        assert "Added automount map \"auto.loc1\"" in result.stdout_text

        # Testing --desc option
        result = master.run_command(["ipa", "automountmap-mod", "loc1", "auto.loc1", "--desc=loc1"])
        assert "Modified automount map \"auto.loc1\"" in result.stdout_text

        result = ldapsearch_dm(
            self.master,
            f"automountmapname=auto.loc1,cn=loc1,cn=automount,{master.domain.basedn}",
            ldap_args=[],
            scope="sub",
            raiseonerr=True
        )
        out = result.stdout_text
        assert "objectClass: automountmap" in out
        assert "automountMapName: auto.loc1" in out
        assert "description: loc1" in out

        # Testing --setattr
        result = master.run_command(["ipa", "automountmap-mod", "loc1", "auto.loc1", "--setattr=description=testmod"])
        assert "Modified automount map \"auto.loc1\"" in result.stdout_text

        result = ldapsearch_dm(
            self.master,
            f"automountmapname=auto.loc1,cn=loc1,cn=automount,{master.domain.basedn}",
            ldap_args=[],
            scope="sub",
            raiseonerr=True
        )
        out = result.stdout_text
        assert "objectClass: automountmap" in out
        assert "automountMapName: auto.loc1" in out
        assert "description: testmod" in out

        # Testing --addattr
        result = master.run_command(["ipa", "automountmap-mod", "loc1", "auto.loc1", "--setattr=description="])
        assert "Modified automount map \"auto.loc1\"" in result.stdout_text

        result = ldapsearch_dm(
            self.master,
            f"automountmapname=auto.loc1,cn=loc1,cn=automount,{master.domain.basedn}",
            ldap_args=[],
            scope="sub",
            raiseonerr=True
        )
        out = result.stdout_text
        assert "description: testmod" not in out

        result = master.run_command(["ipa", "automountmap-mod", "loc1", "auto.loc1", "--addattr=description=testmod"])
        assert "Modified automount map \"auto.loc1\"" in result.stdout_text

        result = ldapsearch_dm(
            self.master,
            f"automountmapname=auto.loc1,cn=loc1,cn=automount,{master.domain.basedn}",
            ldap_args=[],
            scope="sub",
            raiseonerr=True
        )
        out = result.stdout_text
        assert "description: testmod" in out

        # Testing --all --raw --rights
        result = master.run_command(["ipa", "automountmap-mod", "loc1", "auto.loc1", "--setattr=description="])
        assert "Modified automount map \"auto.loc1\"" in result.stdout_text

        result = ldapsearch_dm(
            self.master,
            f"automountmapname=auto.loc1,cn=loc1,cn=automount,{master.domain.basedn}",
            ldap_args=[],
            scope="sub",
            raiseonerr=True
        )
        out = result.stdout_text
        assert "description: testmod" not in out

        result = master.run_command(["ipa", "automountmap-mod", "loc1", "auto.loc1", "--addattr=description=testmod", "--all", "--rights", "--raw"])
        assert "Modified automount map \"auto.loc1\"" in result.stdout_text
        assert "automountmapname: auto.loc1" in result.stdout_text
        assert "description: testmod" in result.stdout_text
        assert "attributelevelrights: {'automountmapname': 'rscwo', 'objectclass': 'rscwo', 'description': 'rscwo', 'aci': 'rscwo', 'nsaccountlock': 'rscwo'}" in result.stdout_text
        assert "objectClass: automountmap" in result.stdout_text
        assert "objectClass: top" in result.stdout_text

        # cleanup location (this removes map too)
        result = master.run_command(["ipa", "automountlocation-del", "loc1"])
        assert "Deleted automount location \"loc1\"" in result.stdout_text

    def test_007_direct_mount_functionality(self):
        master = self.master
        kinit_admin(master)

        result = master.run_command(["ipa", "automountlocation-add", "loc1"])
        assert "Added automount location \"loc1\"" in result.stdout_text

        result = master.run_command([
        "ipa", "automountkey-add", "loc1", "auto.direct",
        "--key=/share",
        "--info=-rw,fsid=0,insecure,no_root_squash,sync,anonuid=65534,anongid=65534 " +
                 f"{master.hostname}:/usr/share/man"
        ])
        assert "Added automount key \"/share\"" in result.stdout_text

        result = master.run_command(["ipa", "automountlocation-tofiles", "loc1"])

        result = master.run_command(["touch", "/usr/share/man/test"])

        # Clear /var/log/messages
        master.run_command(['truncate', '-s', '0', '/var/log/messages'])

        result = master.run_command(["service", "autofs", "restart"])
        result = master.run_command(["service", "nfs-server", "restart"])
        time.sleep(5)  # wait for autofs to restart

        result = master.run_command(["ls", "/share/test"])
        assert "/share/test" in result.stdout_text or result.returncode == 0

        var_logs = master.get_file_contents("/var/log/messages")
        assert "mount(nfs): /share is local, attempt bind mount".encode() in var_logs
        assert "mount(bind): calling mount --bind -o defaults /usr/share/man /share".encode() in var_logs
        assert "mount(bind): mounted /usr/share/man type bind on /share".encode() in var_logs
        assert f"mounting root /share, mountpoint /share, what {master.hostname}:/usr/share/man, fstype nfs, options rw,fsid=0,insecure,no_root_squash,sync,anonuid=65534,anongid=65534".encode() in var_logs

        # cleanup location (this removes map too)
        result = master.run_command(["ipa", "automountlocation-del", "loc1"])
        assert "Deleted automount location \"loc1\"" in result.stdout_text
