
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

DIRSRV_CONFIG_MODS = """
# https://fedorahosted.org/freeipa/ticket/4949
dn: cn=config,cn=ldbm database,cn=plugins,cn=config
changetype: modify
replace: nsslapd-db-locks
nsslapd-db-locks: 100000

# https://fedorahosted.org/freeipa/ticket/1930
dn: cn=config
changetype: modify
replace: nsslapd-allow-unauthenticated-binds
nsslapd-allow-unauthenticated-binds: off
-
replace: nsslapd-require-secure-binds
nsslapd-require-secure-binds: off
-
replace: nsslapd-allow-anonymous-access
nsslapd-allow-anonymous-access: off
-
replace: nsslapd-minssf
nsslapd-minssf: 0

# https://fedorahosted.org/freeipa/ticket/4048
dn: cn=config
changetype: modify
replace: nssslapd-maxbersize
nssslapd-maxbersize: 209715201

dn: cn=userRoot,cn=ldbm database,cn=plugins,cn=config
changetype: modify
replace: nsslapd-cachememsize
nsslapd-cachememsize: 10485761

dn: cn=config,cn=ldbm database,cn=plugins,cn=config
changetype: modify
replace: nsslapd-import_cachesize
nsslapd-import_cachesize: 20000001
-
replace: nsslapd-dbcachesize
nsslapd-dbcachesize: 10000001
"""

CONFIG_LDIF_PATH = "/root/dirsrv-config-mod.ldif"


class TestCustomDSConfigInstall(IntegrationTest):
    """Install master and replica with custom DS config
    """
    topology = 'star'
    num_replicas = 1

    @classmethod
    def install(cls, mh):
        # just prepare LDIF file on both master and replica
        cls.master.put_file_contents(CONFIG_LDIF_PATH, DIRSRV_CONFIG_MODS)
        cls.replicas[0].put_file_contents(CONFIG_LDIF_PATH,
                                          DIRSRV_CONFIG_MODS)

    def test_customized_ds_install_master(self):
        tasks.install_master(self.master, setup_dns=False, extra_args=[
            '--dirsrv-config-file', CONFIG_LDIF_PATH
        ])

    def test_customized_ds_install_replica(self):
        tasks.install_replica(
            self.master, self.replicas[0], setup_ca=False,
            extra_args=['--dirsrv-config-file', CONFIG_LDIF_PATH])
