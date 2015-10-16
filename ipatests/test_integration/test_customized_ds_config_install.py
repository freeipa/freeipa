
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration import tasks

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


class TestCustomInstallMaster(IntegrationTest):
    """
    Install master with customized DS config
    """
    topology = 'star'

    @classmethod
    def install(cls, mh):
        # just prepare LDIF file on both master and replica
        cls.master.put_file_contents(CONFIG_LDIF_PATH, DIRSRV_CONFIG_MODS)

    def test_customized_ds_install_master(self):
        args = [
            'ipa-server-install', '-U',
            '-r', self.master.domain.name,
            '-p', self.master.config.dirman_password,
            '-a', self.master.config.admin_password,
            '--dirsrv-config-file', CONFIG_LDIF_PATH,
        ]
        self.master.run_command(args)


class TestCustomInstallReplica(IntegrationTest):
    """
    Install replica with customized DS config
    """
    topology = 'star'
    num_replicas = 1

    @classmethod
    def install(cls, mh):
        # just prepare LDIF file on both master and replica
        cls.replicas[0].put_file_contents(CONFIG_LDIF_PATH, DIRSRV_CONFIG_MODS)
        tasks.install_master(cls.master)

    def test_customized_ds_install_replica(self):
        tasks.replica_prepare(self.master, self.replicas[0])
        replica_filename = tasks.get_replica_filename(self.replicas[0])
        args = ['ipa-replica-install', '-U',
                '-p', self.replicas[0].config.dirman_password,
                '-w', self.replicas[0].config.admin_password,
                '--ip-address', self.replicas[0].ip,
                '--dirsrv-config-file', CONFIG_LDIF_PATH,
                replica_filename]
        self.replicas[0].run_command(args)
