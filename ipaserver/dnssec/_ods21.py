#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

import os

from ipaserver.dnssec._odsbase import AbstractODSDBConnection
from ipaserver.dnssec._odsbase import AbstractODSSignerConn
from ipaserver.dnssec._odsbase import ODS_SE_MAXLINE
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipapython import ipautil

CLIENT_OPC_STDOUT = 0
CLIENT_OPC_EXIT = 4


class ODSDBConnection(AbstractODSDBConnection):
    def get_zones(self):
        cur = self._db.execute("SELECT name from zone")
        rows = cur.fetchall()
        return [row['name'] for row in rows]

    def get_zone_id(self, zone_name):
        cur = self._db.execute(
            "SELECT id FROM zone WHERE LOWER(name)=LOWER(?)",
            (zone_name,))
        rows = cur.fetchall()
        return [row[0] for row in rows]

    def get_keys_for_zone(self, zone_id):
        cur = self._db.execute(
            "SELECT hsmk.locator, hsmk.inception, hsmk.algorithm, "
            "hsmk.role, hsmk.state "
            "FROM hsmKey AS hsmk "
            "JOIN keyData AS kd ON hsmk.id = kd.hsmKeyId "
            "WHERE kd.zoneId = ?", (zone_id,))
        for row in cur:
            key = dict()
            key['HSMkey_id'] = row['locator']
            key['generate'] = ipautil.datetime_from_utctimestamp(
                row['inception'],
                units=1).replace(tzinfo=None).isoformat(
                    sep=' ', timespec='seconds')
            key['algorithm'] = row['algorithm']
            key['publish'] = key['generate']
            key['active'] = None
            key['retire'] = None
            key['dead'] = None
            if row['role'] == 2:
                key['keytype'] = 256
            elif row['role'] == 1:
                key['keytype'] = 257
            key['state'] = row['state']
            yield key


class ODSSignerConn(AbstractODSSignerConn):
    def read_cmd(self):
        msg = self._conn.recv(ODS_SE_MAXLINE)
        _opc = int(msg[0])
        msglen = int(msg[1]) << 8 + int(msg[2])
        cmd = msg[3:msglen - 1].strip()
        return cmd

    def send_reply_and_close(self, reply):
        prefix = bytearray([CLIENT_OPC_STDOUT, len(reply) >> 8,
                            len(reply) & 255])
        self._conn.sendall(prefix + reply)
        # 2nd message: CLIENT_OPC_EXIT, then len, msg len, exit code
        prefix = bytearray([CLIENT_OPC_EXIT, 0, 1, 0])
        self._conn.sendall(prefix)
        self._conn.close()


class ODSTask():
    def run_ods_setup(self):
        """Initialize a new kasp.db"""
        cmd = [paths.ODS_ENFORCER_DB_SETUP]
        return ipautil.run(cmd, stdin="y", runas=constants.ODS_USER)

    def run_ods_notify(self, **kwargs):
        """Notify ods-enforcerd to reload its conf."""
        cmd = [paths.ODS_ENFORCER, 'flush']

        # run commands as ODS user
        if os.geteuid() == 0:
            kwargs['runas'] = constants.ODS_USER

        return ipautil.run(cmd, **kwargs)

    def run_ods_policy_import(self, **kwargs):
        """Run OpenDNSSEC manager command to import policy."""
        cmd = [paths.ODS_ENFORCER, 'policy', 'import']

        # run commands as ODS user
        if os.geteuid() == 0:
            kwargs['runas'] = constants.ODS_USER
        ipautil.run(cmd, **kwargs)

    def run_ods_manager(self, params, **kwargs):
        """Run OpenDNSSEC manager command (ksmutil, enforcer)

        :param params: parameter for ODS command
        :param kwargs: additional arguments for ipautil.run()
        :return: result from ipautil.run()
        """
        assert params[0] != 'setup'

        cmd = [paths.ODS_ENFORCER]
        cmd.extend(params)

        # run commands as ODS user
        if os.geteuid() == 0:
            kwargs['runas'] = constants.ODS_USER

        return ipautil.run(cmd, **kwargs)
