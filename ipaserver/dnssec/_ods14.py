#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

import os
import socket

from ipapython import ipautil
from ipaserver.dnssec._odsbase import AbstractODSDBConnection
from ipaserver.dnssec._odsbase import AbstractODSSignerConn
from ipaserver.dnssec._odsbase import ODS_SE_MAXLINE
from ipaplatform.constants import constants
from ipaplatform.paths import paths


class ODSDBConnection(AbstractODSDBConnection):
    def get_zones(self):
        cur = self._db.execute("SELECT name from zones")
        rows = cur.fetchall()
        return [row['name'] for row in rows]

    def get_zone_id(self, zone_name):
        cur = self._db.execute(
            "SELECT id FROM zones WHERE LOWER(name)=LOWER(?)",
            (zone_name,))
        rows = cur.fetchall()
        return [row[0] for row in rows]

    def get_keys_for_zone(self, zone_id):
        cur = self._db.execute(
            "SELECT kp.HSMkey_id, kp.generate, kp.algorithm, "
            "dnsk.publish, dnsk.active, dnsk.retire, dnsk.dead, "
            "dnsk.keytype, dnsk.state "
            "FROM keypairs AS kp "
            "JOIN dnsseckeys AS dnsk ON kp.id = dnsk.keypair_id "
            "WHERE dnsk.zone_id = ?", (zone_id,))
        for row in cur:
            yield row


class ODSSignerConn(AbstractODSSignerConn):
    def read_cmd(self):
        cmd = self._conn.recv(ODS_SE_MAXLINE).strip()
        return cmd

    def send_reply_and_close(self, reply):
        self._conn.send(reply + b'\n')
        self._conn.shutdown(socket.SHUT_RDWR)
        self._conn.close()


class ODSTask():
    def run_ods_setup(self):
        """Initialize a new kasp.db"""
        cmd = [paths.ODS_KSMUTIL, 'setup']
        return ipautil.run(cmd, stdin="y", runas=constants.ODS_USER)

    def run_ods_notify(self, **kwargs):
        """Notify ods-enforcerd to reload its conf."""
        cmd = [paths.ODS_KSMUTIL, 'notify']

        # run commands as ODS user
        if os.geteuid() == 0:
            kwargs['runas'] = constants.ODS_USER

        return ipautil.run(cmd, **kwargs)

    def run_ods_policy_import(self, **kwargs):
        """Run OpenDNSSEC manager command to import policy."""
        # This step is needed with OpenDNSSEC 2.1 only
        return

    def run_ods_manager(self, params, **kwargs):
        """Run OpenDNSSEC manager command (ksmutil, enforcer)

        :param params: parameter for ODS command
        :param kwargs: additional arguments for ipautil.run()
        :return: result from ipautil.run()
        """
        assert params[0] != 'setup'

        cmd = [paths.ODS_KSMUTIL]
        cmd.extend(params)

        # run commands as ODS user
        if os.geteuid() == 0:
            kwargs['runas'] = constants.ODS_USER

        return ipautil.run(cmd, **kwargs)
