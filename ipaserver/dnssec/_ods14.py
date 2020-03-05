#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

import socket

from ipaserver.dnssec._odsbase import AbstractODSDBConnection
from ipaserver.dnssec._odsbase import AbstractODSSignerConn
from ipaserver.dnssec._odsbase import ODS_SE_MAXLINE


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
