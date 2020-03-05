#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

from datetime import datetime

from ipaserver.dnssec._odsbase import AbstractODSDBConnection
from ipaserver.dnssec._odsbase import AbstractODSSignerConn
from ipaserver.dnssec._odsbase import ODS_SE_MAXLINE

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
            "hsmk.keyType, hsmk.state "
            "FROM hsmKey AS hsmk "
            "JOIN keyData AS kd ON hsmk.id = kd.hsmKeyId "
            "WHERE kd.zoneId = ?", (zone_id,))
        for row in cur:
            key = dict()
            key['HSMkey_id'] = row['locator']
            key['generate'] = str(datetime.fromtimestamp(row['inception']))
            key['algorithm'] = row['algorithm']
            key['publish'] = key['generate']
            key['active'] = None
            key['retire'] = None
            key['dead'] = None
            if row['keyType'] == 2:
                key['keytype'] = 256
            elif row['keyType'] == 1:
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
