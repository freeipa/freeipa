#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

import six
import abc
import sqlite3
from ipaplatform.paths import paths

ODS_SE_MAXLINE = 1024  # from ODS common/config.h


@six.add_metaclass(abc.ABCMeta)
class AbstractODSDBConnection():
    """Abstract class representing the Connection to ODS database."""
    def __init__(self):
        """Creates a connection to the kasp database."""
        self._db = sqlite3.connect(paths.OPENDNSSEC_KASP_DB)
        self._db.row_factory = sqlite3.Row
        self._db.execute('BEGIN')

    @abc.abstractmethod
    def get_zones(self):
        """Returns a list of zone names."""

    @abc.abstractmethod
    def get_zone_id(self, zone_name):
        """Returns a list of zone ids for the given zone_name."""

    @abc.abstractmethod
    def get_keys_for_zone(self, zone_id):
        """Returns a list of keys for the given zone_id."""

    def close(self):
        """Closes the connection to the kasp database."""
        self._db.close()


@six.add_metaclass(abc.ABCMeta)
class AbstractODSSignerConn():
    """Abstract class representing the Connection to ods-signer."""
    def __init__(self, conn):
        """Initializes the object with a socket conn."""
        self._conn = conn

    @abc.abstractmethod
    def read_cmd(self):
        """Reads the next command on the connection."""

    @abc.abstractmethod
    def send_reply_and_close(self, reply):
        """Sends the reply on the connection."""
