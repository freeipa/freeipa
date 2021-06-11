# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import, print_function

import os
import sqlite3

from custodia.plugin import CSStore, CSStoreError, CSStoreExists
from custodia.plugin import PluginOption, REQUIRED


class SqliteStore(CSStore):
    dburi = PluginOption(str, REQUIRED, None)
    table = PluginOption(str, "CustodiaSecrets", None)
    filemode = PluginOption(oct, '600', None)

    def __init__(self, config, section):
        super(SqliteStore, self).__init__(config, section)
        # Initialize the DB by trying to create the default table
        try:
            conn = sqlite3.connect(self.dburi)
            os.chmod(self.dburi, self.filemode)
            with conn:
                c = conn.cursor()
                self._create(c)
        except sqlite3.Error:
            self.logger.exception("Error creating table %s", self.table)
            raise CSStoreError('Error occurred while trying to init db')

    def get(self, key):
        self.logger.debug("Fetching key %s", key)
        query = "SELECT value from %s WHERE key=?" % self.table
        try:
            conn = sqlite3.connect(self.dburi)
            c = conn.cursor()
            r = c.execute(query, (key,))
            value = r.fetchall()
        except sqlite3.Error:
            self.logger.exception("Error fetching key %s", key)
            raise CSStoreError('Error occurred while trying to get key')
        self.logger.debug("Fetched key %s got result: %r", key, value)
        if len(value) > 0:
            return value[0][0]
        else:
            return None

    def _create(self, cur):
        create = "CREATE TABLE IF NOT EXISTS %s " \
                 "(key PRIMARY KEY UNIQUE, value)" % self.table
        cur.execute(create)

    def set(self, key, value, replace=False):
        self.logger.debug("Setting key %s to value %s (replace=%s)",
                          key, value, replace)
        if key.endswith('/'):
            raise ValueError('Invalid Key name, cannot end in "/"')
        if replace:
            query = "INSERT OR REPLACE into %s VALUES (?, ?)"
        else:
            query = "INSERT into %s VALUES (?, ?)"
        setdata = query % (self.table,)
        try:
            conn = sqlite3.connect(self.dburi)
            with conn:
                c = conn.cursor()
                self._create(c)
                c.execute(setdata, (key, value))
        except sqlite3.IntegrityError as err:
            raise CSStoreExists(str(err))
        except sqlite3.Error as err:
            self.logger.exception("Error storing key %s", key)
            raise CSStoreError('Error occurred while trying to store key')

    def span(self, key):
        name = key.rstrip('/')
        self.logger.debug("Creating container %s", name)
        query = "INSERT into %s VALUES (?, '')"
        setdata = query % (self.table,)
        try:
            conn = sqlite3.connect(self.dburi)
            with conn:
                c = conn.cursor()
                self._create(c)
                c.execute(setdata, (name,))
        except sqlite3.IntegrityError as err:
            raise CSStoreExists(str(err))
        except sqlite3.Error:
            self.logger.exception("Error creating key %s", name)
            raise CSStoreError('Error occurred while trying to span container')

    def list(self, keyfilter=''):
        path = keyfilter.rstrip('/')
        self.logger.debug("Listing keys matching %s", path)
        child_prefix = path if path == '' else path + '/'
        search = "SELECT key, value FROM %s WHERE key LIKE ?" % self.table
        key = "%s%%" % (path,)
        try:
            conn = sqlite3.connect(self.dburi)
            r = conn.execute(search, (key,))
            rows = r.fetchall()
        except sqlite3.Error:
            self.logger.exception("Error listing %s: [%r]", keyfilter)
            raise CSStoreError('Error occurred while trying to list keys')
        self.logger.debug("Searched for %s got result: %r", path, rows)
        if len(rows) > 0:
            parent_exists = False
            result = list()
            for key, value in rows:
                if key == path or key == child_prefix:
                    parent_exists = True
                    continue
                if not key.startswith(child_prefix):
                    continue
                result_value = key[len(child_prefix):].lstrip('/')
                if not value:
                    result.append(result_value + '/')
                else:
                    result.append(result_value)
            if result:
                self.logger.debug("Returning sorted values %r", result)
                return sorted(result)
            elif parent_exists:
                self.logger.debug("Returning empty list")
                return []
        elif keyfilter == '':
            self.logger.debug("Returning empty list")
            return []
        self.logger.debug("Returning 'Not Found'")
        return None

    def cut(self, key):
        self.logger.debug("Removing key %s", key)
        query = "DELETE from %s WHERE key=?" % self.table
        try:
            conn = sqlite3.connect(self.dburi)
            with conn:
                c = conn.cursor()
                r = c.execute(query, (key,))
        except sqlite3.Error:
            self.logger.error("Error removing key %s", key)
            raise CSStoreError('Error occurred while trying to cut key')
        self.logger.debug("Key %s %s", key,
                          "removed" if r.rowcount > 0 else "not found")
        if r.rowcount > 0:
            return True
        return False
