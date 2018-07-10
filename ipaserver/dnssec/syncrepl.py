# -*- coding: utf-8 -*-
#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#
"""
This script implements a syncrepl consumer which syncs data from server
to a local dict.
"""

import logging

import ldap
from ldap.cidict import cidict
from ldap.ldapobject import ReconnectLDAPObject
from ldap.syncrepl import SyncreplConsumer

logger = logging.getLogger(__name__)


class SyncReplConsumer(ReconnectLDAPObject, SyncreplConsumer):
    """
    Syncrepl Consumer interface
    """

    def __init__(self, *args, **kwargs):
        # Initialise the LDAP Connection first
        ldap.ldapobject.ReconnectLDAPObject.__init__(self, *args, **kwargs)
        # Now prepare the data store
        self.__data = cidict()
        self.__data['uuids'] = cidict()
        # We need this for later internal use
        self.__presentUUIDs = cidict()

    def close_db(self):
        # This is useless for dict
        pass

    def syncrepl_get_cookie(self):
        if 'cookie' in self.__data:
            cookie = self.__data['cookie']
            logger.debug('Current cookie is: %s', cookie)
            return cookie
        else:
            logger.debug('Current cookie is: None (not received yet)')
            return None

    def syncrepl_set_cookie(self, cookie):
        logger.debug('New cookie is: %s', cookie)
        self.__data['cookie'] = cookie

    def syncrepl_entry(self, dn, attributes, uuid):
        attributes = cidict(attributes)
        # First we determine the type of change we have here
        # (and store away the previous data for later if needed)
        previous_attributes = cidict()
        if uuid in self.__data['uuids']:
            change_type = 'modify'
            previous_attributes = self.__data['uuids'][uuid]
        else:
            change_type = 'add'
        # Now we store our knowledge of the existence of this entry
        # (including the DN as an attribute for convenience)
        attributes['dn'] = dn
        self.__data['uuids'][uuid] = attributes
        # Debugging
        logger.debug('Detected %s of entry: %s %s', change_type, dn, uuid)
        if change_type == 'modify':
            self.application_sync(uuid, dn, attributes, previous_attributes)
        else:
            self.application_add(uuid, dn, attributes)

    def syncrepl_delete(self, uuids):
        # Make sure we know about the UUID being deleted, just in case...
        uuids = [uuid for uuid in uuids if uuid in self.__data['uuids']]
        # Delete all the UUID values we know of
        for uuid in uuids:
            attributes = self.__data['uuids'][uuid]
            dn = attributes['dn']
            logger.debug('Detected deletion of entry: %s %s', dn, uuid)
            self.application_del(uuid, dn, attributes)
            del self.__data['uuids'][uuid]

    def syncrepl_present(self, uuids, refreshDeletes=False):
        # If we have not been given any UUID values,
        # then we have received all the present controls...
        if uuids is None:
            # We only do things if refreshDeletes is false
            # as the syncrepl extension will call syncrepl_delete instead
            # when it detects a delete notice
            if refreshDeletes is False:
                deletedEntries = [uuid for uuid in self.__data['uuids'].keys()
                                  if uuid not in self.__presentUUIDs]
                self.syncrepl_delete(deletedEntries)
            # Phase is now completed, reset the list
            self.__presentUUIDs = {}
        else:
            # Note down all the UUIDs we have been sent
            for uuid in uuids:
                self.__presentUUIDs[uuid] = True

    def application_add(self, uuid, dn, attributes):
        logger.info('Performing application add for: %s %s', dn, uuid)
        logger.debug('New attributes: %s', attributes)
        return True

    def application_sync(self, uuid, dn, attributes, previous_attributes):
        logger.info('Performing application sync for: %s %s', dn, uuid)
        logger.debug('Old attributes: %s', previous_attributes)
        logger.debug('New attributes: %s', attributes)
        return True

    def application_del(self, uuid, dn, previous_attributes):
        logger.info('Performing application delete for: %s %s', dn, uuid)
        logger.debug('Old attributes: %s', previous_attributes)
        return True
