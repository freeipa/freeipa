# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

from custodia.message.common import InvalidMessage
from custodia.message.common import UnallowedMessage
from custodia.message.common import UnknownMessageType
from custodia.message.kem import KEMHandler
from custodia.message.simple import SimpleKey


default_types = ['simple', 'kem']

key_types = {'simple': SimpleKey,
             'kem': KEMHandler}


class Validator(object):
    """Validates incoming messages."""

    def __init__(self, allowed=None):
        """Creates a Validator object.

        :param allowed: list of allowed message types (optional)
        """
        self.allowed = allowed or default_types
        self.types = key_types.copy()

    def add_types(self, types):
        self.types.update(types)

    def parse(self, request, msg, name):
        if not isinstance(msg, dict):
            raise InvalidMessage('The message must be a dict')

        if 'type' not in msg:
            raise InvalidMessage('The type is missing')

        if isinstance(msg['type'], list):
            if len(msg['type']) != 1:
                raise InvalidMessage('Type is multivalued: %s' % msg['type'])
            msg_type = msg['type'][0]
        else:
            msg_type = msg['type']

        if 'value' not in msg:
            raise InvalidMessage('The value is missing')

        if isinstance(msg['value'], list):
            if len(msg['value']) != 1:
                raise InvalidMessage('Value is multivalued: %s' % msg['value'])
            msg_value = msg['value'][0]
        else:
            msg_value = msg['value']

        if msg_type not in list(self.types.keys()):
            raise UnknownMessageType("Type '%s' is unknown" % msg_type)

        if msg_type not in self.allowed:
            raise UnallowedMessage("Message type '%s' not allowed" % (
                                   msg_type,))

        handler = self.types[msg_type](request)
        handler.parse(msg_value, name)
        return handler
