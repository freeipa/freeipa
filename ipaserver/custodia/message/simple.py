# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

from six import string_types

from custodia.message.common import InvalidMessage
from custodia.message.common import MessageHandler


class SimpleKey(MessageHandler):
    """Handles 'simple' messages"""

    def parse(self, msg, name):
        """Parses a simple message

        :param msg: the json-decoded value
        :param name: the requested name

        :raises UnknownMessageType: if the type is not 'simple'
        :raises InvalidMessage: if the message cannot be parsed or validated
        """

        # On requests we imply 'simple' if there is no input message
        if msg is None:
            return

        if not isinstance(msg, string_types):
            raise InvalidMessage("The 'value' attribute is not a string")

        self.name = name
        self.payload = msg
        self.msg_type = 'simple'

    def reply(self, output):
        if output is None:
            return None

        if self.name.endswith('/'):
            # directory listings are pass-through with simple messages
            return output

        return {'type': self.msg_type, 'value': output}
