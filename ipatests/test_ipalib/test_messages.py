# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 1012  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Test the `ipalib.messages` module.
"""

from ipalib import messages
from ipalib.capabilities import capabilities
from ipatests.test_ipalib import test_errors

import pytest

pytestmark = pytest.mark.tier0

class HelloMessage(messages.PublicMessage):
    type = 'info'
    format = '%(greeting)s, %(object)s!'
    errno = 1234


class test_PublicMessage(test_errors.test_PublicError):
    """Test public messages"""
    # The messages are a lot like public errors; defer testing to that.
    klass = messages.PublicMessage
    required_classes = (UserWarning, messages.PublicMessage)


class test_PublicMessages(test_errors.BaseMessagesTest):
    message_list = messages.public_messages
    errno_range = list(range(10000, 19999))
    required_classes = (UserWarning, messages.PublicMessage)
    texts = messages._texts

    def extratest(self, cls):
        if cls is not messages.PublicMessage:
            assert cls.type in ('debug', 'info', 'warning', 'error')


def test_to_dict():
    expected = dict(
        name=u'HelloMessage',
        type=u'info',
        message=u'Hello, world!',
        code=1234,
        data={'greeting': 'Hello', 'object': 'world'},
    )

    assert HelloMessage(greeting='Hello', object='world').to_dict() == expected


def test_add_message():
    result = {}

    assert capabilities['messages'] == u'2.52'

    messages.add_message(u'2.52', result,
                         HelloMessage(greeting='Hello', object='world'))
    messages.add_message(u'2.1', result,
                         HelloMessage(greeting="'Lo", object='version'))
    messages.add_message(u'2.60', result,
                         HelloMessage(greeting='Hi', object='version'))

    assert result == {'messages': [
        dict(
            name=u'HelloMessage',
            type=u'info',
            message=u'Hello, world!',
            code=1234,
            data={'greeting': 'Hello', 'object': 'world'},
        ),
        dict(
            name=u'HelloMessage',
            type=u'info',
            message=u'Hi, version!',
            code=1234,
            data={'greeting': 'Hi', 'object': 'version'},
        )
    ]}
