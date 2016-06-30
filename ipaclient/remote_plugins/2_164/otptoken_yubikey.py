#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

# pylint: disable=unused-import
import six

from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

if six.PY3:
    unicode = str

__doc__ = _("""
YubiKey Tokens

Manage YubiKey tokens.

This code is an extension to the otptoken plugin and provides support for
reading/writing YubiKey tokens directly.

EXAMPLES:

 Add a new token:
   ipa otptoken-add-yubikey --owner=jdoe --desc="My YubiKey"
""")

register = Registry()
