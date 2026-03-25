#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#


from ipalib.plugable import Registry
from ipalib.text import _

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
