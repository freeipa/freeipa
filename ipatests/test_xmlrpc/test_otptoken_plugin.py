#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#


"""
Test the otptoken plugin.
"""

from __future__ import print_function

import pytest

from ipalib import api, errors
from ipatests.util import change_principal, unlock_principal_password
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker


user_password = u'userSecretPassword123'


@pytest.fixture
def user(request):
    tracker = UserTracker(name=u'user_for_otp_test',
                          givenname=u'Test', sn=u'User for OTP')
    return tracker.make_fixture(request)


def id_function(arg):
    """
    Return a label for the test parameters.

    The params can be:
    - the global config (list containing ipauserauthtypes)
      in this case we need to extract the 'disabled' auth type to evaluate
      whether user setting override is allowed
      Example: [u'disabled', u'otp'] will return a label noOverride-otp
               [u'otp', u'password']                    otp+password
    - the user config (list containing ipauserauthtypes)
    - the expected outcome (boolean True if delete should be allowed)
    """

    if isinstance(arg, list):
        # The arg is a list, need to extract the override flag
        labels = list()
        if u'disabled' in arg:
            labels.append('noOverride')

        label = 'default'
        if arg:
            without_override = [item for item in arg if item != u'disabled']
            if without_override:
                label = '+'.join(without_override)
        labels.append(label)

        return "-".join(labels)

    if isinstance(arg, bool):
        return "allowed" if arg else "forbidden"

    return 'default'


class TestDeleteLastOtpToken(XMLRPC_test):

    @pytest.mark.parametrize(
        "globalCfg,userCfg,allowDelLast", [
            # When Global config is not set and prevents user override,
            # it is possible to delete last token
            ([u'disabled'],  None, True),
            ([u'disabled'], [u'otp'], True),
            ([u'disabled'], [u'password'], True),
            ([u'disabled'], [u'password', u'otp'], True),
            # When Global config is not set and allows user override,
            # the userCfg applies
            # Deletion is forbidden only when usercfg = otp only
            (None,  None, True),
            (None, [u'otp'], False),
            (None, [u'password'], True),
            (None, [u'password', u'otp'], True),
            # When Global config is set to otp and prevents user override,
            # it is forbidden to delete last token
            ([u'disabled', u'otp'], None, False),
            ([u'disabled', u'otp'], [u'otp'], False),
            ([u'disabled', u'otp'], [u'password'], False),
            ([u'disabled', u'otp'], [u'password', u'otp'], False),
            # When Global config is set to otp and allows user override,
            # the userCfg applies
            # Deletion is forbidden when usercfg = otp only or usercfg not set
            ([u'otp'], None, False),
            ([u'otp'], [u'otp'], False),
            ([u'otp'], [u'password'], True),
            ([u'otp'], [u'password', u'otp'], True),
            # When Global config is set to password and prevents user override,
            # it is possible to delete last token
            ([u'disabled', u'password'], None, True),
            ([u'disabled', u'password'], [u'otp'], True),
            ([u'disabled', u'password'], [u'password'], True),
            ([u'disabled', u'password'], [u'password', u'otp'], True),
            # When Global config is set to password and allows user override,
            # the userCfg applies
            # Deletion is forbidden when usercfg = otp only
            ([u'password'], None, True),
            ([u'password'], [u'otp'], False),
            ([u'password'], [u'password'], True),
            ([u'password'], [u'password', u'otp'], True),
            # When Global config is set to password+otp and prevents user
            # override, it is possible to delete last token
            ([u'disabled', u'password', u'otp'], None, True),
            ([u'disabled', u'password', u'otp'], [u'otp'], True),
            ([u'disabled', u'password', u'otp'], [u'password'], True),
            ([u'disabled', u'password', u'otp'], [u'password', u'otp'], True),
            # When Global config is set to password+otp and allows user
            # override, the userCfg applies
            # Deletion is forbidden when usercfg = otp only
            ([u'password', u'otp'], None, True),
            ([u'password', u'otp'], [u'otp'], False),
            ([u'password', u'otp'], [u'password'], True),
            ([u'password', u'otp'], [u'password', u'otp'], True),
        ],
        ids=id_function)
    def test_delete(self, globalCfg, userCfg, allowDelLast, user):
        """
        Test the deletion of the last otp token

        The user auth type can be defined at a global level, or
        per-user if the override is not disabled.
        Depending on the resulting setting, the deletion of last token
        is allowed or forbidden.
        """
        # Save current global config
        result = api.Command.config_show()
        current_globalCfg = result.get('ipauserauthtype', None)

        try:
            # Set the global config for the test
            api.Command.config_mod(ipauserauthtype=globalCfg)
        except errors.EmptyModlist:
            pass

        try:
            user.ensure_exists()
            api.Command.user_mod(user.name, userpassword=user_password)
            unlock_principal_password(user.name,
                                      user_password, user_password)
            # Set the user config for the test
            api.Command.user_mod(user.name, ipauserauthtype=userCfg)

            # Connect as user, create and delete the token
            with change_principal(user.name, user_password):
                api.Command.otptoken_add(u'lastotp', description=u'last otp',
                                         ipatokenowner=user.name)
                if allowDelLast:
                    # We are expecting the del command to succeed
                    api.Command.otptoken_del(u'lastotp')
                else:
                    # We are expecting the del command to fail
                    with pytest.raises(errors.DatabaseError):
                        api.Command.otptoken_del(u'lastotp')

        finally:
            # Make sure the token is removed
            try:
                api.Command.otptoken_del(u'lastotp',)
            except errors.NotFound:
                pass

            # Restore the previous ipauserauthtype
            try:
                api.Command.config_mod(ipauserauthtype=current_globalCfg)
            except errors.EmptyModlist:
                pass
