# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Filip Skola <fskola@redhat.com>
#
# Copyright (C) 2010  Red Hat
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
Test --setattr and --addattr and other attribute-specific issues
"""

from ipalib import errors
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, raises_exact
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
import pytest


@pytest.fixture(scope='class')
def user(request, xmlrpc_setup):
    tracker = UserTracker(name=u'user1', givenname=u'Test', sn=u'User1')
    return tracker.make_fixture(request)


@pytest.mark.tier1
class TestAttrOnUser(XMLRPC_test):
    def test_add_user_with_singlevalue_addattr(self):
        """ Try to add a user with single-value attribute
            set via option and --addattr """
        user = UserTracker(name=u'user', givenname=u'Test', sn=u'User1',
                           addattr=u'sn=User2')
        command = user.make_create_command()
        with raises_exact(errors.OnlyOneValueAllowed(attr='sn')):
            command()

    def test_create_user(self, user):
        """ Create a test user """
        user.ensure_exists()

    def test_change_givenname_add_mail_user(self, user):
        """ Change givenname, add mail to user """
        user.ensure_exists()
        user.update(
            dict(setattr=(u'givenname=Finkle', u'mail=test@example.com')),
            dict(givenname=[u'Finkle'], mail=[u'test@example.com'], setattr='')
        )

    def test_add_another_mail_user(self, user):
        """ Add another mail to user """
        user.ensure_exists()
        update = u'test2@example.com'
        user.attrs['mail'].append(update)
        user.update(dict(addattr='mail='+update),
                    dict(addattr=''))

    def test_add_two_phone_numbers_at_once_user(self, user):
        """ Add two phone numbers at once to user """
        user.ensure_exists()
        update1 = u'410-555-1212'
        update2 = u'301-555-1212'
        user.update(
            dict(setattr=u'telephoneNumber='+update1,
                 addattr=u'telephoneNumber='+update2),
            dict(addattr='', setattr='',
                 telephonenumber=[update1, update2]))

    def test_go_from_two_phone_numbers_to_one(self, user):
        """ Go from two phone numbers to one for user """
        update = u'301-555-1212'
        user.ensure_exists()
        user.update(dict(setattr=u'telephoneNumber='+update),
                    dict(setattr='', telephonenumber=[update]))

    def test_add_two_more_phone_numbers(self, user):
        """ Add two more phone numbers to user """
        user.ensure_exists()
        update1 = u'703-555-1212'
        update2 = u'202-888-9833'
        user.attrs['telephonenumber'].extend([update1, update2])
        user.update(dict(addattr=(u'telephoneNumber='+update1,
                                  u'telephoneNumber='+update2)),
                    dict(addattr=''))

    def test_delete_one_phone_number(self, user):
        """ Delete one phone number for user """
        user.ensure_exists()
        update = u'301-555-1212'
        user.attrs['telephonenumber'].remove(update)
        user.update(dict(delattr=u'telephoneNumber='+update), dict(delattr=''))

    def test_delete_the_number_again(self, user):
        """ Try deleting the number again for user """
        user.ensure_exists()
        update = u'301-555-1212'
        command = user.make_update_command(
            dict(delattr=u'telephoneNumber='+update))
        with raises_exact(errors.AttrValueNotFound(
                attr=u'telephonenumber', value=update)):
            command()

    def test_add_and_delete_one_phone_number(self, user):
        """ Add and delete one phone number for user """
        user.ensure_exists()
        update1 = u'202-888-9833'
        update2 = u'301-555-1212'
        user.attrs['telephonenumber'].remove(update1)
        user.attrs['telephonenumber'].append(update2)
        user.update(dict(addattr=u'telephoneNumber='+update2,
                         delattr=u'telephoneNumber='+update1),
                    dict(addattr='', delattr=''))

    def test_add_and_delete_the_same_phone_number(self, user):
        """ Add and delete the same phone number for user """
        user.ensure_exists()
        update1 = u'301-555-1212'
        update2 = u'202-888-9833'
        user.attrs['telephonenumber'].append(update2)
        user.update(dict(addattr=(u'telephoneNumber='+update1,
                                  u'telephoneNumber='+update2),
                         delattr=u'telephoneNumber='+update1),
                    dict(addattr='', delattr=''))

    def test_set_and_delete_a_phone_number(self, user):
        """ Set and delete a phone number for user """
        user.ensure_exists()
        update1 = u'301-555-1212'
        update2 = u'202-888-9833'
        user.attrs.update(telephonenumber=[update2])
        user.update(dict(setattr=(u'telephoneNumber='+update1,
                                  u'telephoneNumber='+update2),
                         delattr=u'telephoneNumber='+update1),
                    dict(setattr='', delattr=''))

    def test_set_givenname_to_none_with_setattr(self, user):
        """ Try setting givenname to None with setattr in user """
        user.ensure_exists()
        command = user.make_update_command(dict(setattr=(u'givenname=')))
        with raises_exact(errors.RequirementError(name='first')):
            command()

    def test_set_givenname_to_none_with_option(self, user):
        """ Try setting givenname to None with option in user """
        user.ensure_exists()
        command = user.make_update_command(dict(givenname=None))
        with raises_exact(errors.RequirementError(name='first')):
            command()

    def test_set_givenname_with_option_in_user(self, user):
        """ Make sure setting givenname works with option in user """
        user.ensure_exists()
        user.update(dict(givenname=u'Fred'))

    def test_set_givenname_with_setattr_in_user(self, user):
        """ Make sure setting givenname works with setattr in user """
        user.ensure_exists()
        user.update(dict(setattr=u'givenname=Finkle'),
                    dict(givenname=[u'Finkle'], setattr=''))

    def test_remove_empty_location_from_user(self, user):
        """ Try to "remove" empty location from user """
        user.ensure_exists()
        command = user.make_update_command(dict(l=None))
        with raises_exact(errors.EmptyModlist()):
            command()

    def test_lock_user_using_setattr(self, user):
        """ Lock user using setattr """
        user.ensure_exists()
        user.update(dict(setattr=u'nsaccountlock=TrUe'),
                    dict(nsaccountlock=True, setattr=''))

    def test_unlock_user_using_addattr_delattr(self, user):
        """ Unlock user using addattr&delattr """
        user.ensure_exists()
        user.update(dict(addattr=u'nsaccountlock=FaLsE',
                         delattr=u'nsaccountlock=TRUE'),
                    dict(addattr='', delattr='', nsaccountlock=False))


@pytest.mark.tier1
class TestAttrOnConfigs(XMLRPC_test):
    def test_add_new_group_search_fields_config_entry(self, user):
        """ Try adding a new group search fields config entry """
        command = user.make_command(
            'config_mod', **dict(addattr=u'ipagroupsearchfields=newattr')
        )
        with raises_exact(errors.OnlyOneValueAllowed(
                attr='ipagroupsearchfields')):
            command()

    def test_add_a_new_cert_subject_base_config_entry(self, user):
        """ Try adding a new cert subject base config entry """
        command = user.make_command(
            'config_mod',
            **dict(
                addattr=u'ipacertificatesubjectbase=0=DOMAIN.COM')
        )
        with raises_exact(errors.ValidationError(
                name='ipacertificatesubjectbase',
                error='attribute is not configurable')):
            command()

    def test_delete_required_config_entry(self, user):
        """ Try deleting a required config entry """
        command = user.make_command(
            'config_mod',
            **dict(delattr=u'ipasearchrecordslimit=100')
        )
        with raises_exact(errors.RequirementError(
                name='searchrecordslimit')):
            command()

    def test_set_nonexistent_attribute(self, user):
        """ Try setting a nonexistent attribute """
        command = user.make_command(
            'config_mod', **dict(setattr=u'invalid_attr=false')
        )
        with raises_exact(errors.ObjectclassViolation(
                info='attribute "invalid_attr" not allowed')):
            command()

    def test_set_outofrange_krbpwdmaxfailure(self, user):
        """ Try setting out-of-range krbpwdmaxfailure """
        command = user.make_command(
            'pwpolicy_mod', **dict(setattr=u'krbpwdmaxfailure=-1')
        )
        with raises_exact(errors.ValidationError(
                name='krbpwdmaxfailure', error='must be at least 0')):
            command()

    def test_set_outofrange_maxfail(self, user):
        """ Try setting out-of-range maxfail """
        command = user.make_command(
            'pwpolicy_mod', **dict(krbpwdmaxfailure=u'-1')
        )
        with raises_exact(errors.ValidationError(
                name='maxfail', error='must be at least 0')):
            command()

    def test_set_nonnumeric_krbpwdmaxfailure(self, user):
        """ Try setting non-numeric krbpwdmaxfailure """
        command = user.make_command(
            'pwpolicy_mod', **dict(setattr=u'krbpwdmaxfailure=abc')
        )
        with raises_exact(errors.ConversionError(
                name='krbpwdmaxfailure', error='must be an integer')):
            command()

    def test_set_nonnumeric_maxfail(self, user):
        """ Try setting non-numeric maxfail """
        command = user.make_command(
            'pwpolicy_mod', **dict(krbpwdmaxfailure=u'abc')
        )
        with raises_exact(errors.ConversionError(
                name='maxfail', error='must be an integer')):
            command()

    def test_delete_bogus_attribute(self, user):
        """ Try deleting bogus attribute """
        command = user.make_command(
            'config_mod', **dict(delattr=u'bogusattribute=xyz')
        )
        with raises_exact(errors.ValidationError(
                name='bogusattribute',
                error='No such attribute on this entry')):
            command()

    def test_delete_empty_attribute(self, user):
        """ Try deleting empty attribute """
        command = user.make_command(
            'config_mod',
            **dict(delattr=u'ipaCustomFields=See Also,seealso,false')
        )
        with raises_exact(errors.ValidationError(
                name='ipacustomfields',
                error='No such attribute on this entry')):
            command()

    def test_set_and_del_value_and_del_missing_one(self, user):
        """ Set and delete one value, plus try deleting a missing one """
        command = user.make_command(
            'config_mod', **dict(
                delattr=[u'ipaCustomFields=See Also,seealso,false',
                         u'ipaCustomFields=Country,c,false'],
                addattr=u'ipaCustomFields=See Also,seealso,false')
        )
        with raises_exact(errors.AttrValueNotFound(
                attr='ipacustomfields', value='Country,c,false')):
            command()

    def test_delete_an_operational_attribute_with_delattr(self, user):
        """ Try to delete an operational attribute with --delattr """
        command = user.make_command(
            'config_mod', **dict(
                delattr=u'creatorsName=cn=directory manager')
        )
        with raises_exact(errors.DatabaseError(
                desc='Server is unwilling to perform', info='')):
            command()
