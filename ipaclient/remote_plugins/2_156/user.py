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
Users

Manage user entries. All users are POSIX users.

IPA supports a wide range of username formats, but you need to be aware of any
restrictions that may apply to your particular environment. For example,
usernames that start with a digit or usernames that exceed a certain length
may cause problems for some UNIX systems.
Use 'ipa config-mod' to change the username format allowed by IPA tools.

Disabling a user account prevents that user from obtaining new Kerberos
credentials. It does not invalidate any credentials that have already
been issued.

Password management is not a part of this module. For more information
about this topic please see: ipa help passwd

Account lockout on password failure happens per IPA master. The user-status
command can be used to identify which master the user is locked out on.
It is on that master the administrator must unlock the user.

EXAMPLES:

 Add a new user:
   ipa user-add --first=Tim --last=User --password tuser1

 Find all users whose entries include the string "Tim":
   ipa user-find Tim

 Find all users with "Tim" as the first name:
   ipa user-find --first=Tim

 Disable a user account:
   ipa user-disable tuser1

 Enable a user account:
   ipa user-enable tuser1

 Delete a user:
   ipa user-del tuser1
""")

register = Registry()


@register()
class user(Object):
    takes_params = (
        parameters.Str(
            'uid',
            primary_key=True,
            label=_(u'User login'),
        ),
        parameters.Str(
            'givenname',
            label=_(u'First name'),
        ),
        parameters.Str(
            'sn',
            label=_(u'Last name'),
        ),
        parameters.Str(
            'cn',
            label=_(u'Full name'),
        ),
        parameters.Str(
            'displayname',
            required=False,
            label=_(u'Display name'),
        ),
        parameters.Str(
            'initials',
            required=False,
            label=_(u'Initials'),
        ),
        parameters.Str(
            'homedirectory',
            required=False,
            label=_(u'Home directory'),
        ),
        parameters.Str(
            'gecos',
            required=False,
            label=_(u'GECOS'),
        ),
        parameters.Str(
            'loginshell',
            required=False,
            label=_(u'Login shell'),
        ),
        parameters.Str(
            'krbprincipalname',
            required=False,
            label=_(u'Kerberos principal'),
        ),
        parameters.DateTime(
            'krbprincipalexpiration',
            required=False,
            label=_(u'Kerberos principal expiration'),
        ),
        parameters.Str(
            'mail',
            required=False,
            multivalue=True,
            label=_(u'Email address'),
        ),
        parameters.Password(
            'userpassword',
            required=False,
            label=_(u'Password'),
            doc=_(u'Prompt to set the user password'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'random',
            required=False,
            doc=_(u'Generate a random user password'),
        ),
        parameters.Str(
            'randompassword',
            required=False,
            label=_(u'Random password'),
        ),
        parameters.Int(
            'uidnumber',
            required=False,
            label=_(u'UID'),
            doc=_(u'User ID Number (system will assign one if not provided)'),
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            label=_(u'GID'),
            doc=_(u'Group ID Number'),
        ),
        parameters.Str(
            'street',
            required=False,
            label=_(u'Street address'),
        ),
        parameters.Str(
            'l',
            required=False,
            label=_(u'City'),
        ),
        parameters.Str(
            'st',
            required=False,
            label=_(u'State/Province'),
        ),
        parameters.Str(
            'postalcode',
            required=False,
            label=_(u'ZIP'),
        ),
        parameters.Str(
            'telephonenumber',
            required=False,
            multivalue=True,
            label=_(u'Telephone Number'),
        ),
        parameters.Str(
            'mobile',
            required=False,
            multivalue=True,
            label=_(u'Mobile Telephone Number'),
        ),
        parameters.Str(
            'pager',
            required=False,
            multivalue=True,
            label=_(u'Pager Number'),
        ),
        parameters.Str(
            'facsimiletelephonenumber',
            required=False,
            multivalue=True,
            label=_(u'Fax Number'),
        ),
        parameters.Str(
            'ou',
            required=False,
            label=_(u'Org. Unit'),
        ),
        parameters.Str(
            'title',
            required=False,
            label=_(u'Job Title'),
        ),
        parameters.Str(
            'manager',
            required=False,
            label=_(u'Manager'),
        ),
        parameters.Str(
            'carlicense',
            required=False,
            multivalue=True,
            label=_(u'Car License'),
        ),
        parameters.Str(
            'ipasshpubkey',
            required=False,
            multivalue=True,
            label=_(u'SSH public key'),
        ),
        parameters.Str(
            'ipauserauthtype',
            required=False,
            multivalue=True,
            label=_(u'User authentication types'),
            doc=_(u'Types of supported user authentication'),
        ),
        parameters.Str(
            'userclass',
            required=False,
            multivalue=True,
            label=_(u'Class'),
            doc=_(u'User category (semantics placed on this attribute are for local interpretation)'),
        ),
        parameters.Str(
            'ipatokenradiusconfiglink',
            required=False,
            label=_(u'RADIUS proxy configuration'),
        ),
        parameters.Str(
            'ipatokenradiususername',
            required=False,
            label=_(u'RADIUS proxy username'),
        ),
        parameters.Str(
            'departmentnumber',
            required=False,
            multivalue=True,
            label=_(u'Department Number'),
        ),
        parameters.Str(
            'employeenumber',
            required=False,
            label=_(u'Employee Number'),
        ),
        parameters.Str(
            'employeetype',
            required=False,
            label=_(u'Employee Type'),
        ),
        parameters.Str(
            'preferredlanguage',
            required=False,
            label=_(u'Preferred Language'),
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
        ),
        parameters.Bool(
            'nsaccountlock',
            required=False,
            label=_(u'Account disabled'),
        ),
        parameters.Bool(
            'preserved',
            required=False,
            label=_(u'Preserved user'),
        ),
        parameters.Flag(
            'has_password',
            label=_(u'Password'),
        ),
        parameters.Str(
            'memberof_group',
            required=False,
            label=_(u'Member of groups'),
        ),
        parameters.Str(
            'memberof_role',
            required=False,
            label=_(u'Roles'),
        ),
        parameters.Str(
            'memberof_netgroup',
            required=False,
            label=_(u'Member of netgroups'),
        ),
        parameters.Str(
            'memberof_sudorule',
            required=False,
            label=_(u'Member of Sudo rule'),
        ),
        parameters.Str(
            'memberof_hbacrule',
            required=False,
            label=_(u'Member of HBAC rule'),
        ),
        parameters.Str(
            'memberofindirect_group',
            required=False,
            label=_(u'Indirect Member of group'),
        ),
        parameters.Str(
            'memberofindirect_netgroup',
            required=False,
            label=_(u'Indirect Member of netgroup'),
        ),
        parameters.Str(
            'memberofindirect_role',
            required=False,
            label=_(u'Indirect Member of role'),
        ),
        parameters.Str(
            'memberofindirect_sudorule',
            required=False,
            label=_(u'Indirect Member of Sudo rule'),
        ),
        parameters.Str(
            'memberofindirect_hbacrule',
            required=False,
            label=_(u'Indirect Member of HBAC rule'),
        ),
        parameters.Flag(
            'has_keytab',
            label=_(u'Kerberos keys available'),
        ),
    )


@register()
class user_add(Method):
    __doc__ = _("Add a new user.")

    takes_args = (
        parameters.Str(
            'uid',
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'givenname',
            cli_name='first',
            label=_(u'First name'),
        ),
        parameters.Str(
            'sn',
            cli_name='last',
            label=_(u'Last name'),
        ),
        parameters.Str(
            'cn',
            label=_(u'Full name'),
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            autofill=True,
        ),
        parameters.Str(
            'displayname',
            required=False,
            label=_(u'Display name'),
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            autofill=True,
        ),
        parameters.Str(
            'initials',
            required=False,
            label=_(u'Initials'),
            default_from=DefaultFrom(lambda givenname, sn: '%c%c' % (givenname[0], sn[0]), 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            autofill=True,
        ),
        parameters.Str(
            'homedirectory',
            required=False,
            cli_name='homedir',
            label=_(u'Home directory'),
        ),
        parameters.Str(
            'gecos',
            required=False,
            label=_(u'GECOS'),
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            autofill=True,
        ),
        parameters.Str(
            'loginshell',
            required=False,
            cli_name='shell',
            label=_(u'Login shell'),
        ),
        parameters.Str(
            'krbprincipalname',
            required=False,
            cli_name='principal',
            label=_(u'Kerberos principal'),
            default_from=DefaultFrom(lambda uid: '%s@%s' % (uid.lower(), api.env.realm), 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            autofill=True,
            no_convert=True,
        ),
        parameters.DateTime(
            'krbprincipalexpiration',
            required=False,
            cli_name='principal_expiration',
            label=_(u'Kerberos principal expiration'),
        ),
        parameters.Str(
            'mail',
            required=False,
            multivalue=True,
            cli_name='email',
            label=_(u'Email address'),
        ),
        parameters.Password(
            'userpassword',
            required=False,
            cli_name='password',
            label=_(u'Password'),
            doc=_(u'Prompt to set the user password'),
            exclude=('webui',),
            confirm=True,
        ),
        parameters.Flag(
            'random',
            required=False,
            doc=_(u'Generate a random user password'),
            default=False,
            autofill=True,
        ),
        parameters.Int(
            'uidnumber',
            required=False,
            cli_name='uid',
            label=_(u'UID'),
            doc=_(u'User ID Number (system will assign one if not provided)'),
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            label=_(u'GID'),
            doc=_(u'Group ID Number'),
        ),
        parameters.Str(
            'street',
            required=False,
            label=_(u'Street address'),
        ),
        parameters.Str(
            'l',
            required=False,
            cli_name='city',
            label=_(u'City'),
        ),
        parameters.Str(
            'st',
            required=False,
            cli_name='state',
            label=_(u'State/Province'),
        ),
        parameters.Str(
            'postalcode',
            required=False,
            label=_(u'ZIP'),
        ),
        parameters.Str(
            'telephonenumber',
            required=False,
            multivalue=True,
            cli_name='phone',
            label=_(u'Telephone Number'),
        ),
        parameters.Str(
            'mobile',
            required=False,
            multivalue=True,
            label=_(u'Mobile Telephone Number'),
        ),
        parameters.Str(
            'pager',
            required=False,
            multivalue=True,
            label=_(u'Pager Number'),
        ),
        parameters.Str(
            'facsimiletelephonenumber',
            required=False,
            multivalue=True,
            cli_name='fax',
            label=_(u'Fax Number'),
        ),
        parameters.Str(
            'ou',
            required=False,
            cli_name='orgunit',
            label=_(u'Org. Unit'),
        ),
        parameters.Str(
            'title',
            required=False,
            label=_(u'Job Title'),
        ),
        parameters.Str(
            'manager',
            required=False,
            label=_(u'Manager'),
        ),
        parameters.Str(
            'carlicense',
            required=False,
            multivalue=True,
            label=_(u'Car License'),
        ),
        parameters.Str(
            'ipasshpubkey',
            required=False,
            multivalue=True,
            cli_name='sshpubkey',
            label=_(u'SSH public key'),
            no_convert=True,
        ),
        parameters.Str(
            'ipauserauthtype',
            required=False,
            multivalue=True,
            cli_name='user_auth_type',
            cli_metavar="['password', 'radius', 'otp']",
            label=_(u'User authentication types'),
            doc=_(u'Types of supported user authentication'),
        ),
        parameters.Str(
            'userclass',
            required=False,
            multivalue=True,
            cli_name='class',
            label=_(u'Class'),
            doc=_(u'User category (semantics placed on this attribute are for local interpretation)'),
        ),
        parameters.Str(
            'ipatokenradiusconfiglink',
            required=False,
            cli_name='radius',
            label=_(u'RADIUS proxy configuration'),
        ),
        parameters.Str(
            'ipatokenradiususername',
            required=False,
            cli_name='radius_username',
            label=_(u'RADIUS proxy username'),
        ),
        parameters.Str(
            'departmentnumber',
            required=False,
            multivalue=True,
            label=_(u'Department Number'),
        ),
        parameters.Str(
            'employeenumber',
            required=False,
            label=_(u'Employee Number'),
        ),
        parameters.Str(
            'employeetype',
            required=False,
            label=_(u'Employee Type'),
        ),
        parameters.Str(
            'preferredlanguage',
            required=False,
            label=_(u'Preferred Language'),
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
        ),
        parameters.Bool(
            'nsaccountlock',
            required=False,
            label=_(u'Account disabled'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(u'Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(u'Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'noprivate',
            doc=_(u"Don't create user private group"),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class user_add_cert(Method):
    __doc__ = _("Add one or more certificates to the user entry")

    takes_args = (
        parameters.Str(
            'uid',
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
            alwaysask=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class user_del(Method):
    __doc__ = _("Delete a user.")

    takes_args = (
        parameters.Str(
            'uid',
            multivalue=True,
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_(u"Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
        parameters.Bool(
            'preserve',
            required=False,
            exclude=('cli',),
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            dict,
            doc=_(u'List of deletions that failed'),
        ),
        output.ListOfPrimaryKeys(
            'value',
        ),
    )


@register()
class user_disable(Method):
    __doc__ = _("Disable a user account.")

    takes_args = (
        parameters.Str(
            'uid',
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class user_enable(Method):
    __doc__ = _("Enable a user account.")

    takes_args = (
        parameters.Str(
            'uid',
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class user_find(Method):
    __doc__ = _("Search for users.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'uid',
            required=False,
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
        parameters.Str(
            'givenname',
            required=False,
            cli_name='first',
            label=_(u'First name'),
        ),
        parameters.Str(
            'sn',
            required=False,
            cli_name='last',
            label=_(u'Last name'),
        ),
        parameters.Str(
            'cn',
            required=False,
            label=_(u'Full name'),
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
        ),
        parameters.Str(
            'displayname',
            required=False,
            label=_(u'Display name'),
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
        ),
        parameters.Str(
            'initials',
            required=False,
            label=_(u'Initials'),
            default_from=DefaultFrom(lambda givenname, sn: '%c%c' % (givenname[0], sn[0]), 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
        ),
        parameters.Str(
            'homedirectory',
            required=False,
            cli_name='homedir',
            label=_(u'Home directory'),
        ),
        parameters.Str(
            'gecos',
            required=False,
            label=_(u'GECOS'),
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
        ),
        parameters.Str(
            'loginshell',
            required=False,
            cli_name='shell',
            label=_(u'Login shell'),
        ),
        parameters.Str(
            'krbprincipalname',
            required=False,
            cli_name='principal',
            label=_(u'Kerberos principal'),
            default_from=DefaultFrom(lambda uid: '%s@%s' % (uid.lower(), api.env.realm), 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
        parameters.DateTime(
            'krbprincipalexpiration',
            required=False,
            cli_name='principal_expiration',
            label=_(u'Kerberos principal expiration'),
        ),
        parameters.Str(
            'mail',
            required=False,
            multivalue=True,
            cli_name='email',
            label=_(u'Email address'),
        ),
        parameters.Password(
            'userpassword',
            required=False,
            cli_name='password',
            label=_(u'Password'),
            doc=_(u'Prompt to set the user password'),
            exclude=('webui',),
            confirm=True,
        ),
        parameters.Int(
            'uidnumber',
            required=False,
            cli_name='uid',
            label=_(u'UID'),
            doc=_(u'User ID Number (system will assign one if not provided)'),
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            label=_(u'GID'),
            doc=_(u'Group ID Number'),
        ),
        parameters.Str(
            'street',
            required=False,
            label=_(u'Street address'),
        ),
        parameters.Str(
            'l',
            required=False,
            cli_name='city',
            label=_(u'City'),
        ),
        parameters.Str(
            'st',
            required=False,
            cli_name='state',
            label=_(u'State/Province'),
        ),
        parameters.Str(
            'postalcode',
            required=False,
            label=_(u'ZIP'),
        ),
        parameters.Str(
            'telephonenumber',
            required=False,
            multivalue=True,
            cli_name='phone',
            label=_(u'Telephone Number'),
        ),
        parameters.Str(
            'mobile',
            required=False,
            multivalue=True,
            label=_(u'Mobile Telephone Number'),
        ),
        parameters.Str(
            'pager',
            required=False,
            multivalue=True,
            label=_(u'Pager Number'),
        ),
        parameters.Str(
            'facsimiletelephonenumber',
            required=False,
            multivalue=True,
            cli_name='fax',
            label=_(u'Fax Number'),
        ),
        parameters.Str(
            'ou',
            required=False,
            cli_name='orgunit',
            label=_(u'Org. Unit'),
        ),
        parameters.Str(
            'title',
            required=False,
            label=_(u'Job Title'),
        ),
        parameters.Str(
            'manager',
            required=False,
            label=_(u'Manager'),
        ),
        parameters.Str(
            'carlicense',
            required=False,
            multivalue=True,
            label=_(u'Car License'),
        ),
        parameters.Str(
            'ipauserauthtype',
            required=False,
            multivalue=True,
            cli_name='user_auth_type',
            cli_metavar="['password', 'radius', 'otp']",
            label=_(u'User authentication types'),
            doc=_(u'Types of supported user authentication'),
        ),
        parameters.Str(
            'userclass',
            required=False,
            multivalue=True,
            cli_name='class',
            label=_(u'Class'),
            doc=_(u'User category (semantics placed on this attribute are for local interpretation)'),
        ),
        parameters.Str(
            'ipatokenradiusconfiglink',
            required=False,
            cli_name='radius',
            label=_(u'RADIUS proxy configuration'),
        ),
        parameters.Str(
            'ipatokenradiususername',
            required=False,
            cli_name='radius_username',
            label=_(u'RADIUS proxy username'),
        ),
        parameters.Str(
            'departmentnumber',
            required=False,
            multivalue=True,
            label=_(u'Department Number'),
        ),
        parameters.Str(
            'employeenumber',
            required=False,
            label=_(u'Employee Number'),
        ),
        parameters.Str(
            'employeetype',
            required=False,
            label=_(u'Employee Type'),
        ),
        parameters.Str(
            'preferredlanguage',
            required=False,
            label=_(u'Preferred Language'),
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
        ),
        parameters.Bool(
            'nsaccountlock',
            required=False,
            label=_(u'Account disabled'),
            exclude=('cli', 'webui'),
        ),
        parameters.Bool(
            'preserved',
            required=False,
            label=_(u'Preserved user'),
            default=False,
        ),
        parameters.Int(
            'timelimit',
            required=False,
            label=_(u'Time Limit'),
            doc=_(u'Time limit of search in seconds (0 is unlimited)'),
        ),
        parameters.Int(
            'sizelimit',
            required=False,
            label=_(u'Size Limit'),
            doc=_(u'Maximum number of entries returned (0 is unlimited)'),
        ),
        parameters.Flag(
            'whoami',
            label=_(u'Self'),
            doc=_(u'Display user record for current Kerberos principal'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'pkey_only',
            required=False,
            label=_(u'Primary key only'),
            doc=_(u'Results should contain primary key attribute only ("login")'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'in_group',
            required=False,
            multivalue=True,
            cli_name='in_groups',
            label=_(u'group'),
            doc=_(u'Search for users with these member of groups.'),
        ),
        parameters.Str(
            'not_in_group',
            required=False,
            multivalue=True,
            cli_name='not_in_groups',
            label=_(u'group'),
            doc=_(u'Search for users without these member of groups.'),
        ),
        parameters.Str(
            'in_netgroup',
            required=False,
            multivalue=True,
            cli_name='in_netgroups',
            label=_(u'netgroup'),
            doc=_(u'Search for users with these member of netgroups.'),
        ),
        parameters.Str(
            'not_in_netgroup',
            required=False,
            multivalue=True,
            cli_name='not_in_netgroups',
            label=_(u'netgroup'),
            doc=_(u'Search for users without these member of netgroups.'),
        ),
        parameters.Str(
            'in_role',
            required=False,
            multivalue=True,
            cli_name='in_roles',
            label=_(u'role'),
            doc=_(u'Search for users with these member of roles.'),
        ),
        parameters.Str(
            'not_in_role',
            required=False,
            multivalue=True,
            cli_name='not_in_roles',
            label=_(u'role'),
            doc=_(u'Search for users without these member of roles.'),
        ),
        parameters.Str(
            'in_hbacrule',
            required=False,
            multivalue=True,
            cli_name='in_hbacrules',
            label=_(u'HBAC rule'),
            doc=_(u'Search for users with these member of HBAC rules.'),
        ),
        parameters.Str(
            'not_in_hbacrule',
            required=False,
            multivalue=True,
            cli_name='not_in_hbacrules',
            label=_(u'HBAC rule'),
            doc=_(u'Search for users without these member of HBAC rules.'),
        ),
        parameters.Str(
            'in_sudorule',
            required=False,
            multivalue=True,
            cli_name='in_sudorules',
            label=_(u'sudo rule'),
            doc=_(u'Search for users with these member of sudo rules.'),
        ),
        parameters.Str(
            'not_in_sudorule',
            required=False,
            multivalue=True,
            cli_name='not_in_sudorules',
            label=_(u'sudo rule'),
            doc=_(u'Search for users without these member of sudo rules.'),
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.ListOfEntries(
            'result',
        ),
        output.Output(
            'count',
            int,
            doc=_(u'Number of entries returned'),
        ),
        output.Output(
            'truncated',
            bool,
            doc=_(u'True if not all results were returned'),
        ),
    )


@register()
class user_mod(Method):
    __doc__ = _("Modify a user.")

    takes_args = (
        parameters.Str(
            'uid',
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Str(
            'givenname',
            required=False,
            cli_name='first',
            label=_(u'First name'),
        ),
        parameters.Str(
            'sn',
            required=False,
            cli_name='last',
            label=_(u'Last name'),
        ),
        parameters.Str(
            'cn',
            required=False,
            label=_(u'Full name'),
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
        ),
        parameters.Str(
            'displayname',
            required=False,
            label=_(u'Display name'),
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
        ),
        parameters.Str(
            'initials',
            required=False,
            label=_(u'Initials'),
            default_from=DefaultFrom(lambda givenname, sn: '%c%c' % (givenname[0], sn[0]), 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
        ),
        parameters.Str(
            'homedirectory',
            required=False,
            cli_name='homedir',
            label=_(u'Home directory'),
        ),
        parameters.Str(
            'gecos',
            required=False,
            label=_(u'GECOS'),
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
        ),
        parameters.Str(
            'loginshell',
            required=False,
            cli_name='shell',
            label=_(u'Login shell'),
        ),
        parameters.DateTime(
            'krbprincipalexpiration',
            required=False,
            cli_name='principal_expiration',
            label=_(u'Kerberos principal expiration'),
        ),
        parameters.Str(
            'mail',
            required=False,
            multivalue=True,
            cli_name='email',
            label=_(u'Email address'),
        ),
        parameters.Password(
            'userpassword',
            required=False,
            cli_name='password',
            label=_(u'Password'),
            doc=_(u'Prompt to set the user password'),
            exclude=('webui',),
            confirm=True,
        ),
        parameters.Flag(
            'random',
            required=False,
            doc=_(u'Generate a random user password'),
            default=False,
            autofill=True,
        ),
        parameters.Int(
            'uidnumber',
            required=False,
            cli_name='uid',
            label=_(u'UID'),
            doc=_(u'User ID Number (system will assign one if not provided)'),
        ),
        parameters.Int(
            'gidnumber',
            required=False,
            label=_(u'GID'),
            doc=_(u'Group ID Number'),
        ),
        parameters.Str(
            'street',
            required=False,
            label=_(u'Street address'),
        ),
        parameters.Str(
            'l',
            required=False,
            cli_name='city',
            label=_(u'City'),
        ),
        parameters.Str(
            'st',
            required=False,
            cli_name='state',
            label=_(u'State/Province'),
        ),
        parameters.Str(
            'postalcode',
            required=False,
            label=_(u'ZIP'),
        ),
        parameters.Str(
            'telephonenumber',
            required=False,
            multivalue=True,
            cli_name='phone',
            label=_(u'Telephone Number'),
        ),
        parameters.Str(
            'mobile',
            required=False,
            multivalue=True,
            label=_(u'Mobile Telephone Number'),
        ),
        parameters.Str(
            'pager',
            required=False,
            multivalue=True,
            label=_(u'Pager Number'),
        ),
        parameters.Str(
            'facsimiletelephonenumber',
            required=False,
            multivalue=True,
            cli_name='fax',
            label=_(u'Fax Number'),
        ),
        parameters.Str(
            'ou',
            required=False,
            cli_name='orgunit',
            label=_(u'Org. Unit'),
        ),
        parameters.Str(
            'title',
            required=False,
            label=_(u'Job Title'),
        ),
        parameters.Str(
            'manager',
            required=False,
            label=_(u'Manager'),
        ),
        parameters.Str(
            'carlicense',
            required=False,
            multivalue=True,
            label=_(u'Car License'),
        ),
        parameters.Str(
            'ipasshpubkey',
            required=False,
            multivalue=True,
            cli_name='sshpubkey',
            label=_(u'SSH public key'),
            no_convert=True,
        ),
        parameters.Str(
            'ipauserauthtype',
            required=False,
            multivalue=True,
            cli_name='user_auth_type',
            cli_metavar="['password', 'radius', 'otp']",
            label=_(u'User authentication types'),
            doc=_(u'Types of supported user authentication'),
        ),
        parameters.Str(
            'userclass',
            required=False,
            multivalue=True,
            cli_name='class',
            label=_(u'Class'),
            doc=_(u'User category (semantics placed on this attribute are for local interpretation)'),
        ),
        parameters.Str(
            'ipatokenradiusconfiglink',
            required=False,
            cli_name='radius',
            label=_(u'RADIUS proxy configuration'),
        ),
        parameters.Str(
            'ipatokenradiususername',
            required=False,
            cli_name='radius_username',
            label=_(u'RADIUS proxy username'),
        ),
        parameters.Str(
            'departmentnumber',
            required=False,
            multivalue=True,
            label=_(u'Department Number'),
        ),
        parameters.Str(
            'employeenumber',
            required=False,
            label=_(u'Employee Number'),
        ),
        parameters.Str(
            'employeetype',
            required=False,
            label=_(u'Employee Type'),
        ),
        parameters.Str(
            'preferredlanguage',
            required=False,
            label=_(u'Preferred Language'),
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
        ),
        parameters.Bool(
            'nsaccountlock',
            required=False,
            label=_(u'Account disabled'),
            exclude=('cli', 'webui'),
        ),
        parameters.Str(
            'setattr',
            required=False,
            multivalue=True,
            doc=_(u'Set an attribute to a name/value pair. Format is attr=value.\nFor multi-valued attributes, the command replaces the values already present.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'addattr',
            required=False,
            multivalue=True,
            doc=_(u'Add an attribute/value pair. Format is attr=value. The attribute\nmust be part of the schema.'),
            exclude=('webui',),
        ),
        parameters.Str(
            'delattr',
            required=False,
            multivalue=True,
            doc=_(u'Delete an attribute/value pair. The option will be evaluated\nlast, after all sets and adds.'),
            exclude=('webui',),
        ),
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'rename',
            required=False,
            label=_(u'Rename'),
            doc=_(u'Rename the user object'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class user_remove_cert(Method):
    __doc__ = _("Remove one or more certificates to the user entry")

    takes_args = (
        parameters.Str(
            'uid',
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
        parameters.Bytes(
            'usercertificate',
            required=False,
            multivalue=True,
            cli_name='certificate',
            label=_(u'Certificate'),
            doc=_(u'Base-64 encoded server certificate'),
            alwaysask=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class user_show(Method):
    __doc__ = _("Display information about a user.")

    takes_args = (
        parameters.Str(
            'uid',
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'rights',
            label=_(u'Rights'),
            doc=_(u'Display the access rights of this entry (requires --all). See ipa man page for details.'),
            default=False,
            autofill=True,
        ),
        parameters.Str(
            'out',
            required=False,
            doc=_(u'file to store certificate in'),
        ),
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class user_stage(Method):
    __doc__ = _("Move deleted user into staged area")

    takes_args = (
        parameters.Str(
            'uid',
            multivalue=True,
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'continue',
            doc=_(u"Continuous mode: Don't stop on errors."),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            dict,
            doc=_(u'List of deletions that failed'),
        ),
        output.ListOfPrimaryKeys(
            'value',
        ),
    )


@register()
class user_status(Method):
    __doc__ = _("""
Lockout status of a user account

    An account may become locked if the password is entered incorrectly too
    many times within a specific time period as controlled by password
    policy. A locked account is a temporary condition and may be unlocked by
    an administrator.

    This connects to each IPA master and displays the lockout status on
    each one.

    To determine whether an account is locked on a given server you need
    to compare the number of failed logins and the time of the last failure.
    For an account to be locked it must exceed the maxfail failures within
    the failinterval duration as specified in the password policy associated
    with the user.

    The failed login counter is modified only when a user attempts a log in
    so it is possible that an account may appear locked but the last failed
    login attempt is older than the lockouttime of the password policy. This
    means that the user may attempt a login again.
    """)

    takes_args = (
        parameters.Str(
            'uid',
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
    )
    takes_options = (
        parameters.Flag(
            'all',
            doc=_(u'Retrieve and print all attributes from the server. Affects command output.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'raw',
            doc=_(u'Print entries as stored on the server. Only affects output format.'),
            exclude=('webui',),
            default=False,
            autofill=True,
        ),
        parameters.Flag(
            'no_members',
            doc=_(u'Suppress processing of membership attributes.'),
            exclude=('webui', 'cli'),
            default=False,
            autofill=True,
        ),
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.ListOfEntries(
            'result',
        ),
        output.Output(
            'count',
            int,
            doc=_(u'Number of entries returned'),
        ),
        output.Output(
            'truncated',
            bool,
            doc=_(u'True if not all results were returned'),
        ),
    )


@register()
class user_undel(Method):
    __doc__ = _("Undelete a delete user account.")

    takes_args = (
        parameters.Str(
            'uid',
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class user_unlock(Method):
    __doc__ = _("""
Unlock a user account

    An account may become locked if the password is entered incorrectly too
    many times within a specific time period as controlled by password
    policy. A locked account is a temporary condition and may be unlocked by
    an administrator.
    """)

    takes_args = (
        parameters.Str(
            'uid',
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'iparepltoposegmentleftnode', 'iparepltoposegmentrightnode'),
            no_convert=True,
        ),
    )
    takes_options = (
    )
    has_output = (
        output.Output(
            'summary',
            (unicode, type(None)),
            doc=_(u'User-friendly description of action performed'),
        ),
        output.Output(
            'result',
            bool,
            doc=_(u'True means the operation was successful'),
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )
