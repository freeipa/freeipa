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
Stageusers

Manage stage user entries.

Stage user entries are directly under the container: "cn=stage users,
cn=accounts, cn=provisioning, SUFFIX".
User can not authenticate with those entries (even if the entries
contain credentials) and are candidate to become Active entries.

Active user entries are Posix users directly under the container: "cn=accounts, SUFFIX".
User can authenticate with Active entries, at the condition they have
credentials

Delete user entries are Posix users directly under the container: "cn=deleted users,
cn=accounts, cn=provisioning, SUFFIX".
User can not authenticate with those entries (even if the entries contain credentials)

The stage user container contains entries
    - created by 'stageuser-add' commands that are Posix users
    - created by external provisioning system

A valid stage user entry MUST:
    - entry RDN is 'uid'
    - ipaUniqueID is 'autogenerate'

IPA supports a wide range of username formats, but you need to be aware of any
restrictions that may apply to your particular environment. For example,
usernames that start with a digit or usernames that exceed a certain length
may cause problems for some UNIX systems.
Use 'ipa config-mod' to change the username format allowed by IPA tools.


EXAMPLES:

 Add a new stageuser:
   ipa stageuser-add --first=Tim --last=User --password tuser1

 Add a stageuser from the Delete container
   ipa stageuser-add  --first=Tim --last=User --from-delete tuser1
""")

register = Registry()


@register()
class stageuser(Object):
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
class stageuser_activate(Method):
    __doc__ = _("Activate a stage user.")

    takes_args = (
        parameters.Str(
            'uid',
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'principal'),
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
        output.Entry(
            'result',
        ),
        output.PrimaryKey(
            'value',
            doc=_(u"The primary_key value of the entry, e.g. 'jdoe' for a user"),
        ),
    )


@register()
class stageuser_add(Method):
    __doc__ = _("Add a new stage user.")

    takes_args = (
        parameters.Str(
            'uid',
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'principal'),
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
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'principal'),
            autofill=True,
        ),
        parameters.Str(
            'displayname',
            required=False,
            label=_(u'Display name'),
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'principal'),
            autofill=True,
        ),
        parameters.Str(
            'initials',
            required=False,
            label=_(u'Initials'),
            default_from=DefaultFrom(lambda givenname, sn: '%c%c' % (givenname[0], sn[0]), 'principal'),
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
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'principal'),
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
            default_from=DefaultFrom(lambda uid: '%s@%s' % (uid.lower(), api.env.realm), 'principal'),
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
        parameters.Bool(
            'from_delete',
            required=False,
            deprecated=True,
            doc=_(u'Create Stage user in from a delete user'),
            exclude=('cli', 'webui'),
            default=False,
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
class stageuser_del(Method):
    __doc__ = _("Delete a stage user.")

    takes_args = (
        parameters.Str(
            'uid',
            multivalue=True,
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'principal'),
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
class stageuser_find(Method):
    __doc__ = _("Search for stage users.")

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
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'principal'),
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
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'principal'),
        ),
        parameters.Str(
            'displayname',
            required=False,
            label=_(u'Display name'),
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'principal'),
        ),
        parameters.Str(
            'initials',
            required=False,
            label=_(u'Initials'),
            default_from=DefaultFrom(lambda givenname, sn: '%c%c' % (givenname[0], sn[0]), 'principal'),
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
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'principal'),
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
            default_from=DefaultFrom(lambda uid: '%s@%s' % (uid.lower(), api.env.realm), 'principal'),
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
            doc=_(u'Search for stage users with these member of groups.'),
        ),
        parameters.Str(
            'not_in_group',
            required=False,
            multivalue=True,
            cli_name='not_in_groups',
            label=_(u'group'),
            doc=_(u'Search for stage users without these member of groups.'),
        ),
        parameters.Str(
            'in_netgroup',
            required=False,
            multivalue=True,
            cli_name='in_netgroups',
            label=_(u'netgroup'),
            doc=_(u'Search for stage users with these member of netgroups.'),
        ),
        parameters.Str(
            'not_in_netgroup',
            required=False,
            multivalue=True,
            cli_name='not_in_netgroups',
            label=_(u'netgroup'),
            doc=_(u'Search for stage users without these member of netgroups.'),
        ),
        parameters.Str(
            'in_role',
            required=False,
            multivalue=True,
            cli_name='in_roles',
            label=_(u'role'),
            doc=_(u'Search for stage users with these member of roles.'),
        ),
        parameters.Str(
            'not_in_role',
            required=False,
            multivalue=True,
            cli_name='not_in_roles',
            label=_(u'role'),
            doc=_(u'Search for stage users without these member of roles.'),
        ),
        parameters.Str(
            'in_hbacrule',
            required=False,
            multivalue=True,
            cli_name='in_hbacrules',
            label=_(u'HBAC rule'),
            doc=_(u'Search for stage users with these member of HBAC rules.'),
        ),
        parameters.Str(
            'not_in_hbacrule',
            required=False,
            multivalue=True,
            cli_name='not_in_hbacrules',
            label=_(u'HBAC rule'),
            doc=_(u'Search for stage users without these member of HBAC rules.'),
        ),
        parameters.Str(
            'in_sudorule',
            required=False,
            multivalue=True,
            cli_name='in_sudorules',
            label=_(u'sudo rule'),
            doc=_(u'Search for stage users with these member of sudo rules.'),
        ),
        parameters.Str(
            'not_in_sudorule',
            required=False,
            multivalue=True,
            cli_name='not_in_sudorules',
            label=_(u'sudo rule'),
            doc=_(u'Search for stage users without these member of sudo rules.'),
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
class stageuser_mod(Method):
    __doc__ = _("Modify a stage user.")

    takes_args = (
        parameters.Str(
            'uid',
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'principal'),
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
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'principal'),
        ),
        parameters.Str(
            'displayname',
            required=False,
            label=_(u'Display name'),
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'principal'),
        ),
        parameters.Str(
            'initials',
            required=False,
            label=_(u'Initials'),
            default_from=DefaultFrom(lambda givenname, sn: '%c%c' % (givenname[0], sn[0]), 'principal'),
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
            default_from=DefaultFrom(lambda givenname, sn: '%s %s' % (givenname, sn), 'principal'),
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
            doc=_(u'Rename the stage user object'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'principal'),
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
class stageuser_show(Method):
    __doc__ = _("Display information about a stage user.")

    takes_args = (
        parameters.Str(
            'uid',
            cli_name='login',
            label=_(u'User login'),
            default_from=DefaultFrom(lambda givenname, sn: givenname[0] + sn, 'principal'),
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
