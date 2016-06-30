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
Password policy

A password policy sets limitations on IPA passwords, including maximum
lifetime, minimum lifetime, the number of passwords to save in
history, the number of character classes required (for stronger passwords)
and the minimum password length.

By default there is a single, global policy for all users. You can also
create a password policy to apply to a group. Each user is only subject
to one password policy, either the group policy or the global policy. A
group policy stands alone; it is not a super-set of the global policy plus
custom settings.

Each group password policy requires a unique priority setting. If a user
is in multiple groups that have password policies, this priority determines
which password policy is applied. A lower value indicates a higher priority
policy.

Group password policies are automatically removed when the groups they
are associated with are removed.

EXAMPLES:

 Modify the global policy:
   ipa pwpolicy-mod --minlength=10

 Add a new group password policy:
   ipa pwpolicy-add --maxlife=90 --minlife=1 --history=10 --minclasses=3 --minlength=8 --priority=10 localadmins

 Display the global password policy:
   ipa pwpolicy-show

 Display a group password policy:
   ipa pwpolicy-show localadmins

 Display the policy that would be applied to a given user:
   ipa pwpolicy-show --user=tuser1

 Modify a group password policy:
   ipa pwpolicy-mod --minclasses=2 localadmins
""")

register = Registry()


@register()
class cosentry(Object):
    takes_params = (
        parameters.Str(
            'cn',
            primary_key=True,
        ),
        parameters.DNParam(
            'krbpwdpolicyreference',
        ),
        parameters.Int(
            'cospriority',
        ),
    )


@register()
class pwpolicy(Object):
    takes_params = (
        parameters.Str(
            'cn',
            required=False,
            primary_key=True,
            label=_(u'Group'),
            doc=_(u'Manage password policy for specific group'),
        ),
        parameters.Int(
            'krbmaxpwdlife',
            required=False,
            label=_(u'Max lifetime (days)'),
            doc=_(u'Maximum password lifetime (in days)'),
        ),
        parameters.Int(
            'krbminpwdlife',
            required=False,
            label=_(u'Min lifetime (hours)'),
            doc=_(u'Minimum password lifetime (in hours)'),
        ),
        parameters.Int(
            'krbpwdhistorylength',
            required=False,
            label=_(u'History size'),
            doc=_(u'Password history size'),
        ),
        parameters.Int(
            'krbpwdmindiffchars',
            required=False,
            label=_(u'Character classes'),
            doc=_(u'Minimum number of character classes'),
        ),
        parameters.Int(
            'krbpwdminlength',
            required=False,
            label=_(u'Min length'),
            doc=_(u'Minimum length of password'),
        ),
        parameters.Int(
            'cospriority',
            label=_(u'Priority'),
            doc=_(u'Priority of the policy (higher number means lower priority'),
        ),
        parameters.Int(
            'krbpwdmaxfailure',
            required=False,
            label=_(u'Max failures'),
            doc=_(u'Consecutive failures before lockout'),
        ),
        parameters.Int(
            'krbpwdfailurecountinterval',
            required=False,
            label=_(u'Failure reset interval'),
            doc=_(u'Period after which failure count will be reset (seconds)'),
        ),
        parameters.Int(
            'krbpwdlockoutduration',
            required=False,
            label=_(u'Lockout duration'),
            doc=_(u'Period for which lockout is enforced (seconds)'),
        ),
    )


@register()
class cosentry_add(Method):
    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
        ),
    )
    takes_options = (
        parameters.DNParam(
            'krbpwdpolicyreference',
        ),
        parameters.Int(
            'cospriority',
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
class cosentry_del(Method):
    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
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
class cosentry_find(Method):
    NO_CLI = True

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'cn',
            required=False,
        ),
        parameters.DNParam(
            'krbpwdpolicyreference',
            required=False,
        ),
        parameters.Int(
            'cospriority',
            required=False,
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
            'pkey_only',
            required=False,
            label=_(u'Primary key only'),
            doc=_(u'Results should contain primary key attribute only ("cn")'),
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
class cosentry_mod(Method):
    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
        ),
    )
    takes_options = (
        parameters.DNParam(
            'krbpwdpolicyreference',
            required=False,
        ),
        parameters.Int(
            'cospriority',
            required=False,
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
class cosentry_show(Method):
    NO_CLI = True

    takes_args = (
        parameters.Str(
            'cn',
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
class pwpolicy_add(Method):
    __doc__ = _("Add a new group password policy.")

    takes_args = (
        parameters.Str(
            'cn',
            cli_name='group',
            label=_(u'Group'),
            doc=_(u'Manage password policy for specific group'),
        ),
    )
    takes_options = (
        parameters.Int(
            'krbmaxpwdlife',
            required=False,
            cli_name='maxlife',
            label=_(u'Max lifetime (days)'),
            doc=_(u'Maximum password lifetime (in days)'),
        ),
        parameters.Int(
            'krbminpwdlife',
            required=False,
            cli_name='minlife',
            label=_(u'Min lifetime (hours)'),
            doc=_(u'Minimum password lifetime (in hours)'),
        ),
        parameters.Int(
            'krbpwdhistorylength',
            required=False,
            cli_name='history',
            label=_(u'History size'),
            doc=_(u'Password history size'),
        ),
        parameters.Int(
            'krbpwdmindiffchars',
            required=False,
            cli_name='minclasses',
            label=_(u'Character classes'),
            doc=_(u'Minimum number of character classes'),
        ),
        parameters.Int(
            'krbpwdminlength',
            required=False,
            cli_name='minlength',
            label=_(u'Min length'),
            doc=_(u'Minimum length of password'),
        ),
        parameters.Int(
            'cospriority',
            cli_name='priority',
            label=_(u'Priority'),
            doc=_(u'Priority of the policy (higher number means lower priority'),
        ),
        parameters.Int(
            'krbpwdmaxfailure',
            required=False,
            cli_name='maxfail',
            label=_(u'Max failures'),
            doc=_(u'Consecutive failures before lockout'),
        ),
        parameters.Int(
            'krbpwdfailurecountinterval',
            required=False,
            cli_name='failinterval',
            label=_(u'Failure reset interval'),
            doc=_(u'Period after which failure count will be reset (seconds)'),
        ),
        parameters.Int(
            'krbpwdlockoutduration',
            required=False,
            cli_name='lockouttime',
            label=_(u'Lockout duration'),
            doc=_(u'Period for which lockout is enforced (seconds)'),
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
class pwpolicy_del(Method):
    __doc__ = _("Delete a group password policy.")

    takes_args = (
        parameters.Str(
            'cn',
            multivalue=True,
            cli_name='group',
            label=_(u'Group'),
            doc=_(u'Manage password policy for specific group'),
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
class pwpolicy_find(Method):
    __doc__ = _("Search for group password policies.")

    takes_args = (
        parameters.Str(
            'criteria',
            required=False,
            doc=_(u'A string searched in all relevant object attributes'),
        ),
    )
    takes_options = (
        parameters.Str(
            'cn',
            required=False,
            cli_name='group',
            label=_(u'Group'),
            doc=_(u'Manage password policy for specific group'),
        ),
        parameters.Int(
            'krbmaxpwdlife',
            required=False,
            cli_name='maxlife',
            label=_(u'Max lifetime (days)'),
            doc=_(u'Maximum password lifetime (in days)'),
        ),
        parameters.Int(
            'krbminpwdlife',
            required=False,
            cli_name='minlife',
            label=_(u'Min lifetime (hours)'),
            doc=_(u'Minimum password lifetime (in hours)'),
        ),
        parameters.Int(
            'krbpwdhistorylength',
            required=False,
            cli_name='history',
            label=_(u'History size'),
            doc=_(u'Password history size'),
        ),
        parameters.Int(
            'krbpwdmindiffchars',
            required=False,
            cli_name='minclasses',
            label=_(u'Character classes'),
            doc=_(u'Minimum number of character classes'),
        ),
        parameters.Int(
            'krbpwdminlength',
            required=False,
            cli_name='minlength',
            label=_(u'Min length'),
            doc=_(u'Minimum length of password'),
        ),
        parameters.Int(
            'cospriority',
            required=False,
            cli_name='priority',
            label=_(u'Priority'),
            doc=_(u'Priority of the policy (higher number means lower priority'),
        ),
        parameters.Int(
            'krbpwdmaxfailure',
            required=False,
            cli_name='maxfail',
            label=_(u'Max failures'),
            doc=_(u'Consecutive failures before lockout'),
        ),
        parameters.Int(
            'krbpwdfailurecountinterval',
            required=False,
            cli_name='failinterval',
            label=_(u'Failure reset interval'),
            doc=_(u'Period after which failure count will be reset (seconds)'),
        ),
        parameters.Int(
            'krbpwdlockoutduration',
            required=False,
            cli_name='lockouttime',
            label=_(u'Lockout duration'),
            doc=_(u'Period for which lockout is enforced (seconds)'),
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
            'pkey_only',
            required=False,
            label=_(u'Primary key only'),
            doc=_(u'Results should contain primary key attribute only ("group")'),
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
class pwpolicy_mod(Method):
    __doc__ = _("Modify a group password policy.")

    takes_args = (
        parameters.Str(
            'cn',
            required=False,
            cli_name='group',
            label=_(u'Group'),
            doc=_(u'Manage password policy for specific group'),
        ),
    )
    takes_options = (
        parameters.Int(
            'krbmaxpwdlife',
            required=False,
            cli_name='maxlife',
            label=_(u'Max lifetime (days)'),
            doc=_(u'Maximum password lifetime (in days)'),
        ),
        parameters.Int(
            'krbminpwdlife',
            required=False,
            cli_name='minlife',
            label=_(u'Min lifetime (hours)'),
            doc=_(u'Minimum password lifetime (in hours)'),
        ),
        parameters.Int(
            'krbpwdhistorylength',
            required=False,
            cli_name='history',
            label=_(u'History size'),
            doc=_(u'Password history size'),
        ),
        parameters.Int(
            'krbpwdmindiffchars',
            required=False,
            cli_name='minclasses',
            label=_(u'Character classes'),
            doc=_(u'Minimum number of character classes'),
        ),
        parameters.Int(
            'krbpwdminlength',
            required=False,
            cli_name='minlength',
            label=_(u'Min length'),
            doc=_(u'Minimum length of password'),
        ),
        parameters.Int(
            'cospriority',
            required=False,
            cli_name='priority',
            label=_(u'Priority'),
            doc=_(u'Priority of the policy (higher number means lower priority'),
        ),
        parameters.Int(
            'krbpwdmaxfailure',
            required=False,
            cli_name='maxfail',
            label=_(u'Max failures'),
            doc=_(u'Consecutive failures before lockout'),
        ),
        parameters.Int(
            'krbpwdfailurecountinterval',
            required=False,
            cli_name='failinterval',
            label=_(u'Failure reset interval'),
            doc=_(u'Period after which failure count will be reset (seconds)'),
        ),
        parameters.Int(
            'krbpwdlockoutduration',
            required=False,
            cli_name='lockouttime',
            label=_(u'Lockout duration'),
            doc=_(u'Period for which lockout is enforced (seconds)'),
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
class pwpolicy_show(Method):
    __doc__ = _("Display information about password policy.")

    takes_args = (
        parameters.Str(
            'cn',
            required=False,
            cli_name='group',
            label=_(u'Group'),
            doc=_(u'Manage password policy for specific group'),
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
            'user',
            required=False,
            label=_(u'User'),
            doc=_(u'Display effective policy for a specific user'),
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
