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
Server configuration

Manage the default values that IPA uses and some of its tuning parameters.

NOTES:

The password notification value (--pwdexpnotify) is stored here so it will
be replicated. It is not currently used to notify users in advance of an
expiring password.

Some attributes are read-only, provided only for information purposes. These
include:

Certificate Subject base: the configured certificate subject base,
  e.g. O=EXAMPLE.COM.  This is configurable only at install time.
Password plug-in features: currently defines additional hashes that the
  password will generate (there may be other conditions).

When setting the order list for mapping SELinux users you may need to
quote the value so it isn't interpreted by the shell.

EXAMPLES:

 Show basic server configuration:
   ipa config-show

 Show all configuration options:
   ipa config-show --all

 Change maximum username length to 99 characters:
   ipa config-mod --maxusername=99

 Increase default time and size limits for maximum IPA server search:
   ipa config-mod --searchtimelimit=10 --searchrecordslimit=2000

 Set default user e-mail domain:
   ipa config-mod --emaildomain=example.com

 Enable migration mode to make "ipa migrate-ds" command operational:
   ipa config-mod --enable-migration=TRUE

 Define SELinux user map order:
   ipa config-mod --ipaselinuxusermaporder='guest_u:s0$xguest_u:s0$user_u:s0-s0:c0.c1023$staff_u:s0-s0:c0.c1023$unconfined_u:s0-s0:c0.c1023'
""")

register = Registry()


@register()
class config(Object):
    takes_params = (
        parameters.Int(
            'ipamaxusernamelength',
            label=_(u'Maximum username length'),
        ),
        parameters.Str(
            'ipahomesrootdir',
            label=_(u'Home directory base'),
            doc=_(u'Default location of home directories'),
        ),
        parameters.Str(
            'ipadefaultloginshell',
            label=_(u'Default shell'),
            doc=_(u'Default shell for new users'),
        ),
        parameters.Str(
            'ipadefaultprimarygroup',
            label=_(u'Default users group'),
            doc=_(u'Default group for new users'),
        ),
        parameters.Str(
            'ipadefaultemaildomain',
            required=False,
            label=_(u'Default e-mail domain'),
        ),
        parameters.Int(
            'ipasearchtimelimit',
            label=_(u'Search time limit'),
            doc=_(u'Maximum amount of time (seconds) for a search (> 0, or -1 for unlimited)'),
        ),
        parameters.Int(
            'ipasearchrecordslimit',
            label=_(u'Search size limit'),
            doc=_(u'Maximum number of records to search (-1 is unlimited)'),
        ),
        parameters.Str(
            'ipausersearchfields',
            label=_(u'User search fields'),
            doc=_(u'A comma-separated list of fields to search in when searching for users'),
        ),
        parameters.Str(
            'ipagroupsearchfields',
            label=_(u'Group search fields'),
            doc=_(u'A comma-separated list of fields to search in when searching for groups'),
        ),
        parameters.Bool(
            'ipamigrationenabled',
            label=_(u'Enable migration mode'),
        ),
        parameters.DNParam(
            'ipacertificatesubjectbase',
            label=_(u'Certificate Subject base'),
            doc=_(u'Base for certificate subjects (OU=Test,O=Example)'),
        ),
        parameters.Str(
            'ipagroupobjectclasses',
            multivalue=True,
            label=_(u'Default group objectclasses'),
            doc=_(u'Default group objectclasses (comma-separated list)'),
        ),
        parameters.Str(
            'ipauserobjectclasses',
            multivalue=True,
            label=_(u'Default user objectclasses'),
            doc=_(u'Default user objectclasses (comma-separated list)'),
        ),
        parameters.Int(
            'ipapwdexpadvnotify',
            label=_(u'Password Expiration Notification (days)'),
            doc=_(u"Number of days's notice of impending password expiration"),
        ),
        parameters.Str(
            'ipaconfigstring',
            required=False,
            multivalue=True,
            label=_(u'Password plugin features'),
            doc=_(u'Extra hashes to generate in password plug-in'),
        ),
        parameters.Str(
            'ipaselinuxusermaporder',
            label=_(u'SELinux user map order'),
            doc=_(u'Order in increasing priority of SELinux users, delimited by $'),
        ),
        parameters.Str(
            'ipaselinuxusermapdefault',
            required=False,
            label=_(u'Default SELinux user'),
            doc=_(u'Default SELinux user when no match is found in SELinux map rule'),
        ),
        parameters.Str(
            'ipakrbauthzdata',
            required=False,
            multivalue=True,
            label=_(u'Default PAC types'),
            doc=_(u'Default types of PAC supported for services'),
        ),
        parameters.Str(
            'ipauserauthtype',
            required=False,
            multivalue=True,
            label=_(u'Default user authentication types'),
            doc=_(u'Default types of supported user authentication'),
        ),
    )


@register()
class config_mod(Method):
    __doc__ = _("Modify configuration options.")

    takes_options = (
        parameters.Int(
            'ipamaxusernamelength',
            required=False,
            cli_name='maxusername',
            label=_(u'Maximum username length'),
        ),
        parameters.Str(
            'ipahomesrootdir',
            required=False,
            cli_name='homedirectory',
            label=_(u'Home directory base'),
            doc=_(u'Default location of home directories'),
        ),
        parameters.Str(
            'ipadefaultloginshell',
            required=False,
            cli_name='defaultshell',
            label=_(u'Default shell'),
            doc=_(u'Default shell for new users'),
        ),
        parameters.Str(
            'ipadefaultprimarygroup',
            required=False,
            cli_name='defaultgroup',
            label=_(u'Default users group'),
            doc=_(u'Default group for new users'),
        ),
        parameters.Str(
            'ipadefaultemaildomain',
            required=False,
            cli_name='emaildomain',
            label=_(u'Default e-mail domain'),
        ),
        parameters.Int(
            'ipasearchtimelimit',
            required=False,
            cli_name='searchtimelimit',
            label=_(u'Search time limit'),
            doc=_(u'Maximum amount of time (seconds) for a search (> 0, or -1 for unlimited)'),
        ),
        parameters.Int(
            'ipasearchrecordslimit',
            required=False,
            cli_name='searchrecordslimit',
            label=_(u'Search size limit'),
            doc=_(u'Maximum number of records to search (-1 is unlimited)'),
        ),
        parameters.Str(
            'ipausersearchfields',
            required=False,
            cli_name='usersearch',
            label=_(u'User search fields'),
            doc=_(u'A comma-separated list of fields to search in when searching for users'),
        ),
        parameters.Str(
            'ipagroupsearchfields',
            required=False,
            cli_name='groupsearch',
            label=_(u'Group search fields'),
            doc=_(u'A comma-separated list of fields to search in when searching for groups'),
        ),
        parameters.Bool(
            'ipamigrationenabled',
            required=False,
            cli_name='enable_migration',
            label=_(u'Enable migration mode'),
        ),
        parameters.Str(
            'ipagroupobjectclasses',
            required=False,
            multivalue=True,
            cli_name='groupobjectclasses',
            label=_(u'Default group objectclasses'),
            doc=_(u'Default group objectclasses (comma-separated list)'),
        ),
        parameters.Str(
            'ipauserobjectclasses',
            required=False,
            multivalue=True,
            cli_name='userobjectclasses',
            label=_(u'Default user objectclasses'),
            doc=_(u'Default user objectclasses (comma-separated list)'),
        ),
        parameters.Int(
            'ipapwdexpadvnotify',
            required=False,
            cli_name='pwdexpnotify',
            label=_(u'Password Expiration Notification (days)'),
            doc=_(u"Number of days's notice of impending password expiration"),
        ),
        parameters.Str(
            'ipaconfigstring',
            required=False,
            multivalue=True,
            cli_metavar="['AllowNThash', 'KDC:Disable Last Success', 'KDC:Disable Lockout']",
            label=_(u'Password plugin features'),
            doc=_(u'Extra hashes to generate in password plug-in'),
        ),
        parameters.Str(
            'ipaselinuxusermaporder',
            required=False,
            label=_(u'SELinux user map order'),
            doc=_(u'Order in increasing priority of SELinux users, delimited by $'),
        ),
        parameters.Str(
            'ipaselinuxusermapdefault',
            required=False,
            label=_(u'Default SELinux user'),
            doc=_(u'Default SELinux user when no match is found in SELinux map rule'),
        ),
        parameters.Str(
            'ipakrbauthzdata',
            required=False,
            multivalue=True,
            cli_name='pac_type',
            cli_metavar="['MS-PAC', 'PAD', 'nfs:NONE']",
            label=_(u'Default PAC types'),
            doc=_(u'Default types of PAC supported for services'),
        ),
        parameters.Str(
            'ipauserauthtype',
            required=False,
            multivalue=True,
            cli_name='user_auth_type',
            cli_metavar="['password', 'radius', 'otp']",
            label=_(u'Default user authentication types'),
            doc=_(u'Default types of supported user authentication'),
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
class config_show(Method):
    __doc__ = _("Show the current configuration.")

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
