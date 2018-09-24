# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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

from __future__ import absolute_import

import logging
import re
from ldap import MOD_ADD
from ldap import SCOPE_BASE, SCOPE_ONELEVEL, SCOPE_SUBTREE

import six

from ipalib import api, errors, output
from ipalib import Command, Password, Str, Flag, StrEnum, DNParam, Bool
from ipalib.cli import to_cli
from ipalib.plugable import Registry
from ipaserver.plugins.user import NO_UPG_MAGIC
from ipalib import _
from ipapython.dn import DN
from ipapython.ipaldap import LDAPClient
from ipapython.ipautil import write_tmp_file
from ipapython.kerberos import Principal
import datetime
from ipaplatform.paths import paths

if six.PY3:
    unicode = str

__doc__ = _("""
Migration to IPA

Migrate users and groups from an LDAP server to IPA.

This performs an LDAP query against the remote server searching for
users and groups in a container. In order to migrate passwords you need
to bind as a user that can read the userPassword attribute on the remote
server. This is generally restricted to high-level admins such as
cn=Directory Manager in 389-ds (this is the default bind user).

The default user container is ou=People.

The default group container is ou=Groups.

Users and groups that already exist on the IPA server are skipped.

Two LDAP schemas define how group members are stored: RFC2307 and
RFC2307bis. RFC2307bis uses member and uniquemember to specify group
members, RFC2307 uses memberUid. The default schema is RFC2307bis.

The schema compat feature allows IPA to reformat data for systems that
do not support RFC2307bis. It is recommended that this feature is disabled
during migration to reduce system overhead. It can be re-enabled after
migration. To migrate with it enabled use the "--with-compat" option.

Migrated users do not have Kerberos credentials, they have only their
LDAP password. To complete the migration process, users need to go
to http://ipa.example.com/ipa/migration and authenticate using their
LDAP password in order to generate their Kerberos credentials.

Migration is disabled by default. Use the command ipa config-mod to
enable it:

 ipa config-mod --enable-migration=TRUE

If a base DN is not provided with --basedn then IPA will use either
the value of defaultNamingContext if it is set or the first value
in namingContexts set in the root of the remote LDAP server.

Users are added as members to the default user group. This can be a
time-intensive task so during migration this is done in a batch
mode for every 100 users. As a result there will be a window in which
users will be added to IPA but will not be members of the default
user group.

EXAMPLES:

 The simplest migration, accepting all defaults:
   ipa migrate-ds ldap://ds.example.com:389

 Specify the user and group container. This can be used to migrate user
 and group data from an IPA v1 server:
   ipa migrate-ds --user-container='cn=users,cn=accounts' \\
       --group-container='cn=groups,cn=accounts' \\
       ldap://ds.example.com:389

 Since IPA v2 server already contain predefined groups that may collide with
 groups in migrated (IPA v1) server (for example admins, ipausers), users
 having colliding group as their primary group may happen to belong to
 an unknown group on new IPA v2 server.
 Use --group-overwrite-gid option to overwrite GID of already existing groups
 to prevent this issue:
    ipa migrate-ds --group-overwrite-gid \\
        --user-container='cn=users,cn=accounts' \\
        --group-container='cn=groups,cn=accounts' \\
        ldap://ds.example.com:389

 Migrated users or groups may have object class and accompanied attributes
 unknown to the IPA v2 server. These object classes and attributes may be
 left out of the migration process:
    ipa migrate-ds --user-container='cn=users,cn=accounts' \\
       --group-container='cn=groups,cn=accounts' \\
       --user-ignore-objectclass=radiusprofile \\
       --user-ignore-attribute=radiusgroupname \\
       ldap://ds.example.com:389

LOGGING

Migration will log warnings and errors to the Apache error log. This
file should be evaluated post-migration to correct or investigate any
issues that were discovered.

For every 100 users migrated an info-level message will be displayed to
give the current progress and duration to make it possible to track
the progress of migration.

If the log level is debug, either by setting debug = True in
/etc/ipa/default.conf or /etc/ipa/server.conf, then an entry will be printed
for each user added plus a summary when the default user group is
updated.
""")

logger = logging.getLogger(__name__)

register = Registry()

# USER MIGRATION CALLBACKS AND VARS

_krb_err_msg = _('Kerberos principal %s already exists. Use \'ipa user-mod\' to set it manually.')
_krb_failed_msg = _('Unable to determine if Kerberos principal %s already exists. Use \'ipa user-mod\' to set it manually.')
_grp_err_msg = _('Failed to add user to the default group. Use \'ipa group-add-member\' to add manually.')
_ref_err_msg = _('Migration of LDAP search reference is not supported.')
_dn_err_msg = _('Malformed DN')

_supported_schemas = (u'RFC2307bis', u'RFC2307')

# search scopes for users and groups when migrating
_supported_scopes = {u'base': SCOPE_BASE, u'onelevel': SCOPE_ONELEVEL, u'subtree': SCOPE_SUBTREE}
_default_scope = u'onelevel'


def _create_kerberos_principals(ldap, pkey, entry_attrs, failed):
    """
    Create 'krbprincipalname' and 'krbcanonicalname' attributes for incoming
    user entry or skip it if there already is a user with such principal name.
    The code does not search for `krbcanonicalname` since we assume that the
    canonical principal name is always contained among values of
    `krbprincipalname` attribute.Both `krbprincipalname` and `krbcanonicalname`
    are set to default value generated from uid and realm.

    Note: the migration does not currently preserve principal aliases
    """
    principal = Principal((pkey,), realm=api.env.realm)
    try:
        ldap.find_entry_by_attr(
            'krbprincipalname', principal, 'krbprincipalaux', [''],
            DN(api.env.container_user, api.env.basedn)
        )
    except errors.NotFound:
        entry_attrs['krbprincipalname'] = principal
        entry_attrs['krbcanonicalname'] = principal
    except errors.LimitsExceeded:
        failed[pkey] = unicode(_krb_failed_msg % unicode(principal))
    else:
        failed[pkey] = unicode(_krb_err_msg % unicode(principal))


def _pre_migrate_user(ldap, pkey, dn, entry_attrs, failed, config, ctx, **kwargs):
    assert isinstance(dn, DN)
    attr_blacklist = ['krbprincipalkey','memberofindirect','memberindirect']
    attr_blacklist.extend(kwargs.get('attr_blacklist', []))
    ds_ldap = ctx['ds_ldap']
    search_bases = kwargs.get('search_bases', None)
    valid_gids = kwargs['valid_gids']
    invalid_gids = kwargs['invalid_gids']

    if 'gidnumber' not in entry_attrs:
        raise errors.NotFound(reason=_('%(user)s is not a POSIX user') % dict(user=pkey))
    else:
        # See if the gidNumber at least points to a valid group on the remote
        # server.
        if entry_attrs['gidnumber'][0] in invalid_gids:
            logger.warning('GID number %s of migrated user %s does not point '
                           'to a known group.',
                           entry_attrs['gidnumber'][0], pkey)
        elif entry_attrs['gidnumber'][0] not in valid_gids:
            try:
                remote_entry = ds_ldap.find_entry_by_attr(
                    'gidnumber', entry_attrs['gidnumber'][0], 'posixgroup',
                    [''], search_bases['group']
                )
                valid_gids.add(entry_attrs['gidnumber'][0])
            except errors.NotFound:
                logger.warning('GID number %s of migrated user %s does not '
                               'point to a known group.',
                               entry_attrs['gidnumber'][0], pkey)
                invalid_gids.add(entry_attrs['gidnumber'][0])
            except errors.SingleMatchExpected as e:
                # GID number matched more groups, this should not happen
                logger.warning('GID number %s of migrated user %s should '
                               'match 1 group, but it matched %d groups',
                               entry_attrs['gidnumber'][0], pkey, e.found)
            except errors.LimitsExceeded as e:
                logger.warning('Search limit exceeded searching for GID %s',
                               entry_attrs['gidnumber'][0])

    # We don't want to create a UPG so set the magic value in description
    # to let the DS plugin know.
    entry_attrs.setdefault('description', [])
    entry_attrs['description'].append(NO_UPG_MAGIC)

    # fill in required attributes by IPA
    entry_attrs['ipauniqueid'] = 'autogenerate'
    if 'homedirectory' not in entry_attrs:
        homes_root = config.get('ipahomesrootdir', (paths.HOME_DIR, ))[0]
        home_dir = '%s/%s' % (homes_root, pkey)
        home_dir = home_dir.replace('//', '/').rstrip('/')
        entry_attrs['homedirectory'] = home_dir

    if 'loginshell' not in entry_attrs:
        default_shell = config.get('ipadefaultloginshell', [paths.SH])[0]
        entry_attrs.setdefault('loginshell', default_shell)

    # do not migrate all attributes
    for attr in attr_blacklist:
        entry_attrs.pop(attr, None)

    # do not migrate all object classes
    if 'objectclass' in entry_attrs:
        for object_class in kwargs.get('oc_blacklist', []):
            try:
                entry_attrs['objectclass'].remove(object_class)
            except ValueError:  # object class not present
                pass

    _create_kerberos_principals(ldap, pkey, entry_attrs, failed)

    # Fix any attributes with DN syntax that point to entries in the old
    # tree

    for attr in entry_attrs.keys():
        if ldap.has_dn_syntax(attr):
            for ind, value in enumerate(entry_attrs[attr]):
                if not isinstance(value, DN):
                    # value is not DN instance, the automatic encoding may have
                    # failed due to missing schema or the remote attribute type OID was
                    # not detected as DN type. Try to work this around
                    logger.debug('%s: value %s of type %s in attribute %s is '
                                 'not a DN, convert it',
                                 pkey, value, type(value), attr)
                    try:
                        value = DN(value)
                    except ValueError as e:
                        logger.warning('%s: skipping normalization of value '
                                       '%s of type %s in attribute %s which '
                                       'could not be converted to DN: %s',
                                       pkey, value, type(value), attr, e)
                        continue
                try:
                    remote_entry = ds_ldap.get_entry(value, [api.Object.user.primary_key.name, api.Object.group.primary_key.name])
                except errors.NotFound:
                    logger.warning('%s: attribute %s refers to non-existent '
                                   'entry %s', pkey, attr, value)
                    continue
                if value.endswith(search_bases['user']):
                    primary_key = api.Object.user.primary_key.name
                    container = api.env.container_user
                elif value.endswith(search_bases['group']):
                    primary_key = api.Object.group.primary_key.name
                    container = api.env.container_group
                else:
                    logger.warning('%s: value %s in attribute %s does not '
                                   'belong into any known container',
                                   pkey, value, attr)
                    continue

                if not remote_entry.get(primary_key):
                    logger.warning('%s: there is no primary key %s to migrate '
                                   'for %s', pkey, primary_key, attr)
                    continue

                logger.debug('converting DN value %s for %s in %s',
                             value, attr, dn)
                rdnval = remote_entry[primary_key][0].lower()
                entry_attrs[attr][ind] = DN((primary_key, rdnval), container, api.env.basedn)

    return dn


def _post_migrate_user(ldap, pkey, dn, entry_attrs, failed, config, ctx):
    assert isinstance(dn, DN)

    if 'def_group_dn' in ctx:
        _update_default_group(ldap, ctx, False)

    if 'description' in entry_attrs and NO_UPG_MAGIC in entry_attrs['description']:
        entry_attrs['description'].remove(NO_UPG_MAGIC)
        try:
            update_attrs = ldap.get_entry(dn, ['description'])
            update_attrs['description'] = entry_attrs['description']
            ldap.update_entry(update_attrs)
        except (errors.EmptyModlist, errors.NotFound):
            pass

def _update_default_group(ldap, ctx, force):
    migrate_cnt = ctx['migrate_cnt']
    group_dn = ctx['def_group_dn']

    # Purposely let this fire when migrate_cnt == 0 so on re-running migration
    # it can catch any users migrated but not added to the default group.
    if force or migrate_cnt % 100 == 0:
        s = datetime.datetime.now()
        searchfilter = "(&(objectclass=posixAccount)(!(memberof=%s)))" % group_dn
        try:
            result, _truncated = ldap.find_entries(
                searchfilter, [''], DN(api.env.container_user, api.env.basedn),
                scope=ldap.SCOPE_SUBTREE, time_limit=-1, size_limit=-1)
        except errors.NotFound:
            logger.debug('All users have default group set')
            return

        member_dns = [m.dn for m in result]
        modlist = [(MOD_ADD, 'member', ldap.encode(member_dns))]
        try:
            with ldap.error_handler():
                ldap.conn.modify_s(str(group_dn), modlist)
        except errors.DatabaseError as e:
            logger.error('Adding new members to default group failed: %s \n'
                         'members: %s', e, ','.join(member_dns))

        e = datetime.datetime.now()
        d = e - s
        mode = " (forced)" if force else ""
        logger.info('Adding %d users to group%s duration %s',
                    len(member_dns), mode, d)

# GROUP MIGRATION CALLBACKS AND VARS

def _pre_migrate_group(ldap, pkey, dn, entry_attrs, failed, config, ctx, **kwargs):

    def convert_members_rfc2307bis(member_attr, search_bases, overwrite=False):
        """
        Convert DNs in member attributes to work in IPA.
        """
        new_members = []
        entry_attrs.setdefault(member_attr, [])
        for m in entry_attrs[member_attr]:
            try:
                m = DN(m)
            except ValueError as e:
                # This should be impossible unless the remote server
                # doesn't enforce syntax checking.
                logger.error('Malformed DN %s: %s', m, e)
                continue
            try:
                rdnval = m[0].value
            except IndexError:
                logger.error('Malformed DN %s has no RDN?', m)
                continue

            if m.endswith(search_bases['user']):
                logger.debug('migrating %s user %s', member_attr, m)
                m = DN((api.Object.user.primary_key.name, rdnval),
                       api.env.container_user, api.env.basedn)
            elif m.endswith(search_bases['group']):
                logger.debug('migrating %s group %s', member_attr, m)
                m = DN((api.Object.group.primary_key.name, rdnval),
                       api.env.container_group, api.env.basedn)
            else:
                logger.error('entry %s does not belong into any known '
                             'container', m)
                continue

            new_members.append(m)

        del entry_attrs[member_attr]
        if overwrite:
            entry_attrs['member'] = []
        entry_attrs['member'] += new_members

    def convert_members_rfc2307(member_attr):
        """
        Convert usernames in member attributes to work in IPA.
        """
        new_members = []
        entry_attrs.setdefault(member_attr, [])
        for m in entry_attrs[member_attr]:
            memberdn = DN((api.Object.user.primary_key.name, m),
                          api.env.container_user, api.env.basedn)
            new_members.append(memberdn)
        entry_attrs['member'] = new_members

    assert isinstance(dn, DN)
    attr_blacklist = ['memberofindirect','memberindirect']
    attr_blacklist.extend(kwargs.get('attr_blacklist', []))

    schema = kwargs.get('schema', None)
    entry_attrs['ipauniqueid'] = 'autogenerate'
    if schema == 'RFC2307bis':
        search_bases = kwargs.get('search_bases', None)
        if not search_bases:
            raise ValueError('Search bases not specified')

        convert_members_rfc2307bis('member', search_bases, overwrite=True)
        convert_members_rfc2307bis('uniquemember', search_bases)
    elif schema == 'RFC2307':
        convert_members_rfc2307('memberuid')
    else:
        raise ValueError('Schema %s not supported' % schema)

    # do not migrate all attributes
    for attr in attr_blacklist:
        entry_attrs.pop(attr, None)

    # do not migrate all object classes
    if 'objectclass' in entry_attrs:
        for object_class in kwargs.get('oc_blacklist', []):
            try:
                entry_attrs['objectclass'].remove(object_class)
            except ValueError:  # object class not present
                pass

    return dn


def _group_exc_callback(ldap, dn, entry_attrs, exc, options):
    assert isinstance(dn, DN)
    if isinstance(exc, errors.DuplicateEntry):
        if options.get('groupoverwritegid', False) and \
           entry_attrs.get('gidnumber') is not None:
            try:
                new_entry_attrs = ldap.get_entry(dn, ['gidnumber'])
                new_entry_attrs['gidnumber'] = entry_attrs['gidnumber']
                ldap.update_entry(new_entry_attrs)
            except errors.EmptyModlist:
                # no change to the GID
                pass
            # mark as success
            return
        elif not options.get('groupoverwritegid', False) and \
             entry_attrs.get('gidnumber') is not None:
            msg = unicode(exc)
            # add information about possibility to overwrite GID
            msg = msg + unicode(_('. Check GID of the existing group. ' \
                    'Use --group-overwrite-gid option to overwrite the GID'))
            raise errors.DuplicateEntry(message=msg)

    raise exc

# DS MIGRATION PLUGIN

def construct_filter(template, oc_list):
    oc_subfilter = ''.join([ '(objectclass=%s)' % oc for oc in oc_list])
    return template % oc_subfilter

def validate_ldapuri(ugettext, ldapuri):
    m = re.match(r'^ldaps?://[-\w\.]+(:\d+)?$', ldapuri)
    if not m:
        err_msg = _('Invalid LDAP URI.')
        raise errors.ValidationError(name='ldap_uri', error=err_msg)


@register()
class migrate_ds(Command):
    __doc__ = _('Migrate users and groups from DS to IPA.')

    migrate_objects = {
        # OBJECT_NAME: (search_filter, pre_callback, post_callback)
        #
        # OBJECT_NAME - is the name of an LDAPObject subclass
        # search_filter - is the filter to retrieve objects from DS
        # pre_callback - is called for each object just after it was
        #                retrieved from DS and before being added to IPA
        # post_callback - is called for each object after it was added to IPA
        # exc_callback - is called when adding entry to IPA raises an exception
        #
        # {pre, post}_callback parameters:
        #  ldap - ldap2 instance connected to IPA
        #  pkey - primary key value of the object (uid for users, etc.)
        #  dn - dn of the object as it (will be/is) stored in IPA
        #  entry_attrs - attributes of the object
        #  failed - a list of so-far failed objects
        #  config - IPA config entry attributes
        #  ctx - object context, used to pass data between callbacks
        #
        # If pre_callback return value evaluates to False, migration
        # of the current object is aborted.
        'user': {
            'filter_template' : '(&(|%s)(uid=*))',
            'oc_option' : 'userobjectclass',
            'oc_blacklist_option' : 'userignoreobjectclass',
            'attr_blacklist_option' : 'userignoreattribute',
            'pre_callback' : _pre_migrate_user,
            'post_callback' : _post_migrate_user,
            'exc_callback' : None
        },
        'group': {
            'filter_template' : '(&(|%s)(cn=*))',
            'oc_option' : 'groupobjectclass',
            'oc_blacklist_option' : 'groupignoreobjectclass',
            'attr_blacklist_option' : 'groupignoreattribute',
            'pre_callback' : _pre_migrate_group,
            'post_callback' : None,
            'exc_callback' : _group_exc_callback,
        },
    }
    migrate_order = ('user', 'group')

    takes_args = (
        Str('ldapuri', validate_ldapuri,
            cli_name='ldap_uri',
            label=_('LDAP URI'),
            doc=_('LDAP URI of DS server to migrate from'),
        ),
        Password('bindpw',
            cli_name='password',
            label=_('Password'),
            confirm=False,
            doc=_('bind password'),
        ),
    )

    takes_options = (
        DNParam('binddn?',
            cli_name='bind_dn',
            label=_('Bind DN'),
            default=DN(('cn', 'directory manager')),
            autofill=True,
        ),
        DNParam('usercontainer',
            cli_name='user_container',
            label=_('User container'),
            doc=_('DN of container for users in DS relative to base DN'),
            default=DN(('ou', 'people')),
            autofill=True,
        ),
        DNParam('groupcontainer',
            cli_name='group_container',
            label=_('Group container'),
            doc=_('DN of container for groups in DS relative to base DN'),
            default=DN(('ou', 'groups')),
            autofill=True,
        ),
        Str('userobjectclass+',
            cli_name='user_objectclass',
            label=_('User object class'),
            doc=_('Objectclasses used to search for user entries in DS'),
            default=(u'person',),
            autofill=True,
        ),
        Str('groupobjectclass+',
            cli_name='group_objectclass',
            label=_('Group object class'),
            doc=_('Objectclasses used to search for group entries in DS'),
            default=(u'groupOfUniqueNames', u'groupOfNames'),
            autofill=True,
        ),
        Str('userignoreobjectclass*',
            cli_name='user_ignore_objectclass',
            label=_('Ignore user object class'),
            doc=_('Objectclasses to be ignored for user entries in DS'),
            default=tuple(),
            autofill=True,
        ),
        Str('userignoreattribute*',
            cli_name='user_ignore_attribute',
            label=_('Ignore user attribute'),
            doc=_('Attributes to be ignored for user entries in DS'),
            default=tuple(),
            autofill=True,
        ),
        Str('groupignoreobjectclass*',
            cli_name='group_ignore_objectclass',
            label=_('Ignore group object class'),
            doc=_('Objectclasses to be ignored for group entries in DS'),
            default=tuple(),
            autofill=True,
        ),
        Str('groupignoreattribute*',
            cli_name='group_ignore_attribute',
            label=_('Ignore group attribute'),
            doc=_('Attributes to be ignored for group entries in DS'),
            default=tuple(),
            autofill=True,
        ),
        Flag('groupoverwritegid',
            cli_name='group_overwrite_gid',
            label=_('Overwrite GID'),
            doc=_('When migrating a group already existing in IPA domain overwrite the '\
                  'group GID and report as success'),
        ),
        StrEnum('schema?',
            cli_name='schema',
            label=_('LDAP schema'),
            doc=_('The schema used on the LDAP server. Supported values are RFC2307 and RFC2307bis. The default is RFC2307bis'),
            values=_supported_schemas,
            default=_supported_schemas[0],
            autofill=True,
        ),
        Flag('continue?',
            label=_('Continue'),
            doc=_('Continuous operation mode. Errors are reported but the process continues'),
            default=False,
        ),
        DNParam('basedn?',
            cli_name='base_dn',
            label=_('Base DN'),
            doc=_('Base DN on remote LDAP server'),
        ),
        Flag('compat?',
            cli_name='with_compat',
            label=_('Ignore compat plugin'),
            doc=_('Allows migration despite the usage of compat plugin'),
            default=False,
        ),
        Str('cacertfile?',
            cli_name='ca_cert_file',
            label=_('CA certificate'),
            doc=_('Load CA certificate of LDAP server from FILE'),
            default=None,
            noextrawhitespace=False,
            ),
        Bool('use_def_group?',
             cli_name='use_default_group',
             label=_('Add to default group'),
             doc=_('Add migrated users without a group to a default group '
                   '(default: true)'),
             default=True,
             autofill=True,
             ),
        StrEnum('scope',
                cli_name='scope',
                label=_('Search scope'),
                doc=_('LDAP search scope for users and groups: base, '
                      'onelevel, or subtree. Defaults to onelevel'),
                values=sorted(_supported_scopes),
                default=_default_scope,
                autofill=True,
                ),
    )

    has_output = (
        output.Output('result',
            type=dict,
            doc=_('Lists of objects migrated; categorized by type.'),
        ),
        output.Output('failed',
            type=dict,
            doc=_('Lists of objects that could not be migrated; categorized by type.'),
        ),
        output.Output('enabled',
            type=bool,
            doc=_('False if migration mode was disabled.'),
        ),
        output.Output('compat',
            type=bool,
            doc=_('False if migration fails because the compatibility plug-in is enabled.'),
        ),
    )

    exclude_doc = _('%s to exclude from migration')

    truncated_err_msg = _('''\
search results for objects to be migrated
have been truncated by the server;
migration process might be incomplete\n''')

    def get_options(self):
        """
        Call get_options of the baseclass and add "exclude" options
        for each type of object being migrated.
        """
        for option in super(migrate_ds, self).get_options():
            yield option
        for ldap_obj_name in self.migrate_objects:
            ldap_obj = self.api.Object[ldap_obj_name]
            name = 'exclude_%ss' % to_cli(ldap_obj_name)
            doc = self.exclude_doc % ldap_obj.object_name_plural
            yield Str(
                '%s*' % name, cli_name=name, doc=doc, default=tuple(),
                autofill=True
            )

    def normalize_options(self, options):
        """
        Convert all "exclude" option values to lower-case.

        Also, empty List parameters are converted to None, but the migration
        plugin doesn't like that - convert back to empty lists.
        """
        names = ['userobjectclass', 'groupobjectclass',
                 'userignoreobjectclass', 'userignoreattribute',
                 'groupignoreobjectclass', 'groupignoreattribute']
        names.extend('exclude_%ss' % to_cli(n) for n in self.migrate_objects)
        for name in names:
            if options[name]:
                options[name] = tuple(
                    v.lower() for v in options[name]
                )
            else:
                options[name] = tuple()

    def _get_search_bases(self, options, ds_base_dn, migrate_order):
        search_bases = dict()
        for ldap_obj_name in migrate_order:
            container = options.get('%scontainer' % to_cli(ldap_obj_name))
            if container:
                # Don't append base dn if user already appended it in the container dn
                if container.endswith(ds_base_dn):
                    search_base = container
                else:
                    search_base = DN(container, ds_base_dn)
            else:
                search_base = ds_base_dn
            search_bases[ldap_obj_name] = search_base
        return search_bases

    def migrate(self, ldap, config, ds_ldap, ds_base_dn, options):
        """
        Migrate objects from DS to LDAP.
        """
        assert isinstance(ds_base_dn, DN)
        migrated = {} # {'OBJ': ['PKEY1', 'PKEY2', ...], ...}
        failed = {} # {'OBJ': {'PKEY1': 'Failed 'cos blabla', ...}, ...}
        search_bases = self._get_search_bases(options, ds_base_dn, self.migrate_order)
        migration_start = datetime.datetime.now()

        scope = _supported_scopes[options.get('scope')]

        for ldap_obj_name in self.migrate_order:
            ldap_obj = self.api.Object[ldap_obj_name]

            template = self.migrate_objects[ldap_obj_name]['filter_template']
            oc_list = options[to_cli(self.migrate_objects[ldap_obj_name]['oc_option'])]
            search_filter = construct_filter(template, oc_list)

            exclude = options['exclude_%ss' % to_cli(ldap_obj_name)]
            context = dict(ds_ldap = ds_ldap)

            migrated[ldap_obj_name] = []
            failed[ldap_obj_name] = {}

            try:
                entries, truncated = ds_ldap.find_entries(
                    search_filter, ['*'], search_bases[ldap_obj_name],
                    scope,
                    time_limit=0, size_limit=-1
                )
            except errors.NotFound:
                if not options.get('continue',False):
                    raise errors.NotFound(
                        reason=_('%(container)s LDAP search did not return any result '
                                 '(search base: %(search_base)s, '
                                 'objectclass: %(objectclass)s)')
                                 % {'container': ldap_obj_name,
                                    'search_base': search_bases[ldap_obj_name],
                                    'objectclass': ', '.join(oc_list)}
                    )
                else:
                    truncated = False
                    entries = []
            if truncated:
                logger.error(
                    '%s: %s',
                    ldap_obj.name, self.truncated_err_msg
                )

            blacklists = {}
            for blacklist in ('oc_blacklist', 'attr_blacklist'):
                blacklist_option = self.migrate_objects[ldap_obj_name][blacklist+'_option']
                if blacklist_option is not None:
                    blacklists[blacklist] = options.get(blacklist_option, tuple())
                else:
                    blacklists[blacklist] = tuple()

            # get default primary group for new users
            if 'def_group_dn' not in context and options.get('use_def_group'):
                def_group = config.get('ipadefaultprimarygroup')
                context['def_group_dn'] = api.Object.group.get_dn(def_group)
                try:
                    ldap.get_entry(context['def_group_dn'], ['gidnumber', 'cn'])
                except errors.NotFound:
                    error_msg = _('Default group for new users not found')
                    raise errors.NotFound(reason=error_msg)

            context['has_upg'] = ldap.has_upg()

            valid_gids = set()
            invalid_gids = set()
            migrate_cnt = 0
            context['migrate_cnt'] = 0
            for entry_attrs in entries:
                context['migrate_cnt'] = migrate_cnt
                s = datetime.datetime.now()

                ava = entry_attrs.dn[0][0]
                if ava.attr == ldap_obj.primary_key.name:
                    # In case if pkey attribute is in the migrated object DN
                    # and the original LDAP is multivalued, make sure that
                    # we pick the correct value (the unique one stored in DN)
                    pkey = ava.value.lower()
                else:
                    pkey = entry_attrs[ldap_obj.primary_key.name][0].lower()

                if pkey in exclude:
                    continue

                entry_attrs.dn = ldap_obj.get_dn(pkey)
                entry_attrs['objectclass'] = list(
                    set(
                        config.get(
                            ldap_obj.object_class_config, ldap_obj.object_class
                        ) + [o.lower() for o in entry_attrs['objectclass']]
                    )
                )
                entry_attrs[ldap_obj.primary_key.name][0] = entry_attrs[ldap_obj.primary_key.name][0].lower()

                callback = self.migrate_objects[ldap_obj_name]['pre_callback']
                if callable(callback):
                    try:
                        entry_attrs.dn = callback(
                            ldap, pkey, entry_attrs.dn, entry_attrs,
                            failed[ldap_obj_name], config, context,
                            schema=options['schema'],
                            search_bases=search_bases,
                            valid_gids=valid_gids,
                            invalid_gids=invalid_gids,
                            **blacklists
                        )
                        if not entry_attrs.dn:
                            continue
                    except errors.NotFound as e:
                        failed[ldap_obj_name][pkey] = unicode(e.reason)
                        continue

                try:
                    ldap.add_entry(entry_attrs)
                except errors.ExecutionError as e:
                    callback = self.migrate_objects[ldap_obj_name]['exc_callback']
                    if callable(callback):
                        try:
                            callback(
                                ldap, entry_attrs.dn, entry_attrs, e, options)
                        except errors.ExecutionError as e:
                            failed[ldap_obj_name][pkey] = unicode(e)
                            continue
                    else:
                        failed[ldap_obj_name][pkey] = unicode(e)
                        continue

                migrated[ldap_obj_name].append(pkey)

                callback = self.migrate_objects[ldap_obj_name]['post_callback']
                if callable(callback):
                    callback(
                        ldap, pkey, entry_attrs.dn, entry_attrs,
                        failed[ldap_obj_name], config, context)
                e = datetime.datetime.now()
                d = e - s
                total_dur = e - migration_start
                migrate_cnt += 1
                if migrate_cnt > 0 and migrate_cnt % 100 == 0:
                    logger.info("%d %ss migrated. %s elapsed.",
                                migrate_cnt, ldap_obj_name, total_dur)
                logger.debug("%d %ss migrated, duration: %s (total %s)",
                             migrate_cnt, ldap_obj_name, d, total_dur)

        if 'def_group_dn' in context:
            _update_default_group(ldap, context, True)

        return (migrated, failed)

    def execute(self, ldapuri, bindpw, **options):
        ldap = self.api.Backend.ldap2
        self.normalize_options(options)
        config = ldap.get_ipa_config()

        ds_base_dn = options.get('basedn')
        if ds_base_dn is not None:
            assert isinstance(ds_base_dn, DN)

        # check if migration mode is enabled
        if config.get('ipamigrationenabled', ('FALSE', ))[0] == 'FALSE':
            return dict(result={}, failed={}, enabled=False, compat=True)

        # connect to DS
        cacert = None
        if options.get('cacertfile') is not None:
            # store CA cert into file
            tmp_ca_cert_f = write_tmp_file(options['cacertfile'])
            cacert = tmp_ca_cert_f.name

            # start TLS connection
            ds_ldap = LDAPClient(ldapuri, cacert=cacert)
            ds_ldap.simple_bind(options['binddn'], bindpw)

            tmp_ca_cert_f.close()
        else:
            ds_ldap = LDAPClient(ldapuri, cacert=cacert)
            ds_ldap.simple_bind(options['binddn'], bindpw)

        # check whether the compat plugin is enabled
        if not options.get('compat'):
            try:
                ldap.get_entry(DN(('cn', 'compat'), (api.env.basedn)))
                return dict(result={}, failed={}, enabled=True, compat=False)
            except errors.NotFound:
                pass

        if not ds_base_dn:
            # retrieve base DN from remote LDAP server
            entries, _truncated = ds_ldap.find_entries(
                '', ['namingcontexts', 'defaultnamingcontext'], DN(''),
                ds_ldap.SCOPE_BASE, size_limit=-1, time_limit=0,
            )
            if 'defaultnamingcontext' in entries[0]:
                ds_base_dn = DN(entries[0]['defaultnamingcontext'][0])
                assert isinstance(ds_base_dn, DN)
            else:
                try:
                    ds_base_dn = DN(entries[0]['namingcontexts'][0])
                    assert isinstance(ds_base_dn, DN)
                except (IndexError, KeyError) as e:
                    raise Exception(str(e))

        # migrate!
        (migrated, failed) = self.migrate(
            ldap, config, ds_ldap, ds_base_dn, options
        )

        return dict(result=migrated, failed=failed, enabled=True, compat=True)
