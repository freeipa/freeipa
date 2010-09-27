# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
"""
Migration to IPA

Example: Migrate users and groups from DS to IPA

  ipa migrate-ds ldap://example.com:389
"""

import logging
import re

from ipalib import api, errors, output, uuid
from ipalib import Command, List, Password, Str, Flag
from ipalib.cli import to_cli
if api.env.in_server and api.env.context in ['lite', 'server']:
    try:
        from ipaserver.plugins.ldap2 import ldap2
    except StandardError, e:
        raise e
from ipalib import _
from ipalib.text import Gettext # FIXME: remove once the other Gettext FIXME is removed


# USER MIGRATION CALLBACKS AND VARS

_krb_err_msg = _('Kerberos principal %s already exists. Use \'ipa user-mod\' to set it manually.')
_grp_err_msg = _('Failed to add user to the default group. Use \'ipa group-add-member\' to add manually.')


def _pre_migrate_user(ldap, pkey, dn, entry_attrs, failed, config, ctx):
    # get default primary group for new users
    if 'def_group_dn' not in ctx:
        def_group = config.get('ipadefaultprimarygroup')
        ctx['def_group_dn'] = api.Object.group.get_dn(def_group)
        try:
            (g_dn, g_attrs) = ldap.get_entry(ctx['def_group_dn'], ['gidnumber'])
        except errors.NotFound:
            error_msg = 'Default group for new users not found.'
            raise errors.NotFound(reason=error_msg)
        ctx['def_group_gid'] = g_attrs['gidnumber'][0]

    # fill in required attributes by IPA
    entry_attrs['ipauniqueid'] = str(uuid.uuid1())
    if 'homedirectory' not in entry_attrs:
        homes_root = config.get('ipahomesrootdir', ('/home', ))[0]
        home_dir = '%s/%s' % (homes_root, pkey)
        home_dir = home_dir.replace('//', '/').rstrip('/')
        entry_attrs['homedirectory'] = home_dir
    entry_attrs.setdefault('gidnumber', ctx['def_group_gid'])

    # generate a principal name and check if it isn't already taken
    principal = u'%s@%s' % (pkey, api.env.realm)
    try:
        ldap.find_entry_by_attr(
            'krbprincipalname', principal, 'krbprincipalaux', ['']
        )
    except errors.NotFound:
        entry_attrs['krbprincipalname'] = principal
    else:
        failed[pkey] = _krb_err_msg % principal

    return dn


def _post_migrate_user(ldap, pkey, dn, entry_attrs, failed, config, ctx):
    # add user to the default group
    try:
        ldap.add_entry_to_group(dn, ctx['def_group_dn'])
    except errors.ExecutionError, e:
        failed[pkey] = _grp_err_msg


# GROUP MIGRATION CALLBACKS AND VARS

def _pre_migrate_group(ldap, pkey, dn, entry_attrs, failed, config, ctx):
    def convert_members(member_attr, overwrite=False):
        """
        Convert DNs in member attributes to work in IPA.
        """
        new_members = []
        entry_attrs.setdefault(member_attr, [])
        for m in entry_attrs[member_attr]:
            col = m.find(',')
            if col == -1:
                continue
            if m.startswith('uid'):
                m = '%s,%s' % (m[0:col], api.env.container_user)
            elif m.startswith('cn'):
                m = '%s,%s' % (m[0:col], api.env.container_group)
            m = ldap.normalize_dn(m)
            new_members.append(m)
        del entry_attrs[member_attr]
        if overwrite:
            entry_attrs['member'] = []
        entry_attrs['member'] += new_members

    entry_attrs['ipauniqueid'] = str(uuid.uuid1())
    convert_members('member', overwrite=True)
    convert_members('uniquemember')

    return dn


# DS MIGRATION PLUGIN

def validate_ldapuri(ugettext, ldapuri):
    m = re.match('^ldaps?://[-\w\.]+(:\d+)?$', ldapuri)
    if not m:
        err_msg = 'Invalid LDAP URI.'
        raise errors.ValidationError(name='ldap_uri', error=err_msg)


class migrate_ds(Command):
    """
    Migrate users and groups from DS to IPA.
    """
    migrate_objects = {
        # OBJECT_NAME: (search_filter, pre_callback, post_callback)
        #
        # OBJECT_NAME - is the name of an LDAPObject subclass
        # search_filter - is the filter to retrieve objects from DS
        # pre_callback - is called for each object just after it was
        #                retrieved from DS and before being added to IPA
        # post_callback - is called for each object after it was added to IPA
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
        'user': (
            '(&(objectClass=person)(uid=*))',
            _pre_migrate_user, _post_migrate_user
        ),
        'group': (
            '(&(|(objectClass=groupOfUniqueNames)(objectClass=groupOfNames))(cn=*))',
            _pre_migrate_group, None
        ),
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
            doc=_('bind password'),
        ),
    )

    takes_options = (
        Str('binddn?',
            cli_name='bind_dn',
            label=_('Bind DN'),
            default=u'cn=directory manager',
            autofill=True,
        ),
        Str('usercontainer?',
            cli_name='user_container',
            label=_('User container'),
            doc=_('RDN of container for users in DS'),
            default=u'ou=people',
            autofill=True,
        ),
        Str('groupcontainer?',
            cli_name='group_container',
            label=_('Group container'),
            doc=_('RDN of container for groups in DS'),
            default=u'ou=groups',
            autofill=True,
        ),
        Flag('continue?',
            doc=_('Continous operation mode. Errors are reported but the process continues'),
            default=False,
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
    )

    exclude_doc = _('comma-separated list of %s to exclude from migration')

    truncated_err_msg = _('''\
search results for objects to be migrated
have been truncated by the server;
migration process might be uncomplete\n''')

    migration_disabled_msg = _('''\
Migration mode is disabled. Use \'ipa config-mod\' to enable it.''')

    pwd_migration_msg = _('''\
Passwords have been migrated in pre-hashed format.
IPA is unable to generate Kerberos keys unless provided
with clear text passwords. All migrated users need to
login at https://your.domain/ipa/migration/ before they
can use their Kerberos accounts.''')

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
            # FIXME: can't substitute strings static Gettext instance
            doc = Gettext(self.exclude_doc % ldap_obj.object_name_plural)
            yield List(
                '%s?' % name, cli_name=name, doc=doc, default=tuple(),
                autofill=True
            )

    def normalize_options(self, options):
        """
        Convert all "exclude" option values to lower-case.

        Also, empty List parameters are converted to None, but the migration
        plugin doesn't like that - convert back to empty lists.
        """
        for p in self.params():
            if isinstance(p, List):
                if options[p.name]:
                    options[p.name] = tuple(
                        v.lower() for v in options[p.name]
                    )
                else:
                    options[p.name] = tuple()

    def migrate(self, ldap, config, ds_ldap, ds_base_dn, options):
        """
        Migrate objects from DS to LDAP.
        """
        migrated = {} # {'OBJ': ['PKEY1', 'PKEY2', ...], ...}
        failed = {} # {'OBJ': {'PKEY1': 'Failed 'cos blabla', ...}, ...}
        for ldap_obj_name in self.migrate_order:
            ldap_obj = self.api.Object[ldap_obj_name]

            search_filter = self.migrate_objects[ldap_obj_name][0]
            search_base = '%s,%s' % (
                options['%scontainer' % to_cli(ldap_obj_name)], ds_base_dn
            )
            exclude = options['exclude_%ss' % to_cli(ldap_obj_name)]
            context = {}

            migrated[ldap_obj_name] = []
            failed[ldap_obj_name] = {}

            # FIXME: with limits set, we get a strange 'Success' exception
            try:
                (entries, truncated) = ds_ldap.find_entries(
                    search_filter, ['*'], search_base, ds_ldap.SCOPE_ONELEVEL#,
                    #time_limit=0, size_limit=0
                )
            except errors.NotFound:
                if not options.get('continue',False):
                    raise errors.NotFound(reason=_('Container for %(container)s not found' % {'container':ldap_obj_name}))
                else:
                    truncated = False
                    entries = []
            if truncated:
                self.log.error(
                    '%s: %s' % (
                        ldap_obj.object_name_plural, self.truncated_err_msg
                    )
                )

            for (dn, entry_attrs) in entries:
                pkey = entry_attrs[ldap_obj.primary_key.name][0].lower()
                if pkey in exclude:
                    continue

                dn = ldap_obj.get_dn(pkey)
                entry_attrs['objectclass'] = list(
                    set(
                        config.get(
                            ldap_obj.object_class_config, ldap_obj.object_class
                        ) + [o.lower() for o in entry_attrs['objectclass']]
                    )
                )

                callback = self.migrate_objects[ldap_obj_name][1]
                if callable(callback):
                    dn = callback(
                        ldap, pkey, dn, entry_attrs, failed[ldap_obj_name],
                        config, context
                    )
                    if not dn:
                        continue

                try:
                    ldap.add_entry(dn, entry_attrs)
                except errors.ExecutionError, e:
                    failed[ldap_obj_name][pkey] = unicode(e)
                else:
                    migrated[ldap_obj_name].append(pkey)

                    callback = self.migrate_objects[ldap_obj_name][2]
                    if callable(callback):
                        callback(
                            ldap, pkey, dn, entry_attrs, failed[ldap_obj_name],
                            config, context
                        )

        return (migrated, failed)

    def execute(self, ldapuri, bindpw, **options):
        ldap = self.api.Backend.ldap2
        self.normalize_options(options)

        config = ldap.get_ipa_config()[1]

        # check if migration mode is enabled
        if config.get('ipamigrationenabled', ('FALSE', ))[0] == 'FALSE':
            return dict(result={}, failed={}, enabled=False)

        # connect to DS
        ds_ldap = ldap2(shared_instance=False, ldap_uri=ldapuri, base_dn='')
        ds_ldap.connect(bind_dn=options['binddn'], bind_pw=bindpw)

        # retrieve DS base DN
        (entries, truncated) = ds_ldap.find_entries(
            '', ['namingcontexts'], '', ds_ldap.SCOPE_BASE
        )
        try:
            ds_base_dn = entries[0][1]['namingcontexts'][0]
        except (IndexError, KeyError), e:
            raise StandardError(str(e))

        # migrate!
        (migrated, failed) = self.migrate(
            ldap, config, ds_ldap, ds_base_dn, options
        )

        return dict(result=migrated, failed=failed, enabled=True)

    def output_for_cli(self, textui, result, ldapuri, bindpw, **options):
        textui.print_name(self.name)
        if not result['enabled']:
            textui.print_plain(self.migration_disabled_msg)
            return 1
        textui.print_plain('Migrated:')
        textui.print_entry1(
            result['result'], attr_order=self.migrate_order,
            one_value_per_line=False
        )
        for ldap_obj_name in self.migrate_order:
            textui.print_plain('Failed %s:' % ldap_obj_name)
            textui.print_entry1(
                result['failed'][ldap_obj_name], attr_order=self.migrate_order,
                one_value_per_line=True,
            )
        textui.print_plain('-' * len(self.name))
        textui.print_plain(unicode(self.pwd_migration_msg))

api.register(migrate_ds)
