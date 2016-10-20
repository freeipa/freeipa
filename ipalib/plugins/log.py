from ipalib import api, Object, Str, _, ngettext, Int, Flag, crud, errors, output, create_api
from ipalib.parameters import Any
from ipalib.output import Output
from ipalib.plugins.baseldap import *
from ipalib.plugins import baseldap
from ipalib.plugable import Registry
from ipalib.cli import to_cli
from ipapython.version import API_VERSION
from ipalib.capabilities import client_has_capability

register = Registry()

def gen_pkey_only_option(cli_name):
    return Flag('pkey_only?',
                label=_('Primary key only'),
                doc=_('Results should contain primary key attribute only ("%s")') \
                    % to_cli(cli_name),)

def pkey_to_value(key, options):
    version = options.get('version', API_VERSION)
    if client_has_capability(version, 'primary_key_types'):
        return key
    return pkey_to_unicode(key)

@register()
class log(LDAPObject):

    default_attributes = [
        'logtime', 'loglevel', 'loguser', 'logip', 'logstatus', 'logmessage'
    ]

    search_display_attributes = [
        'logtime', 'loglevel', 'loguser', 'logip', 'logstatus', 'logmessage',
    ]

    takes_params = (
        Str('logline', primary_key=True),
        Str('logtime', cli_name="time", label='time'),
        Str('loglevel', cli_name="level", label='level'),
        Str('loguser', cli_name="user", label='user'),
        Str('logip', cli_name="ip", label='ip'),
        Str('logstatus', cli_name="status", label='status'),
        Str('logmessage', cli_name="message", label='message'),
    )

    parent_object = ''
    object_not_found_msg = _('%(pkey)s: not found')

    def get_ancestor_primary_keys(self):
        if self.parent_object:
            parent_obj = self.api.Object[self.parent_object]
            for key in parent_obj.get_ancestor_primary_keys():
                yield key
            if parent_obj.primary_key:
                pkey = parent_obj.primary_key
                yield pkey.clone_rename(
                    parent_obj.name + pkey.name, required=True, query=True,
                    cli_name=parent_obj.name, label=pkey.label
                )

    def handle_not_found(self, *keys):
        pkey = ''
        if self.primary_key:
            pkey = keys[-1]
        raise errors.NotFound(
            reason=self.object_not_found_msg % {
                'pkey': pkey,
            }
        )

@register()
class log_show(crud.Retrieve):
    __doc__ = _('Display information about a log.')

    takes_options = (
        Flag('rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
        ),
    )

    def get_args(self):
        for key in self.obj.get_ancestor_primary_keys():
            yield key
        for arg in super(crud.Retrieve, self).get_args():
            yield arg

    # list of attributes we want exported to JSON
    json_friendly_attributes = (
        'takes_args',
    )

    def execute(self, *keys, **options):
        flag=keys[-1]
        entry_list=[]

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
        else:
            attrs_list = set(self.obj.default_attributes)
            if options.get('no_members', False):
                attrs_list.difference_update(self.obj.attribute_members)
            attrs_list = list(attrs_list)

        linenumber = 0
        for line in open("/var/log/ipa/ipa.log"):
            line_ignore_enter = line.strip('\n')
            line_list = line_ignore_enter.split('\t')
            (logtime, loglevel, loguser, logip, logstatus, logmessage) = line_list
            entry_attrs=dict()
            linenumber += 1
            entry_attrs[u'logline'] = unicode(linenumber)
            i = 0
            for param in self.obj.default_attributes:
                entry_attrs[unicode(param)] = unicode(line_list[i]).split("\n", 1)
                i += 1
            entry_list.append(entry_attrs)

        try:
            int(flag)
        except(ValueError):
            raise errors.NotInt(
                reason=_('%(pkey)s: not logline') % {
                    'pkey': flag,
                }
            )

        results = dict()
        for entry in entry_list:
            if flag == entry['logline']:
                results = entry
                break
        if self.obj.primary_key:
            pkey = keys[-1]
        else:
            pkey = None
        if not results:
            self.obj.handle_not_found(*keys)

        return dict(result=results, value=pkey_to_value(pkey, options))

@register()
class log_find(crud.Search):
    __doc__ = _('search for log.')
    
    takes_options = (
        Int('timelimit?',
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds'),
            flags=['no_display'],
            minvalue=0,
            autofill=False,
        ),
        Int('sizelimit?',
            label=_('Size Limit'),
            doc=_('Maximum number of entries returned'),
            flags=['no_display'],
            minvalue=0,
            autofill=False,
        ),
    )

    member_attributes = []

    def get_member_options(self, attr):
        for ldap_obj_name in self.obj.attribute_members[attr]:
            ldap_obj = self.api.Object[ldap_obj_name]
            relationship = self.obj.relationships.get(
                attr, ['member', '', 'no_']
            )
            doc = self.member_param_incl_doc % dict(
                searched_object=self.obj.object_name_plural,
                relationship=relationship[0].lower(),
                ldap_object=ldap_obj.object_name_plural
            )
            name = '%s%s' % (relationship[1], to_cli(ldap_obj_name))
            yield Str(
                '%s*' % name, cli_name='%ss' % name, doc=doc,
                label=ldap_obj.object_name, csv=True
            )
            doc = self.member_param_excl_doc % dict(
                searched_object=self.obj.object_name_plural,
                relationship=relationship[0].lower(),
                ldap_object=ldap_obj.object_name_plural
            )
            name = '%s%s' % (relationship[2], to_cli(ldap_obj_name))
            yield Str(
                '%s*' % name, cli_name='%ss' % name, doc=doc,
                label=ldap_obj.object_name, csv=True
            )

    def get_options(self):
        for option in super(crud.Search, self).get_options():
            yield option
        if self.obj.primary_key and \
                'no_output' not in self.obj.primary_key.flags:
            yield gen_pkey_only_option(self.obj.primary_key.cli_name)
        for attr in self.member_attributes:
            for option in self.get_member_options(attr):
                yield option

    def execute(self, *args, **options):
        flag = args[-1]
        entries=[]
        linenumber = 0
        truncated = False

        for line in open("/var/log/ipa/ipa.log"):
            line_ignore_enter = line.strip('\n')
            line_list = line_ignore_enter.split('\t')
            (logtime, loglevel, loguser, logip, logstatus, logmessage) = line_list

            entry_dict=dict()
            linenumber += 1
            entry_dict[u'logline'] = unicode(linenumber)
            i = 0
            for params in self.obj.default_attributes:
                entry_dict[unicode(params)] = unicode(line_list[i]).split("\n", 1)
                i += 1
            if flag:
                if flag in line:
                    entries.append(entry_dict)
                else:
                    entries = entries
            else:
                entries.append(entry_dict)
        return dict(result=entries[::-1], count=len(entries), truncated=truncated)
