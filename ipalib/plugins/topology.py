#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipalib import api, errors
from ipalib import Int, Str, Bool, StrEnum, Flag
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import (
    LDAPObject, LDAPSearch, LDAPCreate, LDAPDelete, LDAPUpdate, LDAPQuery,
    LDAPRetrieve)
from ipalib import _, ngettext
from ipalib import output
from ipapython.dn import DN


__doc__ = _("""
Topology

Management of a replication topology.

Requires minimum domain level 1.
""")

register = Registry()

MINIMUM_DOMAIN_LEVEL = 1


def validate_domain_level(api):
    current = int(api.Command.domainlevel_get()['result'])
    if current < MINIMUM_DOMAIN_LEVEL:
        raise errors.InvalidDomainLevelError(
            _('Topology management requires minimum domain level {0} '
              .format(MINIMUM_DOMAIN_LEVEL))
        )


@register()
class topologysegment(LDAPObject):
    """
    Topology segment.
    """
    parent_object = 'topologysuffix'
    container_dn = api.env.container_topology
    object_name = _('segment')
    object_name_plural = _('segments')
    object_class = ['iparepltoposegment']
    default_attributes = [
        'cn',
        'ipaReplTopoSegmentdirection', 'ipaReplTopoSegmentrightNode',
        'ipaReplTopoSegmentLeftNode', 'nsds5replicastripattrs',
        'nsds5replicatedattributelist', 'nsds5replicatedattributelisttotal',
        'nsds5replicatimeout', 'nsds5replicaenabled'
    ]
    search_display_attributes = [
        'cn', 'ipaReplTopoSegmentdirection', 'ipaReplTopoSegmentrightNode',
        'ipaReplTopoSegmentLeftNode'
    ]

    label = _('Topology Segments')
    label_singular = _('Topology Segment')

    takes_params = (
        Str(
            'cn',
            maxlength=255,
            cli_name='name',
            primary_key=True,
            label=_('Segment name'),
            default_from=lambda iparepltoposegmentleftnode, iparepltoposegmentrightnode:
                         '%s-%s' % (iparepltoposegmentleftnode, iparepltoposegmentrightnode),
            normalizer=lambda value: value.lower(),
            doc=_('Arbitrary string identifying the segment'),
        ),
        Str(
            'iparepltoposegmentleftnode',
            pattern='^[a-zA-Z0-9.][a-zA-Z0-9.-]{0,252}[a-zA-Z0-9.$-]?$',
            pattern_errmsg='may only include letters, numbers, -, . and $',
            maxlength=255,
            cli_name='leftnode',
            label=_('Left node'),
            normalizer=lambda value: value.lower(),
            doc=_('Left replication node - an IPA server'),
            flags={'no_update'},
        ),
        Str(
            'iparepltoposegmentrightnode',
            pattern='^[a-zA-Z0-9.][a-zA-Z0-9.-]{0,252}[a-zA-Z0-9.$-]?$',
            pattern_errmsg='may only include letters, numbers, -, . and $',
            maxlength=255,
            cli_name='rightnode',
            label=_('Right node'),
            normalizer=lambda value: value.lower(),
            doc=_('Right replication node - an IPA server'),
            flags={'no_update'},
        ),
        StrEnum(
            'iparepltoposegmentdirection',
            cli_name='direction',
            label=_('Connectivity'),
            values=(u'both', u'left-right', u'right-left', u'none'),
            default=u'both',
            doc=_('Direction of replication between left and right replication '
                  'node'),
        ),
        Str(
            'nsds5replicastripattrs?',
            cli_name='stripattrs',
            label=_('Attributes to strip'),
            normalizer=lambda value: value.lower(),
            doc=_('A space separated list of attributes which are removed from '
                  'replication updates.')
        ),
        Str(
            'nsds5replicatedattributelist?',
            cli_name='replattrs',
            label='Attributes to replicate',
            doc=_('Attributes that are not replicated to a consumer server '
                  'during a fractional update. E.g., `(objectclass=*) '
                  '$ EXCLUDE accountlockout memberof'),
        ),
        Str(
            'nsds5replicatedattributelisttotal?',
            cli_name='replattrstotal',
            label=_('Attributes for total update'),
            doc=_('Attributes that are not replicated to a consumer server '
                  'during a total update. E.g. (objectclass=*) $ EXCLUDE '
                  'accountlockout'),
        ),
        Int(
            'nsds5replicatimeout?',
            cli_name='timeout',
            label=_('Session timeout'),
            minvalue=0,
            doc=_('Number of seconds outbound LDAP operations waits for a '
                  'response from the remote replica before timing out and '
                  'failing'),
        ),
        StrEnum(
            'nsds5replicaenabled?',
            cli_name='enabled',
            label=_('Replication agreement enabled'),
            doc=_('Whether a replication agreement is active, meaning whether '
                  'replication is occurring per that agreement'),
            values=(u'on', u'off'),
        ),
    )

    def validate_nodes(self, ldap, dn, entry_attrs):
        leftnode = entry_attrs.get('iparepltoposegmentleftnode')
        rightnode = entry_attrs.get('iparepltoposegmentrightnode')

        if not leftnode and not rightnode:
            return  # nothing to check

        # check if nodes are IPA servers
        masters = self.api.Command.server_find('', sizelimit=0)['result']
        m_hostnames = [master['cn'][0].lower() for master in masters]

        if leftnode and leftnode not in m_hostnames:
            raise errors.ValidationError(
                name='leftnode',
                error=_('left node is not a topology node: %(leftnode)s') %
                     dict(leftnode=leftnode)
            )

        if rightnode and rightnode not in m_hostnames:
            raise errors.ValidationError(
                name='rightnode',
                error=_('right node is not a topology node: %(rightnode)s') %
                     dict(rightnode=rightnode)
            )

        # prevent creation of reflexive relation
        key = 'leftnode'
        if not leftnode or not rightnode:  # get missing end
            _entry_attrs = ldap.get_entry(dn, ['*'])
            if not leftnode:
                key = 'rightnode'
                leftnode = _entry_attrs['iparepltoposegmentleftnode'][0]
            else:
                rightnode = _entry_attrs['iparepltoposegmentrightnode'][0]

        if leftnode == rightnode:
            raise errors.ValidationError(
                name=key,
                error=_('left node and right node must not be the same')
            )


@register()
class topologysegment_find(LDAPSearch):
    __doc__ = _('Search for topology segments.')

    msg_summary = ngettext(
        '%(count)d segment matched',
        '%(count)d segments matched', 0
    )


@register()
class topologysegment_add(LDAPCreate):
    __doc__ = _('Add a new segment.')

    msg_summary = _('Added segment "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        validate_domain_level(self.api)
        self.obj.validate_nodes(ldap, dn, entry_attrs)
        return dn


@register()
class topologysegment_del(LDAPDelete):
    __doc__ = _('Delete a segment.')

    msg_summary = _('Deleted segment "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        validate_domain_level(self.api)
        return dn


@register()
class topologysegment_mod(LDAPUpdate):
    __doc__ = _('Modify a segment.')

    msg_summary = _('Modified segment "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        validate_domain_level(self.api)
        self.obj.validate_nodes(ldap, dn, entry_attrs)
        return dn


@register()
class topologysegment_reinitialize(LDAPQuery):
    __doc__ = _('Request a full re-initialization of the node '
                'retrieving data from the other node.')

    has_output = output.standard_value
    msg_summary = _('%(value)s')

    takes_options = (
        Flag(
            'left?',
            doc=_('Initialize left node'),
            default=False,
        ),
        Flag(
            'right?',
            doc=_('Initialize right node'),
            default=False,
        ),
        Flag(
            'stop?',
            doc=_('Stop already started refresh of chosen node(s)'),
            default=False,
        ),
    )

    def execute(self, *keys, **options):
        dn = self.obj.get_dn(*keys, **options)
        validate_domain_level(self.api)

        entry = self.obj.backend.get_entry(
            dn, [
                'nsds5beginreplicarefresh;left',
                'nsds5beginreplicarefresh;right'
            ])

        left = options.get('left')
        right = options.get('right')
        stop = options.get('stop')

        if not left and not right:
            raise errors.OptionError(
                _('left or right node has to be specified')
            )

        if left and right:
            raise errors.OptionError(
                _('only one node can be specified')
            )

        action = u'start'
        msg = _('Replication refresh for segment: "%(pkey)s" requested.')
        if stop:
            action = u'stop'
            msg = _('Stopping of replication refresh for segment: "'
                    '%(pkey)s" requested.')

        if left:
            entry['nsds5beginreplicarefresh;left'] = [action]
        if right:
            entry['nsds5beginreplicarefresh;right'] = [action]

        self.obj.backend.update_entry(entry)

        msg = msg % {'pkey': keys[-1]}
        return dict(
            result=True,
            value=msg,
        )


@register()
class topologysegment_show(LDAPRetrieve):
    __doc__ = _('Display a segment.')


@register()
class topologysuffix(LDAPObject):
    """
    Suffix managed by the topology plugin.
    """
    container_dn = api.env.container_topology
    object_name = _('suffix')
    object_name_plural = _('suffices')
    object_class = ['iparepltopoconf']
    default_attributes = ['cn', 'ipaReplTopoConfRoot']
    search_display_attributes = ['cn', 'ipaReplTopoConfRoot']
    label = _('Topology suffices')
    label_singular = _('Topology suffix')

    takes_params = (
        Str(
            'cn',
            cli_name='name',
            primary_key=True,
            label=_('Suffix name'),
        ),
        Str(
            'iparepltopoconfroot',
            maxlength=255,
            cli_name='suffix',
            label=_('LDAP suffix to be managed'),
            normalizer=lambda value: value.lower(),
        ),
    )


@register()
class topologysuffix_find(LDAPSearch):
    __doc__ = _('Search for topology suffices.')

    msg_summary = ngettext(
        '%(count)d topology suffix matched',
        '%(count)d topology suffices matched', 0
    )


@register()
class topologysuffix_del(LDAPDelete):
    __doc__ = _('Delete a topology suffix.')

    NO_CLI = True

    msg_summary = _('Deleted topology suffix "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        validate_domain_level(self.api)
        return dn


@register()
class topologysuffix_add(LDAPCreate):
    __doc__ = _('Add a new topology suffix to be managed.')

    NO_CLI = True

    msg_summary = _('Added topology suffix "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        validate_domain_level(self.api)
        return dn


@register()
class topologysuffix_mod(LDAPUpdate):
    __doc__ = _('Modify a topology suffix.')

    NO_CLI = True

    msg_summary = _('Modified topology suffix "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        validate_domain_level(self.api)
        return dn


@register()
class topologysuffix_show(LDAPRetrieve):
    __doc__ = _('Show managed suffix.')
