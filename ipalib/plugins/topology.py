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
from ipalib.util import create_topology_graph, get_topology_connection_errors
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
    NO_CLI = True
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
                         '%s-to-%s' % (iparepltoposegmentleftnode, iparepltoposegmentrightnode),
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
            values=(u'both', u'left-right', u'right-left'),
            default=u'both',
            doc=_('Direction of replication between left and right replication '
                  'node'),
            flags={'no_option', 'no_update'},
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
            flags={'no_option'},
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

    NO_CLI = True
    msg_summary = ngettext(
        '%(count)d segment matched',
        '%(count)d segments matched', 0
    )


@register()
class topologysegment_add(LDAPCreate):
    __doc__ = _('Add a new segment.')

    NO_CLI = True
    msg_summary = _('Added segment "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        validate_domain_level(self.api)
        self.obj.validate_nodes(ldap, dn, entry_attrs)
        return dn


@register()
class topologysegment_del(LDAPDelete):
    __doc__ = _('Delete a segment.')

    NO_CLI = True
    msg_summary = _('Deleted segment "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        validate_domain_level(self.api)
        return dn


@register()
class topologysegment_mod(LDAPUpdate):
    __doc__ = _('Modify a segment.')

    NO_CLI = True
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

    NO_CLI = True
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

        # left and right are swapped because internally it's a push not
        # pull operation
        if right:
            entry['nsds5beginreplicarefresh;left'] = [action]
        if left:
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
    NO_CLI = True


@register()
class topologysuffix(LDAPObject):
    """
    Suffix managed by the topology plugin.
    """
    NO_CLI = True
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

    NO_CLI = True
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
    NO_CLI = True


@register()
class topologysuffix_verify(LDAPQuery):
    __doc__ = _('''
Verify replication topology for suffix.

Checks done:
  1. check if a topology is not disconnected. In other words if there are
     replication paths between all servers.
  2. check if servers don't have more than the recommended number of
     replication agreements
''')
    NO_CLI = True

    def execute(self, *keys, **options):

        validate_domain_level(self.api)

        masters = self.api.Command.server_find('', sizelimit=0)['result']
        segments = self.api.Command.topologysegment_find(
            keys[0], sizelimit=0)['result']
        graph = create_topology_graph(masters, segments)
        master_cns = [m['cn'][0] for m in masters]
        master_cns.sort()

        # check if each master can contact others
        connect_errors = get_topology_connection_errors(graph)

        # check if suggested maximum number of agreements per replica
        max_agmts_errors = []
        for m in master_cns:
            # chosen direction doesn't matter much given that 'both' is the
            # only allowed direction
            suppliers = graph.get_tails(m)
            if len(suppliers) > self.api.env.recommended_max_agmts:
                max_agmts_errors.append((m, suppliers))

        return dict(
            result={
                'in_order': not connect_errors and not max_agmts_errors,
                'connect_errors': connect_errors,
                'max_agmts_errors': max_agmts_errors,
                'max_agmts': self.api.env.recommended_max_agmts
            },
        )

    def output_for_cli(self, textui, output, *args, **options):

        in_order = output['result']['in_order']
        connect_errors = output['result']['connect_errors']
        max_agmts_errors = output['result']['max_agmts_errors']

        if in_order:
            header = _('Replication topology of suffix "%(suffix)s" '
                       'is in order.')
        else:
            header = _('Replication topology of suffix "%(suffix)s" contains '
                       'errors.')
        textui.print_h1(header % {'suffix': args[0]})

        if connect_errors:
            textui.print_dashed(unicode(_('Topology is disconnected')))
            for err in connect_errors:
                msg = _("Server %(srv)s can't contact servers: %(replicas)s")
                msg = msg % {'srv': err[0], 'replicas': ', '.join(err[2])}
                textui.print_indented(msg)

        if max_agmts_errors:
            textui.print_dashed(unicode(_('Recommended maximum number of '
                                          'agreements per replica exceeded')))
            textui.print_attribute(
                unicode(_("Maximum number of agreements per replica")),
                [output['result']['max_agmts']]
            )
            for err in max_agmts_errors:
                msg = _('Server "%(srv)s" has %(n)d agreements with servers:')
                msg = msg % {'srv': err[0], 'n': len(err[1])}
                textui.print_indented(msg)
                for replica in err[1]:
                    textui.print_indented(replica, 2)

        return 0
