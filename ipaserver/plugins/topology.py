#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import six

from ipalib import api, errors
from ipalib import Int, Str, StrEnum, Flag, DNParam
from ipalib.plugable import Registry
from .baseldap import (
    LDAPObject, LDAPSearch, LDAPCreate, LDAPDelete, LDAPUpdate, LDAPQuery,
    LDAPRetrieve)
from ipalib import _, ngettext
from ipalib import output
from ipalib.constants import MIN_DOMAIN_LEVEL, DOMAIN_LEVEL_1
from ipaserver.topology import (
    create_topology_graph, get_topology_connection_errors,
    map_masters_to_suffixes)
from ipapython.dn import DN

if six.PY3:
    unicode = str

__doc__ = _("""
Topology

Management of a replication topology at domain level 1.
""") + _("""
IPA server's data is stored in LDAP server in two suffixes:
* domain suffix, e.g., 'dc=example,dc=com', contains all domain related data
* ca suffix, 'o=ipaca', is present only on server with CA installed. It
  contains data for Certificate Server component
""") + _("""
Data stored on IPA servers is replicated to other IPA servers. The way it is
replicated is defined by replication agreements. Replication agreements needs
to be set for both suffixes separately. On domain level 0 they are managed
using ipa-replica-manage and ipa-csreplica-manage tools. With domain level 1
they are managed centrally using `ipa topology*` commands.
""") + _("""
Agreements are represented by topology segments. By default topology segment
represents 2 replication agreements - one for each direction, e.g., A to B and
B to A. Creation of unidirectional segments is not allowed.
""") + _("""
To verify that no server is disconnected in the topology of the given suffix,
use:
  ipa topologysuffix-verify $suffix
""") + _("""

Examples:
  Find all IPA servers:
    ipa server-find
""") + _("""
  Find all suffixes:
    ipa topologysuffix-find
""") + _("""
  Add topology segment to 'domain' suffix:
    ipa topologysegment-add domain --left IPA_SERVER_A --right IPA_SERVER_B
""") + _("""
  Add topology segment to 'ca' suffix:
    ipa topologysegment-add ca --left IPA_SERVER_A --right IPA_SERVER_B
""") + _("""
  List all topology segments in 'domain' suffix:
    ipa topologysegment-find domain
""") + _("""
  List all topology segments in 'ca' suffix:
    ipa topologysegment-find ca
""") + _("""
  Delete topology segment in 'domain' suffix:
    ipa topologysegment-del domain segment_name
""") + _("""
  Delete topology segment in 'ca' suffix:
    ipa topologysegment-del ca segment_name
""") + _("""
  Verify topology of 'domain' suffix:
    ipa topologysuffix-verify domain
""") + _("""
  Verify topology of 'ca' suffix:
    ipa topologysuffix-verify ca
""")

register = Registry()


def validate_domain_level(api):
    try:
        current = int(api.Command.domainlevel_get()['result'])
    except errors.NotFound:
        current = MIN_DOMAIN_LEVEL

    if current < DOMAIN_LEVEL_1:
        raise errors.InvalidDomainLevelError(
            reason=_('Topology management requires minimum domain level {0} '
                   .format(DOMAIN_LEVEL_1))
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
                         '%s-to-%s' % (iparepltoposegmentleftnode, iparepltoposegmentrightnode),
            normalizer=lambda value: value.lower(),
            doc=_('Arbitrary string identifying the segment'),
        ),
        Str(
            'iparepltoposegmentleftnode',
            pattern='^[a-zA-Z0-9.][a-zA-Z0-9.-]*[a-zA-Z0-9.$-]?$',
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
            pattern='^[a-zA-Z0-9.][a-zA-Z0-9.-]*[a-zA-Z0-9.$-]?$',
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
            autofill=True,
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

    def validate_nodes(self, ldap, dn, entry_attrs, suffix):
        leftnode = entry_attrs.get('iparepltoposegmentleftnode')
        rightnode = entry_attrs.get('iparepltoposegmentrightnode')

        if not leftnode and not rightnode:
            return  # nothing to check

        # check if nodes are IPA servers
        masters = self.api.Command.server_find(
            '', sizelimit=0, no_members=False)['result']
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

        # don't allow segment between nodes where both don't have the suffix
        masters_to_suffix = map_masters_to_suffixes(masters)
        suffix_masters = masters_to_suffix.get(suffix, [])
        suffix_m_hostnames = [m['cn'][0].lower() for m in suffix_masters]

        if leftnode not in suffix_m_hostnames:
            raise errors.ValidationError(
                name='leftnode',
                error=_("left node ({host}) does not support "
                        "suffix '{suff}'"
                        .format(host=leftnode, suff=suffix))
            )

        if rightnode not in suffix_m_hostnames:
            raise errors.ValidationError(
                name='rightnode',
                error=_("right node ({host}) does not support "
                        "suffix '{suff}'"
                        .format(host=rightnode, suff=suffix))
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
        self.obj.validate_nodes(ldap, dn, entry_attrs, keys[0])
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
        self.obj.validate_nodes(ldap, dn, entry_attrs, keys[0])
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


@register()
class topologysuffix(LDAPObject):
    """
    Suffix managed by the topology plugin.
    """
    container_dn = api.env.container_topology
    object_name = _('suffix')
    object_name_plural = _('suffixes')
    object_class = ['iparepltopoconf']
    default_attributes = ['cn', 'ipaReplTopoConfRoot']
    search_display_attributes = ['cn', 'ipaReplTopoConfRoot']
    label = _('Topology suffixes')
    label_singular = _('Topology suffix')

    takes_params = (
        Str(
            'cn',
            cli_name='name',
            primary_key=True,
            label=_('Suffix name'),
        ),
        DNParam(
            'iparepltopoconfroot',
            cli_name='suffix_dn',
            label=_('Managed LDAP suffix DN'),
        ),
    )


@register()
class topologysuffix_find(LDAPSearch):
    __doc__ = _('Search for topology suffixes.')

    msg_summary = ngettext(
        '%(count)d topology suffix matched',
        '%(count)d topology suffixes matched', 0
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

    def execute(self, *keys, **options):

        validate_domain_level(self.api)

        masters = self.api.Command.server_find(
            '', sizelimit=0, no_members=False)['result']
        masters = map_masters_to_suffixes(masters).get(keys[0], [])
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
