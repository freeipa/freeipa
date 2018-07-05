#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from ipalib.crud import Retrieve, Search
from ipalib.errors import NotFound
from ipalib.frontend import Object
from ipalib.parameters import Flag, Int, Str, StrEnum
from ipalib.plugable import Registry
from ipalib import _, ngettext


__doc__ = _("""
IPA server roles
""") + _("""
Get status of roles (DNS server, CA, etc.) provided by IPA masters.
""") + _("""
The status of a role is either enabled, configured, or absent.
""") + _("""
EXAMPLES:
""") + _("""
  Show status of 'DNS server' role on a server:
    ipa server-role-show ipa.example.com "DNS server"
""") + _("""
  Show status of all roles containing 'AD' on a server:
    ipa server-role-find --server ipa.example.com --role="AD trust controller"
""") + _("""
  Show status of all configured roles on a server:
    ipa server-role-find ipa.example.com
""") + _("""
  Show implicit IPA master role:
    ipa server-role-find --include-master
""")


register = Registry()


@register()
class server_role(Object):
    """
    association between certain role (e.g. DNS server) and its status with
    an IPA master
    """
    backend_name = 'serverroles'
    object_name = _('server role')
    object_name_plural = _('server roles')
    default_attributes = [
        'role', 'status'
    ]
    label = _('IPA Server Roles')
    label_singular = _('IPA Server Role')

    takes_params = (
        Str(
            'server_server',
            cli_name='server',
            label=_('Server name'),
            doc=_('IPA server hostname'),
        ),
        Str(
            'role_servrole',
            cli_name='role',
            label=_("Role name"),
            doc=_("IPA server role name"),
            flags={u'virtual_attribute'}
        ),
        StrEnum(
            'status?',
            cli_name='status',
            label=_('Role status'),
            doc=_('Status of the role'),
            values=(u'enabled', u'configured', u'absent'),
            default=u'enabled',
            flags={'virtual_attribute', 'no_create', 'no_update'}
        )
    )

    def ensure_master_exists(self, fqdn):
        server_obj = self.api.Object.server
        try:
            server_obj.get_dn_if_exists(fqdn)
        except NotFound:
            raise server_obj.handle_not_found(fqdn)


@register()
class server_role_show(Retrieve):
    __doc__ = _('Show role status on a server')

    obj_name = 'server_role'
    attr_name = 'show'

    def get_args(self):
        for arg in super(server_role_show, self).get_args():
            yield arg

        for param in self.obj.params():
            if param.name != u'status':
                yield param.clone()

    def execute(self, *keys, **options):
        self.obj.ensure_master_exists(keys[0])

        role_status = self.obj.backend.server_role_retrieve(
            server_server=keys[0], role_servrole=keys[1])

        return dict(result=role_status[0], value=None)


@register()
class server_role_find(Search):
    __doc__ = _('Find a server role on a server(s)')

    obj_name = 'server_role'
    attr_name = 'find'

    msg_summary = ngettext('%(count)s server role matched',
                           '%(count)s server roles matched', 0)
    takes_options = Search.takes_options + (
        Int(
            'timelimit?',
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds (0 is unlimited)'),
            flags=['no_display'],
            minvalue=0,
            autofill=False,
        ),
        Int(
            'sizelimit?',
            label=_('Size Limit'),
            doc=_('Maximum number of entries returned (0 is unlimited)'),
            flags=['no_display'],
            minvalue=0,
            autofill=False,
        ),
        Flag(
            'include_master',
            doc=_('Include IPA master entries'),
        )
    )

    def execute(self, *keys, **options):
        if keys:
            return dict(
                result=[],
                count=0,
                truncated=False
            )

        server = options.get('server_server', None)
        role_name = options.get('role_servrole', None)
        status = options.get('status', None)

        if server is not None:
            self.obj.ensure_master_exists(server)

        role_status = self.obj.backend.server_role_search(
            server_server=server,
            role_servrole=role_name,
            status=status)

        # Don't display "IPA master" information unless the role is
        # requested explicitly. All servers are considered IPA masters,
        # except for replicas during installation.
        if options.get('include_master') or role_name == "IPA master":
            result = role_status
        else:
            result = [
                r for r in role_status
                if r[u'role_servrole'] != "IPA master"
            ]
        return dict(
            result=result,
            count=len(result),
            truncated=False,
        )


@register()
class servrole(Object):
    """
    Server role object
    """
    object_name = _('role')
    object_name_plural = _('roles')
    takes_params = (
        Str(
            'name',
            primary_key=True,
            label=_("Role name"),
            doc=_("IPA role name"),
            flags=(u'virtual_attribute',)
        )
    )
