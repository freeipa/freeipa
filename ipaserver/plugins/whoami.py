#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

import six
from ipalib import api, Command, errors, output, Str
from ipalib import _
from ipapython.dn import DN
from ipalib.plugable import Registry
from .idviews import DEFAULT_TRUST_VIEW_NAME

if six.PY3:
    unicode = str

__doc__ = _("""
Return information about currently authenticated identity

Who am I command returns information on how to get
more details about the identity authenticated for this
request. The information includes:

 * type of object
 * command to retrieve details of the object
 * arguments and options to pass to the command

The information is returned as a dictionary. Examples below use
'key: value' output for illustrative purposes.

EXAMPLES:

 Look up as IPA user:
   kinit admin
   ipa console
   >> api.Command.whoami()
   ------------------------------------------
   object: user
   command: user_show/1
   arguments: admin
   ------------------------------------------

 Look up as a user from a trusted domain:
   kinit user@AD.DOMAIN
   ipa console
   >> api.Command.whoami()
   ------------------------------------------
   object: idoverrideuser
   command: idoverrideuser_show/1
   arguments: ('default trust view', 'user@ad.domain')
   ------------------------------------------

 Look up as a host:
   kinit -k
   ipa console
   >> api.Command.whoami()
   ------------------------------------------
   object: host
   command: host_show/1
   arguments: ipa.example.com
   ------------------------------------------

 Look up as a Kerberos service:
   kinit -k -t /path/to/keytab HTTP/ipa.example.com
   ipa console
   >> api.Command.whoami()
   ------------------------------------------
   object: service
   command: service_show/1
   arguments: HTTP/ipa.example.com
   ------------------------------------------
""")

register = Registry()


@register()
class whoami(Command):
    __doc__ = _('Describe currently authenticated identity.')

    NO_CLI = True

    output_params = (
        Str('object', label=_('Object class name')),
        Str('command', label= _('Function to get details')),
        Str('arguments*', label=_('Arguments to details function')),
    )

    has_output = (
        output.Output('object', unicode, _('Object class name')),
        output.Output('command', unicode, _('Function to get details')),
        output.Output('arguments', (list, tuple),
                      _('Arguments to details function')),
    )

    def execute(self, **options):
        """
        Retrieve the DN we are authenticated as to LDAP and find bindable IPA
        object that handles the container where this DN belongs to. Then report
        details about this object.
        """
        exceptions = {
                'idoverrideuser': (DN("cn={0}".format(DEFAULT_TRUST_VIEW_NAME)),
                                   DEFAULT_TRUST_VIEW_NAME, 'ipaOriginalUid'),
        }
        ldap = api.Backend.ldap2

        # whoami_s() call returns a string 'dn: <actual DN value>'
        # We also reject ldapi-as-root connections as DM is a virtual object
        dn = DN(ldap.conn.whoami_s()[4:])
        if dn == DN('cn=Directory Manager'):
            raise errors.NotFound(
                    reason=_('Cannot query Directory Manager with API'))

        entry = ldap.get_entry(dn)
        o_name = None
        o_func = None
        o_args = []
        for o in api.Object():
            if not getattr(o, 'bindable', None):
                continue
            container = getattr(o, 'container_dn', None)
            if container is None:
                continue
            # Adjust container for exception two-level objects
            if o.name in exceptions:
                container = exceptions[o.name][0] + container
            if dn.find(container + api.env.basedn) == 1:
                # We found exact container this DN belongs to
                o_name = unicode(o.name)
                o_args = [unicode(entry.single_value.get(o.primary_key.name))]
                o_func = unicode(o.methods.show.full_name)
                if o.name in exceptions:
                    o_args = [unicode(exceptions[o.name][1]),
                              unicode(entry.single_value.get(
                                      exceptions[o.name][2]))]
                break

        return {'object': o_name, 'command': o_func, 'arguments': o_args}
