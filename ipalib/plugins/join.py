# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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
join a machine to the IPA domain
"""

from ipalib import api, util
from ipalib import Command, Str, Int
from ipalib import errors
import krbV
import os, subprocess
from ipapython import ipautil
import tempfile
import sha
import stat
import shutil

def get_realm():
    krbctx = krbV.default_context()

    return unicode(krbctx.default_realm)

def validate_host(ugettext, cn):
    """
    Require at least one dot in the hostname (to support localhost.localdomain)
    """
    dots = len(cn.split('.'))
    if dots < 2:
        return 'Fully-qualified hostname required'
    return None

class join(Command):
    """Join an IPA domain"""

    requires_root = True

    takes_args = (
        Str('cn',
            validate_host,
            cli_name='hostname',
            doc="The hostname to register as",
            create_default=lambda **kw: unicode(util.get_fqdn()),
            autofill=True,
            #normalizer=lamda value: value.lower(),
        ),
    )
    takes_options= (
        Str('realm',
            doc="The IPA realm",
            create_default=lambda **kw: get_realm(),
            autofill=True,
        ),
    )

    def execute(self, hostname, **kw):
        """
        Execute the machine join operation.

        Returns the entry as it will be created in LDAP.

        :param hostname: The name of the host joined
        :param kw: Keyword arguments for the other attributes.
        """
        assert 'cn' not in kw

        try:
            host = api.Command['host_show'](hostname)
        except errors.NotFound:
            pass
        else:
            raise errors.DuplicateEntry

        return api.Command['host_add'](hostname)

    def output_for_cli(self, textui, result, args, **options):
        textui.print_plain("Welcome to the %s realm" % options['realm'])
        textui.print_plain("Your keytab is in %s" % result.get('keytab'))

    def run(self, *args, **options):
        """
        Dispatch to forward() and execute() to do work locally and on the
        server.
        """
        if self.env.in_server:
            return self.execute(*args, **options)

        # This forward will call the server-side portion of join
        result = self.forward(*args, **options)

        self._get_keytab(result['krbprincipalname'])
        result['keytab'] = '/etc/krb5.keytab'
        return result

    def _get_keytab(self, principal, stdin=None):
        args = ["/usr/sbin/ipa-getkeytab", "-s", self.env.host, "-p", principal,"-k", "/etc/krb5.keytab"]
        return ipautil.run(args, stdin)

api.register(join)
