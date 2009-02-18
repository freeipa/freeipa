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
Machine join
"""

from ipalib import api, util
from ipalib import Command, Str, Int
from ipalib import errors2
import krbV
import os, subprocess

def get_realm():
    krbctx = krbV.default_context()

    return krbctx.default_realm

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

    takes_args = (
        Str('cn',
            validate_host,
            cli_name='hostname',
            doc="The hostname to register as",
            default_from=util.get_fqdn,
            #normalizer=lamda value: value.lower(),
        ),
    )
    takes_options= (
        Str('realm',
            doc="The IPA realm",
            default_from=get_realm,
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
        ldap = self.api.Backend.ldap

        try:
            host = api.Command['host_show'](hostname)
        except errors2.NotFound:
            pass
        else:
            raise errors2.DuplicateEntry

        return api.Command['host_add'](hostname)

    def output_for_cli(self, textui, result, variables, **options):
        textui.print_plain(result)

    def run(self, *args, **options):
        """
        Dispatch to forward() and execute() to do work locally and on the
        server.
        """
        if not self.env.in_server:
#            if os.getegid() != 0:
#                raise errors2.RequiresRoot
            result = self.forward(*args, **options)
        else:
            return self.execute(*args, **options)

        self.__get_keytab(result['krbprincipalname'])
        import pdb
        pdb.set_trace()
        return "Welcome to the %s realm" % options['realm']

    def __get_keytab(self, principal, stdin=None):
        args = ["/usr/sbin/ipa-getkeytab", "-s", self.env.host, "-p", principal,"-k", "/tmp/kt"]
        return self.__run(args, stdin)

    def __run(self, args, stdin=None):
        if stdin:
            p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            stdout,stderr = p.communicate(stdin)
        else:
            p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            stdout,stderr = p.communicate()

api.register(join)
