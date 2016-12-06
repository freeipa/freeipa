# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
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

import os

import six

from ipaclient.frontend import MethodOverride
from ipalib import api, errors
from ipalib import Flag, Str
from ipalib.frontend import Command, Method, Object
from ipalib.plugable import Registry
from ipalib.util import classproperty
from ipalib import _
from ipapython.dn import DN

if six.PY3:
    unicode = str

register = Registry()

DEFAULT_MAPS = (u'auto.direct', )
DEFAULT_KEYS = (u'/-', )


@register(no_fail=True)
class _fake_automountlocation(Object):
    name = 'automountlocation'


@register(no_fail=True)
class _fake_automountlocation_show(Method):
    name = 'automountlocation_show'
    NO_CLI = True


@register(override=True, no_fail=True)
class automountlocation_tofiles(MethodOverride):
    @classmethod
    def __NO_CLI_getter(cls):
        return (api.Command.get_plugin('automountlocation_show') is
                _fake_automountlocation_show)

    NO_CLI = classproperty(__NO_CLI_getter)

    @property
    def api_version(self):
        return self.api.Command.automountlocation_show.api_version

    def output_for_cli(self, textui, result, *keys, **options):
        maps = result['result']['maps']
        keys = result['result']['keys']
        orphanmaps = result['result']['orphanmaps']
        orphankeys = result['result']['orphankeys']

        textui.print_plain('/etc/auto.master:')
        for m in maps:
            if m['automountinformation'][0].startswith('-'):
                textui.print_plain(
                    '%s\t%s' % (
                        m['automountkey'][0], m['automountinformation'][0]
                    )
                )
            else:
                textui.print_plain(
                    '%s\t/etc/%s' % (
                        m['automountkey'][0], m['automountinformation'][0]
                    )
                )
        for m in maps:
            if m['automountinformation'][0].startswith('-'):
                continue
            info = m['automountinformation'][0]
            textui.print_plain('---------------------------')
            textui.print_plain('/etc/%s:' % info)
            for k in keys[info]:
                textui.print_plain(
                    '%s\t%s' % (
                        k['automountkey'][0], k['automountinformation'][0]
                    )
                )

        textui.print_plain('')
        textui.print_plain(_('maps not connected to /etc/auto.master:'))
        for m in orphanmaps:
            textui.print_plain('---------------------------')
            textui.print_plain('/etc/%s:' % m['automountmapname'])
            for k in orphankeys:
                if len(k) == 0: continue
                dn = DN(k[0]['dn'])
                if dn['automountmapname'] == m['automountmapname'][0]:
                    textui.print_plain(
                        '%s\t%s' % (
                            k[0]['automountkey'][0], k[0]['automountinformation'][0]
                        )
                    )


@register()
class automountlocation_import(Command):
    __doc__ = _('Import automount files for a specific location.')

    takes_args = (
        Str('masterfile',
            label=_('Master file'),
            doc=_('Automount master file.'),
        ),
    )

    takes_options = (
        Flag('continue?',
             cli_name='continue',
             doc=_('Continuous operation mode. Errors are reported but the process continues.'),
        ),
    )

    def get_args(self):
        for arg in self.api.Command.automountlocation_show.args():
            yield arg
        for arg in super(automountlocation_import, self).get_args():
            yield arg

    def __read_mapfile(self, filename):
        try:
            fp = open(filename, 'r')
            map = fp.readlines()
            fp.close()
        except IOError as e:
            if e.errno == 2:
                raise errors.NotFound(
                    reason=_('File %(file)s not found') % {'file': filename}
                )
            else:
                raise
        return map

    def forward(self, *args, **options):
        """
        The basic idea is to read the master file and create all the maps
        we need, then read each map file and add all the keys for the map.
        """
        self.api.Command['automountlocation_show'](args[0])

        result = {'maps':[], 'keys':[], 'skipped':[], 'duplicatekeys':[], 'duplicatemaps':[]}
        maps = {}
        master = self.__read_mapfile(args[1])
        for m in master:
            if m.startswith('#'):
                continue
            m = m.rstrip()
            if m.startswith('+'):
                result['skipped'].append([m,args[1]])
                continue
            if len(m) == 0:
                continue
            am = m.split(None)
            if len(am) < 2:
                continue

            if am[1].startswith('/'):
                mapfile = am[1].replace('"','')
                am[1] = os.path.basename(am[1])
                maps[am[1]] = mapfile

            # Add a new key to the auto.master map for the new map file
            try:
                api.Command['automountkey_add'](
                            args[0],
                            u'auto.master',
                            automountkey=unicode(am[0]),
                            automountinformation=unicode(' '.join(am[1:])))
                result['keys'].append([am[0], u'auto.master'])
            except errors.DuplicateEntry:
                if unicode(am[0]) in DEFAULT_KEYS:
                    # ignore conflict when the key was pre-created by the framework
                    pass
                elif options.get('continue', False):
                    result['duplicatekeys'].append(am[0])
                else:
                    raise errors.DuplicateEntry(
                        message=_('key %(key)s already exists') % dict(
                            key=am[0]))
            # Add the new map
            if not am[1].startswith('-'):
                try:
                    api.Command['automountmap_add'](args[0], unicode(am[1]))
                    result['maps'].append(am[1])
                except errors.DuplicateEntry:
                    if unicode(am[1]) in DEFAULT_MAPS:
                        # ignore conflict when the map was pre-created by the framework
                        pass
                    elif options.get('continue', False):
                        result['duplicatemaps'].append(am[0])
                    else:
                        raise errors.DuplicateEntry(
                            message=_('map %(map)s already exists') % dict(
                                map=am[1]))

        # Now iterate over the map files and add the keys. To handle
        # continuation lines I'll make a pass through it to skip comments
        # etc and also to combine lines.
        for m in maps:
            map = self.__read_mapfile(maps[m])
            lines = []
            cont = ''
            for x in map:
                if x.startswith('#'):
                    continue
                x = x.rstrip()
                if x.startswith('+'):
                    result['skipped'].append([m, maps[m]])
                    continue
                if len(x) == 0:
                    continue
                if x.endswith("\\"):
                    cont = cont + x[:-1] + ' '
                else:
                    lines.append(cont + x)
                    cont=''
            for x in lines:
                am = x.split(None)
                key = unicode(am[0].replace('"',''))
                try:
                    api.Command['automountkey_add'](
                            args[0],
                            unicode(m),
                            automountkey=key,
                            automountinformation=unicode(' '.join(am[1:])))
                    result['keys'].append([key,m])
                except errors.DuplicateEntry as e:
                    if options.get('continue', False):
                        result['duplicatekeys'].append(am[0])
                    else:
                        raise e

        return dict(result=result)

    def output_for_cli(self, textui, result, *keys, **options):
        maps = result['result']['maps']
        keys = result['result']['keys']
        duplicatemaps = result['result']['duplicatemaps']
        duplicatekeys = result['result']['duplicatekeys']
        skipped = result['result']['skipped']

        textui.print_plain(_('Imported maps:'))
        for m in maps:
            textui.print_plain(
                _('Added %(map)s') % dict(map=m)
            )
        textui.print_plain('')

        textui.print_plain(_('Imported keys:'))
        for k in keys:
            textui.print_plain(
                _('Added %(src)s to %(dst)s') % dict(
                    src=k[0], dst=k[1]
                )
            )
        textui.print_plain('')

        if len(skipped) > 0:
            textui.print_plain(_('Ignored keys:'))
            for k in skipped:
                textui.print_plain(
                    _('Ignored %(src)s to %(dst)s') % dict(
                        src=k[0], dst=k[1]
                    )
                )


        if options.get('continue', False) and len(duplicatemaps) > 0:
            textui.print_plain('')
            textui.print_plain(_('Duplicate maps skipped:'))
            for m in duplicatemaps:
                textui.print_plain(
                    _('Skipped %(map)s') % dict(map=m)
                )


        if options.get('continue', False) and len(duplicatekeys) > 0:
            textui.print_plain('')
            textui.print_plain(_('Duplicate keys skipped:'))
            for k in duplicatekeys:
                textui.print_plain(
                    _('Skipped %(key)s') % dict(key=k)
                )
