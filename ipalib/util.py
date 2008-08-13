# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
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

"""

import os
from os import path

__import__('Plugins', globals(), locals(), [], -1)



def import_plugins():
    plugins = 'Plugins'
    d = path.join(path.dirname(path.abspath(__file__)), plugins)
    assert path.isdir(d) and not path.islink(d), 'not regular dir: %r' % d
    print d
    suffix = '.py'
    for name in os.listdir(d):
        if not name.endswith(suffix):
            continue
        if name.startswith('__init__.'):
            continue
        print name
        mod = name[:len(suffix)+1]
        __import__(
            '%s.%s' % (plugins, mod),
            globals(),
            locals(),
            [],
            -1
        )




if __name__ == '__main__':
    pass
    import_plugins()
