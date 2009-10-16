# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
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
Abstracts some compatability issues for Python2.4 - Python2.6.

The ``json`` module was added in Python2.6, which previously was in a seperate
package and called ``simplejson``.  This hack abstracts the difference so you
can use the ``json`` module generically like this:

>>> from compat import json
>>> json.dumps({'hello': 'world'})
'{"hello": "world"}'

In Python 2.6 the ``parse_qs()`` function was moved from the ``cgi`` module to
the ``urlparse`` module.  Although ``cgi.parse_qs()`` is still available and
only raises a ``PendingDeprecationWarning``, we still provide some
future-proofing here so you can import ``parse_qs()`` generically like this:

>>> from compat import parse_qs
>>> parse_qs('hello=world&how=are+you%3F')
{'how': ['are you?'], 'hello': ['world']}

For more information, see *What's New in Python 2.6*:

    http://docs.python.org/whatsnew/2.6.html
"""

import sys
if sys.version_info[:2] >= (2, 6):
    import json
    from urlparse import parse_qs
else:
    import simplejson as json
    from cgi import parse_qs
