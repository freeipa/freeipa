# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2009  Red Hat
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

"""
Abstracts some compatibility issues for Python 2.4 - Python 2.6.

Python 2.6
==========

The ``json`` module was added in Python 2.6, which previously was in an external
package and called ``simplejson``.  The `compat` module abstracts the difference
so you can use the ``json`` module generically like this:

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


Python 2.5
==========

The ``hashlib`` module was added in Python2.5, after which use of the ``sha``
and ``md5`` modules is deprecated.  You can generically import a ``sha1`` class
from the `compat` module like this:

>>> from compat import sha1
>>> sha1('hello world').hexdigest()
'2aae6c35c94fcfb415dbe95f408b9ce91ee846ed'

And generically import an ``md5`` class like this:

>>> from compat import md5
>>> md5('hello world').hexdigest()
'5eb63bbbe01eeed093cb22bb8f5acdc3'

For more information, see *What's New in Python 2.5*:

    http://python.org/doc/2.5/whatsnew/whatsnew25.html
"""

import sys
if sys.version_info[:2] >= (2, 6):
    import json
    from urlparse import parse_qs
else:
    import simplejson as json
    from cgi import parse_qs
try:
    from hashlib import sha1, md5   #pylint: disable=E0611
except ImportError:
    from sha import new as sha1
    from md5 import new as md5
