#!/usr/bin/python

# Authors: Jason Gerard DeRose <jderose@redhat.com>
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
A web-UI test server using cherrypy.
"""

from cherrypy import expose, config, quickstart
from ipa_webui.templates import form, main
from ipa_webui import controller
from ipalib import api
from ipalib import load_plugins


api.finalize()


class root(object):
    index = controller.Index(api, main)

    def __init__(self):
        for cmd in api.Command():
            ctr = controller.Command(cmd, form)
            setattr(self, cmd.name, ctr)





quickstart(root())
