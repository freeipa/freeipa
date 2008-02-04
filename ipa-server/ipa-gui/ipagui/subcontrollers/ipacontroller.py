# Copyright (C) 2007  Red Hat
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
#
 
import os
import logging

import cherrypy
import turbogears
from turbogears import controllers, expose, flash
from turbogears import validators, validate
from turbogears import widgets, paginate
from turbogears import error_handler
from turbogears import identity

import ipa.ipaclient
from ipaserver import funcs
import ipa.config

log = logging.getLogger(__name__)

ipa.config.init_config()

class IPAController(controllers.Controller):
    def restrict_post(self):
        if cherrypy.request.method != "POST":
            turbogears.flash("This method only accepts posts")
            raise turbogears.redirect("/")

    def get_ipaclient(self):
        transport = funcs.IPAServer()
        client = ipa.ipaclient.IPAClient(transport)
        client.set_krbccache(os.environ["KRB5CCNAME"])
        return client

    def utf8_encode(self, value):
        if value != None:
            value = value.encode('utf-8')
        return value

    def sort_group_member(self, a, b):
        """Comparator function used for sorting group members."""
        if a.getValue('uid') and b.getValue('uid'):
            if a.getValue('sn') == b.getValue('sn'):
                if a.getValue('givenName') == b.getValue('givenName'):
                    if a.getValue('uid') == b.getValue('uid'):
                        return 0
                    elif a.getValue('uid') < b.getValue('uid'):
                        return -1
                    else:
                        return 1
                elif a.getValue('givenName') < b.getValue('givenName'):
                    return -1
                else:
                    return 1
            elif a.getValue('sn') < b.getValue('sn'):
                return -1
            else:
                return 1
        elif a.getValue('uid'):
            return -1
        elif b.getValue('uid'):
            return 1
        else:
            if a.getValue('cn') == b.getValue('cn'):
                return 0
            elif a.getValue('cn') < b.getValue('cn'):
                return -1
            else:
                return 1

    def sort_by_cn(self, a, b):
        """Comparator function used for sorting groups."""
        if a.getValue('cn') == b.getValue('cn'):
            return 0
        elif a.getValue('cn') < b.getValue('cn'):
            return -1
        else:
            return 1
