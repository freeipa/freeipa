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

from turbogears.visit.api import BaseVisitManager, Visit
from turbogears import config

import logging

log = logging.getLogger("turbogears.visit.proxyvisit")

class ProxyVisitManager(BaseVisitManager):
    """Virtually empty class just so can avoid saving this stuff in a
       database."""
    def __init__(self, timeout):
        super(ProxyVisitManager,self).__init__(timeout)
        return

    def create_model(self):
        return

    def new_visit_with_key(self, visit_key):
        return Visit(visit_key, True)

    def visit_for_key(self, visit_key):
        return Visit(visit_key, False)

    def update_queued_visits(self, queue):
        return None
