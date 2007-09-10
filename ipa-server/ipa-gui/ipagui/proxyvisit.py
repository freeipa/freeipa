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
