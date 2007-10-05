import cherrypy
import turbogears
from turbogears import controllers, expose, flash
from turbogears import validators, validate
from turbogears import widgets, paginate
from turbogears import error_handler
from turbogears import identity

class IPAController(controllers.Controller):
    def restrict_post(self):
        if cherrypy.request.method != "POST":
            turbogears.flash("This method only accepts posts")
            raise turbogears.redirect("/")

    def utf8_encode(self, value):
        if value != None:
            value = value.encode('utf-8')
        return value

    def sort_group_member(self, a, b):
        """Comparator function used for sorting group members."""
        if a.getValue('uid') and b.getValue('uid'):
            if a.getValue('givenname') == b.getValue('givenname'):
                if a.getValue('sn') == b.getValue('sn'):
                    if a.getValue('uid') == b.getValue('uid'):
                        return 0
                    elif a.getValue('uid') < b.getValue('uid'):
                        return -1
                    else:
                        return 1
                elif a.getValue('sn') < b.getValue('sn'):
                    return -1
                else:
                    return 1
            elif a.getValue('givenname') < b.getValue('givenname'):
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
