# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#   Adam YOung <ayoung@redhat.com>
#
# Copyright (c) 2010  Red Hat
# See file 'copying' for use and warranty information
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
Plugins not accessible directly through the CLI, commands used internally
"""

import json

from ipalib import api, errors
from ipalib import Command
from ipalib import Str
from ipalib.output import Output
from ipalib.text import _
from ipalib.util import json_serialize

class json_metadata(Command):
    """
    Export plugin meta-data for the webUI.
    """
    NO_CLI = True


    takes_args = (
        Str('objname?',
            doc=_('Name of object to export'),
        ),
    )

    has_output = (
        Output('metadata', dict, doc=_('Dict of JSON encoded IPA Objects')),
    )

    def execute(self, objname):

        if objname and objname in self.api.Object:

            meta = dict(
                result=dict(
                    ((objname, json_serialize(self.api.Object[objname])), )
                )
            )
            retval= dict([("metadata",meta)])

        else:
            meta=dict(
                (o.name, json_serialize(o)) for o in self.api.Object()
                )

            retval= dict([("metadata",meta)])

        return retval

    def output_for_cli(self, textui, result, *args, **options):
        print json.dumps(result, default=json_serialize)

api.register(json_metadata)

class i18n_messages(Command):
    NO_CLI = True

    messages={
        "login": {"header" :_("Logged In As")},
        "button":{
            "add":_("Add"),
            "find": _("Find"),
            "reset":_("Reset"),
            "update":_("Update"),
            "enroll":_("Enroll"),
            "remove":_("Delete"),
            },
        "facets":{
            "search":_("Search"),
            "details": _("Settings"),
            },
        "search":{
            "quick_links":_("Quick Links"),
            "select_all":_("Select All"),
            "unselect_all":_("Unselect All"),
            "delete_confirm":_("Are you sure you want to delete selected entries?"),
            },
        "details":{
            "identity":_("Identity Settings"),
            "account":_("Account Settings"),
            "contact":_("Contact Settings"),
            "mailing":_("Mailing Address"),
            "employee":_("Employee Information"),
            "misc":_("Misc. Information"),
            "to_top":_("Back to Top")},
        "association":{
            "managedby":_("Managed by"),
            "members":_("Members"),
            "membershipin":_("Membership in")},
        "ajax":{
            "401":_("Your kerberos ticket no longer valid."+
                "Please run KInit and then click 'retry'"+
                "If this is your first time running the IPA Web UI"+
                "<a href='/ipa/errors/ssbrowser.html'> "+
                "Follow these directions</a> to configure your browser.")
            }
        }
    has_output = (
        Output('messages', dict, doc=_('Dict of I18N messages')),
    )
    def execute(self):
        return dict([("messages",json_serialize(self.messages))])

    def output_for_cli(self, textui, result, *args, **options):
        print json.dumps(result, default=json_serialize)


api.register(i18n_messages)
