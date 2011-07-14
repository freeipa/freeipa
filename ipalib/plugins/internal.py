# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#   Adam Young <ayoung@redhat.com>
#   Endi S. Dewata <edewata@redhat.com>
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
        Str('methodname?',
            doc=_('Name of method to export'),
        ),
    )

    has_output = (
        Output('objects', dict, doc=_('Dict of JSON encoded IPA Objects')),
        Output('methods', dict, doc=_('Dict of JSON encoded IPA Methods')),
    )

    def execute(self, objname, methodname):

        if objname and objname in self.api.Object:

            objects = dict(
                (objname, json_serialize(self.api.Object[objname]))
            )

        else:
            objects = dict(
                (o.name, json_serialize(o)) for o in self.api.Object()
            )

        if methodname and methodname in self.api.Method:

            methods = dict(
                (methodname, json_serialize(self.api.Method[methodname]))
            )

        else:
            methods = dict(
                (m.name, json_serialize(m)) for m in self.api.Method()
            )

        retval = dict([
            ("objects", objects),
            ("methods", methods),
        ])

        return retval

    def output_for_cli(self, textui, result, *args, **options):
        print json.dumps(result, default=json_serialize)

api.register(json_metadata)

class i18n_messages(Command):
    NO_CLI = True

    messages={
        "login": {"header" :_("Logged In As")},
        "objects": {
            "aci": {
                "attribute":_("Attribute"),
                },
            "automountlocation": {
                "identity":_("Automount Location Settings")
                },
            "automountmap": {
                "map_type":_("Map Type"),
                "direct":_("Direct"),
                "indirect":_("Indirect"),
                },
            "automountkey": {
                },
            "cert": {
                "unspecified":_("Unspecified"),
                "key_compromise":_("Key Compromise"),
                "ca_compromise":_("CA Compromise"),
                "affiliation_changed":_("Affiliation Changed"),
                "superseded":_("Superseded"),
                "cessation_of_operation":_("Cessation of Operation"),
                "certificate_hold":_("Certificate Hold"),
                "remove_from_crl":_("Remove from CRL"),
                "privilege_withdrawn":_("Privilege Withdrawn"),
                "aa_compromise":_("AA Compromise"),
                "revoke_confirmation":_(
                    "To confirm your intention to revoke this certificate, select a reason from the pull-down list, and click the \"Revoke\" button."),
                "note":_("Note"),
                "reason":_("Reason for Revocation"),
                "restore_confirmation":_(
                    "To confirm your intention to restore this certificate, click the \"Restore\" button."),
                "issued_to":_("Issued To"),
                "common_name":_("Common Name"),
                "organization":_("Organization"),
                "organizational_unit":_("Organizational Unit"),
                "serial_number":_("Serial Number"),
                "issued_by":_("Issued By"),
                "validity":_("Validity"),
                "issued_on":_("Issued On"),
                "expires_on":_("Expires On"),
                "fingerprints":_("Fingerprints"),
                "sha1_fingerprint":_("SHA1 Fingerprint"),
                "md5_fingerprint":_("MD5 Fingerprint"),
                "enter_csr":_("Enter the Base64-encoded CSR below"),
                "valid":_("Valid Certificate Present"),
                "new_certificate":_("New Certificate"),
                "revoked":_("Certificate Revoked"),
                "missing":_("No Valid Certificate"),
                "view_certificate":_("Certificate for ${entity} ${primary_key}"),
                "issue_certificate":_("Issue New Certificate for ${entity} ${primary_key}"),
                "revoke_certificate":_("Revoke Certificate for ${entity} ${primary_key}"),
                "restore_certificate":_("Restore Certificate for ${entity} ${primary_key}"),
                },
            "config": {
                "user":_("User Options"),
                "search":_("Search Options"),
                "group":_("Group Options"),
                },
            "delegation": {
                },
            "dnszone": {
                "identity":_("DNS Zone Settings"),
                },
            "dnsrecord": {
                "type":_("Record Type"),
                "data":_("Data"),
                "title":_("Records for DNS Zone"),
                },
            "entitle": {
                "account":_("Account"),
                "certificate":_("Certificate"),
                "certificates":_("Certificates"),
                "consume":_("Consume"),
                "consume_entitlement":_("Consume Entitlement"),
                "consumed":_("Consumed"),
                "download":_("Download"),
                "download_certificate":_("Download Certificate"),
                "end":_("End"),
                "import_button":_("Import"),
                "import_certificate":_("Import Certificate"),
                "import_message":_("Enter the Base64-encoded entitlement certificate below:"),
                "loading":_("Loading..."),
                "no_certificate":_("No Certificate."),
                "product":_("Product"),
                "register":_("Register"),
                "registration":_("Registration"),
                "start":_("Start"),
                "status":_("Status"),
                },
            "group": {
                "details":_("Group Settings"),
                "posix":_("Is this a POSIX group?"),
                },
            "hbacrule": {
                "active":_("Active"),
                "allow":_("Allow"),
                "deny":_("Deny"),
                "inactive":_("Inactive"),
                "ipaenabledflag":_("Rule status"),
                "user":_("Who"),
                "anyone":_("Anyone"),
                "specified_users":_("Specified Users and Groups"),
                "host":_("Accessing"),
                "any_host":_("Any Host"),
                "specified_hosts":_("Specified Hosts and Groups"),
                "service":_("Via Service"),
                "any_service":_("Any Service"),
                "specified_services":_("Specified Services and Groups"),
                "sourcehost":_("From"),
                },
            "hbacsvc": {
                },
            "hbacsvcgroup": {
                "services":_("Services"),
                },
            "host": {
                "certificate":_("Host Certificate"),
                "cn":_("Host Name"),
                "details":_("Host Settings"),
                "enrolled":_("Enrolled?"),
                "enrollment":_("Enrollment"),
                "fqdn":_("Fully Qualified Host Name"),
                "posix":_("Is this a POSIX group?"),
                "status":_("Status"),
                "valid":_("Kerberos Key Present, Host Provisioned"),
                "delete_key_unprovision":_("Delete Key, Unprovision"),
                "missing":_("Kerberos Key Not Present"),
                "enroll_otp":_("Enroll via One-Time-Password"),
                "set_otp":_("Set OTP"),
                "otp_confirmation":_("One-Time-Password has been set."),
                "unprovision_title":_("Unprovisioning ${entity}"),
                "unprovision_confirmation":_("Are you sure you want to unprovision this host?"),
                "unprovision":_("Unprovision"),
                },
            "hostgroup": {
                "identity":_("Host Group Settings"),
                },
            "krbtpolicy": {
                "identity":_("Kerberos ticket policy"),
                },
            "netgroup": {
                "identity":_("Netgroup Settings"),
                },
            "permission": {
                "identity":_("Identity"),
                "rights":_("Rights"),
                "target":_("Target"),
                "filter":_("Filter"),
                "subtree":_("By Subtree"),
                "targetgroup":_("Target Group"),
                "type":_("Object By Type"),
                "invalid_target":_("Permission with invalid target specification"),
                },
            "privilege": {
                "identity":_("Privilege Settings"),
                },
            "pwpolicy": {
                "identity":_("Password Policy"),
                },
            "role": {
                "identity":_("Role Settings"),
                },
            "selfservice": {
                },
            "service": {
                "certificate":_("Service Certificate"),
                "details":_("Service Settings"),
                "host":_("Host Name"),
                "provisioning":_("Provisioning"),
                "service":_("Service"),
                "status":_("Status"),
                "valid":_("Kerberos Key Present, Service Provisioned"),
                "delete_key_unprovision":_("Delete Key, Unprovision"),
                "missing":_("Kerberos Key Not Present"),
                "unprovision_title":_("Unprovisioning ${entity}"),
                "unprovision_confirmation":_("Are you sure you want to unprovision this service?"),
                "unprovision":_("Unprovision"),
                },
            "sudocmd": {
                "groups":_("Groups"),
                },
            "sudocmdgroup": {
                "commands":_("Commands"),
                },
            "sudorule": {
                "active":_("Active"),
                "inactive":_("Inactive"),
                "allow":_("Allow"),
                "deny":_("Deny"),
                "user":_("Who"),
                "anyone":_("Anyone"),
                "specified_users":_("Specified Users and Groups"),
                "host":_("Access this host"),
                "any_host":_("Any Host"),
                "specified_hosts":_("Specified Hosts and Groups"),
                "command":_("Run Commands"),
                "any_command":_("Any Command"),
                "specified_commands":_("Specified Commands and Groups"),
                "options":_("Options"),
                "runas":_("As Whom"),
                "any_group":_("Any Group"),
                "specified_groups":_("Specified Groups"),
                "ipaenabledflag":_("Rule status"),
                "external":_("External"),
                },
            "user": {
                "account":_("Account Settings"),
                "account_status":_("Account Status"),
                "activate":_("Activate"),
                "activation_link":_("Click to ${action}"),
                "activation_confirmation":_("Are you sure you want to ${action} the user?<br/>The change will take effect immediately."),
                "active":_("Active"),
                "contact":_("Contact Settings"),
                "deactivate":_("Deactivate"),
                "employee":_("Employee Information"),
                "error_changing_status":_("Error changing account status"),
                "inactive":_("Inactive"),
                "mailing":_("Mailing Address"),
                "misc":_("Misc. Information"),
                "new_password":_("New Password"),
                "password_change_complete":_("Password change complete"),
                "password_must_match":_("Passwords must match"),
                "repeat_password":_("Repeat Password"),
                "reset_password":_("Reset Password"),
                },
            },
        "buttons": {
            "add":_("Add"),
            "add_and_add_another":_("Add and Add Another"),
            "add_and_edit":_("Add and Edit"),
            "add_and_close":_("Add and Close"),
            "add_many":_("Add Many"),
            "cancel": _("Cancel"),
            "close": _("Close"),
            "enroll":_("Enroll"),
            "find": _("Find"),
            "get": _("Get"),
            "issue": _("Issue"),
            "ok": _("OK"),
            "reset":_("Reset"),
            "remove":_("Delete"),
            "restore":_("Restore"),
            "retry":_("Retry"),
            "revoke":_("Revoke"),
            "update":_("Update"),
            "view":_("View"),
            },
        "dialogs": {
            "add_title":_("Add ${entity}"),
            "available":_("Available"),
            "confirmation":_("Confirmation"),
            "dirty_message":_("This page has unsaved changes. Please save or revert."),
            "dirty_title":_("Dirty"),
            "hide_already_enrolled":_("Hide already enrolled."),
            "remove_empty":_("Select entries to be removed."),
            "remove_title":_("Remove ${entity}"),
            "prospective":_("Prospective"),
            },
        "facet_groups": {
            "managedby":_("Managed by"),
            "member":_("Member"),
            "memberindirect":_("Indirect Member"),
            "memberof":_("Member Of"),
            "memberofindirect":_("Indirect Member Of"),
            "settings": _("Settings"),
            },
        "facets": {
            "search":_("Search"),
            "details": _("Settings"),
            },
        "search": {
            "quick_links":_("Quick Links"),
            "select_all":_("Select All"),
            "unselect_all":_("Unselect All"),
            "delete_confirm":_("Are you sure you want to delete selected entries?"),
            "truncated":_(
                "Query returned more results than the configured size limit. Displaying the first ${counter} results."),
            },
        "details": {
            "collapse_all":_("Collapse All"),
            "expand_all":_("Expand All"),
            "general":_("General"),
            "identity":_("Identity Settings"),
            "settings":_("${entity} ${primary_key} Settings"),
            "to_top":_("Back to Top")
            },
        "tabs": {
            "dns":_("DNS"),
            "identity":_("Identity"),
            "policy":_("Policy"),
            "audit": _("Audit"),
            "ipaserver":_("IPA Server"),
            "sudo":_("Sudo"),
            "hbac":_("Host Based Access Control"),
            "role":_("Role Based Access Control"),
            "automount":_("Automount")
            },
        "association": {
            "add":_("Add ${other_entity} into ${entity} ${primary_key}"),
            "direct_enrollment":_("Direct Enrollment"),
            "indirect_enrollment":_("Indirect Enrollment"),
            "no_entries":_("No entries."),
            "paging":_("Showing ${start} to ${end} of ${total} entries."),
            "remove":_("Remove ${other_entity} from ${entity} ${primary_key}"),
            "show_results":_("Show Results"),
            },
        "widget": {
            "next":_("Next"),
            "optional":_("Optional field: click to show"),
            "page":_("Page"),
            "prev":_("Prev"),
            "validation": {
                    "error":_("Text does not match field pattern"),
                    "integer": _("Must be an integer"),
                    "max_value": _("Maximum value is ${value}"),
                    "min_value": _("Minimum value is ${value}"),
                    "required": _("Required field"),
                },
            },
        "ajax": {
            "401":_("Your Kerberos ticket is no longer valid. Please run kinit and then click 'Retry'. If this is your first time running the IPA Web UI <a href='/ipa/config/unauthorized.html'>follow these directions</a> to configure your browser.")
            },
        }
    has_output = (
        Output('messages', dict, doc=_('Dict of I18N messages')),
    )
    def execute(self):
        return dict([("messages",json_serialize(self.messages))])

    def output_for_cli(self, textui, result, *args, **options):
        print json.dumps(result, default=json_serialize)


api.register(i18n_messages)
