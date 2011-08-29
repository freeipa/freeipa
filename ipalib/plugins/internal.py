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

    messages = {
        "ajax": {
            "401": {
                "message": _("Your Kerberos ticket is no longer valid. Please run kinit and then click 'Retry'. If this is your first time running the IPA Web UI <a href='/ipa/config/unauthorized.html'>follow these directions</a> to configure your browser."),
                "title": _("Kerberos ticket no longer valid."),
            },
        },
        "association": {
            "add": {
                "ipasudorunas": _("Add RunAs ${other_entity} into ${entity} ${primary_key}"),
                "ipasudorunasgroup": _("Add RunAs Groups into ${entity} ${primary_key}"),
                "managedby": _("Add ${other_entity} Managing ${entity} ${primary_key}"),
                "member": _("Add ${other_entity} into ${entity} ${primary_key}"),
                "memberallowcmd": _("Add Allow ${other_entity} into ${entity} ${primary_key}"),
                "memberdenycmd": _("Add Deny ${other_entity} into ${entity} ${primary_key}"),
                "memberof": _("Add ${entity} ${primary_key} into ${other_entity}"),
                "sourcehost": _("Add Source ${other_entity} into ${entity} ${primary_key}"),
            },
            "direct_enrollment": _("Direct Enrollment"),
            "indirect_enrollment": _("Indirect Enrollment"),
            "no_entries": _("No entries."),
            "paging": _("Showing ${start} to ${end} of ${total} entries."),
            "remove": {
                "ipasudorunas": _("Remove RunAs ${other_entity} from ${entity} ${primary_key}"),
                "ipasudorunasgroup": _("Remove RunAs Groups from ${entity} ${primary_key}"),
                "managedby": _("Remove ${other_entity} Managing ${entity} ${primary_key}"),
                "member": _("Remove ${other_entity} from ${entity} ${primary_key}"),
                "memberallowcmd": _("Remove Allow ${other_entity} from ${entity} ${primary_key}"),
                "memberdenycmd": _("Remove Deny ${other_entity} from ${entity} ${primary_key}"),
                "memberof": _("Remove ${entity} ${primary_key} from ${other_entity}"),
                "sourcehost": _("Remove Source ${other_entity} from ${entity} ${primary_key}"),
            },
            "show_results": _("Show Results"),
        },
        "buttons": {
            "add": _("Add"),
            "add_and_add_another": _("Add and Add Another"),
            "add_and_close": _("Add and Close"),
            "add_and_edit": _("Add and Edit"),
            "add_many": _("Add Many"),
            "cancel": _("Cancel"),
            "close": _("Close"),
            "enroll": _("Enroll"),
            "find": _("Find"),
            "get": _("Get"),
            "issue": _("Issue"),
            "ok": _("OK"),
            "remove": _("Delete"),
            "reset": _("Reset"),
            "restore": _("Restore"),
            "retry": _("Retry"),
            "revoke": _("Revoke"),
            "update": _("Update"),
            "view": _("View"),
        },
        "details": {
            "collapse_all": _("Collapse All"),
            "expand_all": _("Expand All"),
            "general": _("General"),
            "identity": _("Identity Settings"),
            "settings": _("${entity} ${primary_key} Settings"),
            "to_top": _("Back to Top")
        },
        "dialogs": {
            "add_title": _("Add ${entity}"),
            "available": _("Available"),
            "batch_error_message": _("Some operations failed."),
            "batch_error_title": _("Operations Error"),
            "confirmation": _("Confirmation"),
            "dirty_message": _("This page has unsaved changes. Please save or revert."),
            "dirty_title": _("Unsaved Changes"),
            "hide_details": _("Hide details"),
            "prospective": _("Prospective"),
            "redirection": _("Redirection"),
            "remove_empty": _("Select entries to be removed."),
            "remove_title": _("Remove ${entity}"),
            "show_details": _("Show details"),
            "validation_title": _("Validation error"),
            "validation_message": _("Input form contains invalid or missing values."),
        },
        "errors": {
            "http_error": _("HTTP Error"),
            "internal_error": _("Internal Error"),
            "ipa_error": _("IPA Error"),
            "no_response": _("No response"),
            "unknown_error": _("Unknown Error"),
            "url": _("URL"),
        },
        "facet_groups": {
            "managedby": _("${primary_key} is managed by:"),
            "member": _("Entities enrolled in ${primary_key}:"),
            "memberof": _("${primary_key} is a member of these:"),
        },
        "facets": {
            "details": _("Settings"),
            "search": _("Search"),
        },
        "false": _("False"),
        "login": {
            "header": _("Logged In As")
        },
        "objects": {
            "aci": {
                "attribute": _("Attribute"),
            },
            "automountkey": {
            },
            "automountlocation": {
                "identity": _("Automount Location Settings")
            },
            "automountmap": {
                "map_type": _("Map Type"),
                "direct": _("Direct"),
                "indirect": _("Indirect"),
            },
            "cert": {
                "aa_compromise": _("AA Compromise"),
                "affiliation_changed": _("Affiliation Changed"),
                "ca_compromise": _("CA Compromise"),
                "certificate_hold": _("Certificate Hold"),
                "cessation_of_operation": _("Cessation of Operation"),
                "common_name": _("Common Name"),
                "enter_csr": _("Enter the Base64-encoded CSR below"),
                "expires_on": _("Expires On"),
                "fingerprints": _("Fingerprints"),
                "issue_certificate": _("Issue New Certificate for ${entity} ${primary_key}"),
                "issued_by": _("Issued By"),
                "issued_on": _("Issued On"),
                "issued_to": _("Issued To"),
                "key_compromise": _("Key Compromise"),
                "md5_fingerprint": _("MD5 Fingerprint"),
                "missing": _("No Valid Certificate"),
                "new_certificate": _("New Certificate"),
                "note": _("Note"),
                "organization": _("Organization"),
                "organizational_unit": _("Organizational Unit"),
                "privilege_withdrawn": _("Privilege Withdrawn"),
                "reason": _("Reason for Revocation"),
                "remove_from_crl": _("Remove from CRL"),
                "restore_certificate": _("Restore Certificate for ${entity} ${primary_key}"),
                "restore_confirmation": _("To confirm your intention to restore this certificate, click the \"Restore\" button."),
                "revoke_certificate": _("Revoke Certificate for ${entity} ${primary_key}"),
                "revoke_confirmation": _("To confirm your intention to revoke this certificate, select a reason from the pull-down list, and click the \"Revoke\" button."),
                "revoked": _("Certificate Revoked"),
                "serial_number": _("Serial Number"),
                "sha1_fingerprint": _("SHA1 Fingerprint"),
                "superseded": _("Superseded"),
                "unspecified": _("Unspecified"),
                "valid": _("Valid Certificate Present"),
                "validity": _("Validity"),
                "view_certificate": _("Certificate for ${entity} ${primary_key}"),
            },
            "config": {
                "group": _("Group Options"),
                "search": _("Search Options"),
                "user": _("User Options"),
            },
            "delegation": {
            },
            "dnsrecord": {
                "data": _("Data"),
                "deleted_no_data": _("DNS record was deleted because it contained no data."),
                "other": _("Other Record Types"),
                "redirection_dnszone": _("You will be redirected to DNS Zone."),
                "standard": _("Standard Record Types"),
                "title": _("Records for DNS Zone"),
                "type": _("Record Type"),
            },
            "dnszone": {
                "identity": _("DNS Zone Settings"),
            },
            "entitle": {
                "account": _("Account"),
                "certificate": _("Certificate"),
                "certificates": _("Certificates"),
                "consume": _("Consume"),
                "consume_entitlement": _("Consume Entitlement"),
                "consumed": _("Consumed"),
                "download": _("Download"),
                "download_certificate": _("Download Certificate"),
                "end": _("End"),
                "import_button": _("Import"),
                "import_certificate": _("Import Certificate"),
                "import_message": _("Enter the Base64-encoded entitlement certificate below:"),
                "loading": _("Loading..."),
                "no_certificate": _("No Certificate."),
                "product": _("Product"),
                "register": _("Register"),
                "registration": _("Registration"),
                "start": _("Start"),
                "status": _("Status"),
            },
            "group": {
                "details": _("Group Settings"),
                "posix": _("Is this a POSIX group?"),
            },
            "hbacrule": {
                "active": _("Active"),
                "allow": _("Allow"),
                "any_host": _("Any Host"),
                "any_service": _("Any Service"),
                "anyone": _("Anyone"),
                "deny": _("Deny"),
                "host": _("Accessing"),
                "inactive": _("Inactive"),
                "ipaenabledflag": _("Rule status"),
                "service": _("Via Service"),
                "sourcehost": _("From"),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_services": _("Specified Services and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "user": _("Who"),
            },
            "hbacsvc": {
            },
            "hbacsvcgroup": {
                "services": _("Services"),
            },
            "host": {
                "certificate": _("Host Certificate"),
                "cn": _("Host Name"),
                "delete_key_unprovision": _("Delete Key, Unprovision"),
                "details": _("Host Settings"),
                "enrolled": _("Enrolled?"),
                "enrollment": _("Enrollment"),
                "fqdn": _("Fully Qualified Host Name"),
                "keytab": _("Kerberos Key"),
                "keytab_missing": _("Kerberos Key Not Present"),
                "keytab_present": _("Kerberos Key Present, Host Provisioned"),
                "password": _("One-Time-Password"),
                "password_missing": _("One-Time-Password Not Present"),
                "password_present": _("One-Time-Password Present"),
                "password_reset_button": _("Reset OTP"),
                "password_reset_title": _("Reset One-Time-Password"),
                "password_set_button": _("Set OTP"),
                "password_set_title": _("Set One-Time-Password"),
                "status": _("Status"),
                "unprovision": _("Unprovision"),
                "unprovision_confirmation": _("Are you sure you want to unprovision this host?"),
                "unprovision_title": _("Unprovisioning ${entity}"),
            },
            "hostgroup": {
                "identity": _("Host Group Settings"),
            },
            "krbtpolicy": {
                "identity": _("Kerberos ticket policy"),
                },
            "netgroup": {
                "identity": _("Netgroup Settings"),
                },
            "permission": {
                "filter": _("Filter"),
                "identity": _("Identity"),
                "invalid_target": _("Permission with invalid target specification"),
                "rights": _("Rights"),
                "subtree": _("By Subtree"),
                "target": _("Target"),
                "targetgroup": _("Target Group"),
                "type": _("Object By Type"),
            },
            "privilege": {
                "identity": _("Privilege Settings"),
            },
            "pwpolicy": {
                "identity": _("Password Policy"),
            },
            "role": {
                "identity": _("Role Settings"),
            },
            "selfservice": {
            },
            "service": {
                "certificate": _("Service Certificate"),
                "delete_key_unprovision": _("Delete Key, Unprovision"),
                "details": _("Service Settings"),
                "host": _("Host Name"),
                "missing": _("Kerberos Key Not Present"),
                "provisioning": _("Provisioning"),
                "service": _("Service"),
                "status": _("Status"),
                "unprovision": _("Unprovision"),
                "unprovision_confirmation": _("Are you sure you want to unprovision this service?"),
                "unprovision_title": _("Unprovisioning ${entity}"),
                "valid": _("Kerberos Key Present, Service Provisioned"),
            },
            "sudocmd": {
                "groups": _("Groups"),
            },
            "sudocmdgroup": {
                "commands": _("Commands"),
            },
            "sudorule": {
                "active": _("Active"),
                "allow": _("Allow"),
                "any_command": _("Any Command"),
                "any_group": _("Any Group"),
                "any_host": _("Any Host"),
                "anyone": _("Anyone"),
                "command": _("Run Commands"),
                "deny": _("Deny"),
                "external": _("External"),
                "host": _("Access this host"),
                "inactive": _("Inactive"),
                "ipaenabledflag": _("Rule status"),
                "options": _("Options"),
                "runas": _("As Whom"),
                "specified_commands": _("Specified Commands and Groups"),
                "specified_groups": _("Specified Groups"),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "user": _("Who"),
            },
            "user": {
                "account": _("Account Settings"),
                "account_status": _("Account Status"),
                "activate": _("Activate"),
                "activation_confirmation": _("Are you sure you want to ${action} the user?<br/>The change will take effect immediately."),
                "activation_link": _("Click to ${action}"),
                "active": _("Active"),
                "contact": _("Contact Settings"),
                "deactivate": _("Deactivate"),
                "employee": _("Employee Information"),
                "error_changing_status": _("Error changing account status"),
                "inactive": _("Inactive"),
                "mailing": _("Mailing Address"),
                "misc": _("Misc. Information"),
            },
        },
        "password": {
            "new_password": _("New Password"),
            "password_change_complete": _("Password change complete"),
            "password_must_match": _("Passwords must match"),
            "reset_password": _("Reset Password"),
            "verify_password": _("Verify Password"),
        },
        "search": {
            "delete_confirm": _("Are you sure you want to delete selected entries?"),
            "partial_delete": _("Some entries were not deleted"),
            "quick_links": _("Quick Links"),
            "select_all": _("Select All"),
            "truncated": _("Query returned more results than the configured size limit. Displaying the first ${counter} results."),
            "unselect_all": _("Unselect All"),
        },
        "tabs": {
            "audit": _("Audit"),
            "automount": _("Automount"),
            "dns": _("DNS"),
            "hbac": _("Host Based Access Control"),
            "identity": _("Identity"),
            "ipaserver": _("IPA Server"),
            "policy": _("Policy"),
            "role": _("Role Based Access Control"),
            "sudo": _("Sudo"),
        },
        "true": _("True"),
        "widget": {
            "next": _("Next"),
            "optional": _("Optional field: click to show"),
            "page": _("Page"),
            "prev": _("Prev"),
            "validation": {
                "error": _("Text does not match field pattern"),
                "integer": _("Must be an integer"),
                "max_value": _("Maximum value is ${value}"),
                "min_value": _("Minimum value is ${value}"),
                "required": _("Required field"),
            },
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
