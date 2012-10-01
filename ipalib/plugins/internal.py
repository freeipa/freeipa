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

    takes_options = (
        Str('object?',
            doc=_('Name of object to export'),
        ),
        Str('method?',
            doc=_('Name of method to export'),
        ),
        Str('command?',
            doc=_('Name of command to export'),
        ),
    )

    has_output = (
        Output('objects', dict, doc=_('Dict of JSON encoded IPA Objects')),
        Output('methods', dict, doc=_('Dict of JSON encoded IPA Methods')),
        Output('commands', dict, doc=_('Dict of JSON encoded IPA Commands')),
    )

    def execute(self, objname, methodname, **options):
        objects = dict()
        methods = dict()
        commands = dict()

        empty = True

        try:
            if not objname:
                objname = options['object']
            if objname in self.api.Object:
                o = self.api.Object[objname]
                objects = dict([(o.name, json_serialize(o))])
            elif objname == "all":
                objects = dict(
                    (o.name, json_serialize(o)) for o in self.api.Object()
                )
            empty = False
        except KeyError:
            pass

        try:
            if not methodname:
                methodname = options['method']
            if methodname in self.api.Method:
                m = self.api.Method[methodname]
                methods = dict([(m.name, json_serialize(m))])
            elif methodname == "all":
                methods = dict(
                    (m.name, json_serialize(m)) for m in self.api.Method()
                )
            empty = False
        except KeyError:
            pass

        try:
            cmdname = options['command']
            if cmdname in self.api.Command:
                c = self.api.Command[cmdname]
                commands = dict([(c.name, json_serialize(c))])
            elif cmdname == "all":
                commands = dict(
                    (c.name, json_serialize(c)) for c in self.api.Command()
                )
            empty = False
        except KeyError:
            pass

        if empty:
            objects = dict(
                (o.name, json_serialize(o)) for o in self.api.Object()
            )
            methods = dict(
                (m.name, json_serialize(m)) for m in self.api.Method()
            )
            commands = dict(
                (c.name, json_serialize(c)) for c in self.api.Command()
            )

        retval = dict([
            ("objects", objects),
            ("methods", methods),
            ("commands", commands),
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
                "message": _("Your session has expired. Please re-login."),
            },
        },
        "actions": {
            "apply": _("Apply"),
            "confirm": _("Are you sure you want to proceed with the action."),
            "delete_confirm": _("Are you sure you want to delete ${object}"),
            "disable_confirm": _("Are you sure you want to disable ${object}"),
            "enable_confirm": _("Are you sure you want to enable ${object}"),
            "title": _("Actions"),
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
            "added": _("Items added"),
            "direct_membership": _("Direct Membership"),
            "indirect_membership": _("Indirect Membership"),
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
            "removed": _("Items removed"),
            "show_results": _("Show Results"),
        },
        "buttons": {
            "add": _("Add"),
            "add_and_add_another": _("Add and Add Another"),
            "add_and_close": _("Add and Close"),
            "add_and_edit": _("Add and Edit"),
            "add_many": _("Add Many"),
            "back": _("Back"),
            "cancel": _("Cancel"),
            "close": _("Close"),
            "disable": _("Disable"),
            "edit": _("Edit"),
            "enable": _("Enable"),
            "find": _("Find"),
            "get": _("Get"),
            "issue": _("Issue"),
            "ok": _("OK"),
            "refresh": _("Refresh"),
            "remove": _("Delete"),
            "reset": _("Reset"),
            "reset_password_and_login": _("Reset Password and Login"),
            "restore": _("Restore"),
            "retry": _("Retry"),
            "revoke": _("Revoke"),
            "set": _("Set"),
            "update": _("Update"),
            "view": _("View"),
        },
        "details": {
            "collapse_all": _("Collapse All"),
            "expand_all": _("Expand All"),
            "general": _("General"),
            "identity": _("Identity Settings"),
            "settings": _("${entity} ${primary_key} Settings"),
            "to_top": _("Back to Top"),
            "updated": _("${entity} ${primary_key} updated"),
        },
        "dialogs": {
            "add_confirmation": _("${entity} successfully added"),
            "add_title": _("Add ${entity}"),
            "available": _("Available"),
            "batch_error_message": _("Some operations failed."),
            "batch_error_title": _("Operations Error"),
            "confirmation": _("Confirmation"),
            "dirty_message": _("This page has unsaved changes. Please save or revert."),
            "dirty_title": _("Unsaved Changes"),
            "edit_title": _("Edit ${entity}"),
            "hide_details": _("Hide details"),
            "prospective": _("Prospective"),
            "redirection": _("Redirection"),
            "remove_empty": _("Select entries to be removed."),
            "remove_title": _("Remove ${entity}"),
            "show_details": _("Show details"),
            "validation_title": _("Validation error"),
            "validation_message": _("Input form contains invalid or missing values."),
        },
        "error_report": {
            "options": _("Please try the following options:"),
            "problem_persists": _("If the problem persists please contact the system administrator."),
            "refresh": _("Refresh the page."),
            "reload": _("Reload the browser."),
            "main_page": _("Return to the main page and retry the operation"),
            "title": _("An error has occurred (${error})"),
        },
        "errors": {
            "error": _("Error"),
            "http_error": _("HTTP Error"),
            "internal_error": _("Internal Error"),
            "ipa_error": _("IPA Error"),
            "no_response": _("No response"),
            "unknown_error": _("Unknown Error"),
            "url": _("URL"),
        },
        "facet_groups": {
            "managedby": _("${primary_key} is managed by:"),
            "member": _("${primary_key} members:"),
            "memberof": _("${primary_key} is a member of:"),
        },
        "facets": {
            "details": _("Settings"),
            "search": _("Search"),
        },
        "false": _("False"),
        "login": {
            "form_auth": _("To login with username and password, enter them in the fields below then click Login."),
            "header": _("Logged In As"),
            "krb_auth_msg": _("To login with Kerberos, please make sure you have valid tickets (obtainable via kinit) and <a href='http://${host]/ipa/config/unauthorized.html'>configured</a> the browser correctly, then click Login."),
            "login": _("Login"),
            "logout": _("Logout"),
            "logout_error": _("Logout error"),
            "password": _("Password"),
            "username": _("Username"),
        },
        "measurement_units": {
            "number_of_passwords": _("number of passwords"),
            "seconds": _("seconds"),
        },
        "objects": {
            "aci": {
                "attribute": _("Attribute"),
            },
            "automember": {
                "add_condition": _("Add Condition into ${pkey}"),
                "add_rule": _("Add Rule"),
                "attribute": _("Attribute"),
                "default_host_group": _("Default host group"),
                "default_user_group": _("Default user group"),
                "exclusive": _("Exclusive"),
                "expression": _("Expression"),
                "hostgrouprule": _("Host group rule"),
                "hostgrouprules": _("Host group rules"),
                "inclusive": _("Inclusive"),
                "usergrouprule": _("User group rule"),
                "usergrouprules": _("User group rules"),
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
                "request_message": _("<ol><li>Examples uses NSS database located in current directory. Replace \"-d  .\" in example with \"-d /path/to/database\" if NSS database is located elsewhere. If you don't have a NSS database you can create one in current directory by \"certutil -N -d .\" </li><li>Create a CSR with \"CN=${hostname},O=${realm}\", for example:<br/># certutil -R -d . -a <em title=\"key size in bits\">-g 2048</em> -s 'CN=${hostname},O=${realm}'</li><li>Copy and paste the CSR (the text block which starts with \"-----BEGIN NEW CERTIFICATE REQUEST-----\" and ends with \"-----END NEW CERTIFICATE REQUEST-----\") below:</li></ol>"),
                "requested": _("Certificate requested"),
                "restore_certificate": _("Restore Certificate for ${entity} ${primary_key}"),
                "restore_confirmation": _("To confirm your intention to restore this certificate, click the \"Restore\" button."),
                "restored": _("Certificate restored"),
                "revoke_certificate": _("Revoke Certificate for ${entity} ${primary_key}"),
                "revoke_confirmation": _("To confirm your intention to revoke this certificate, select a reason from the pull-down list, and click the \"Revoke\" button."),
                "revoked": _("Certificate Revoked"),
                "serial_number": _("Serial Number"),
                "serial_number_hex": _("Serial Number (hex)"),
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
                "selinux": _("SELinux Options"),
                "service": _("Service Options"),
                "user": _("User Options"),
            },
            "delegation": {
            },
            "dnsconfig": {
                "forward_first": _("Forward first"),
                "forward_only": _("Forward only"),
                "options": _("Options"),
            },
            "dnsrecord": {
                "data": _("Data"),
                "deleted_no_data": _("DNS record was deleted because it contained no data."),
                "other": _("Other Record Types"),
                "ptr_redir_address_err": _("Address not valid, can't redirect"),
                "ptr_redir_create": _("Create dns record"),
                "ptr_redir_creating": _("Creating record."),
                "ptr_redir_creating_err": _("Record creation failed."),
                "ptr_redir_record": _("Checking if record exists."),
                "ptr_redir_record_err": _("Record not found."),
                "ptr_redir_title": _("Redirection to PTR record"),
                "ptr_redir_zone": _("Zone found: ${zone}"),
                "ptr_redir_zone_err": _("Target reverse zone not found."),
                "ptr_redir_zones": _("Fetching DNS zones."),
                "ptr_redir_zones_err": _("An error occurred while fetching dns zones."),
                "redirection_dnszone": _("You will be redirected to DNS Zone."),
                "standard": _("Standard Record Types"),
                "title": _("Records for DNS Zone"),
                "type": _("Record Type"),
            },
            "dnszone": {
                "identity": _("DNS Zone Settings"),
                "add_permission":_("Add Permission"),
                "remove_permission": _("Remove Permission"),
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
                "external": _("External"),
                "make_external": _("Change to external group"),
                "make_posix": _("Change to POSIX group"),
                "normal": _("Normal"),
                "posix": _("POSIX"),
                "type": _("Group Type"),
            },
            "hbacrule": {
                "any_host": _("Any Host"),
                "any_service": _("Any Service"),
                "anyone": _("Anyone"),
                "host": _("Accessing"),
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
            "hbactest": {
                "access_denied": _("Access Denied"),
                "access_granted": _("Access Granted"),
                "include_disabled": _("Include Disabled"),
                "include_enabled": _("Include Enabled"),
                "label": _("HBAC Test"),
                "matched": _("Matched"),
                "missing_values": _("Missing values: "),
                "new_test": _("New Test"),
                "rules": _("Rules"),
                "run_test": _("Run Test"),
                "specify_external": _("Specify external ${entity}"),
                "unmatched": _("Unmatched"),
            },
            "host": {
                "certificate": _("Host Certificate"),
                "cn": _("Host Name"),
                "delete_key_unprovision": _("Delete Key, Unprovision"),
                "details": _("Host Settings"),
                "enrolled": _("Enrolled"),
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
                "password_set_success": _("OTP set"),
                "password_set_title": _("Set One-Time-Password"),
                "status": _("Status"),
                "unprovision": _("Unprovision"),
                "unprovision_confirmation": _("Are you sure you want to unprovision this host?"),
                "unprovision_title": _("Unprovisioning ${entity}"),
                "unprovisioned": _("Host unprovisioned"),
            },
            "hostgroup": {
                "identity": _("Host Group Settings"),
            },
            "krbtpolicy": {
                "identity": _("Kerberos Ticket Policy"),
                },
            "netgroup": {
                "any_host": _("Any Host"),
                "anyone": _("Anyone"),
                "external": _("External"),
                "host": _("Host"),
                "hostgroups": _("Host Groups"),
                "hosts": _("Hosts"),
                "identity": _("Netgroup Settings"),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "user": _("User"),
                "usergroups": _("User Groups"),
                "users": _("Users"),
                },
            "permission": {
                "identity": _("Identity"),
                "invalid_target": _("Permission with invalid target specification"),
                "rights": _("Rights"),
                "target": _("Target"),
            },
            "privilege": {
                "identity": _("Privilege Settings"),
            },
            "pwpolicy": {
                "identity": _("Password Policy"),
            },
            "idrange": {
                "details": _("Range Settings"),
                "ipabaseid": _("Base ID"),
                "ipabaserid": _("Primary RID base"),
                "ipaidrangesize": _("Range size"),
                "ipanttrusteddomainsid": _("Domain SID"),
                "ipasecondarybaserid": _("Secondary RID base"),
                "type": _("Range type"),
                "type_ad": _("Active Directory domain"),
                "type_local": _("Local domain"),
            },
            "role": {
                "identity": _("Role Settings"),
            },
            "selfservice": {
            },
            "selinuxusermap": {
                "any_host": _("Any Host"),
                "anyone": _("Anyone"),
                "host": _("Host"),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "user": _("User"),
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
                "unprovisioned": _("Service unprovisioned"),
                "valid": _("Kerberos Key Present, Service Provisioned"),
            },
            "sshkeystore": {
                "keys": _("SSH public keys"),
                "set_dialog_help": _("SSH public key:"),
                "set_dialog_title": _("Set SSH key"),
                "show_set_key": _("Show/Set key"),
                "status_mod_ns": _("Modified: key not set"),
                "status_mod_s": _("Modified"),
                "status_new_ns": _("New: key not set"),
                "status_new_s": _("New: key set"),
            },
            "sudocmd": {
                "groups": _("Groups"),
            },
            "sudocmdgroup": {
                "commands": _("Commands"),
            },
            "sudorule": {
                "allow": _("Allow"),
                "any_command": _("Any Command"),
                "any_group": _("Any Group"),
                "any_host": _("Any Host"),
                "anyone": _("Anyone"),
                "command": _("Run Commands"),
                "deny": _("Deny"),
                "external": _("External"),
                "host": _("Access this host"),
                "ipaenabledflag": _("Rule status"),
                "option_added": _("Option added"),
                "option_removed": _("Option(s) removed"),
                "options": _("Options"),
                "runas": _("As Whom"),
                "specified_commands": _("Specified Commands and Groups"),
                "specified_groups": _("Specified Groups"),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "user": _("Who"),
            },
            "trust": {
                "account": _("Account"),
                "admin_account": _("Administrative account"),
                "details": _("Trust Settings"),
                "domain": _("Domain"),
                "establish_using": _("Establish using"),
                "ipantflatname": _("Domain NetBIOS name"),
                "ipanttrusteddomainsid": _("Domain Security Identifier"),
                "preshared_password": _("Pre-shared password"),
                "trustdirection": _("Trust direction"),
                "truststatus": _("Trust status"),
                "trusttype": _("Trust type"),
            },
            "user": {
                "account": _("Account Settings"),
                "account_status": _("Account Status"),
                "contact": _("Contact Settings"),
                "employee": _("Employee Information"),
                "error_changing_status": _("Error changing account status"),
                "krbpasswordexpiration": _("Password expiration"),
                "mailing": _("Mailing Address"),
                "misc": _("Misc. Information"),
                "status_confirmation": _("Are you sure you want to ${action} the user?<br/>The change will take effect immediately."),
                "status_link": _("Click to ${action}"),
            },
        },
        "password": {
            "current_password": _("Current Password"),
            "current_password_required": _("Current password is required"),
            "expires_in": _("Your password expires in ${days} days."),
            "invalid_password": _("The password or username you entered is incorrect."),
            "new_password": _("New Password"),
            "new_password_required": _("New password is required"),
            "password": _("Password"),
            "password_change_complete": _("Password change complete"),
            "password_must_match": _("Passwords must match"),
            "reset_failure": _("Password reset was not successful."),
            "reset_password": _("Reset Password"),
            "reset_password_sentence": _("Reset your password."),
            "verify_password": _("Verify Password"),
        },
        "search": {
            "delete_confirm": _("Are you sure you want to delete selected entries?"),
            "deleted": _("Selected entries were deleted."),
            "disable_confirm": _("Are you sure you want to disable selected entries?"),
            "disabled": _("${count} items were disabled"),
            "enable_confirm": _("Are you sure you want to enable selected entries?"),
            "enabled": _("${count} items were enabled"),
            "partial_delete": _("Some entries were not deleted"),
            "quick_links": _("Quick Links"),
            "select_all": _("Select All"),
            "truncated": _("Query returned more results than the configured size limit. Displaying the first ${counter} results."),
            "unselect_all": _("Unselect All"),
        },
        "status": {
            "disable": _("Disable"),
            "disabled": _("Disabled"),
            "enable": _("Enable"),
            "enabled": _("Enabled"),
            "label": _("Status"),
        },
        "tabs": {
            "audit": _("Audit"),
            "automember": _("Automember"),
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
            "page": _("Page"),
            "prev": _("Prev"),
            "undo": _("undo"),
            "undo_all": _("undo all"),
            "validation": {
                "error": _("Text does not match field pattern"),
                "decimal": _("Must be a decimal number"),
                "integer": _("Must be an integer"),
                "ip_address": _('Not a valid IP address'),
                "ip_v4_address": _('Not a valid IPv4 address'),
                "ip_v6_address": _('Not a valid IPv6 address'),
                "max_value": _("Maximum value is ${value}"),
                "min_value": _("Minimum value is ${value}"),
                "net_address": _("Not a valid network address"),
                "port": _("'${port}' is not a valid port"),
                "required": _("Required field"),
                "unsupported": _("Unsupported value"),
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
