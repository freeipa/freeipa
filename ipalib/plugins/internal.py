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
                "add":_("Add Automount Location"),
                "identity":_("Automount Location Settings"),
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
                "ipaserver":_("Configuration"),
                "cn":_("Name"),
                },
            "delegation": {
                "add":_("Add Delegation"),
                },
            "dnszone": {
                "add":_("Add DNS Zone"),
                "identity":_("DNS Zone Settings"),
                },
            "dnsrecord": {
                "add":_("Add DNS Resource Record"),
                "resource":_("Resource"),
                "type":_("Type"),
                "data":_("Data"),
                "title":_("Records for DNS Zone"),
                },
            "group": {
                "add":_("Add Group"),
                "details":_("Group Settings"),
                "posix":_("Is this a POSIX group?"),
                },
            "hbacrule": {
                "add":_("Add HBAC Rule"),
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
                "add":_("Add HBAC Service"),
                },
            "hbacsvcgroup": {
                "add":_("Add HBAC Service Group"),
                "services":_("Services"),
                },
            "host": {
                "add":_("Add Host"),
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
                "add":_("Add Host Group"),
                "identity":_("Host Group Settings"),
                },
            "krbtpolicy": {
                "identity":_("Kerberos ticket policy"),
                },
            "netgroup": {
                "add":_("Add Netgroup"),
                "identity":_("Netgroup Settings"),
                },
            "permission": {
                "add":_("Add Permission"),
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
                "add":_("Add Privilege"),
                "identity":_("Privilege Settings"),
                },
            "pwpolicy": {
                "add":_("Add Password Policy"),
                "identity":_("Password Policy"),
                },
            "role": {
                "add":_("Add Role"),
                "identity":_("Role Settings"),
                },
            "selfservice": {
                "add":_("Add Self Service Definition"),
                },
            "service": {
                "add":_("Add Service"),
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
                "add":_("Add Sudo Command"),
                "groups":_("Groups"),
                },
            "sudocmdgroup": {
                "add":_("Add Sudo Command Group"),
                "commands":_("Commands"),
                },
            "sudorule": {
                "add":_("Add Sudo Rule"),
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
                "runas":_("As Whom"),
                "any_group":_("Any Group"),
                "specified_groups":_("Specified Groups"),
                "ipaenabledflag":_("Rule status"),
                "external":_("External"),
                },
            "user": {
                "add":_("Add User"),
                "account":_("Account Settings"),
                "contact":_("Contact Settings"),
                "mailing":_("Mailing Address"),
                "employee":_("Employee Information"),
                "misc":_("Misc. Information"),
                "active":_("Active"),
                "deactivate":_("Click to Deactivate"),
                "inactive":_("Inactive"),
                "activate":_("Click to Activate"),
                "error_changing_status":_("Error changing account status"),
                "reset_password":_("Reset Password"),
                "new_password":_("New Password"),
                "repeat_password":_("Repeat Password"),
                "password_change_complete":_("Password change complete"),
                "password_must_match":_("Passwords must match"),
                },
            },
        "buttons":{
            "add":_("Add"),
            "add_and_add_another":_("Add and Add Another"),
            "add_and_edit":_("Add and Edit"),
            "add_and_close":_("Add and Close"),
            "add_many":_("Add Many"),
            "back_to_list":_("Back to List"),
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
        "dialogs":{
            "available":_("Available"),
            "dirty_message":_("This page has unsaved changes. Please save or revert."),
            "dirty_title":_("Dirty"),
            "hide_already_enrolled":_("Hide already enrolled."),
            "remove_empty":_("Select ${entity} to be removed."),
            "remove_title":_("Remove ${entity}."),
            "prospective":_("Prospective"),
            },
        "facet_groups":{
            "managedby":_("Managed by"),
            "member":_("Member"),
            "memberindirect":_("Indirect Member"),
            "memberof":_("Member Of"),
            "memberofindirect":_("Indirect Member Of"),
            "settings": _("Settings"),
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
            "truncated":_(
                "Query returned more results than the configured size limit. Displaying the first ${counter} results."),
            },
        "details":{
            "general":_("General"),
            "identity":_("Identity Settings"),
            "settings":_("${entity} ${primary_key} Settings"),
            "to_top":_("Back to Top")
            },
        "tabs": {
            "identity":_("Identity"),
            "policy":_("Policy"),
            "audit": _("Audit"),
            "ipaserver":_("IPA Server"),
            "sudo":_("Sudo"),
            "hbac":_("HBAC"),
            "role":_("Role Based Access Control")
            },
        "association":{
            "add":_("Add ${other_entity} into ${entity} ${primary_key}"),
            "member":_("${other_entity} enrolled in ${entity} ${primary_key}"),
            "memberof":_("${entity} ${primary_key} is enrolled in the following ${other_entity}"),
            "remove":_("Remove ${other_entity} from ${entity} ${primary_key}"),
            },
        "widget":{
            "validation_error":_("Text does not match field pattern"),
            },
        "ajax":{
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
