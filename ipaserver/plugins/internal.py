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

from ipalib import Command
from ipalib import Str
from ipalib.frontend import Local
from ipalib.output import Output
from ipalib.text import _
from ipalib.util import json_serialize
from ipalib.plugable import Registry

__doc__ = _("""
Plugins not accessible directly through the CLI, commands used internally
""")

register = Registry()

@register()
class json_metadata(Command):
    __doc__ = _('Export plugin meta-data for the webUI.')
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

    def execute(self, objname=None, methodname=None, **options):
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
                    if o is self.api.Object[o.name]
                )
            empty = False
        except KeyError:
            pass

        try:
            if not methodname:
                methodname = options['method']
            if (methodname in self.api.Method and
                    not isinstance(self.api.Method[methodname], Local)):
                m = self.api.Method[methodname]
                methods = dict([(m.name, json_serialize(m))])
            elif methodname == "all":
                methods = dict(
                    (m.name, json_serialize(m)) for m in self.api.Method()
                    if (m is self.api.Method[m.name] and
                        not isinstance(m, Local))
                )
            empty = False
        except KeyError:
            pass

        try:
            cmdname = options['command']
            if (cmdname in self.api.Command and
                    not isinstance(self.api.Command[cmdname], Local)):
                c = self.api.Command[cmdname]
                commands = dict([(c.name, json_serialize(c))])
            elif cmdname == "all":
                commands = dict(
                    (c.name, json_serialize(c)) for c in self.api.Command()
                    if (c is self.api.Command[c.name] and
                        not isinstance(c, Local))
                )
            empty = False
        except KeyError:
            pass

        if empty:
            objects = dict(
                (o.name, json_serialize(o)) for o in self.api.Object()
                if o is self.api.Object[o.name]
            )
            methods = dict(
                (m.name, json_serialize(m)) for m in self.api.Method()
                if (m is self.api.Method[m.name] and
                    not isinstance(m, Local))
            )
            commands = dict(
                (c.name, json_serialize(c)) for c in self.api.Command()
                if (c is self.api.Command[c.name] and
                    not isinstance(c, Local))
            )

        retval = dict([
            ("objects", objects),
            ("methods", methods),
            ("commands", commands),
        ])

        return retval


@register()
class i18n_messages(Command):
    __doc__ = _('Internationalization messages')
    NO_CLI = True

    messages = {
        "ajax": {
            "401": {
                "message": _("Your session has expired. Please log in again."),
            },
        },
        "actions": {
            "apply": _("Apply"),
            "automember_rebuild": _("Rebuild auto membership"),
            "automember_rebuild_confirm": _("Are you sure you want to rebuild auto membership?"),
            "automember_rebuild_success": _("Automember rebuild membership task completed"),
            "confirm": _("Are you sure you want to proceed with the action?"),
            "delete_confirm": _("Are you sure you want to delete ${object}?"),
            "disable_confirm": _("Are you sure you want to disable ${object}?"),
            "enable_confirm": _("Are you sure you want to enable ${object}?"),
            "title": _("Actions"),
        },
        "association": {
            "add_title_default": _("Add"),
            "added": _("${count} item(s) added"),
            "direct_membership": _("Direct Membership"),
            "filter_placeholder": _("Filter available ${other_entity}"),
            "indirect_membership": _("Indirect Membership"),
            "no_entries": _("No entries."),
            "paging": _("Showing ${start} to ${end} of ${total} entries."),
            "remove_title_default": _("Remove"),
            "removed": _("${count} item(s) removed"),
            "show_results": _("Show Results"),
        },
        "authtype": {
            "auth_indicators": _("Authentication indicators"),
            "auth_indicator": _("Authentication indicator"),
            "config_tooltip": _("<p>Implicit method (password) will be used if no method is chosen.</p><p><strong>Password + Two-factor:</strong> LDAP and Kerberos allow authentication with either one of the authentication types but Kerberos uses pre-authentication method which requires to use armor ccache.</p><p><strong>RADIUS with another type:</strong> Kerberos always use RADIUS, but LDAP never does. LDAP only recognize the password and two-factor authentication options.</p>"),
            "custom_auth_ind_title": _("Add Custom Authentication Indicator"),
            "otp": _("OTP"),
            "type_otp": _("Two factor authentication (password + OTP)"),
            "type_password": _("Password"),
            "type_radius": _("RADIUS"),
            "type_disabled": _("Disable per-user override"),
            "user_tooltip": _("<p>Per-user setting, overwrites the global setting if any option is checked.</p><p><strong>Password + Two-factor:</strong> LDAP and Kerberos allow authentication with either one of the authentication types but Kerberos uses pre-authentication method which requires to use armor ccache.</p><p><strong>RADIUS with another type:</strong> Kerberos always use RADIUS, but LDAP never does. LDAP only recognize the password and two-factor authentication options.</p>"),
        },
        "buttons": {
            "about": _("About"),
            "activate": _("Activate"),
            "add": _("Add"),
            "add_and_add_another": _("Add and Add Another"),
            "add_and_close": _("Add and Close"),
            "add_and_edit": _("Add and Edit"),
            "add_many": _("Add Many"),
            "apply": _("Apply"),
            "back": _("Back"),
            "cancel": _("Cancel"),
            "clear": _("Clear"),
            "clear_title": _("Clear all fields on the page."),
            "close": _("Close"),
            "disable": _("Disable"),
            "download": _("Download"),
            "download_title": _("Download certificate as PEM formatted file."),
            "edit": _("Edit"),
            "enable": _("Enable"),
            "filter": _("Filter"),
            "find": _("Find"),
            "get": _("Get"),
            "hide": _("Hide"),
            "issue": _("Issue"),
            "match": _("Match"),
            "match_title": _("Match users according to certificate."),
            "migrate": _("Migrate"),
            "ok": _("OK"),
            "refresh": _("Refresh"),
            "refresh_title": _("Reload current settings from the server."),
            "remove": _("Delete"),
            "remove_hold": _("Remove hold"),
            "reset": _("Reset"),
            "reset_password": _("Reset Password"),
            "reset_password_and_login": _("Reset Password and Log in"),
            "restore": _("Restore"),
            "retry": _("Retry"),
            "revert": _("Revert"),
            "revert_title": ("Undo all unsaved changes."),
            "revoke": _("Revoke"),
            "save": _("Save"),
            "set": _("Set"),
            "show": _("Show"),
            "stage": _("Stage"),
            "unapply": ("Un-apply"),
            "update": _("Update"),
            "view": _("View"),
        },
        "customization": {
            "customization": _("Customization"),
            "table_pagination": _("Pagination Size"),
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
            "add_custom_value": _("Add custom value"),
            "add_title_default": _("Add"),
            "available": _("Available"),
            "batch_error_message": _("Some operations failed."),
            "batch_error_title": _("Operations Error"),
            "confirmation": _("Confirmation"),
            "custom_value": _("Custom value"),
            "dirty_message": _("This page has unsaved changes. Please save or revert."),
            "dirty_title": _("Unsaved Changes"),
            "edit_title": _("Edit ${entity}"),
            "hide_details": _("Hide details"),
            "about_title": _("About"),
            "about_message": _("${product}, version: ${version}"),
            "prospective": _("Prospective"),
            "redirection": _("Redirection"),
            "remove_empty": _("Select entries to be removed."),
            "remove_title_default": _("Remove"),
            "result": _("Result"),
            "show_details": _("Show details"),
            "success": _("Success"),
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
        "keytab": {
            "add_create": _("Allow ${other_entity} to create keytab of ${primary_key}"),
            "add_retrive": _("Allow ${other_entity} to retrieve keytab of ${primary_key}"),
            "allowed_to_create": _("Allowed to create keytab"),
            "allowed_to_retrieve": _("Allowed to retrieve keytab"),
            "remove_groups_create": _(
                "Disallow user groups to create keytab of '${primary_key}'"
            ),
            "remove_groups_retrieve": _(
                "Disallow user groups to retrieve keytab of '${primary_key}'"
            ),
            "remove_hostgroups_create": _(
                "Disallow host groups to create keytab of '${primary_key}'"
            ),
            "remove_hostgroups_retrieve": _(
                "Disallow host groups to retrieve keytab of '${primary_key}'"
            ),
            "remove_hosts_create": _(
                "Disallow hosts to create keytab of '${primary_key}'"
            ),
            "remove_hosts_retrieve": _(
                "Disallow hosts to retrieve keytab of '${primary_key}'"
            ),
            "remove_users_create": _(
                "Disallow users to create keytab of '${primary_key}'"
            ),
            "remove_users_retrieve": _(
                "Disallow users to retrieve keytab of '${primary_key}'"
            ),
        },
        "krbaliases": {
            "adder_title": _("Add Kerberos Principal Alias"),
            "add_krbal_label": _("New kerberos principal alias"),
            "remove_title": _("Remove Kerberos Alias"),
            "remove_message": _("Do you want to remove kerberos alias ${alias}?"),
        },
        "krbauthzdata": {
            "inherited": _("Inherited from server configuration"),
            "mspac": _("MS-PAC"),
            "override": _("Override inherited settings"),
            "pad": _("PAD"),
        },
        "login": {
            "authenticating": _("Authenticating"),
            "cert_auth_failed": _(
                "Authentication with personal certificate failed"),
            "cert_msg": _(
                "<i class=\"fa fa-info-circle\"></i> To log in with "
                "<strong>certificate</strong>, please make sure you have "
                "valid personal certificate. "
            ),
            "continue_msg": _("Continue to next page"),
            "form_auth": _(
                "<i class=\"fa fa-info-circle\"></i> To log in with "
                "<strong>username and password</strong>, enter them in the "
                "corresponding fields, then click 'Log in'."),
            "form_auth_failed": _("Login failed due to an unknown reason"),
            "header": _("Logged In As"),
            "krb_auth_failed": _("Authentication with Kerberos failed"),
            "krb_auth_msg": _(
                "<i class=\"fa fa-info-circle\"></i> To log in with "
                "<strong>Kerberos</strong>, please make sure you have valid "
                "tickets (obtainable via kinit) and <a href='http://${host}/"
                "ipa/config/ssbrowser.html'>configured</a> the browser "
                "correctly, then click 'Log in'."),
            "loading": _("Loading"),
            "krbprincipal_expired": _(
                "Kerberos Principal you entered is expired"),
            "loading_md": _("Loading data"),
            "login": _("Log in"),
            "login_certificate": _("Log In Using Certificate"),
            "login_certificate_desc": _("Log in using personal certificate"),
            "logout": _("Log out"),
            "logout_error": _("Log out error"),
            "password": _("Password"),
            "password_and_otp": _("Password or Password+One-Time-Password"),
            "redirect_msg": _("You will be redirected in ${count}s"),
            "sync_otp_token": _("Sync OTP Token"),
            "synchronizing": _("Synchronizing"),
            "username": _("Username"),
            "user_locked": _("The user account you entered is locked"),
        },
        "measurement_units": {
            "number_of_passwords": _("number of passwords"),
            "seconds": _("seconds"),
        },
        "migration": {
            "migrating": _("Migrating"),
            "migration_error_msg": _(
                "There was a problem with your request. Please, try again "
                "later."),
            "migration_failure_msg": _(
                "Password migration was not successful"),
            "migration_info_msg": _(
                "<h1>Password Migration</h1><p>If you have been sent here by "
                "your administrator, your personal information is being "
                "migrated to a new identity management solution (IPA).</p><p>"
                "Please, enter your credentials in the form to complete the "
                "process. Upon successful login your kerberos account will be "
                "activated.</p>"),
            "migration_invalid_password": _(
                "The password or username you entered is incorrect"),
            "migration_success": _("Password migration was successful"),
        },
        "objects": {
            "aci": {
                "attribute": _("Attribute"),
            },
            "acidelegation": {
                "add": _("Add delegation"),
                "remove": _("Remove delegations"),
            },
            "acipermission": {
                "add": _("Add permission"),
                "remove": _("Remove permissions"),
                "remove_privileges": _(
                    "Remove privileges from permission '${primary_key}'"
                ),
            },
            "aciprivilege": {
                "add": _("Add privilege"),
                "remove": _("Remove privileges"),
                "remove_from_permissions": _(
                    "Remove privilege '${primary_key}' from permissions"
                ),
                "remove_roles": _(
                    "Remove roles from privilege '${primary_key}'"
                ),
            },
            "acirole": {
                "identity": _("Role Settings"),
                "add": _("Add role"),
                "remove": _("Remove roles"),
                "remove_from_privileges": _(
                    "Remove role '${primary_key}' from privileges"
                ),
                "remove_groups": _(
                    "Remove user groups from role '${primary_key}'"
                ),
                "remove_hosts": _(
                    "Remove hosts from role '${primary_key}'"
                ),
                "remove_hostgroups": _(
                    "Remove host groups from role '${primary_key}'"
                ),
                "remove_services": _(
                    "Remove services from role '${primary_key}'"
                ),
                "remove_users": _(
                    "Remove users from role '${primary_key}'"
                ),
            },
            "aciselfservice": {
                "add": _("Add self service permission"),
                "remove": _("Remove self service permissions"),
            },
            "automember": {
                "add": _("Add rule"),
                "add_inc_condition": _(
                    "Add inclusive condition into '${primary_key}'"
                ),
                "add_exc_condition": _(
                    "Add exclusive condition into '${primary_key}'"
                ),
                "attribute": _("Attribute"),
                "default_host_group": _("Default host group"),
                "default_user_group": _("Default user group"),
                "exclusive": _("Exclusive"),
                "expression": _("Expression"),
                "hostgrouprule": _("Host group rule"),
                "hostgrouprules": _("Host group rules"),
                "inclusive": _("Inclusive"),
                "remove": _("Remove auto membership rules"),
                "remove_exc_conditions": _(
                    "Remove exclusive conditions from rule '${primary_key}'"
                ),
                "remove_inc_conditions": _(
                    "Remove inclusive conditions from rule '${primary_key}'"
                ),
                "usergrouprule": _("User group rule"),
                "usergrouprules": _("User group rules"),
            },
            "automountkey": {
                "add": _("Add automount key"),
                "remove": _("Remove automount keys"),
            },
            "automountlocation": {
                "add": _("Add automount location"),
                "identity": _("Automount Location Settings"),
                "remove": _("Remove automount locations"),
            },
            "automountmap": {
                "add": _("Add automount map"),
                "map_type": _("Map Type"),
                "direct": _("Direct"),
                "indirect": _("Indirect"),
                "remove": _("Remove automount maps"),
            },
            "ca": {
                "add": _("Add certificate authority"),
                "remove": _("Remove certificate authorities"),
            },
            "caacl": {
                "add": _("Add CA ACL"),
                "all": _("All"),
                "any_ca": _("Any CA"),
                "any_host": _("Any Host"),
                "any_service": _("Any Service"),
                "any_profile": _("Any Profile"),
                "anyone": _("Anyone"),
                "ipaenabledflag": _("Rule status"),
                "no_ca_msg": _("If no CAs are specified, requests to the default CA are allowed."),
                "profile": _("Profiles"),
                "remove": _("Remove CA ACLs"),
                "remove_ca": _(
                    "Remove Certificate Authorities from CA ACL "
                    "'${primary_key}'"
                ),
                "remove_groups": _(
                    "Remove user groups from CA ACL '${primary_key}'"
                ),
                "remove_hostgroups": _(
                    "Remove host groups from CA ACL '${primary_key}'"
                ),
                "remove_hosts": _(
                    "Remove hosts from CA ACL '${primary_key}'"
                ),
                "remove_profiles": _(
                    "Remove certificate profiles from CA ACL '${primary_key}'"
                ),
                "remove_services": _(
                    "Remove services from CA ACL '${primary_key}'"
                ),
                "remove_users": _(
                    "Remove users from CA ACL '${primary_key}'"
                ),
                "specified_cas": _("Specified CAs"),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_profiles": _("Specified Profiles"),
                "specified_services": _("Specified Services and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "who": _("Permitted to have certificates issued"),
            },
            "caprofile": {
                "remove": _("Remove certificate profiles"),
            },
            "cert": {
                "aa_compromise": _("AA Compromise"),
                "add_principal": _("Add principal"),
                "affiliation_changed": _("Affiliation Changed"),
                "ca": _("CA"),
                "ca_compromise": _("CA Compromise"),
                "certificate": _("Certificate"),
                "certificates": _("Certificates"),
                "certificate_hold": _("Certificate Hold"),
                "cessation_of_operation": _("Cessation of Operation"),
                "common_name": _("Common Name"),
                "download": _("Download"),
                "delete_cert_end": _("the certificate with serial number "),
                "expires_on": _("Expires On"),
                "find_issuedon_from": _("Issued on from"),
                "find_issuedon_to": _("Issued on to"),
                "find_max_serial_number": _("Maximum serial number"),
                "find_min_serial_number": _("Minimum serial number"),
                "find_revocation_reason": _("Revocation reason"),
                "find_revokedon_from": _("Revoked on from"),
                "find_revokedon_to": _("Revoked on to"),
                "find_subject": _("Subject"),
                "find_validnotafter_from": _("Valid not after from"),
                "find_validnotafter_to": _("Valid not after to"),
                "find_validnotbefore_from": _("Valid not before from"),
                "find_validnotbefore_to": _("Valid not before to"),
                "fingerprints": _("Fingerprints"),
                "get_certificate": _("Get Certificate"),
                "hold_removed": _("Certificate Hold Removed"),
                "issue_for_user": _(
                    "Issue new certificate for user '${primary_key}'"
                ),
                "issue_certificate_generic": _("Issue new certificate"),
                "issued_by": _("Issued By"),
                "issued_on": _("Issued On"),
                "issued_to": _("Issued To"),
                "key_compromise": _("Key Compromise"),
                "missing": _("No Valid Certificate"),
                "new_certificate": _("New Certificate"),
                "new_cert_format": _("Certificate in base64 or PEM format"),
                "note": _("Note"),
                "organization": _("Organization"),
                "organizational_unit": _("Organizational Unit"),
                "present": _("${count} certificate(s) present"),
                "privilege_withdrawn": _("Privilege Withdrawn"),
                "reason": _("Reason for Revocation"),
                "remove_hold": _("Remove hold"),
                "remove_certificate_hold_simple": _("Remove certificate hold"),
                "remove_certificate_hold_confirmation": _("Do you want to remove the certificate hold?"),
                "remove_from_crl": _("Remove from CRL"),
                "request_message": _("<ol> <li>Create a certificate database or use an existing one. To create a new database:<br/> <code># certutil -N -d &lt;database path&gt;</code> </li> <li>Create a CSR with subject <em>CN=&lt;${cn_name}&gt;,O=&lt;realm&gt;</em>, for example:<br/> <code># certutil -R -d &lt;database path&gt; -a -g &lt;key size&gt; -s 'CN=${cn},O=${realm}'${san}</code> </li> <li> Copy and paste the CSR (from <em>-----BEGIN NEW CERTIFICATE REQUEST-----</em> to <em>-----END NEW CERTIFICATE REQUEST-----</em>) into the text area below: </li> </ol>"),
                "request_message_san": _(" -8 '${cn}'"),
                "requested": _("Certificate requested"),
                "revocation_reason": _("Revocation reason"),
                "revoke_certificate_simple": _("Revoke certificate"),
                "revoke_confirmation": _("Do you want to revoke this certificate? Select a reason from the pull-down list."),
                "revoked": _("Certificate Revoked"),
                "revoked_status": _("REVOKED"),
                "serial_number": _("Serial Number"),
                "serial_number_hex": _("Serial Number (hex)"),
                "sha1_fingerprint": _("SHA1 Fingerprint"),
                "sha256_fingerprint": _("SHA256 Fingerprint"),
                "status": _("Status"),
                "superseded": _("Superseded"),
                "unspecified": _("Unspecified"),
                "valid": _("Valid Certificate Present"),
                "valid_from": _("Valid from"),
                "valid_to": _("Valid to"),
                "validity": _("Validity"),
                "view_certificate": _("Certificate for ${entity} ${primary_key}"),
                "view_certificate_btn": _("View Certificate"),
            },
            "certmap_match": {
                "cert_data": _("Certificate Data"),
                "cert_for_match": _("Certificate For Match"),
                "facet_label": _("Certificate Mapping Match"),
                "domain": _("Domain"),
                "matched_users": _("Matched Users"),
                "userlogin": _("User Login"),
            },
            "certmap": {
                "add": _("Add certificate identity mapping rule"),
                "adder_title": _("Add certificate mapping data"),
                "data_label": _("Certificate mapping data"),
                "certificate": _("Certificate"),
                "conf_str": _("Configuration string"),
                "deleter_content": _("Do you want to remove certificate mapping data ${data}?"),
                "deleter_title": _("Remove certificate mapping data"),
                "issuer": _("Issuer"),
                "issuer_subject": _("Issuer and subject"),
                "remove": _("Remove certificate identity mapping rules"),
                "subject": _("Subject"),
                "version": _("Version"),
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
                "forward_none": _("Forwarding disabled"),
                "forward_only": _("Forward only"),
                "options": _("Options"),
                "update_dns": _("Update System DNS Records"),
                "update_dns_dialog_msg": _("Do you want to update system DNS records?"),
                "updated_dns": _("System DNS records updated"),
            },
            "dnsforwardzone": {
                "add": _("Add DNS forward zone"),
                "remove": _("Remove DNS forward zones"),
            },
            "dnsrecord": {
                "add": _("Add DNS resource record"),
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
                "remove": _("Remove DNS resource records"),
                "standard": _("Standard Record Types"),
                "title": _("Records for DNS Zone"),
                "type": _("Record Type"),
            },
            "dnszone": {
                "add": _("Add DNS zone"),
                "add_permission": _("Add permission"),
                "add_permission_confirm":_("Are you sure you want to add permission for DNS Zone ${object}?"),
                "identity": _("DNS Zone Settings"),
                "remove": _("Remove DNS zones"),
                "remove_permission": _("Remove Permission"),
                "remove_permission_confirm": _("Are you sure you want to remove permission for DNS Zone ${object}?"),
                "skip_dns_check": _("Skip DNS check"),
                "skip_overlap_check": _("Skip overlap check"),
                "soamname_change_message": _("Do you want to check if new authoritative nameserver address is in DNS"),
                "soamname_change_title": _("Authoritative nameserver change"),
            },
            "domainlevel": {
                "label": _("Domain Level"),
                "label_singular": _("Domain Level"),
                "ipadomainlevel": _("Level"),
                "set": _("Set Domain Level"),
            },
            "group": {
                "add": _("Add user group"),
                "details": _("Group Settings"),
                "external": _("External"),
                "groups": _("Groups"),
                "group_categories": _("Group categories"),
                "make_external": _("Change to external group"),
                "make_posix": _("Change to POSIX group"),
                "nonposix": _("Non-POSIX"),
                "posix": _("POSIX"),
                "remove": _("Remove user groups"),
                "remove_from_groups": _(
                    "Remove user group '${primary_key}' from user groups"
                ),
                "remove_from_netgroups": _(
                    "Remove user group '${primary_key}' from netgroups"
                ),
                "remove_from_roles": _(
                    "Remove user group '${primary_key}' from roles"
                ),
                "remove_from_hbac": _(
                    "Remove user group '${primary_key}' from HBAC rules"
                ),
                "remove_from_sudo": _(
                    "Remove user group '${primary_key}' from sudo rules"
                ),
                "remove_groups": _(
                    "Remove user groups from user group '${primary_key}'"
                ),
                "remove_services": _(
                    "Remove services from user group '${primary_key}'"
                ),
                "remove_users": _(
                    "Remove users from user group '${primary_key}'"
                ),
                "type": _("Group Type"),
                "user_groups": _("User Groups"),
            },
            "hbacrule": {
                "add": _("Add HBAC rule"),
                "any_host": _("Any Host"),
                "any_service": _("Any Service"),
                "anyone": _("Anyone"),
                "host": _("Accessing"),
                "ipaenabledflag": _("Rule status"),
                "remove": _("Remove HBAC rules"),
                "remove_groups": _(
                    "Remove user groups from HBAC rule '${primary_key}'"
                ),
                "remove_hostgroups": _(
                    "Remove host groups from HBAC rule '${primary_key}'"
                ),
                "remove_hosts": _(
                    "Remove hosts from HBAC rule '${primary_key}'"
                ),
                "remove_servicegroups": _(
                    "Remove HBAC service groups from HBAC rule "
                    "'${primary_key}'"
                ),
                "remove_services": _(
                    "Remove HBAC services from HBAC rule '${primary_key}'"
                ),
                "remove_users": _(
                    "Remove users from HBAC rule '${primary_key}'"
                ),
                "service": _("Via Service"),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_services": _("Specified Services and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "user": _("Who"),
            },
            "hbacsvc": {
                "add": _("Add HBAC service"),
                "remove": _("Remove HBAC services"),
                "remove_from_hbacsvcgroups": _(
                    "Remove HBAC service '${primary_key}' from HBAC service "
                    "groups"
                ),
            },
            "hbacsvcgroup": {
                "add": _("Add HBAC service group"),
                "remove": _("Remove HBAC service groups"),
                "remove_hbacsvcs": _(
                    "Remove HBAC services from HBAC service group "
                    "'${primary_key}'"
                ),
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
                "add": _("Add host"),
                "certificate": _("Host Certificate"),
                "cn": _("Host Name"),
                "delete_key_unprovision": _("Delete Key, Unprovision"),
                "details": _("Host Settings"),
                "enrolled": _("Enrolled"),
                "enrollment": _("Enrollment"),
                "fqdn": _("Fully Qualified Host Name"),
                "generate_otp": _("Generate OTP"),
                "generated_otp": _("Generated OTP"),
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
                "remove": _("Remove hosts"),
                "remove_hosts_managing": _(
                    "Remove hosts managing host '${primary_key}'"
                ),
                "remove_from_groups": _(
                    "Remove host '${primary_key}' from host groups"
                ),
                "remove_from_netgroups": _(
                    "Remove host '${primary_key}' from netgroups"
                ),
                "remove_from_roles": _(
                    "Remove host '${primary_key}' from roles"
                ),
                "remove_from_hbac": _(
                    "Remove host '${primary_key}' from HBAC rules"
                ),
                "remove_from_sudo": _(
                    "Remove host '${primary_key}' from sudo rules"
                ),
                "status": _("Status"),
                "unprovision": _("Unprovision"),
                "unprovision_confirmation": _("Are you sure you want to unprovision this host?"),
                "unprovision_title": _("Unprovisioning host"),
                "unprovisioned": _("Host unprovisioned"),
            },
            "hostgroup": {
                "add": _("Add host group"),
                "host_group": _("Host Groups"),
                "identity": _("Host Group Settings"),
                "remove": _("Remove host groups"),
                "remove_from_hostgroups": _(
                    "Remove host group '${primary_key}' from host groups"
                ),
                "remove_from_netgroups": _(
                    "Remove host group '${primary_key}' from netgroups"
                ),
                "remove_from_hbac": _(
                    "Remove host group '${primary_key}' from HBAC rules"
                ),
                "remove_from_sudo": _(
                    "Remove host group '${primary_key}' from sudo rules"
                ),
                "remove_hosts": _(
                    "Remove hosts from host group '${primary_key}'"
                ),
                "remove_hostgroups": _(
                    "Remove host groups from host group '${primary_key}'"
                ),
            },
            "idoverrideuser": {
                "anchor_label": _("User to override"),
                "anchor_tooltip": _("Enter trusted or IPA user login. Note: search doesn't list users from trusted domains."),
                "anchor_tooltip_ad": _("Enter trusted user login."),
                "profile": _("Profile"),
            },
            "idoverridegroup": {
                "anchor_label": _("Group to override"),
                "anchor_tooltip": _("Enter trusted or IPA group name. Note: search doesn't list groups from trusted domains."),
                "anchor_tooltip_ad": _("Enter trusted group name."),
            },
            "idview": {
                "add": _("Add ID view"),
                "add_group": _("Add group ID override"),
                "add_user": _("Add user ID override"),
                "appliesto_tab": _("${primary_key} applies to:"),
                "appliedtohosts": _("Applied to hosts"),
                "appliedtohosts_title": _("Applied to hosts"),
                "apply_hostgroups": _("Apply to host groups"),
                "apply_hostgroups_title": _("Apply ID View ${primary_key} on hosts of ${entity}"),
                "apply_hosts": _("Apply to hosts"),
                "apply_hosts_title": _("Apply ID view ${primary_key} on ${entity}"),
                "ipaassignedidview": _("Assigned ID View"),
                "overrides_tab": _("${primary_key} overrides:"),
                "remove": _("Remove ID views"),
                "remove_users": _("Remove user ID overrides"),
                "remove_groups": _("Remove group ID overrides"),
                "unapply_hostgroups": _("Un-apply from host groups"),
                "unapply_hostgroups_all_title": _("Un-apply ID Views from hosts of hostgroups"),
                "unapply_hostgroups_title": _("Un-apply ID View ${primary_key} from hosts of ${entity}"),
                "unapply_hosts": _("Un-apply"),
                "unapply_hosts_all": _("Un-apply from hosts"),
                "unapply_hosts_all_title": _("Un-apply ID Views from hosts"),
                "unapply_hosts_confirm": _("Are you sure you want to un-apply ID view from selected entries?"),
                "unapply_hosts_title": _("Un-apply ID View ${primary_key} from hosts"),
            },
            "krbtpolicy": {
                "identity": _("Kerberos Ticket Policy"),
            },
            "netgroup": {
                "add": _("Add netgroup"),
                "any_host": _("Any Host"),
                "anyone": _("Anyone"),
                "external": _("External"),
                "host": _("Host"),
                "hostgroups": _("Host Groups"),
                "hosts": _("Hosts"),
                "identity": _("Netgroup Settings"),
                "netgroups": _("Netgroups"),
                "remove": _("Remove netgroups"),
                "remove_from_netgroups": _(
                    "Remove netgroup '${primary_key}' from netgroups"
                ),
                "remove_groups": _(
                    "Remove user groups from netgroup '${primary_key}'"
                ),
                "remove_hosts": _(
                    "Remove hosts from netgroup '${primary_key}'"
                ),
                "remove_hostgroups": _(
                    "Remove host groups from netgroup '${primary_key}'"
                ),
                "remove_netgroups": _(
                    "Remove netgroups from netgroup '${primary_key}'"
                ),
                "remove_users": _(
                    "Remove users from netgroup '${primary_key}'"
                ),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "user": _("User"),
                "usergroups": _("User Groups"),
                "users": _("Users"),
            },
            "otptoken": {
                "add": _("Add OTP token"),
                "app_link": _("You can use <a href=\"${link}\" target=\"_blank\">FreeOTP<a/> as a software OTP token application."),
                "config_title": _("Configure your token"),
                "config_instructions": _("Configure your token by scanning the QR code below. Click on the QR code if you see this on the device you want to configure."),
                "details": _("OTP Token Settings"),
                "disable": _("Disable token"),
                "enable": _("Enable token"),
                "remove": _("Remove OTP tokens"),
                "remove_users_managing": _(
                    "Remove users managing OTP token '${primary_key}'"
                ),
                "show_qr": _("Show QR code"),
                "show_uri": _("Show configuration uri"),
                "type_hotp": _("Counter-based (HOTP)"),
                "type_totp": _("Time-based (TOTP)"),
            },
            "permission": {
                "add_custom_attr": _("Add Custom Attribute"),
                "attribute": _("Attribute"),
                "filter": _("Filter"),
                "identity": _("Permission settings"),
                "managed": _("Attribute breakdown"),
                "target": _("Target"),
            },
            "privilege": {
                "identity": _("Privilege Settings"),
            },
            "publickey": {
                "set_dialog_help": _("Public key:"),
                "set_dialog_title": _("Set public key"),
                "show_set_key": _("Show/Set key"),
                "status_mod_ns": _("Modified: key not set"),
                "status_mod_s": _("Modified"),
                "status_new_ns": _("New: key not set"),
                "status_new_s": _("New: key set"),
            },
            "pwpolicy": {
                "add": _("Add password policy"),
                "identity": _("Password Policy"),
                "remove": _("Remove password policies"),
            },
            "idrange": {
                "add": _("Add ID range"),
                "details": _("Range Settings"),
                "ipabaseid": _("Base ID"),
                "ipabaserid": _("Primary RID base"),
                "ipaidrangesize": _("Range size"),
                "ipanttrusteddomainsid": _("Domain SID"),
                "ipasecondarybaserid": _("Secondary RID base"),
                "remove": _("Remove ID ranges"),
                "type": _("Range type"),
                "type_ad": _("Active Directory domain"),
                "type_ad_posix": _("Active Directory domain with POSIX attributes"),
                "type_detect": _("Detect"),
                "type_local": _("Local domain"),
                "type_ipa": _("IPA trust"),
                "type_winsync": _("Active Directory winsync"),
            },
            "radiusproxy": {
                "add": _("Add RADIUS server"),
                "details": _("RADIUS Proxy Server Settings"),
                "remove": _("Remove RADIUS servers"),
            },
            "realmdomains": {
                "identity": _("Realm Domains"),
                "check_dns": _("Check DNS"),
                "check_dns_confirmation": _("Do you also want to perform DNS check?"),
                "force_update": _("Force Update"),
            },
            "selfservice": {
            },
            "selinuxusermap": {
                "add": _("Add SELinux user map"),
                "any_host": _("Any Host"),
                "anyone": _("Anyone"),
                "host": _("Host"),
                "remove": _("Remove selinux user maps"),
                "remove_groups": _(
                    "Remove user groups from SELinux user map '${primary_key}'"
                ),
                "remove_hostgroups": _(
                    "Remove host groups from SELinux user map '${primary_key}'"
                ),
                "remove_hosts": _(
                    "Remove hosts from SELinux user map '${primary_key}'"
                ),
                "remove_users": _(
                    "Remove users from SELinux user map '${primary_key}'"
                ),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "user": _("User"),
            },
            "server_role": {
                "label": _("Server Roles"),
                "label_singular": _("Server Role"),
            },
            "servers": {
                "svc_warning_title": _("Warning: Consider service replication"),
                "svc_warning_message": _("It is strongly recommended to keep the following services installed on more than one server:"),
                "remove_server": _("Delete Server"),
                "remove_server_msg": _("Deleting a server removes it permanently from the topology. Note that this is a non-reversible action.")
            },
            "service": {
                "add": _("Add service"),
                "certificate": _("Service Certificate"),
                "delete_key_unprovision": _("Delete Key, Unprovision"),
                "details": _("Service Settings"),
                "host": _("Host Name"),
                "missing": _("Kerberos Key Not Present"),
                "provisioning": _("Provisioning"),
                "remove": _("Remove services"),
                "remove_from_roles": _(
                    "Remove service '${primary_key}' from roles"
                ),
                "remove_hosts_managing": _(
                    "Remove hosts managing service '${primary_key}'"
                ),
                "service": _("Service"),
                "status": _("Status"),
                "unprovision": _("Unprovision"),
                "unprovision_confirmation": _("Are you sure you want to unprovision this service?"),
                "unprovision_title": _("Unprovisioning service"),
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
            "stageuser": {
                "activate_confirm": _("Are you sure you want to activate selected users?"),
                "activate_one_confirm": _("Are you sure you want to activate ${object}?"),
                "activate_success": _("${count} user(s) activated"),
                "add": _("Add stage user"),
                "label": _("Stage users"),
                "preserved_label": _("Preserved users"),
                "preserved_remove": _("Remove preserved users"),
                "remove": _("Remove stage users"),
                "stage_confirm": _("Are you sure you want to stage selected users?"),
                "stage_success": _("${count} users(s) staged"),
                "stage_one_confirm": _("Are you sure you want to stage ${object}?"),
                "undel_confirm": _("Are you sure you want to restore selected users?"),
                "undel_one_confirm": _("Are you sure you want to restore ${object}?"),
                "undel_success": _("${count} user(s) restored"),
                "user_categories": _("User categories"),
            },
            "sudocmd": {
                "add": _("Add sudo command"),
                "groups": _("Groups"),
                "remove": _("Remove sudo commands"),
                "remove_from_sudocmdgroups": _(
                    "Remove sudo command '${primary_key}' from sudo command "
                    "groups"
                ),
            },
            "sudocmdgroup": {
                "add": _("Add sudo command group"),
                "commands": _("Commands"),
                "remove": _("Remove sudo command groups"),
                "remove_sudocmds": _(
                    "Remove sudo commands from sudo command group "
                    "'${primary_key}'"
                ),
            },
            "sudorule": {
                "add": _("Add sudo rule"),
                "add_option": _("Add sudo option"),
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
                "option_removed": _("${count} option(s) removed"),
                "options": _("Options"),
                "remove": _("Remove sudo rules"),
                "remove_allow_cmds": _(
                    "Remove allow sudo commands from sudo rule "
                    "'${primary_key}'"
                ),
                "remove_allow_cmdgroups": _(
                    "Remove allow sudo command groups from sudo rule "
                    "'${primary_key}'"
                ),
                "remove_deny_cmds": _(
                    "Remove deny sudo commands from sudo rule "
                    "'${primary_key}'"
                ),
                "remove_deny_cmdgroups": _(
                    "Remove deny sudo command groups from sudo rule "
                    "'${primary_key}'"
                ),
                "remove_groups": _(
                    "Remove user groups from sudo rule '${primary_key}'"
                ),
                "remove_hostgroups": _(
                    "Remove host groups from sudo rule '${primary_key}'"
                ),
                "remove_hosts": _(
                    "Remove hosts from sudo rule '${primary_key}'"
                ),
                "remove_runas_users": _(
                    "Remove RunAs users from sudo rule '${primary_key}'"
                ),
                "remove_runas_usergroups": _(
                    "Remove RunAs user groups from sudo rule '${primary_key}'"
                ),
                "remove_runas_groups": _(
                    "Remove RunAs groups from sudo rule '${primary_key}'"
                ),
                "remove_users": _(
                    "Remove users from sudo rule '${primary_key}'"
                ),
                "runas": _("As Whom"),
                "specified_commands": _("Specified Commands and Groups"),
                "specified_groups": _("Specified Groups"),
                "specified_hosts": _("Specified Hosts and Groups"),
                "specified_users": _("Specified Users and Groups"),
                "user": _("Who"),
            },
            "sudooptions": {
                "remove": _("Remove sudo options"),
            },
            "topology": {
                "autogenerated": _("Autogenerated"),
                "segment_details": _("Segment details"),
                "replication_config": _("Replication configuration"),
                "insufficient_domain_level" : _("Managed topology requires minimal domain level ${domainlevel}"),
            },
            "topologylocation": {
                "add": _("Add IPA location"),
                "remove": _("Remove IPA locations"),
                "remove_servers": _(
                    "Remove IPA servers from IPA location '${primary_key}'"
                ),
            },
            "topologysegment": {
                "add": _("Add topology segment"),
                "remove": _("Remove topology segments"),
            },
            "trust": {
                "account": _("Account"),
                "add": _("Add trust"),
                "admin_account": _("Administrative account"),
                "blacklists": _("SID blacklists"),
                "details": _("Trust Settings"),
                "domain": _("Domain"),
                "establish_using": _("Establish using"),
                "fetch_domains": _("Fetch domains"),
                "ipantflatname": _("Domain NetBIOS name"),
                "ipanttrusteddomainsid": _("Domain Security Identifier"),
                "preshared_password": _("Pre-shared password"),
                "remove": _("Remove trusts"),
                "remove_domains": _("Remove domains"),
                "trustdirection": _("Trust direction"),
                "truststatus": _("Trust status"),
                "trusttype": _("Trust type"),
                "ipantadditionalsuffixes": _("Alternative UPN suffixes"),
            },
            "trustconfig": {
                "options": _("Options"),
            },
            "user": {
                "account": _("Account Settings"),
                "account_status": _("Account Status"),
                "activeuser_label": _("Active users"),
                "add": _("Add user"),
                "contact": _("Contact Settings"),
                "delete_mode": _("Delete mode"),
                "employee": _("Employee Information"),
                "error_changing_status": _("Error changing account status"),
                "krbpasswordexpiration": _("Password expiration"),
                "mailing": _("Mailing Address"),
                "misc": _("Misc. Information"),
                "mode_delete": _("delete"),
                "mode_preserve": _("preserve"),
                "noprivate": _("No private group"),
                "remove": _("Remove users"),
                "remove_from_groups": _(
                    "Remove user '${primary_key}' from user groups"
                ),
                "remove_from_netgroups": _(
                    "Remove user '${primary_key}' from netgroups"
                ),
                "remove_from_roles": _(
                    "Remove user '${primary_key}' from roles"
                ),
                "remove_from_hbac": _(
                    "Remove user '${primary_key}' from HBAC rules"
                ),
                "remove_from_sudo": _(
                    "Remove user '${primary_key}' from sudo rules"
                ),
                "status_confirmation": _("Are you sure you want to ${action} the user?<br/>The change will take effect immediately."),
                "status_link": _("Click to ${action}"),
                "unlock": _("Unlock"),
                "unlock_confirm": _("Are you sure you want to unlock user ${object}?"),
            },
            "vault": {
                "add": _("Add vault"),
                "add_warn_arch_ret": _(
                    "Secrets can be added/retrieved to vault only by using "
                    "vault-archive and vault-retrieve from CLI."
                    ),
                "add_warn_standard": _(
                    "Content of 'standard' vaults can be seen by users with "
                    "higher privileges (admins)."
                    ),
                "asymmetric_type": _("Asymmetric"),
                "config_title": _("Vaults Config"),
                "group": _("Group"),
                "members": _("Members"),
                "my_vaults_title": _("My User Vaults"),
                "owners": _("Owners"),
                "remove": _("Remove vaults"),
                "remove_member_groups": _(
                    "Remove user groups from members of vault '${primary_key}'"
                ),
                "remove_member_services": _(
                    "Remove services from members of vault '${primary_key}'"
                ),
                "remove_member_users": _(
                    "Remove users from members of vault '${primary_key}'"
                ),
                "remove_owner_groups": _(
                    "Remove user groups from owners of vault '${primary_key}'"
                ),
                "remove_owner_services": _(
                    "Remove services from owners of vault '${primary_key}'"
                ),
                "remove_owner_users": _(
                    "Remove users from owners of vault '${primary_key}'"
                ),
                "service": _("Service"),
                "service_vaults_title": _("Service Vaults"),
                "shared": _("Shared"),
                "shared_vaults_title": _("Shared Vaults"),
                "standard_type": _("Standard"),
                "symmetric_type": _("Symmetric"),
                "type": _("Vault Type"),
                "type_tooltip": _(
                    "Only standard vaults can be created in WebUI, use CLI "
                    "for other types of vaults."
                    ),
                "user": _("User"),
                "user_vaults_title": _("User Vaults"),
            },
        },
        "password": {
            "current_password": _("Current Password"),
            "current_password_required": _("Current password is required"),
            "expires_in": _("Your password expires in ${days} days."),
            "first_otp": _("First OTP"),
            "invalid_password": _(
                "The password or username you entered is incorrect"),
            "new_password": _("New Password"),
            "new_password_required": _("New password is required"),
            "otp": _("OTP"),
            "otp_info": _("<i class=\"fa fa-info-circle\"></i> <strong>One-Time-Password(OTP):</strong> Generate new OTP code for each OTP field."),
            "otp_long": _("One-Time-Password"),
            "otp_sync_fail": _("Token synchronization failed"),
            "otp_sync_invalid": _("The username, password or token codes are not correct"),
            "otp_sync_success":_("Token was synchronized"),
            "password": _("Password"),
            "password_and_otp": _("Password or Password+One-Time-Password"),
            "password_change_complete": _("Password change complete"),
            "password_expired": _(
                "Your password has expired. Please enter a new password."),
            "password_must_match": _("Passwords must match"),
            "reset_failure": _("Password reset was not successful."),
            "reset_password": _("Reset Password"),
            "reset_password_sentence": _("Reset your password."),
            "second_otp": _("Second OTP"),
            "token_id": _("Token ID"),
            "verify_password": _("Verify Password"),
        },
        "profile-menu": {
            "about": _("About"),
            "configuration": _("Customization"),
            "logout": _("Log out"),
            "password_reset": _("Change password"),
            "profile": _("Profile"),
        },
        "search": {
            "delete_confirm": _("Are you sure you want to delete selected entries?"),
            "deleted": _("${count} item(s) deleted"),
            "disable_confirm": _("Are you sure you want to disable selected entries?"),
            "disabled": _("${count} item(s) disabled"),
            "enable_confirm": _("Are you sure you want to enable selected entries?"),
            "enabled": _("${count} item(s) enabled"),
            "partial_delete": _("Some entries were not deleted"),
            "placeholder": _("Search"),
            "placeholder_filter": _("Filter"),
            "quick_links": _("Quick Links"),
            "select_all": _("Select All"),
            "truncated": _("Query returned more results than the configured size limit. Displaying the first ${counter} results."),
            "unselect_all": _("Unselect All"),
        },
        "ssbrowser-page": {
            "header": _(
                "<h1>Browser Kerberos Setup</h1>\n"
                "\n"
            ),
            "firefox-header": _(
                "<h2>Firefox</h2>\n"
                "\n"
                "<p>\n"
                "            You can configure Firefox to use Kerberos for "
                "Single Sign-on. The following instructions will guide you in "
                "configuring your web browser to send your Kerberos "
                "credentials to the appropriate Key Distribution Center which "
                "enables Single Sign-on.\n"
                "</p>\n"
                "\n"
            ),
            "firefox-actions": _(
                "<ol>\n"
                "<li>\n"
                "<p>\n"
                "<a href=\"ca.crt\" id=\"ca-link\" class=\"btn btn-default\">"
                "Import Certificate Authority certificate</a>\n"
                "</p>\n"
                "<p>\n"
                "                    Make sure you select <b>all three</b> "
                "checkboxes.\n"
                "</p>\n"
                "</li>\n"
                "<li>\n"
                "                In the address bar of Firefox, type <code>"
                "about:config</code> to display the list of current "
                "configuration options.\n"
                "</li>\n"
                "<li>\n"
                "                In the Filter field, type <code>negotiate"
                "</code> to restrict the list of options.\n"
                "</li>\n"
                "<li>\n"
                "                Double-click the <code>network.negotiate-auth"
                ".trusted-uris</code> entry to display the Enter string value "
                "dialog box.\n"
                "</li>\n"
                "<li>\n"
                "                Enter the name of the domain against which "
                "you want to authenticate, for example, <code class=\""
                "example-domain\">.example.com.</code>\n"
                "</li>\n"
                "<li><a href=\"../ui/index.html\" id=\"return-link\" class=\""
                "btn btn-default\">Return to Web UI</a></li>\n"
                "</ol>\n"
                "\n"
            ),
            "chrome-header": _(
                "<h2>Chrome</h2>\n"
                "\n"
                "<p>\n"
                "            You can configure Chrome to use Kerberos for "
                "Single Sign-on. The following instructions will guide you in "
                "configuring your web browser to send your Kerberos "
                "credentials to the appropriate Key Distribution Center which "
                "enables Single Sign-on.\n"
                "</p>\n"
                "\n"
            ),
            "chrome-certificate": _(
                "<h3>Import CA Certificate</h3>\n"
                "<ol>\n"
                "<li>\n"
                "                Download the <a href=\"ca.crt\">CA "
                "certificate</a>. Alternatively, if the host is also an IdM "
                "client, you can find the certificate in /etc/ipa/ca.crt.\n"
                "</li>\n"
                "<li>\n"
                "                Click the menu button with the <em>Customize "
                "and control Google Chrome</em> tooltip, which is by default "
                "in the top right-hand corner of Chrome, and click <em>"
                "Settings</em>.\n"
                "</li>\n"
                "<li>\n"
                "                Click <em>Show advanced settings</em> to "
                "display more options, and then click the <em>Manage "
                "certificates</em> button located under the HTTPS/SSL heading."
                "\n"
                "</li>\n"
                "<li>\n"
                "                In the <em>Authorities</em> tab, click the "
                "<em>Import</em> button at the bottom.\n"
                "</li>\n"
                "<li>Select the CA certificate file that you downloaded in the"
                " first step.</li>\n"
                "</ol>\n"
                "\n"
            ),
            "chrome-spnego": _(
                "<h3>\n"
                "            Enable SPNEGO (Simple and Protected GSSAPI "
                "Negotiation Mechanism) to Use Kerberos Authentication\n"
                "            in Chrome\n"
                "</h3>\n"
                "<ol>\n"
                "<li>\n"
                "                Make sure you have the necessary directory "
                "created by running:\n"
                "<div><code>\n"
                "                    [root@client]# mkdir -p /etc/opt/chrome/"
                "policies/managed/\n"
                "</code></div>\n"
                "</li>\n"
                "<li>\n"
                "                Create a new <code>/etc/opt/chrome/policies/"
                "managed/mydomain.json</code> file with write privileges "
                "limited to the system administrator or root, and include the "
                "following line:\n"
                "<div><code>\n"
                "                    { \"AuthServerWhitelist\": \"*<span "
                "class=\"example-domain\">.example.com.</span>\" }\n"
                "</code></div>\n"
                "<div>\n"
                "                    You can do this by running:\n"
                "</div>\n"
                "<div><code>\n"
                "                    [root@server]# echo \'{ \""
                "AuthServerWhitelist\": \"*<span class=\"example-domain\">"
                ".example.com.</span>\" }' > /etc/opt/chrome/policies/managed/"
                "mydomain.json\n"
                "</code></div>\n"
                "</li>\n"
                "</ol>\n"
                "<ol>\n"
                "<p>\n"
                "<strong>Note:</strong> If using Chromium, use <code>/etc/"
                "chromium/policies/managed/</code> instead of <code>/etc/opt/"
                "chrome/policies/managed/</code> for the two SPNEGO Chrome "
                "configuration steps above.\n"
                "</p>\n"
                "</ol>\n"
                "\n"
            ),
            "ie-header": _(
                "<h2>Internet Explorer</h2>\n"
                "<p><strong>WARNING:</strong> Internet Explorer is no longer a"
                " supported browser.</p>\n"
                "<p>\n"
                "            Once you are able to log into the workstation "
                "with your kerberos key you are now able to use that ticket in"
                " Internet Explorer.\n"
                "</p>\n"
                "<p>\n"
            ),
            "ie-actions": _(
                "<strong>Log into the Windows machine using an account of your"
                " Kerberos realm (administrative domain)</strong>\n"
                "</p>\n"
                "<p>\n"
                "<strong>In Internet Explorer, click Tools, and then click "
                "Internet Options.</strong>\n"
                "</p>\n"
                "<div>\n"
                "<ol>\n"
                "<li>Click the Security tab</li>\n"
                "<li>Click Local intranet</li>\n"
                "<li>Click Sites </li>\n"
                "<li>Click Advanced </li>\n"
                "<li>Add your domain to the list</li>\n"
                "</ol>\n"
                "<ol>\n"
                "<li>Click the Security tab</li>\n"
                "<li>Click Local intranet</li>\n"
                "<li>Click Custom Level</li>\n"
                "<li>Select Automatic logon only in Intranet zone</li>\n"
                "</ol>\n"
                "\n"
                "<ol>\n"
                "<li> Visit a kerberized web site using IE (You must use the "
                "fully-qualified Domain Name in the URL)</li>\n"
                "<li><strong> You are all set.</strong></li>\n"
                "</ol>\n"
                "</div>\n"
                "\n"
            ),
        },
        "status": {
            "disable": _("Disable"),
            "disabled": _("Disabled"),
            "enable": _("Enable"),
            "enabled": _("Enabled"),
            "label": _("Status"),
            "working": _("Working"),
        },
        "tabs": {
            "audit": _("Audit"),
            "authentication": _("Authentication"),
            "automember": _("Automember"),
            "automount": _("Automount"),
            "cert": _("Certificates"),
            "dns": _("DNS"),
            "hbac": _("Host-Based Access Control"),
            "identity": _("Identity"),
            "ipaserver": _("IPA Server"),
            "network_services": _("Network Services"),
            "policy": _("Policy"),
            "role": _("Role-Based Access Control"),
            "sudo": _("Sudo"),
            "topology": _("Topology"),
            "trust": _("Trusts"),
        },
        "true": _("True"),
        "unauthorized-page": _(
            "<h1>Unable to verify your Kerberos credentials</h1>\n"
            "<p>\n"
            "            Please make sure that you have valid Kerberos "
            "tickets (obtainable via <strong>kinit</strong>), and that you"
            " have configured your browser correctly.\n"
            "</p>\n"
            "\n"
            "<h2>Browser configuration</h2>\n"
            "\n"
            "<div id=\"first-time\">\n"
            "<p>\n"
            "                If this is your first time, please <a href="
            "\"ssbrowser.html\">configure your browser</a>.\n"
            "</p>\n"
            "</div>\n"
        ),
        "widget": {
            "api_browser": _("API Browser"),
            "first": _("First"),
            "last": _("Last"),
            "next": _("Next"),
            "page": _("Page"),
            "prev": _("Prev"),
            "undo": _("Undo"),
            "undo_title": _("Undo this change."),
            "undo_all": _("Undo All"),
            "undo_all_title": _("Undo all changes in this field."),
            "validation": {
                "error": _("Text does not match field pattern"),
                "datetime": _("Must be an UTC date/time value (e.g., \"2014-01-20 17:58:01Z\")"),
                "decimal": _("Must be a decimal number"),
                "format": _("Format error"),
                "integer": _("Must be an integer"),
                "ip_address": _('Not a valid IP address'),
                "ip_v4_address": _('Not a valid IPv4 address'),
                "ip_v6_address": _('Not a valid IPv6 address'),
                "max_value": _("Maximum value is ${value}"),
                "min_value": _("Minimum value is ${value}"),
                "net_address": _("Not a valid network address (examples: 2001:db8::/64, 192.0.2.0/24)"),
                "parse": _("Parse error"),
                "positive_number": _("Must be a positive number"),
                "port": _("'${port}' is not a valid port"),
                "required": _("Required field"),
                "unsupported": _("Unsupported value"),
            },
        },
    }
    has_output = (
        Output('texts', dict, doc=_('Dict of I18N messages')),
    )
    def execute(self, **options):
        return dict(texts=json_serialize(self.messages))
