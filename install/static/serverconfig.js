/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */



/* ACI */
ipa_entity_set_search_definition('aci', [
    ['cn', 'ACI name', null],
    ['quick_links', 'Quick Links', ipa_entity_quick_links]
]);

ipa_entity_set_add_definition('aci', [
    'dialog-add-aci', 'Add New Aci', [
        ['cn', 'Name', null],
        ['description', 'Description', null],
    ]
]);

ipa_entity_set_details_definition('aci', [
    ['ipaserver', 'Aci Details', [
        ['cn', 'Name', null],
        ['description', 'Description', null],
    ]]
]);


/* Taskgroup*/

ipa_entity_set_search_definition('taskgroup', [
    ['cn', 'Role-group name', null],
    ['description', 'Description', null],
    ['quick_links', 'Quick Links', ipa_entity_quick_links]
]);

ipa_entity_set_add_definition('taskgroup', [
    'dialog-add-taskgroup', 'Add New Taskgroup', [
        ['cn', 'Name', null],
        ['description', 'Description', null],
    ]
]);

ipa_entity_set_details_definition('taskgroup', [
    ['ipaserver', 'Taskgroup Details', [
        ['cn', 'Name', null],
        ['description', 'Description', null],
    ]]
]);

ipa_entity_set_association_definition('rolegroup', {
    'rolegroup': { associator: BulkAssociator }
});




/* Rolegroup*/

ipa_entity_set_search_definition('rolegroup', [
    ['cn', 'Role-group name', null],
    ['description', 'Description', null],
    ['quick_links', 'Quick Links', ipa_entity_quick_links]
]);

ipa_entity_set_add_definition('rolegroup', [
    'dialog-add-rolegroup', 'Add New Rolegroup', [
        ['cn', 'Name', null],
        ['description', 'Description', null],
    ]
]);

ipa_entity_set_details_definition('rolegroup', [
    ['ipaserver', 'Rolegroup Details', [
        ['cn', 'Name', null],
        ['description', 'Description', null],
    ]]
]);

ipa_entity_set_association_definition('rolegroup', {
    'taskgroup': { associator: SerialAssociator }
});

/* Configuration */
ipa_entity_set_details_definition('config',[
    ['ipaserver', 'Configuration', [
        ['cn', 'Name', null],
        ['description', 'Description', null],
        ['ipacertificatesubjectbase', 'Certificat Subject Base',null],
        [ 'ipadefaultloginshell', 'Default Login Shell',null],
        ['ipadefaultprimarygroup', 'Default Primary Group',null],
        ['ipagroupsearchfields', 'Group Search Fields',null],
        ['ipahomesrootdir', 'Home Root Dir',null],
        ['ipamaxusernamelength', 'Max Username Length',null],
        ['ipamigrationenabled', 'Migration enabled?',null],
        ['ipasearchrecordslimit', 'Search Record Limit',null],
        ['ipasearchtimelimit', 'Search Time Limit',null],
        ['ipausersearchfields', 'User Search Fields',null]
    ]]
]);
