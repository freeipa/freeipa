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
    {name:'ipaserver', label:'Aci Details', fields:[
        {name:'cn', label:'Name'},
        {name:'description', label:'Description'}
    ]}
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
    {name:'ipaserver', label:'Taskgroup Details', fields:[
        {name:'cn', label:'Name'},
        {name:'description', label:'Description'}
    ]}
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
    {name:'ipaserver', label:'Rolegroup Details', fields:[
        {name:'cn', label:'Name'},
        {name:'description', label:'Description'}
    ]}
]);

ipa_entity_set_association_definition('rolegroup', {
    'taskgroup': { associator: SerialAssociator }
});

/* Configuration */
ipa_entity_set_details_definition('config',[
    {name:'ipaserver', label:'Configuration', fields:[
        {name:'cn', label:'Name'},
        {name:'description', label:'Description'},
        {name:'ipacertificatesubjectbase', label:'Certificat Subject Base'},
        {name:'ipadefaultloginshell', label:'Default Login Shell'},
        {name:'ipadefaultprimarygroup', label:'Default Primary Group'},
        {name:'ipagroupsearchfields', label:'Group Search Fields'},
        {name:'ipahomesrootdir', label:'Home Root Dir'},
        {name:'ipamaxusernamelength', label:'Max Username Length'},
        {name:'ipamigrationenabled', label:'Migration enabled?'},
        {name:'ipasearchrecordslimit', label:'Search Record Limit'},
        {name:'ipasearchtimelimit', label:'Search Time Limit'},
        {name:'ipausersearchfields', label:'User Search Fields'}
    ]}
]);
