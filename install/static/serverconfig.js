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
    ['cn', 'ACI name', null]
]);

ipa_entity_set_add_definition('aci', [
    'dialog-add-aci', 'Add New Aci', [
        ['cn', 'Name', null],
        ['description', 'Description', null],
    ]
]);

ipa_entity_set_details_definition('aci', [
    ipa_stanza({name:'ipaserver', label:'Aci Details'}).
        input({name:'cn', label:'Name'}).
        input({name:'description', label:'Description'})
]);



/* Taskgroup*/

ipa_entity_set_search_definition('taskgroup', [
    ['cn', 'Role-group name', null],
    ['description', 'Description', null]
]);

ipa_entity_set_add_definition('taskgroup', [
    'dialog-add-taskgroup', 'Add New Taskgroup', [
        ['cn', 'Name', null],
        ['description', 'Description', null],
    ]
]);


ipa_entity_set_details_definition('taskgroup', [
    ipa_stanza({name:'ipaserver', label:'Taskgroup Details'}).
        input({name:'cn', label:'Name'}).
        input({name:'description', label:'Description'})
]);

ipa_entity_set_association_definition('taskgroup', {
});

ipa_entity_set_association_definition('rolegroup', {
    'rolegroup': { }
});




/* Rolegroup*/

ipa_entity_set_search_definition('rolegroup', [
    ['cn', 'Role-group name', null],
    ['description', 'Description', null]
]);

ipa_entity_set_add_definition('rolegroup', [
    'dialog-add-rolegroup', 'Add New Rolegroup', [
        ['cn', 'Name', null],
        ['description', 'Description', null],
    ]
]);

ipa_entity_set_details_definition('rolegroup', [
    ipa_stanza({name:'ipaserver', label:'Rolegroup Details'}).
        input({name:'cn', label:'Name'}).
        input({name:'description', label:'Description'})
]);

ipa_entity_set_association_definition('rolegroup', {
    'taskgroup': { associator: 'serial' }
});

/* Configuration */
ipa_entity_set_details_definition('config',[

    ipa_stanza({name:'ipaserver', lable:'Configuration'}).
        input({name:'cn', label:'Name'}).
        input({name:'description', label:'Description'}).
        input({name:'ipacertificatesubjectbase', label:'Certificat Subject Base'}).
        input({name: 'ipadefaultloginshell', label:'Default Login Shell'}).
        input({name:'ipadefaultprimarygroup', label:'Default Primary Group'}).
        input({name:'ipagroupsearchfields', label:'Group Search Fields'}).
        input({name:'ipahomesrootdir', label:'Home Root Dir'}).
        input({name:'ipamaxusernamelength', label:'Max Username Length'}).
        input({name:'ipamigrationenabled', label:'Migration enabled?'}).
        input({name:'ipasearchrecordslimit', label:'Search Record Limit'}).
        input({name:'ipasearchtimelimit', label:'Search Time Limit'}).
        input({name:'ipausersearchfields', label:'User Search Fields'})
]);

IPA.get_entity('config').default_facet = 'details';
