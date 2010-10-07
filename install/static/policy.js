/*  Authors:
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

ipa_entity_set_search_definition('hbac', [
    ['cn', 'Name', null],
    ['description', 'description', null],
    ['quick_links', 'Quick Links', ipa_entity_quick_links]
]);

ipa_entity_set_add_definition('hbac', [
    'dialog-add-hbac', 'Add New Zone', [
        ['cn', 'Name', null]
    ]
]);

ipa_entity_set_details_definition('hbac', [
    {name:'identity', label:'HBAC Details', fields:[
        {name:'cn', label:'HBAC Name'},
        {name:'accessruletype', label:'Rule Type'},
        {name:'description', label:'Description'},
        {name:'hostcategory', label:'Host Category'},
        {name:'ipaenabledflag', label:'Enabled'},
        {name:'servicecategory', label:'Service Category'},
        {name:'sourcehostcategory', label:'Source Host Category'},
        {name:'usercategory', label:'User Category'}
    ]}
]);

ipa_entity_set_association_definition('hbac', {
});

/* DNS */
ipa_entity_set_search_definition('dns', [
    ['idnsname', 'Zone Name', null],
    ['quick_links', 'Quick Links', ipa_entity_quick_links]
]);

ipa_entity_set_add_definition('dns', [
    'dialog-add-dns', 'Add New Zone', [
        ['idnsname', 'Name', null],
        ['idnssoamname', 'Authoritative name server'],
        ['idnssoarname','administrator e-mail address']
    ]
]);

ipa_entity_set_details_definition('dns', [
    {name:'identity', label:'DNS Zone Details', fields:[
        {name:'idnsname', label:'DNS Name'},
        {name:'idnszoneactive', label:'Zone Active'},
        {name:'idnssoamname', label:'Authoritative name server'},
        {name:'idnssoarname', label:'administrator e-mail address'},
        {name:'idnssoaserial', label:'SOA serial'},
        {name:'idnssoarefresh', label:'SOA refresh'},
        {name:'idnssoaretry', label:'SOA retry'},
        {name:'idnssoaexpire',label:'SOA expire'},
        {name:'idnssoaminimum', label:'SOA minimum'},
        {name:'dnsttl', label:'SOA time to live'},
        {name:'dnsclass', label:'SOA class'},
        {name:'idnsallowdynupdate', label:'allow dynamic update?'},
        {name:'idnsupdatepolicy', label:'BIND update policy'}
    ]}
]);

ipa_entity_set_association_definition('dns', {
});


/**Automount*/

ipa_entity_set_search_definition('automountlocation', [
    ['cn', 'Name', null],
    ['quick_links', 'Quick Links', ipa_entity_quick_links]

]);

ipa_entity_set_add_definition('automountlocation', [
    'dialog-add-location', 'Add New Location', [
        ['cn', 'Name', null]
    ]
]);

ipa_entity_set_details_definition('automountlocation', [
    {name:'identity', label:'Automount Location Details', fields:[
        {name:'cn', label:'Automount Location'}
    ]}
]);

ipa_entity_set_association_definition('automountlocation', {
});


/**pwpolicy*/

ipa_entity_set_search_definition('pwpolicy', [
    ['cn', 'Name', null],
    ['quick_links', 'Quick Links', ipa_entity_quick_links]

]);

ipa_entity_set_add_definition('pwpolicy', [
    'dialog-add-dns', 'Add New Location', [
        ['cn', 'Name', null]
    ]
]);

ipa_entity_set_details_definition('pwpolicy', [
    {name:'identity', label:'Password Policy', fields:[
        {name:'krbmaxpwdlife', label:'Max Password Life'},
        {name:'krbminpwdlife', label:'Min Password Life'},
        {name:'krbpwdhistorylength', label:'Password History Length'},
        {name:'krbpwdmindiffchars', label:'Min Different Characters'},
        {name:'krbpwdminlength', label:'Password Minimum Length'}
    ]}
]);

ipa_entity_set_association_definition('pwpolicy', {
});


/**
   krbtpolicy
   Does not have search
*/

ipa_entity_set_details_definition('krbtpolicy', [
    {name:'identity', label:'Krbtpolicy Location Details', fields:[
        {name:'cn', label:'Krbtpolicy Location'},
        {name:'krbmaxrenewableage', label:'Max Renewable Age'},
        {name:'krbmaxticketlife', label:'Max Ticket Life'}
    ]}
]);

ipa_entity_set_association_definition('krbtpolicy', {
});
