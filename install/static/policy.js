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
    ipa_stanza({name:'identity', label:'HBAC Details'}).
        input({name:'cn', label:'HBAC Name'}).
        input({name:'accessruletype', label:'Rule Type'}).
        input({name:'description', label:'Description'}).
        input({name:'hostcategory', label:'Host Category'}).
        input({name:'ipaenabledflag', label:'Enabled'}).
        input({name:'servicecategory', label:'Service Category'}).
        input({name:'sourcehostcategory', label:'Source Host Category'}).
        input({name:'usercategory', label:'User Category'})
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
    ipa_stanza({name:'identity', label:'DNS Zone Details'}).
        input({name:'idnsname', label:'DNS Name'}).
        input({name:'idnszoneactive', label:'Zone Active'}).
        input({name:'idnssoamname', label:'Authoritative name server'}).
        input({name:'idnssoarname', label:'administrator e-mail address'}).
        input({name:'idnssoaserial', label:'SOA serial'}).
        input({name:'idnssoarefresh', label:'SOA refresh'}).
        input({name:'idnssoaretry', label:'SOA retry'}).
        input({name:'idnssoaexpire', label:'SOA expire'}).
        input({name:'idnssoaminimum', label:'SOA minimum'}).
        input({name:'dnsttl', label:'SOA time to live'}).
        input({name:'dnsclass', label:'SOA class'}).
        input({name:'idnsallowdynupdate', label:'allow dynamic update?'}).
        input({name:'idnsupdatepolicy', label:'BIND update policy'})
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
    ipa_stanza({name:'identity', label:'Automount Location Details'}).
        input({name:'cn', label:'Automount Location'})
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
    ipa_stanza({name:'identity', label:'Password Policy'}).
        input({name:'krbmaxpwdlife',label:'Max Password Life'}).
        input({name:'krbminpwdlife',label:'Min Password Life'}).
        input({name:'krbpwdhistorylength',label:'Password History Length'}).
        input({name:'krbpwdmindiffchars',
                   label:'Min Different Characters'}).
        input({name:'krbpwdminlength', label:'Password Minimum Length'})
]);

ipa_entity_set_association_definition('pwpolicy', {
});


/**
   krbtpolicy
   Does not have search
*/

ipa_entity_set_details_definition('krbtpolicy', [
    ipa_stanza({name:'identity', label:'Krbtpolicy Location Details'}).
        input({name:'cn', label:'Krbtpolicy Location'}).
        input({name:'krbmaxrenewableage', label:'Max Renewable Age'}).
        input({name:'krbmaxticketlife', label:'Max Ticket Life'})
]);

ipa_entity_set_association_definition('krbtpolicy', {
});
