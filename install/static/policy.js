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
        ['cn', 'Name', null],
    ]
]);

ipa_entity_set_details_definition('hbac', [
    ['identity', 'HBAC Details', [
        ['cn', 'HBAC Name'],
        ["accessruletype", "Rule Type"],
        [ "description", "Description"],
        ["hostcategory", "Host Category"],
        ["ipaenabledflag", "Enabled"],
        ["servicecategory", "Service Category"],
        ["sourcehostcategory", "Source Host Category"],
        ["usercategory", "User Category"]
    ]]
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
        ['idnssoarname','administrator e-mail address'],
    ]
]);

ipa_entity_set_details_definition('dns', [
    ['identity', 'DNS Zone Details', [
        ['idnsname', 'DNS Name'],
        ['idnszoneactive', 'Zone Active'],
        ['idnssoamname', 'Authoritative name server'],
        ['idnssoarname','administrator e-mail address'],
        ['idnssoaserial', 'SOA serial'],
        ['idnssoarefresh', 'SOA refresh'],
        ['idnssoaretry', 'SOA retry'],
        ['idnssoaexpire','SOA expire'],
        ['idnssoaminimum', 'SOA minimum'],
        ['dnsttl','SOA time to live'],
        ['dnsclass','SOA class'],
        ['idnsallowdynupdate','allow dynamic update?'],
        ['idnsupdatepolicy', 'BIND update policy'],
    ]]
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
        ['cn', 'Name', null],
    ]
]);

ipa_entity_set_details_definition('automountlocation', [
    ['identity', 'Automount Location Details', [
        ['cn', 'Automount Location'],]
]]);

ipa_entity_set_association_definition('automountlocation', {
});


/**pwpolicy*/

ipa_entity_set_search_definition('pwpolicy', [
    ['cn', 'Name', null],
    ['quick_links', 'Quick Links', ipa_entity_quick_links]

]);

ipa_entity_set_add_definition('pwpolicy', [
    'dialog-add-dns', 'Add New Location', [
        ['cn', 'Name', null],
    ]
]);

ipa_entity_set_details_definition('pwpolicy', [
    ['identity', 'Password Policy', [
        ["krbmaxpwdlife","Max Password Life"],
        ["krbminpwdlife","Min Password Life"],
        ["krbpwdhistorylength","Password History Length"],
        ["krbpwdmindiffchars", "Min Different Characters"],
        ["krbpwdminlength", "Password Minimum Length"]
    ]]
]);

ipa_entity_set_association_definition('pwpolicy', {
});


/**
   krbtpolicy
   Does not have search
*/

ipa_entity_set_details_definition('krbtpolicy', [
    ['identity', 'Krbtpolicy Location Details', [
        ['cn', 'Krbtpolicy Location'],
        ["krbmaxrenewableage", "Max Renewable Age"],
        ["krbmaxticketlife", "Max Ticket Life"]
]]]);

ipa_entity_set_association_definition('krbtpolicy', {
});
