/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
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

ipa_entity_set_search_definition('host', [
    ['fqdn', 'Name', null],
    ['description', 'Description', null],
    ['enrolled', 'Enrolled?', null],
    ['manages', 'Manages?', null],
    ['quick_links', 'Quick Links', ipa_entity_quick_links]
]);

ipa_entity_set_add_definition('host', [
    'dialog-add-host', 'Add New Host', [
        ['fqdn', 'Name', null]
    ]
]);

ipa_entity_set_details_definition('host', [
    ipa_stanza({name:'details', label:'Host Details'}).
        input({name:'fqdn', label:'Fully Qualified Domain Name'}).
        input({name:'krbprincipalname', label:'Kerberos Principal'}).
        input({name:'serverhostname', label:'Server Host Name'}),
    ipa_stanza({name:'enrollment', label:'Enrollment'}).
        input({name:'enrollment_status', label:'Status',
               load:host_enrollment_status_load}),
    ipa_stanza({name:'certificate', label:'Host Certificate'}).
        input({name:'certificate_status', label:'Status',
               load:host_usercertificate_load})
]);

ipa_entity_set_association_definition('host', {
    'hostgroup': { associator: 'serial' },
    'rolegroup': { associator: 'serial' }
});

function host_enrollment_status_load(container, result) {
    // skip enrollment_status
}

function host_usercertificate_load(container, result) {

    var dt = $('dt[title='+this.name+']', container);
    if (!dt.length) return;

    var panel = certificate_status_panel({
        'entity_type': 'host',
        'entity_label': 'Host',
        'result': result,
        'get_entity_pkey': function(result) {
            var values = result['fqdn'];
            return values ? values[0] : null;
        },
        'get_entity_name': function(result) {
            return this.get_entity_pkey(result);
        },
        'get_entity_principal': function(result) {
            var values = result['krbprincipalname'];
            return values ? values[0] : null;
        },
        'get_entity_certificate': function(result) {
            var values = result['usercertificate'];
            return values ? values[0].__base64__ : null;
        }
    });

    var dd = ipa_create_first_dd(this.name, panel);
    dt.after(dd);
}
