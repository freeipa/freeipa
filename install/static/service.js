/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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

ipa_entity_set_search_definition('service', [
    ['krbprincipalname', 'Principal', null],
    ['quick_links', 'Quick Links', ipa_entity_quick_links]
]);

ipa_entity_set_add_definition('service', [
    'dialog-add-service', 'Add New Service', [
        ['krbprincipalname', 'Principal', service_add_krbprincipalname],
        ['service', 'Service', null],
        ['host', 'Host Name', null]
    ]
]);

ipa_entity_set_details_definition('service', [
    ipa_stanza({name:'details', label:'Service Details'}).
        input({name:'krbprincipalname',
               label:'Principal',
               setup:service_krbprincipalname_setup,
               load:service_krbprincipalname_load}).
        input({name:'service', label:'Service', load:service_service_load}).
        input({name:'host', label:'Host Name', load:service_host_load}),
    ipa_stanza({name:'provisioning', label:'Provisioning'}).
        input({name:'provisioning_status', label:'Status',
               load:service_provisioning_status_load}),
    ipa_stanza({name:'certificate', label:'Service Certificate'}).
        input({name:'certificate_status', label:'Status',
               load:service_usercertificate_load})
]);

function service_add_krbprincipalname(add_dialog, mode) {
    if (mode == IPA_ADD_UPDATE) {
        var service = add_dialog.find('input[name=service]').val();
        var host = add_dialog.find('input[name=host]').val();
        return service+'/'+host;
    }
    return null;
}

ipa_entity_set_association_definition('service', {
    'host': { method: 'add_host' }
});

function service_krbprincipalname_setup(container, dl, section) {
    // skip krbprincipalname
}

function service_krbprincipalname_load(container, dt, result) {
    // skip krbprincipalname
}

function service_service_load(container, dt, result) {
    var krbprincipalname = result['krbprincipalname'][0];
    var service = krbprincipalname.replace(/\/.*$/, '');
    var dd = ipa_create_first_dd(this.name, service);
    dt.after(dd);
}

function service_host_load(container, dt, result) {
    var krbprincipalname = result['krbprincipalname'][0];
    var host = krbprincipalname.replace(/^.*\//, '').replace(/@.*$/, '');
    var dd = ipa_create_first_dd(this.name, host);
    dt.after(dd);
}

function service_provisioning_status_load(container, dt, result) {
    // skip provisioning_status
}

function service_usercertificate_load(container, dt, result) {

    var panel = certificate_status_panel({
        'entity_type': 'service',
        'entity_label': 'Service',
        'result': result,
        'get_entity_pkey': function(result) {
            var values = result['krbprincipalname'];
            return values ? values[0] : null;
        },
        'get_entity_name': function(result) {
            var value = this.get_entity_pkey(result);
            return value ? value.replace(/@.*$/, '') : null;
        },
        'get_entity_principal': function(result) {
            return this.get_entity_pkey(result);
        },
        'get_entity_certificate': function(result) {
            var values = result['usercertificate'];
            return values ? values[0].__base64__ : null;
        }
    });

    var dd = ipa_create_first_dd(this.name, panel);
    dt.after(dd);
}
