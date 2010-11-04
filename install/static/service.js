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

function ipa_service() {

    var that = ipa_entity({
        'name': 'service'
    });

    that.init = function() {
        that.create_add_dialog({
            'name': 'add',
            'title': 'Add New Service',
            'init': ipa_service_add_init
        });

        that.create_search_facet({
            'name': 'search',
            'label': 'Search',
            'init': ipa_service_search_init
        });

        that.create_details_facet({
            'name': 'details',
            'label': 'Details',
            'init': ipa_service_details_init
        });
    };

    that.init();

    return that;
}

IPA.add_entity(ipa_service());

function ipa_service_add_init() {

    this.create_field({
        name: 'krbprincipalname',
        label: 'Principal',
        setup: service_add_krbprincipalname
    });

    this.create_field({name:'service', label:'Service'});
    this.create_field({name:'host', label:'Host Name'});
}

function ipa_service_search_init() {

    this.create_column({name:'krbprincipalname', label:'Principal'});

    this.create_column({
        name: 'quick_links',
        label: 'Quick Links',
        setup: ipa_entity_quick_links
    });
}

function ipa_service_details_init() {

    var section = this.create_section({name:'details', label:'Service Details'});

    section.create_field({
        name: 'krbprincipalname',
        label: 'Principal',
        setup: service_krbprincipalname_setup,
        load: service_krbprincipalname_load
    });

    section.create_field({
        name: 'service',
        label: 'Service',
        load: service_service_load
    });

    section.create_field({
        name: 'host',
        label: 'Host Name',
        load: service_host_load
    });

    section = this.create_section({name:'provisioning', label:'Provisioning'});

    section.create_field({
        name: 'provisioning_status',
        label: 'Status',
        load: service_provisioning_status_load
    });

    section = this.create_section({name:'certificate', label:'Service Certificate'});

    section.create_field({
        name: 'certificate_status',
        label: 'Status',
        load: service_usercertificate_load
    });
}

function service_add_krbprincipalname(add_dialog, mode) {
    if (mode == IPA_ADD_UPDATE) {
        var service = add_dialog.find('input[name=service]').val();
        var host = add_dialog.find('input[name=host]').val();
        return service+'/'+host;
    }
    return null;
}

ipa_entity_set_association_definition('service', {
    'host': { add_method: 'add_host', delete_host: 'remove_host' }
});

function service_krbprincipalname_setup(container) {
    // skip krbprincipalname
}

function service_krbprincipalname_load(container, result) {
    // skip krbprincipalname
}

function service_service_load(container, result) {
    var dt = $('dt[title='+this.name+']', container);
    if (!dt.length) return;

    var krbprincipalname = result['krbprincipalname'][0];
    var service = krbprincipalname.replace(/\/.*$/, '');
    var dd = ipa_create_first_dd(this.name, service);
    dt.after(dd);
}

function service_host_load(container, result) {
    var dt = $('dt[title='+this.name+']', container);
    if (!dt.length) return;

    var krbprincipalname = result['krbprincipalname'][0];
    var host = krbprincipalname.replace(/^.*\//, '').replace(/@.*$/, '');
    var dd = ipa_create_first_dd(this.name, host);
    dt.after(dd);
}

function service_provisioning_status_load(container, result) {
    // skip provisioning_status
}

function service_usercertificate_load(container, result) {

    var dt = $('dt[title='+this.name+']', container);
    if (!dt.length) return;

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
