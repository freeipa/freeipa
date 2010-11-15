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

    that.superior_init = that.superior('init');

    that.init = function() {

        that.create_association({
            'name': 'host',
            'add_method': 'add_host',
            'delete_method': 'remove_host'
        });

        var dialog = ipa_service_add_dialog({
            'name': 'add',
            'title': 'Add New Service'
        });
        that.add_dialog(dialog);
        dialog.init();

        var facet = ipa_service_search_facet({
            'name': 'search',
            'label': 'Search'
        });
        that.add_facet(facet);

        facet = ipa_service_details_facet({
            'name': 'details',
            'label': 'Details'
        });
        that.add_facet(facet);

        facet = ipa_association_facet({
            'name': 'associate'
        });
        that.add_facet(facet);

        that.superior_init();
    };

    return that;
}

IPA.add_entity(ipa_service());

function ipa_service_add_dialog(spec) {

    spec = spec || {};

    var that = ipa_add_dialog(spec);

    that.superior_init = that.superior('init');

    that.init = function() {

        this.superior_init();

        this.add_field(ipa_widget({
            name: 'krbprincipalname',
            label: 'Principal'
        }));

        this.add_field(ipa_text_widget({
            'name': 'service', 'label': 'Service',
            'size': 20,
            'undo': false
        }));

        this.add_field(ipa_text_widget({
            'name': 'host',
            'label': 'Host Name',
            'size': 40,
            'undo': false
        }));
    };

    that.create = function() {

        var table = $('<table/>').appendTo(that.container);

        var field = that.get_field('service');

        var tr = $('<tr/>').appendTo(table);

        var td = $('<td/>', {
            'style': 'vertical-align: top;'
        }).appendTo(tr);
        td.append(field.label+': ');

        td = $('<td/>', {
            'style': 'vertical-align: top;'
        }).appendTo(tr);

        var span = $('<span/>', { 'name': 'service' }).appendTo(td);
        field.create(span);

        field = that.get_field('host');

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>', {
            'style': 'vertical-align: top;'
        }).appendTo(tr);
        td.append(field.label+': ');

        td = $('<td/>', {
            'style': 'vertical-align: top;'
        }).appendTo(tr);

        span = $('<span/>', { 'name': 'host' }).appendTo(td);
        field.create(span);
    };

    that.get_record = function() {
        var record = {};

        var field = that.get_field('service');
        var service = field.save(that.container)[0];

        field = that.get_field('host');
        var host = field.save(that.container)[0];

        record['krbprincipalname'] = service+'/'+host;

        return record;
    };

    return that;
}

function ipa_service_search_facet(spec) {

    spec = spec || {};

    var that = ipa_search_facet(spec);

    that.superior_init = that.superior('init');

    that.init = function() {

        this.create_column({name:'krbprincipalname', label:'Principal'});
        that.superior_init();
    };

    return that;
}

function ipa_service_details_facet(spec) {

    spec = spec || {};

    var that = ipa_details_facet(spec);

    that.superior_init = that.superior('init');

    that.init = function() {

        var section = ipa_details_list_section({
            name:'details',
            label:'Service Details'
        });
        that.add_section(section);

        section.create_field({
            name: 'krbprincipalname',
            label: 'Principal'
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

        section = ipa_details_list_section({
            name:'provisioning',
            label:'Provisioning'
        });
        that.add_section(section);

        section.create_field({
            name: 'provisioning_status',
            label: 'Status',
            load: service_provisioning_status_load
        });

        section = ipa_details_list_section({
            name:'certificate',
            label:'Service Certificate'
        });
        that.add_section(section);

        section.create_field({
            name: 'certificate_status',
            label: 'Status',
            load: service_usercertificate_load
        });

        that.superior_init();
    };

    return that;
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
