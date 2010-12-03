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

        that.create_association({
            'name': 'host',
            'add_method': 'add_host',
            'remove_method': 'remove_host'
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

        facet = ipa_service_managedby_host_facet({
            'name': 'managedby_host',
            'label': IPA.messages.association.managedby+' '+IPA.metadata['host'].label,
            'other_entity': 'host'
        });
        that.add_facet(facet);

        that.entity_init();
    };

    return that;
}

IPA.add_entity(ipa_service());

function ipa_service_add_dialog(spec) {

    spec = spec || {};

    var that = ipa_add_dialog(spec);

    that.init = function() {

        that.add_dialog_init();

        that.add_field(ipa_widget({
            name: 'krbprincipalname',
        }));

        that.add_field(ipa_text_widget({
            'name': 'service', 'label': 'Service',
            'size': 20,
            'undo': false
        }));

        that.add_field(ipa_text_widget({
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
        var service = field.save()[0];

        field = that.get_field('host');
        var host = field.save()[0];

        record['krbprincipalname'] = service+'/'+host;

        return record;
    };

    return that;
}

function ipa_service_search_facet(spec) {

    spec = spec || {};

    var that = ipa_search_facet(spec);

    that.init = function() {

        that.create_column({name:'krbprincipalname'});
        that.search_facet_init();
    };

    return that;
}

function ipa_service_details_facet(spec) {

    spec = spec || {};

    var that = ipa_details_facet(spec);

    that.init = function() {

        var section = ipa_details_list_section({
            name: 'details',
            label: 'Service Details'
        });
        that.add_section(section);

        section.create_field({
            name: 'krbprincipalname'
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
            name: 'provisioning',
            label: 'Provisioning'
        });
        that.add_section(section);

        section.add_field(service_provisioning_status_widget({
            name: 'provisioning_status',
            label: 'Status'
        }));

        section = ipa_details_list_section({
            name: 'certificate',
            label: 'Service Certificate'
        });
        that.add_section(section);

        section.add_field(service_certificate_status_widget({
            name: 'certificate_status',
            label: 'Status'
        }));

        that.details_facet_init();
    };

    return that;
}

function service_service_load(result) {

    var that = this;

    $('dd', that.container).remove();

    var dd = ipa_create_first_dd(this.name);
    dd.appendTo(that.container);

    var krbprincipalname = result['krbprincipalname'][0];
    var service = krbprincipalname.replace(/\/.*$/, '');
    dd.append(service);
}

function service_host_load(result) {

    var that = this;

    $('dd', that.container).remove();

    var dd = ipa_create_first_dd(this.name);
    dd.appendTo(that.container);

    var krbprincipalname = result['krbprincipalname'][0];
    var host = krbprincipalname.replace(/^.*\//, '').replace(/@.*$/, '');
    dd.append(host);
}

function service_provisioning_status_widget(spec) {

    spec = spec || {};

    var that = ipa_widget(spec);

    that.create = function(container) {

        that.widget_create(container);

        var table = $('<table/>').appendTo(container);

        var tr = $('<tr/>').appendTo(table);

        var td = $('<td/>').appendTo(tr);
        var li = $('<li/>', {
            'class': 'key-status-valid'
        }).appendTo(td);

        td = $('<td/>').appendTo(tr);
        td.append('Kerberos Key Present, Service Provisioned:');

        td = $('<td/>').appendTo(tr);

        $('<input/>', {
            'type': 'button',
            'name': 'unprovision',
            'value': 'Delete Key, Unprovision'
        }).appendTo(td);

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>').appendTo(tr);
        li = $('<li/>', {
            'class': 'key-status-missing'
        }).appendTo(td);

        td = $('<td/>').appendTo(tr);
        td.append('Kerberos Key Not Present');
    };

    that.setup = function(container) {

        that.widget_setup(container);

        that.valid = $('li.key-status-valid', that.container);
        that.missing = $('li.key-status-missing', that.container);

        var button = $('input[name=unprovision]', that.container);
        that.unprovision_button = ipa_button({
            'label': 'Delete Key, Unprovision',
            'click': that.unprovision
        });
        button.replaceWith(that.unprovision_button);
    };

    that.unprovision = function() {

        var label = IPA.metadata[that.entity_name].label;
        var dialog = ipa_dialog({
            'title': 'Unprovisioning '+label
        });

        dialog.create = function() {
            dialog.container.append(
                'To confirm your intention to unprovision this service, '+
                'click the "Unprovision" button.');
        };

        dialog.add_button('Unprovision', function() {
            var pkey = that.result['krbprincipalname'][0];
            ipa_cmd(that.entity_name+'_disable', [pkey], {},
                function(data, text_status, xhr) {
                    set_status('missing');
                    dialog.close();
                },
                function(xhr, text_status, error_thrown) {
                    dialog.close();
                }
            );
        });

        dialog.add_button('Cancel', function() {
            dialog.close();
        });

        dialog.init();

        dialog.open(that.container);

        return false;
    };

    that.load = function(result) {
        that.result = result;
        var krblastpwdchange = result['krblastpwdchange'];
        set_status(krblastpwdchange ? 'valid' : 'missing');
    };

    function set_status(status) {
        that.valid.toggleClass('key-status-active', status == 'valid');
        that.missing.toggleClass('key-status-active', status == 'missing');

        that.unprovision_button.css('visibility', status == 'valid' ? 'visible' : 'hidden');
    }

    return that;
}

function service_certificate_status_widget(spec) {

    spec = spec || {};

    var that = certificate_status_widget(spec);

    that.init = function() {

        that.entity_label = IPA.metadata[that.entity_name].label;

        that.get_entity_pkey = function(result) {
            var values = result['krbprincipalname'];
            return values ? values[0] : null;
        };

        that.get_entity_name = function(result) {
            var value = that.get_entity_pkey(result);
            return value ? value.replace(/@.*$/, '') : null;
        };

        that.get_entity_principal = function(result) {
            return that.get_entity_pkey(result);
        };

        that.get_entity_certificate = function(result) {
            var values = result['usercertificate'];
            return values ? values[0].__base64__ : null;
        };
    };

    return that;
}

function ipa_service_managedby_host_facet(spec) {

    spec = spec || {};

    var that = ipa_association_facet(spec);

    that.init = function() {

        var column = that.create_column({
            name: 'fqdn',
            label: 'Name',
            primary_key: true
        });

        column.setup = function(container, record) {
            container.empty();

            var value = record[column.name];
            value = value ? value.toString() : '';

            $('<a/>', {
                'href': '#'+value,
                'html': value,
                'click': function (value) {
                    return function() {
                        var state = IPA.tab_state(that.other_entity);
                        state[that.other_entity + '-facet'] = 'details';
                        state[that.other_entity + '-pkey'] = value;
                        $.bbq.pushState(state);
                        return false;
                    }
                }(value)
            }).appendTo(container);
        };

        that.create_column({name: 'description', label: 'Description'});

        that.create_adder_column({
            name: 'fqdn',
            label: 'Name',
            primary_key: true,
            width: '100px'
        });

        that.create_adder_column({
            name: 'description',
            label: 'Description',
            width: '100px'
        });

        that.association_facet_init();
    };

    return that;
}