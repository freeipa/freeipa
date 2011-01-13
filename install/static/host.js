/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */

function ipa_host() {

    var that = ipa_entity({
        'name': 'host'
    });

    that.init = function() {

        that.create_association({
            'name': 'hostgroup',
            'associator': 'serial'
        });

        that.create_association({
            'name': 'rolegroup',
            'associator': 'serial'
        });

        var dialog = ipa_host_add_dialog({
            'name': 'add',
            'title': 'Add New Host'
        });
        that.add_dialog(dialog);
        dialog.init();

        var facet = ipa_host_search_facet({
            'name': 'search',
            'label': 'Search'
        });
        that.add_facet(facet);

        facet = ipa_host_details_facet({
            'name': 'details',
            'label': 'Details'
        });
        that.add_facet(facet);

        facet = ipa_host_managedby_host_facet({
            'name': 'managedby_host',
            'label': IPA.messages.association.managedby+' '+IPA.metadata['host'].label,
            'other_entity': 'host'
        });
        that.add_facet(facet);

        that.create_association_facets();

        that.entity_init();
    };

    return that;
}

IPA.add_entity(ipa_host());

function ipa_host_add_dialog(spec) {

    spec = spec || {};

    var that = ipa_add_dialog(spec);

    that.init = function() {

        that.add_field(ipa_text_widget({
            'name': 'fqdn',
            'size': 40,
            'undo': false
        }));

        that.add_dialog_init();
    };

    return that;
}

function ipa_host_search_facet(spec) {

    spec = spec || {};

    var that = ipa_search_facet(spec);

    that.init = function() {

        that.create_column({name:'fqdn'});
        that.create_column({name:'description'});
        //TODO use the value of this field to set enrollment status
        that.create_column({name:'krblastpwdchange', label:'Enrolled?'});
        that.create_column({name:'nshostlocation'});

        that.search_facet_init();
    };

    return that;
}

function ipa_host_details_facet(spec) {

    spec = spec || {};

    var that = ipa_details_facet(spec);

    that.init = function() {

        var section = ipa_details_list_section({
            'name': 'details',
            'label': 'Host Details'
        });
        that.add_section(section);

        //TODO: use i18n labels
        section.create_field({
            name: 'fqdn',
            label: 'Fully Qualified Host Name'
        });

        section.create_field({'name': 'krbprincipalname'});

        //TODO: add this to the host plugin
        //TODO: use i18n labels
        section.create_field({
            'name': 'serverhostname',
            'label': 'Host Name'
        });

        section.create_field({'name': 'description'});

        //TODO: use i18n labels
        section = ipa_details_list_section({
            'name': 'enrollment',
            'label': 'Enrollment'
        });
        that.add_section(section);

        //TODO add label to messages
        section.add_field(host_provisioning_status_widget({
            'name': 'provisioning_status',
            'label': 'Status',
            'facet': that
        }));

        section = ipa_details_list_section({
            'name': 'certificate',
            'label': 'Host Certificate'
        });
        that.add_section(section);

        section.add_field(host_certificate_status_widget({
            'name': 'certificate_status',
            'label': 'Status'
        }));

        that.details_facet_init();
    };

    that.refresh = function() {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var command = ipa_command({
            'name': that.entity_name+'_show_'+pkey,
            'method': that.entity_name+'_show',
            'args': [pkey],
            'options': { 'all': true, 'rights': true }
        });

        command.on_success = function(data, text_status, xhr) {
            that.load(data.result.result);
        };

        command.on_error = function(xhr, text_status, error_thrown) {
            var details = $('.details', that.container).empty();
            details.append('<p>Error: '+error_thrown.name+'</p>');
            details.append('<p>'+error_thrown.title+'</p>');
            details.append('<p>'+error_thrown.message+'</p>');
        };

        command.execute();
    };

    return that;
}

function host_provisioning_status_widget(spec) {

    spec = spec || {};

    var that = ipa_widget(spec);

    that.facet = spec.facet;

    that.create = function(container) {

        that.widget_create(container);

        var table = $('<table/>').appendTo(container);

        var tr = $('<tr/>').appendTo(table);

        var td = $('<td/>').appendTo(tr);
        $('<div/>', {
            'class': 'status-icon status-valid'
        }).appendTo(td);

        td = $('<td/>').appendTo(tr);
        td.append('Kerberos Key Present, Host Provisioned:');

        td = $('<td/>').appendTo(tr);

        $('<input/>', {
            'type': 'button',
            'name': 'unprovision',
            'value': 'Delete Key, Unprovision'
        }).appendTo(td);

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>').appendTo(tr);
        $('<div/>', {
            'class': 'status-icon status-missing'
        }).appendTo(td);

        td = $('<td/>').appendTo(tr);
        td.append('Kerberos Key Not Present');

        td = $('<td/>').appendTo(tr);

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>').appendTo(tr);

        td = $('<td/>').appendTo(tr);
        td.append('Enroll via One-Time-Password:');

        td = $('<td/>').appendTo(tr);

        $('<input/>', {
            'type': 'text',
            'name': 'otp',
            'size': 10
        }).appendTo(td);

        $('<input/>', {
            'type': 'button',
            'name': 'enroll',
            'value': 'Set OTP'
        }).appendTo(td);
    };

    that.setup = function(container) {

        that.widget_setup(container);

        that.valid = $('.status-valid', that.container);
        that.missing = $('.status-missing', that.container);

        var button = $('input[name=unprovision]', that.container);
        that.unprovision_button = ipa_button({
            'label': 'Delete Key, Unprovision',
            'click': that.show_unprovision_dialog
        });
        button.replaceWith(that.unprovision_button);

        that.otp_input = $('input[name=otp]', that.container);

        that.enroll_button = $('input[name=enroll]', that.container);
        button = ipa_button({
            'label': 'Set OTP',
            'click': that.set_otp
        });

        that.enroll_button.replaceWith(button);
        that.enroll_button = button;
    };

    that.show_unprovision_dialog = function() {

        var label = IPA.metadata[that.entity_name].label;
        var dialog = ipa_dialog({
            'title': 'Unprovisioning '+label
        });

        dialog.create = function() {
            dialog.container.append(
                'To confirm your intention to unprovision this host, '+
                'click the "Unprovision" button.');
        };

        dialog.add_button('Unprovision', function() {
            that.unprovision(
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

    that.unprovision = function(on_success, on_error) {

        var pkey = that.facet.get_primary_key();

        var command = ipa_command({
            'name': that.entity_name+'_disable_'+pkey,
            'method': that.entity_name+'_disable',
            'args': [pkey],
            'options': { 'all': true, 'rights': true },
            'on_success': on_success,
            'on_error': on_error
        });

        command.execute();
    };

    that.set_otp = function() {

        var pkey = that.facet.get_primary_key();
        var otp = that.otp_input.val();
        that.otp_input.val('');

        var command = ipa_command({
            'method': that.entity_name+'_mod',
            'args': [pkey],
            'options': {
                'all': true,
                'rights': true,
                'userpassword': otp
            },
            'on_success': function(data, text_status, xhr) {
                alert('One-Time-Password has been set.');
            }
        });

        command.execute();
    };

    that.load = function(result) {
        that.result = result;
        var krblastpwdchange = result['krblastpwdchange'];
        set_status(krblastpwdchange ? 'valid' : 'missing');
    };

    function set_status(status) {
        that.valid.toggleClass('status-valid-active', status == 'valid');
        that.missing.toggleClass('status-missing-active', status == 'missing');

        that.unprovision_button.css('visibility', status == 'valid' ? 'visible' : 'hidden');
        that.otp_input.css('visibility', status == 'missing' ? 'visible' : 'hidden');
        that.enroll_button.css('visibility', status == 'missing' ? 'visible' : 'hidden');
    }

    return that;
}

function host_certificate_status_widget(spec) {

    spec = spec || {};

    var that = certificate_status_widget(spec);

    that.init = function() {

        that.entity_label = IPA.metadata[that.entity_name].label;

        that.get_entity_pkey = function(result) {
            var values = result['fqdn'];
            return values ? values[0] : null;
        };

        that.get_entity_name = function(result) {
            return that.get_entity_pkey(result);
        };

        that.get_entity_principal = function(result) {
            var values = result['krbprincipalname'];
            return values ? values[0] : null;
        };

        that.get_entity_certificate = function(result) {
            var values = result['usercertificate'];
            return values ? values[0].__base64__ : null;
        };
    };

    return that;
}

function ipa_host_managedby_host_facet(spec) {

    spec = spec || {};

    var that = ipa_association_facet(spec);

    that.add_method = 'add_managedby';
    that.remove_method = 'remove_managedby';

    that.init = function() {

        var column = that.create_column({
            name: 'fqdn',
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
                    };
                }(value)
            }).appendTo(container);
        };

        that.create_column({name: 'description'});

        that.create_adder_column({
            name: 'fqdn',
            primary_key: true,
            width: '100px'
        });

        that.create_adder_column({
            name: 'description',
            width: '100px'
        });

        that.association_facet_init();
    };

    return that;
}