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

        facet = ipa_association_facet({
            'name': 'associate'
        });
        that.add_facet(facet);

        that.entity_init();
    };

    return that;
}

IPA.add_entity(ipa_host());

function ipa_host_add_dialog(spec) {

    spec = spec || {};

    var that = ipa_add_dialog(spec);

    that.init = function() {

        that.add_dialog_init();

        that.add_field(ipa_text_widget({
            'name': 'fqdn',
            'label': 'Name',
            'size': 40,
            'undo': false
        }));
    };

    return that;
}

function ipa_host_search_facet(spec) {

    spec = spec || {};

    var that = ipa_search_facet(spec);

    that.init = function() {

        this.create_column({name:'fqdn', label:'Name'});
        this.create_column({name:'description', label:'Description'});
        this.create_column({name:'enrolled', label:'Enrolled?'});
        this.create_column({name:'manages', label:'Manages?'});

        that.search_facet_init();
    };

    return that;
}

function ipa_host_details_facet(spec) {

    spec = spec || {};

    var that = ipa_details_facet(spec);

    that.init = function() {

        var section = ipa_details_list_section({
            name: 'details',
            label: 'Host Details'
        });
        that.add_section(section);

        section.create_field({
            name: 'fqdn',
            label: 'Fully Qualified Domain Name'
        });

        section.create_field({
            name: 'krbprincipalname',
            label: 'Kerberos Principal'
        });

        section.create_field({
            name: 'serverhostname',
            label: 'Server Host Name'
        });

        section = ipa_details_list_section({
            name: 'enrollment',
            label: 'Enrollment'
        });
        that.add_section(section);

        section.add_field(host_provisioning_status_widget({
            name: 'provisioning_status',
            label: 'Status'
        }));

        section = ipa_details_list_section({
            name:'certificate',
            label:'Host Certificate'
        });
        that.add_section(section);

        section.add_field(host_certificate_status_widget({
            name: 'certificate_status',
            label: 'Status'
        }));

        that.details_facet_init();
    };

    return that;
}

function host_provisioning_status_widget(spec) {

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
        td.append('Kerberos Key Present, Host Provisioned:');

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

        that.container = container;

        that.valid = $('li.key-status-valid', that.container);
        that.missing = $('li.key-status-missing', that.container);

        var button = $('input[name=unprovision]', that.container);
        that.unprovision_button = ipa_button({
            'label': 'Delete Key, Unprovision',
            'click': that.unprovision
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

    that.unprovision = function() {

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
            var pkey = that.result['fqdn'][0];
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

    that.set_otp = function() {
        // TODO: enroll via OTP
        alert(that.otp.val());
    };

    that.load = function(container, result) {
        that.result = result;
        var krblastpwdchange = result['krblastpwdchange'];
        set_status(krblastpwdchange ? 'valid' : 'missing');
    };

    function set_status(status) {
        that.valid.toggleClass('key-status-active', status == 'valid');
        that.missing.toggleClass('key-status-active', status == 'missing');

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
        }
    };

    return that;
}
