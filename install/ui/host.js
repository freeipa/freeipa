/*jsl:import ipa.js */
/*jsl:import certificate.js */

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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.host = {};

IPA.host.entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.search_facet({
            columns: [
                'fqdn',
                'description',
                {
                    name: 'has_keytab',
                    label: IPA.messages.objects.host.enrolled,
                    formatter: IPA.boolean_formatter()
                }
            ]
        }).
        details_facet({
            factory: IPA.host.details_facet,
            sections: [
                {
                    name: 'details',
                    fields: [
                        {
                            type: 'host_dnsrecord_entity_link',
                            name: 'fqdn',
                            other_entity: 'dnsrecord'
                        },
                        'krbprincipalname',
                        {
                            type: 'textarea',
                            name: 'description'
                        },
                        'l',
                        'nshostlocation',
                        'nshardwareplatform',
                        'nsosversion',
                        {
                            type: 'sshkeys',
                            name: 'ipasshpubkey',
                            label: IPA.messages.objects.sshkeystore.keys
                        },
                        {
                            type: 'multivalued',
                            name: 'macaddress'
                        }
                    ]
                },
                {
                    name: 'enrollment',
                    fields: [
                        {
                            factory: IPA.host_keytab_widget,
                            name: 'has_keytab',
                            label: IPA.messages.objects.host.keytab
                        },
                        {
                            type: 'host_password',
                            name: 'has_password',
                            label: IPA.messages.objects.host.password
                        }
                    ]
                },
                {
                    name: 'certificate',
                    fields: [
                        {
                            type: 'host_certificate_status',
                            name: 'certificate_status',
                            label: IPA.messages.objects.host.status
                        }
                    ]
                }
            ],
            policies: [
                IPA.host_enrollment_policy()
            ]
        }).
        association_facet({
            name: 'managedby_host',
            add_method: 'add_managedby',
            remove_method: 'remove_managedby'
        }).
        association_facet({
            name: 'memberof_hostgroup',
            associator: IPA.serial_associator
        }).
        association_facet({
            name: 'memberof_netgroup',
            associator: IPA.serial_associator
        }).
        association_facet({
            name: 'memberof_role',
            associator: IPA.serial_associator
        }).
        association_facet({
            name: 'memberof_hbacrule',
            associator: IPA.serial_associator,
            add_method: 'add_host',
            remove_method: 'remove_host'
        }).
        association_facet({
            name: 'memberof_sudorule',
            associator: IPA.serial_associator,
            add_method: 'add_host',
            remove_method: 'remove_host'
        }).
        standard_association_facets().
        adder_dialog({
            factory: IPA.host_adder_dialog,
            height: 300,
            sections: [
                {
                    factory: IPA.composite_widget,
                    name: 'fqdn',
                    fields: [
                        {
                            type: 'host_fqdn',
                            name: 'fqdn',
                            required: true
                        }
                    ]
                },
                {
                    name: 'other',
                    fields: [
                        {
                            name: 'ip_address',
                            validators: [ IPA.ip_address_validator() ],
                            metadata: IPA.get_command_option('host_add', 'ip_address')
                        },
                        {
                            type: 'force_host_add_checkbox',
                            name: 'force',
                            metadata: IPA.get_command_option('host_add', 'force')
                        }
                    ]
                }
            ]
        }).
        deleter_dialog({
            factory: IPA.host_deleter_dialog
        });
    };

    return that;
};

IPA.host.details_facet = function(spec) {

    var that = IPA.details_facet(spec);

    that.get_refresh_command_name = function() {
        return that.entity.name+'_show_'+that.pkey;
    };

    return that;
};

IPA.host_fqdn_widget = function(spec) {

    spec = spec || {};

    spec.widgets = [
        {
            type: 'text',
            name: 'hostname',
            label: IPA.messages.objects.service.host,
            required: true
        },
        {
            type: 'dnszone_select',
            name: 'dnszone',
            label: IPA.metadata.objects.dnszone.label_singular,
            editable: true,
            empty_option: false,
            required: true,
            searchable: true
        }
    ];

    var that = IPA.composite_widget(spec);

    that.create = function(container) {
        that.container = container;

        var hostname = that.widgets.get_widget('hostname');
        var dnszone = that.widgets.get_widget('dnszone');

        var table = $('<table/>', {
            'class': 'fqdn'
        }).appendTo(that.container);

        var tr = $('<tr/>').appendTo(table);

        var th = $('<th/>', {
            'class': 'hostname',
            title: hostname.label,
            text: hostname.label
        }).appendTo(tr);

        $('<span/>', {
            'class': 'required-indicator',
            text: IPA.required_indicator
        }).appendTo(th);

        th = $('<th/>', {
            'class': 'dnszone',
            title: dnszone.label,
            text: dnszone.label
        }).appendTo(tr);

        $('<span/>', {
            'class': 'required-indicator',
            text: IPA.required_indicator
        }).appendTo(th);

        tr = $('<tr/>').appendTo(table);

        var td = $('<td/>', {
            'class': 'hostname'
        }).appendTo(tr);

        var span = $('<span/>', {
            name: hostname.name
        }).appendTo(td);
        hostname.create(span);

        td = $('<td/>', {
            'class': 'dnszone'
        }).appendTo(tr);

        span = $('<span/>', {
            name: dnszone.name
        }).appendTo(td);
        dnszone.create(span);

        var hostname_input = $('input', hostname.container);
        var dnszone_input = $('input', dnszone.container);

        hostname_input.keyup(function(e) {
            var value = hostname_input.val();
            var i = value.indexOf('.');
            if (i >= 0) {
                var hostname = value.substr(0, i);
                var dnszone = value.substr(i+1);
                hostname_input.val(hostname);
                if (dnszone) {
                    dnszone_input.val(dnszone);
                    dnszone_input.focus();
                }
                IPA.select_range(dnszone_input, 0, dnszone_input.val().length);
            }
        });
    };

    return that;
};

IPA.host_fqdn_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    that.validate_required = function() {

        var hostname = that.hostname_widget.save();
        var dnszone = that.dns_zone_widget.save();

        var valid = true;

        if(!hostname.length || hostname[0] === '') {
            that.hostname_widget.show_error(IPA.messages.widget.validation.required);
            that.valid = valid = false;
        }

        if(!dnszone.length || dnszone[0] === '') {
            that.dns_zone_widget.show_error(IPA.messages.widget.validation.required);
            that.valid = valid = false;
        }

        return valid;
    };

    that.hide_error = function() {
        that.hostname_widget.hide_error();
        that.dns_zone_widget.hide_error();
    };

    that.save = function(record) {

        if(!record) record = {};

        var hostname = that.hostname_widget.save()[0];
        var dnszone = that.dns_zone_widget.save()[0];

        record.fqdn = hostname && dnszone ? [ hostname+'.'+dnszone ] : [];

        return record.fqdn;
    };

    that.reset = function() {

        that.hostname_widget.update([]);
        that.dns_zone_widget.update([]);
    };

    that.widgets_created = function() {

        that.widget = that.container.widgets.get_widget(that.widget_name);
        that.hostname_widget = that.widget.widgets.get_widget('hostname');
        that.dns_zone_widget = that.widget.widgets.get_widget('dnszone');
    };

    return that;
};

IPA.field_factories['host_fqdn'] = IPA.host_fqdn_field;
IPA.widget_factories['host_fqdn'] = IPA.host_fqdn_widget;

IPA.host_adder_dialog = function(spec) {

    spec = spec || {};
    spec.retry = spec.retry !== undefined ? spec.retry : false;

    var that = IPA.entity_adder_dialog(spec);

    that.create = function() {
        that.entity_adder_dialog_create();
        that.container.addClass('host-adder-dialog');
    };

    that.on_error = IPA.create_4304_error_handler(that);

    return that;
};

IPA.host_deleter_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.search_deleter_dialog(spec);

    that.create = function() {

        that.deleter_dialog_create();

        var metadata = IPA.get_command_option('host_del', 'updatedns');

        that.updatedns = $('<input/>', {
            type: 'checkbox',
            name: 'updatedns',
            title: metadata.doc
        }).appendTo(that.container);

        that.container.append(' ');

        that.container.append(metadata.doc);
    };

    that.create_command = function() {
        var batch = that.search_deleter_dialog_create_command();
        var updatedns = that.updatedns.is(':checked');

        for (var i=0; i<batch.commands.length; i++) {
            var command = batch.commands[i];
            command.set_option('updatedns', updatedns);
        }

        return batch;
    };

    return that;
};

IPA.dnszone_select_widget = function(spec) {

    spec = spec || {};
    spec.other_entity = 'dnszone';
    spec.other_field = 'idnsname';

    var that = IPA.entity_select_widget(spec);

    that.create_search_command = function(filter) {
        return IPA.command({
            entity: that.other_entity.name,
            method: 'find',
            args: [filter],
            options: {
                forward_only: true
            }
        });
    };

    return that;
};

IPA.field_factories['dnszone_select'] = IPA.field;
IPA.widget_factories['dnszone_select'] = IPA.dnszone_select_widget;

IPA.host_dnsrecord_entity_link_field = function(spec){
    var that = IPA.link_field(spec);

    that.other_pkeys = function(){
        var pkey = that.entity.get_primary_key()[0];
        var first_dot = pkey.search(/\./);
        var pkeys = [];
        pkeys[1] = pkey.substring(0,first_dot);
        pkeys[0] = pkey.substring(first_dot+1);
        return pkeys;
    };

    return that;
};

IPA.field_factories['host_dnsrecord_entity_link'] = IPA.host_dnsrecord_entity_link_field;
IPA.widget_factories['host_dnsrecord_entity_link'] = IPA.link_widget;

IPA.force_host_add_checkbox_widget = function(spec) {
    var metadata = IPA.get_command_option('host_add', spec.name);
    spec.label = metadata.label;
    spec.tooltip = metadata.doc;
    return IPA.checkbox_widget(spec);
};

IPA.widget_factories['force_host_add_checkbox'] = IPA.force_host_add_checkbox_widget;
IPA.field_factories['force_host_add_checkbox'] = IPA.checkbox_field;

IPA.host_enrollment_policy = function(spec) {

    var that =  IPA.facet_policy();

    that.init = function() {

        var keytab_field = that.container.fields.get_field('has_keytab');
        var password_field = that.container.fields.get_field('has_password');

        var super_set_password = password_field.set_password;
        password_field.set_password = function(password, on_success, on_error) {
            super_set_password.call(
                this,
                password,
                function(data, text_status, xhr) {
                    keytab_field.load(data.result.result);
                    if (on_success) on_success.call(this, data, text_status, xhr);
                },
                on_error);
        };
    };

    return that;
};

IPA.host_keytab_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.create = function(container) {

        that.widget_create(container);

        that.missing_span = $('<span/>', {
            name: 'missing',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'images/caution-icon.png',
            'class': 'status-icon'
        }).appendTo(that.missing_span);

        that.missing_span.append(' ');

        that.missing_span.append(IPA.messages.objects.host.keytab_missing);

        that.present_span = $('<span/>', {
            name: 'present',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'images/check-icon.png',
            'class': 'status-icon'
        }).appendTo(that.present_span);

        that.present_span.append(' ');

        that.present_span.append(IPA.messages.objects.host.keytab_present);

        that.present_span.append(': ');

        IPA.button({
            name: 'unprovision',
            label: IPA.messages.objects.host.delete_key_unprovision,
            click: function() {
                that.show_unprovision_dialog();
                return false;
            }
        }).appendTo(that.present_span);
    };

    that.show_unprovision_dialog = function() {

        var label = that.entity.metadata.label_singular;
        var title = IPA.messages.objects.host.unprovision_title;
        title = title.replace('${entity}', label);

        var dialog = IPA.dialog({
            'title': title
        });

        dialog.create = function() {
            dialog.container.append(IPA.messages.objects.host.unprovision_confirmation);
        };

        dialog.create_button({
            name: 'unprovision',
            label: IPA.messages.objects.host.unprovision,
            click: function() {
                that.unprovision(
                    function(data, text_status, xhr) {
                        set_status('missing');
                        dialog.close();
                    },
                    function(xhr, text_status, error_thrown) {
                        dialog.close();
                    }
                );
            }
        });

        dialog.create_button({
            name: 'cancel',
            label: IPA.messages.buttons.cancel,
            click: function() {
                dialog.close();
            }
        });

        dialog.open(that.container);
    };

    that.unprovision = function(on_success, on_error) {

        var pkey = that.entity.get_primary_key();

        var command = IPA.command({
            name: that.entity.name+'_disable_'+pkey,
            entity: that.entity.name,
            method: 'disable',
            args: pkey,
            options: { all: true, rights: true },
            on_success: on_success,
            on_error: on_error
        });

        command.execute();
    };

    that.update = function(values) {
        set_status(values[0] ? 'present' : 'missing');
    };

    that.clear = function() {
        that.present_span.css('display', 'none');
        that.missing_span.css('display', 'none');
    };

    function set_status(status) {
        that.present_span.css('display', status == 'present' ? 'inline' : 'none');
        that.missing_span.css('display', status == 'missing' ? 'inline' : 'none');
    }

    return that;
};

IPA.host_password_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.password_change_request = IPA.observer();

    that.create = function(container) {

        that.widget_create(container);

        that.missing_span = $('<span/>', {
            name: 'missing'
        }).appendTo(container);

        $('<img/>', {
            src: 'images/caution-icon.png',
            'class': 'status-icon'
        }).appendTo(that.missing_span);

        that.missing_span.append(' ');

        that.missing_span.append(IPA.messages.objects.host.password_missing);

        that.present_span = $('<span/>', {
            name: 'present',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'images/check-icon.png',
            'class': 'status-icon'
        }).appendTo(that.present_span);

        that.present_span.append(' ');

        that.present_span.append(IPA.messages.objects.host.password_present);

        container.append(': ');

        that.set_password_button = IPA.button({
            name: 'set_password',
            label: IPA.messages.objects.host.password_set_button,
            click: function() {
                that.show_password_dialog();
                return false;
            }
        }).appendTo(container);
    };

    that.show_password_dialog = function() {

        var title;
        var label;

        if (that.status == 'missing') {
            title = IPA.messages.objects.host.password_set_title;
            label = IPA.messages.objects.host.password_set_button;
        } else {
            title = IPA.messages.objects.host.password_reset_title;
            label = IPA.messages.objects.host.password_reset_button;
        }


        var dialog = that.dialog = IPA.dialog({
            title: title,
            width: 400,
            sections: [
                {
                    fields: [
                        {
                            name: 'password1',
                            label: IPA.messages.password.new_password,
                            type: 'password'
                        },
                        {
                            name: 'password2',
                            label: IPA.messages.password.verify_password,
                            type: 'password'
                        }
                    ]
                }
            ]
        });


        dialog.create_button({
            name: 'set_password',
            label: label,
            click: function() {

                var record = {};
                dialog.save(record);

                var new_password = record.password1[0];
                var repeat_password = record.password2[0];

                if (new_password != repeat_password) {
                    alert(IPA.messages.password.password_must_match);
                    return;
                }

                that.password_change_request.notify([new_password], that);

                dialog.close();
            }
        });

        dialog.create_button({
            name: 'cancel',
            label: IPA.messages.buttons.cancel,
            click: function() {
                dialog.close();
            }
        });

        dialog.open(that.container);
    };

    that.update = function(values) {
        set_status(values[0] ? 'present' : 'missing');
    };

    that.clear = function() {
        that.missing_span.css('display', 'none');
        that.present_span.css('display', 'none');
        var password_label = $('.button-label', that.set_password_button);
        password_label.text('');
    };

    function set_status(status) {

        that.status = status;
        var password_label = $('.button-label', that.set_password_button);

        if (status == 'missing') {
            that.missing_span.css('display', 'inline');
            that.present_span.css('display', 'none');
            password_label.text(IPA.messages.objects.host.password_set_button);

        } else {
            that.missing_span.css('display', 'none');
            that.present_span.css('display', 'inline');
            password_label.text(IPA.messages.objects.host.password_reset_button);
        }
    }

    return that;
};

IPA.host_password_field = function (spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    that.widgets_created = function() {

        that.field_widgets_created();
        that.widget.password_change_request.attach(that.set_password);
        that.widget.search = that.search;
    };

    that.set_password = function(password) {
        var pkey = that.entity.get_primary_key();

        var command = IPA.command({
            entity: that.entity.name,
            method: 'mod',
            args: pkey,
            options: {
                all: true,
                rights: true,
                userpassword: password
            },
            on_success: function(result) {
                that.load(result.result.result);
                that.widget.dialog.close();
            },
            on_error: function() {
                that.widget.dialog.close();
            }
        });

        command.execute();
    };


    return that;
};

IPA.widget_factories['host_password'] = IPA.host_password_widget;
IPA.field_factories['host_password'] = IPA.host_password_field;

IPA.host.certificate_status_field = function(spec) {

    spec = spec || {};

    var that = IPA.cert.status_field(spec);

    that.load = function(result) {

        that.widget.result = result;

        var message = IPA.messages.objects.cert.request_message;
        message = message.replace(/\$\{hostname\}/g, result.fqdn[0]);
        message = message.replace(/\$\{realm\}/g, IPA.env.realm);
        that.widget.request_message = message;

        that.reset();
    };

    return that;
};

IPA.host.certificate_status_widget = function(spec) {

    spec = spec || {};

    var that = IPA.cert.status_widget(spec);

    that.get_entity_pkey = function(result) {
        var values = result.fqdn;
        return values ? values[0] : null;
    };

    that.get_entity_name = function(result) {
        return that.get_entity_pkey(result);
    };

    that.get_entity_principal = function(result) {
        var values = result.krbprincipalname;
        return values ? values[0] : null;
    };

    that.get_entity_certificate = function(result) {
        var values = result.usercertificate;
        return values ? values[0].__base64__ : null;
    };

    return that;
};

IPA.widget_factories['host_certificate_status'] = IPA.host.certificate_status_widget;
IPA.field_factories['host_certificate_status'] = IPA.host.certificate_status_field;

IPA.register('host', IPA.host.entity);
