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

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */

IPA.entity_factories.host = function () {

    return IPA.entity_builder().
        entity('host').
        search_facet({
            columns: [
                'fqdn',
                'description',
                {
                    name: 'krblastpwdchange',
                    label: IPA.messages.objects.host.enrolled,
                    format: IPA.utc_date_column_format
                }
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'details',
                    fields: [
                        {
                            factory: IPA.host_dnsrecord_entity_link_widget,
                            name: 'fqdn',
                            other_entity: 'dnsrecord'
                        },
                        'krbprincipalname',
                        {
                            factory: IPA.textarea_widget,
                            name: 'description'
                        },
                        'l',
                        'nshostlocation',
                        'nshardwareplatform',
                        'nsosversion'
                    ]
                },
                {
                    factory: IPA.host_enrollment_section,
                    name: 'enrollment',
                    fields: [
                        {
                            factory: IPA.host_keytab_widget,
                            name: 'has_keytab',
                            label: IPA.messages.objects.host.keytab
                        },
                        {
                            factory: IPA.host_password_widget,
                            name: 'has_password',
                            label: IPA.messages.objects.host.password
                        }
                    ]
                },
                {
                    name: 'certificate',
                    fields: [
                        {
                            factory: IPA.host_certificate_status_widget,
                            name: 'certificate_status',
                            label: IPA.messages.objects.host.status
                        }
                    ]
                }
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
            height: 250,
            sections: [
                {
                    factory: IPA.host_fqdn_section,
                    name: 'fqdn',
                    fields: [
                        {
                            factory: IPA.widget,
                            name: 'fqdn',
                            optional: true,
                            hidden: true
                        },
                        {
                            factory: IPA.text_widget,
                            name: 'hostname',
                            label: IPA.messages.objects.service.host,
                            param_info: { required: true }
                        },
                        {
                            factory: IPA.dnszone_select_widget,
                            name: 'dnszone',
                            label: IPA.metadata.objects.dnszone.label_singular,
                            editable: true,
                            empty_option: false,
                            param_info: { required: true }
                        }
                    ]
                },
                {
                    name: 'other',
                    fields: [
                        {
                            factory: IPA.text_widget,
                            name: 'ip_address',
                            param_info: IPA.get_method_option('host_add', 'ip_address')
                        },
                        {
                            factory: IPA.force_host_add_checkbox_widget,
                            name: 'force',
                            param_info: IPA.get_method_option('host_add', 'force')
                        }
                    ]
                }
            ]
        }).
        deleter_dialog({
            factory: IPA.host_deleter_dialog
        }).
        build();
};

IPA.host_fqdn_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_section(spec);

    that.create = function(container) {
        that.container = container;

        var hostname = that.get_field('hostname');
        var dnszone = that.get_field('dnszone');

        var table = $('<table/>', {
            'class': 'fqdn'
        }).appendTo(that.container);

        var tr = $('<tr/>').appendTo(table);

        var th = $('<th/>', {
            'class': 'hostname',
            title: hostname.label,
            text: hostname.label
        }).appendTo(tr);

        th = $('<th/>', {
            'class': 'dnszone',
            title: dnszone.label,
            text: dnszone.label
        }).appendTo(tr);

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

    that.save = function(record) {
        var field = that.get_field('hostname');
        var hostname = field.save()[0];

        field = that.get_field('dnszone');
        var dnszone = field.save()[0];

        record.fqdn = hostname && dnszone ? [ hostname+'.'+dnszone ] : [];
    };

    return that;
};

IPA.host_adder_dialog = function(spec) {

    spec = spec || {};
    spec.retry = typeof spec.retry !== 'undefined' ? spec.retry : false;

    var that = IPA.add_dialog(spec);

    that.create = function() {
        that.dialog_create();
        that.container.addClass('host-adder-dialog');
    };

    that.on_error = function(xhr, text_status, error_thrown) {
        var ajax = this;
        var command = that.command;
        var data = error_thrown.data;
        var dialog = null;

        if(data && data.error && data.error.code === 4304) {
            dialog = IPA.message_dialog({
                message: data.error.message,
                title: spec.title,
                on_ok: function() {
                    data.result = {
                        result: {
                            fqdn: command.args[0]
                        }
                    };
                    command.on_success.call(ajax, data, text_status, xhr);
                }
            });
        } else {
            dialog = IPA.error_dialog({
                xhr: xhr,
                text_status: text_status,
                error_thrown: error_thrown,
                command: command
            });
        }

        dialog.open(that.container);
    };

    return that;
};

IPA.host_deleter_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.search_deleter_dialog(spec);

    that.create = function() {

        that.deleter_dialog_create();

        var metadata = IPA.get_method_option('host_del', 'updatedns');

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
            entity: that.other_entity,
            method: 'find',
            args: [filter],
            options: {
                forward_only: true
            }
        });
    };

    return that;
};

IPA.host_dnsrecord_entity_link_widget = function(spec){
    var that = IPA.entity_link_widget(spec);

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

/* Take an LDAP format date in UTC and format it */
IPA.utc_date_column_format = function(value){
    if (!value) {
        return "";
    }
    if (value.length  != "20101119025910Z".length){
        return value;
    }
    /* We only handle GMT */
    if (value.charAt(value.length -1) !== 'Z'){
        return value;
    }

    var date = new Date();

    date.setUTCFullYear(
        value.substring(0, 4),    // YYYY
        value.substring(4, 6)-1,  // MM (0-11)
        value.substring(6, 8));   // DD (1-31)
    date.setUTCHours(
        value.substring(8, 10),   // HH (0-23)
        value.substring(10, 12),  // MM (0-59)
        value.substring(12, 14)); // SS (0-59)
    var formated = date.toString();
    return  formated;
};


IPA.force_host_add_checkbox_widget = function(spec) {
    var param_info = IPA.get_method_option('host_add', spec.name);
    spec.label = param_info.label;
    spec.tooltip = param_info.doc;
    return IPA.checkbox_widget(spec);
};

IPA.host_enrollment_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_table_section(spec);

    that.create = function(container) {
        that.table_section_create(container);

        var keytab_field = that.get_field('has_keytab');
        var password_field = that.get_field('has_password');

        /**
         * The set_password() in the password field is being customized to
         * update the keytab field.
         *
         * The customization needs to be done here because the section
         * doesn't create the fields. The IPA.entity_builder adds the fields
         * after creating the section. This needs to be improved.
         */
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

    var that = IPA.widget(spec);

    that.create = function(container) {

        that.widget_create(container);

        that.missing_span = $('<span/>', {
            name: 'missing',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'caution.png',
            'class': 'status-icon'
        }).appendTo(that.missing_span);

        that.missing_span.append(' ');

        that.missing_span.append(IPA.messages.objects.host.keytab_missing);

        that.present_span = $('<span/>', {
            name: 'present',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'check.png',
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

    that.load = function(result) {
        that.result = result;
        var value = result[that.name];
        set_status(value ? 'present' : 'missing');
    };

    function set_status(status) {
        that.present_span.css('display', status == 'present' ? 'inline' : 'none');
        that.missing_span.css('display', status == 'missing' ? 'inline' : 'none');
    }

    return that;
};

IPA.host_password_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.create = function(container) {

        that.widget_create(container);

        that.missing_span = $('<span/>', {
            name: 'missing'
        }).appendTo(container);

        $('<img/>', {
            src: 'caution.png',
            'class': 'status-icon'
        }).appendTo(that.missing_span);

        that.missing_span.append(' ');

        that.missing_span.append(IPA.messages.objects.host.password_missing);

        that.present_span = $('<span/>', {
            name: 'present',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'check.png',
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

        var dialog = IPA.dialog({
            title: title,
            width: 400
        });

        var password1 = dialog.add_field(IPA.text_widget({
            name: 'password1',
            label: IPA.messages.password.new_password,
            type: 'password'
        }));

        var password2 = dialog.add_field(IPA.text_widget({
            name: 'password2',
            label: IPA.messages.password.verify_password,
            type: 'password'
        }));

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

                that.set_password(
                    new_password,
                    function(data, text_status, xhr) {
                        that.load(data.result.result);
                        dialog.close();
                    },
                    function(xhr, text_status, error_thrown) {
                        dialog.close();
                    }
                );
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

    that.set_password = function(password, on_success, on_error) {
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
            on_success: on_success,
            on_error: on_error
        });

        command.execute();
    };

    that.load = function(result) {
        that.result = result;
        var value = result[that.name];
        set_status(value ? 'present' : 'missing');
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

IPA.host_certificate_status_widget = function (spec) {

    spec = spec || {};

    var that = IPA.cert.status_widget(spec);

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

    return that;
};
