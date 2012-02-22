/*jsl:import ipa.js */
/*jsl:import certificate.js */

/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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

IPA.service = {};

IPA.service.entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.search_facet({
            columns: [ 'krbprincipalname' ]
        }).
        details_facet({
            sections: [
                {
                    name: 'details',
                    fields: [
                        'krbprincipalname',
                        {
                            type: 'service_name',
                            name: 'service',
                            label: IPA.messages.objects.service.service,
                            read_only: true
                        },
                        {
                            type: 'service_host',
                            name: 'host',
                            label: IPA.messages.objects.service.host,
                            read_only: true
                        }
                    ]
                },
                {
                    name: 'provisioning',
                    fields: [
                        {
                            type: 'service_provisioning_status',
                            name: 'krblastpwdchange',
                            label: IPA.messages.objects.service.status
                        }
                    ]
                },
                {
                    name: 'certificate',
                    fields: [
                        {
                            type: 'service_certificate_status',
                            name: 'certificate_status',
                            label: IPA.messages.objects.service.status
                        }
                    ]
                }
            ]
        }).
        association_facet({
            name: 'managedby_host',
            add_method: 'add_host',
            remove_method: 'remove_host'
        }).
        standard_association_facets().
        adder_dialog({
            factory: IPA.service_adder_dialog,
            height: 350,
            sections: [
                {
                    fields: [
                        {
                            type: 'combobox',
                            name: 'service',
                            label: IPA.messages.objects.service.service,
                            options: [
                                'cifs',
                                'DNS',
                                'ftp',
                                'HTTP',
                                'imap',
                                'ldap',
                                'libvirt',
                                'nfs',
                                'smtp',
                                'qpidd'
                            ],
                            editable: true,
                            size: 10,
                            required: true
                        },
                        {
                            type: 'entity_select',
                            name: 'host',
                            other_entity: 'host',
                            other_field: 'fqdn',
                            label: IPA.messages.objects.service.host,
                            required: true
                        },
                        {
                            type: 'checkbox',
                            name: 'force',
                            metadata: IPA.get_command_option('service_add', 'force')
                        }
                    ]
                }
            ]
        });
    };

    return that;
};

IPA.service_adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.entity_adder_dialog(spec);

    var init = function() {

        //small hack - krbprincipalname should not be displayed. This way
        //creation of associated widget is skipped.
        //In future it would be better split section definion into widget and
        //fields definition and create custom field with two associated
        //widgets - 'service' and 'host' with this dialog's save logic.
        that.builder.build_field({
            type: 'field',
            name: 'krbprincipalname',
            required: false
        });
    };

    that.save = function(record) {

        var field = that.fields.get_field('service');
        var service = field.save()[0];

        field = that.fields.get_field('host');
        var host = field.save()[0];

        record['krbprincipalname'] = [ service+'/'+host ];

        field = that.fields.get_field('force');
        record['force'] = field.save();
    };

    init();

    return that;
};

IPA.service_name_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    that.load = function(record) {

        that.field_load(record);

        var krbprincipalname = record.krbprincipalname[0];
        var value = krbprincipalname.replace(/\/.*$/, '');
        that.values = [value];

        that.reset();
    };

    return that;
};

IPA.field_factories['service_name'] = IPA.service_name_field;
IPA.widget_factories['service_name'] = IPA.text_widget;


IPA.service_host_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    that.load = function(record) {

        that.field_load(record);

        var krbprincipalname = record.krbprincipalname[0];
        var value = krbprincipalname.replace(/^.*\//, '').replace(/@.*$/, '');
        that.values = [value];

        that.reset();
    };

    return that;
};

IPA.field_factories['service_host'] = IPA.service_host_field;
IPA.widget_factories['service_host'] = IPA.text_widget;

IPA.service_provisioning_status_widget = function (spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.create = function(container) {

        that.widget_create(container);

        var div = $('<div/>', {
            name: 'kerberos-key-valid',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'images/check-icon.png',
            style: 'float: left;',
            'class': 'status-icon'
        }).appendTo(div);

        var content_div = $('<div/>', {
            style: 'float: left;'
        }).appendTo(div);

        content_div.append('<b>'+IPA.messages.objects.service.valid+':</b>');

        content_div.append(' ');

        $('<input/>', {
            'type': 'button',
            'name': 'unprovision',
            'value': IPA.messages.objects.service.delete_key_unprovision
        }).appendTo(content_div);

        div = $('<div/>', {
            name: 'kerberos-key-missing',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'images/caution-icon.png',
            style: 'float: left;',
            'class': 'status-icon'
        }).appendTo(div);

        content_div = $('<div/>', {
            style: 'float: left;'
        }).appendTo(div);

        content_div.append('<b>'+IPA.messages.objects.service.missing+'</b>');

        that.status_valid = $('div[name=kerberos-key-valid]', that.container);
        that.status_missing = $('div[name=kerberos-key-missing]', that.container);

        var button = $('input[name=unprovision]', that.container);
        that.unprovision_button = IPA.button({
            name: 'unprovision',
            'label': IPA.messages.objects.service.delete_key_unprovision,
            'click': that.unprovision
        });
        button.replaceWith(that.unprovision_button);
    };

    that.unprovision = function() {

        var label = that.entity.metadata.label_singular;
        var title = IPA.messages.objects.service.unprovision_title;
        title = title.replace('${entity}', label);

        var dialog = IPA.dialog({
            'title': title
        });

        dialog.create = function() {
            dialog.container.append(IPA.messages.objects.service.unprovision_confirmation);
        };

        dialog.create_button({
            name: 'unprovision',
            label: IPA.messages.objects.service.unprovision,
            click: function() {
                IPA.command({
                    entity: that.entity.name,
                    method: 'disable',
                    args: [that.pkey],
                    on_success: function(data, text_status, xhr) {
                        set_status('missing');
                        dialog.close();
                    },
                    on_error: function(xhr, text_status, error_thrown) {
                        dialog.close();
                    }
                }).execute();
            }
        });

        dialog.open(that.container);

        return false;
    };

    that.update = function(values) {
        that.pkey = values.pkey;
        that.status = values.value;
        set_status(values.value ? 'valid' : 'missing');
    };

    that.clear = function() {
        that.status_valid.css('display', 'none');
        that.status_missing.css('display', 'none');
    };

    function set_status(status) {
        that.status_valid.css('display', status == 'valid' ? 'inline' : 'none');
        that.status_missing.css('display', status == 'missing' ? 'inline' : 'none');
    }

    return that;
};

IPA.service_provisioning_status_field = function (spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    that.load = function(record) {

        that.values = {
            value: record[that.param],
            pkey: record['krbprincipalname'][0]
        };

        that.load_writable(record);

        that.reset();
    };

    return that;
};

IPA.field_factories['service_provisioning_status'] = IPA.service_provisioning_status_field;
IPA.widget_factories['service_provisioning_status'] = IPA.service_provisioning_status_widget;

IPA.service.certificate_status_field = function(spec) {

    spec = spec || {};

    var that = IPA.cert.status_field(spec);

    that.load = function(result) {

        that.widget.result = result;

        var krbprincipalname = result.krbprincipalname[0];
        var hostname = krbprincipalname.replace(/^.*\//, '').replace(/@.*$/, '');

        var message = IPA.messages.objects.cert.request_message;
        message = message.replace(/\$\{hostname\}/g, hostname);
        message = message.replace(/\$\{realm\}/g, IPA.env.realm);
        that.widget.request_message = message;

        that.reset();
    };

    return that;
};

IPA.service.certificate_status_widget = function(spec) {

    spec = spec || {};

    var that = IPA.cert.status_widget(spec);

    that.get_entity_pkey = function(result) {
        var values = result.krbprincipalname;
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
        var values = result.usercertificate;
        return values ? values[0].__base64__ : null;
    };

    return that;
};

IPA.widget_factories['service_certificate_status'] = IPA.service.certificate_status_widget;
IPA.field_factories['service_certificate_status'] = IPA.service.certificate_status_field;

IPA.register('service', IPA.service.entity);
