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
            factory: IPA.service.details_facet,
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
                        },
                        {
                            name: 'ipakrbauthzdata',
                            type: 'checkboxes',
                            options: IPA.create_options(['MS-PAC', 'PAD'])
                        }
                    ]
                },
                {
                    name: 'provisioning',
                    action_panel: {
                        factory: IPA.action_panel,
                        name: 'provisioning_actions',
                        actions: ['unprovision']
                    },
                    fields: [
                        {
                            type: 'service_provisioning_status',
                            name: 'has_keytab',
                            label: IPA.messages.objects.service.status
                        }
                    ]
                },
                {
                    name: 'certificate',
                    action_panel: {
                        factory: IPA.action_panel,
                        name: 'cert_actions',
                        actions: [
                            'request_cert', 'view_cert', 'get_cert',
                            'revoke_cert', 'restore_cert'
                        ]
                    },
                    fields: [
                        {
                            type: 'certificate_status',
                            name: 'certificate_status',
                            label: IPA.messages.objects.service.status
                        }
                    ]
                }
            ],
            actions: [
                IPA.service.unprovision_action,
                IPA.cert.view_action,
                IPA.cert.get_action,
                IPA.cert.request_action,
                IPA.cert.revoke_action,
                IPA.cert.restore_action
            ],
            state: {
                evaluators: [
                    IPA.service.has_keytab_evaluator,
                    IPA.service.krbprincipalkey_acl_evaluator,
                    IPA.cert.certificate_evaluator
                ]
            },
            policies: [
                IPA.service.certificate_policy()
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
                            required: true,
                            z_index: 2
                        },
                        {
                            type: 'entity_select',
                            name: 'host',
                            other_entity: 'host',
                            other_field: 'fqdn',
                            label: IPA.messages.objects.service.host,
                            required: true,
                            z_index: 1
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

IPA.service.details_facet = function(spec, no_init) {

    var that = IPA.details_facet(spec, true);
    that.certificate_loaded = IPA.observer();

    if (!no_init) that.init_details_facet();

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

        that.status_valid = $('<div/>', {
            name: 'kerberos-key-valid',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'images/check-icon.png',
            style: 'float: left;',
            'class': 'status-icon'
        }).appendTo(that.status_valid);

        var content_div = $('<div/>', {
            style: 'float: left;'
        }).appendTo(that.status_valid);

        content_div.append('<b>'+IPA.messages.objects.service.valid+'</b>');

        that.status_missing = $('<div/>', {
            name: 'kerberos-key-missing',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'images/caution-icon.png',
            style: 'float: left;',
            'class': 'status-icon'
        }).appendTo(that.status_missing);

        content_div = $('<div/>', {
            style: 'float: left;'
        }).appendTo(that.status_missing);

        content_div.append('<b>'+IPA.messages.objects.service.missing+'</b>');
    };

    that.update = function(values) {
        that.status = values && values.length ? values[0] : false;
        set_status(that.status ? 'valid' : 'missing');
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

IPA.field_factories['service_provisioning_status'] = IPA.field;
IPA.widget_factories['service_provisioning_status'] = IPA.service_provisioning_status_widget;


IPA.service.unprovision_dialog = function(spec) {

    spec = spec || {};
    spec.title = spec.title || IPA.messages.objects.service.unprovision_title;

    var that = IPA.dialog(spec);
    that.facet = spec.facet;

    var entity_singular = that.entity.metadata.label_singular;
    that.title = that.title.replace('${entity}', entity_singular);

    that.create = function() {
        that.container.append(IPA.messages.objects.service.unprovision_confirmation);
    };

    that.create_buttons = function() {

        that.create_button({
            name: 'unprovision',
            label: IPA.messages.objects.service.unprovision,
            click: function() {
                that.unprovision();
            }
        });

        that.create_button({
            name: 'cancel',
            label: IPA.messages.buttons.cancel,
            click: function() {
                that.close();
            }
        });
    };

    that.unprovision = function() {

        var principal_f  = that.facet.fields.get_field('krbprincipalname');
        var pkey = principal_f.values[0];

        IPA.command({
            entity: that.entity.name,
            method: 'disable',
            args: [pkey],
            on_success: function(data, text_status, xhr) {
                that.facet.refresh();
                that.close();
                IPA.notify_success(IPA.messages.objects.service.unprovisioned);
            },
            on_error: function(xhr, text_status, error_thrown) {
                that.close();
            }
        }).execute();
    };

    that.create_buttons();

    return that;
};

IPA.service.unprovision_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'unprovision';
    spec.label = spec.label || IPA.messages.objects.service.delete_key_unprovision;
    spec.enable_cond = spec.enable_cond || ['has_keytab', 'krbprincipalkey_w'];

    var that = IPA.action(spec);

    that.execute_action = function(facet) {

        var dialog = IPA.service.unprovision_dialog({
            entity: facet.entity,
            facet: facet
        });

        dialog.open();
    };

    return that;
};

IPA.service.krbprincipalkey_acl_evaluator = function(spec) {

    spec.name = spec.name || 'unprovision_acl_evaluator';
    spec.attribute = spec.attribute || 'krbprincipalkey';

    var that = IPA.acl_state_evaluator(spec);
    return that;
};

IPA.service.has_keytab_evaluator = function(spec) {

    spec.name = spec.name || 'has_keytab_evaluator';
    spec.attribute = spec.attribute || 'has_keytab';
    spec.value = spec.value || [true];
    spec.representation = spec.representation || 'has_keytab';

    var that = IPA.value_state_evaluator(spec);
    return that;
};

IPA.service.certificate_policy = function(spec) {

    spec = spec || {};

    function get_pkey(result) {
        var values = result.krbprincipalname;
        return values ? values[0] : null;
    }

    spec.get_pkey = spec.get_pkey || get_pkey;

    spec.get_name = spec.get_name || function(result) {
        var value = get_pkey(result);
        return value ? value.replace(/@.*$/, '') : null;
    };

    spec.get_principal = spec.get_principal || get_pkey;

    spec.get_hostname = spec.get_hostname || function(result) {
        var value = get_pkey(result);
        if (value) {
            value = value.replace(/@.*$/, '').replace(/^.*\//, '');
        }
        return value;
    };

    var that = IPA.cert.load_policy(spec);
    return that;
};

IPA.register('service', IPA.service.entity);
