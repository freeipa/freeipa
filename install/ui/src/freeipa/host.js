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

define(['./builder',
        './ipa',
        './jquery',
        './phases',
        './reg',
        './rpc',
        './text',
        './details',
        './search',
        './association',
        './entity',
        './certificate'],
    function(builder, IPA, $, phases, reg, rpc, text) {

var exp = IPA.host = {};

var make_spec = function() {
return {
    name: 'host',
    policies: [
        IPA.search_facet_update_policy,
        IPA.details_facet_update_policy,
        {
            $factory: IPA.cert.cert_update_policy,
            source_facet: 'details',
            dest_entity: 'cert',
            dest_facet: 'details'
        },
        {
            $factory: IPA.cert.cert_update_policy,
            source_facet: 'details',
            dest_entity: 'cert',
            dest_facet: 'search'
        }
    ],
    facets: [
        {
            $type: 'search',
            columns: [
                'fqdn',
                'description',
                {
                    name: 'has_keytab',
                    label: '@i18n:objects.host.enrolled',
                    formatter: 'boolean'
                }
            ],
            actions: [
                'select',
                {
                    $type: 'automember_rebuild',
                    name: 'automember_rebuild',
                    label: '@i18n:actions.automember_rebuild'
                }
            ],
            header_actions: ['automember_rebuild']
        },
        {
            $type: 'details',
            $factory: IPA.host.details_facet,
            sections: [
                {
                    name: 'details',
                    fields: [
                        {
                            $type: 'host_dnsrecord_entity_link',
                            name: 'fqdn',
                            other_entity: 'dnsrecord'
                        },
                        {
                            $type: 'krb_principal_multivalued',
                            name: 'krbprincipalname',
                            item_name: 'principal',
                            child_spec: {
                                $type: 'non_editable_row',
                                data_name: 'krb-principal'
                            }
                        },
                        {
                            $type: 'textarea',
                            name: 'description'
                        },
                        'userclass',
                        'l',
                        'nshostlocation',
                        'nshardwareplatform',
                        'nsosversion',
                        {
                            $type: 'sshkeys',
                            name: 'ipasshpubkey',
                            label: '@i18n:objects.sshkeystore.keys'
                        },
                        {
                            $type: 'multivalued',
                            name: 'macaddress',
                            flags: ['w_if_no_aci']
                        },
                        {
                            $type: 'checkboxes',
                            label: '@i18n:authtype.auth_indicators',
                            name: 'krbprincipalauthind',
                            options: [
                                {
                                    label: '@i18n:authtype.type_otp',
                                    value: 'otp'
                                },
                                {
                                    label: '@i18n:authtype.type_radius',
                                    value: 'radius'
                                },
                                {
                                    label: '@i18n:authtype.type_pkinit',
                                    value: 'pkinit'
                                },
                                {
                                    label: '@i18n:authtype.type_hardened',
                                    value: 'hardened'
                                }
                            ],
                            tooltip: {
                                title: '@mc-opt:host_add:krbprincipalauthind:doc'
                            }
                        },
                        {
                            name: 'ipakrbokasdelegate',
                            $type: 'checkbox',
                            acl_param: 'krbticketflags',
                            flags: ['w_if_no_aci']
                        },
                        {
                            name: 'ipakrboktoauthasdelegate',
                            $type: 'checkbox',
                            acl_param: 'krbticketflags'
                        },
                        {
                            name: 'ipaassignedidview',
                            $type: 'link',
                            label: '@i18n:objects.idview.ipaassignedidview',
                            other_entity: 'idview'
                        }
                    ]
                },
                {
                    name: 'enrollment',
                    fields: [
                        {
                            $factory: IPA.host_keytab_widget,
                            name: 'has_keytab',
                            label: '@i18n:objects.host.keytab'
                        },
                        {
                            $type: 'host_password',
                            name: 'has_password',
                            label: '@i18n:objects.host.password'
                        }
                    ]
                },
                {
                    name: 'certificate',
                    fields: [
                        {
                            $type: 'certs',
                            adapter: {
                                $type: 'object_adapter',
                                result_index: 1
                            },
                            label: '@i18n:objects.cert.certificates'
                        }
                    ]
                },
                {
                    $factory: IPA.section,
                    name: 'divider',
                    layout_css_class: 'col-sm-12',
                    fields: []
                },
                {
                    name: 'read',
                    label: '@i18n:keytab.allowed_to_retrieve',
                    $factory: IPA.section,
                    fields: [
                        {
                            $type: 'association_table',
                            id: 'host_ipaallowedtoperform_read_keys_user',
                            name: 'ipaallowedtoperform_read_keys_user',
                            flags: ['w_if_no_aci'],
                            add_method: 'allow_retrieve_keytab',
                            remove_method: 'disallow_retrieve_keytab',
                            add_title: '@i18n:keytab.add_users_retrieve',
                            remove_title: '@i18n:keytab.remove_users_retrieve',
                            columns: [
                                {
                                    name: 'ipaallowedtoperform_read_keys_user',
                                    label: '@mo:user.label_singular',
                                    link: true
                                }
                            ]
                        },
                        {
                            $type: 'association_table',
                            id: 'host_ipaallowedtoperform_read_keys_group',
                            name: 'ipaallowedtoperform_read_keys_group',
                            flags: ['w_if_no_aci'],
                            add_method: 'allow_retrieve_keytab',
                            remove_method: 'disallow_retrieve_keytab',
                            add_title: '@i18n:keytab.add_groups_retrieve',
                            remove_title: '@i18n:keytab.remove_groups_retrieve',
                            columns: [
                                {
                                    name: 'ipaallowedtoperform_read_keys_group',
                                    label: '@mo:group.label_singular',
                                    link: true
                                }
                            ]
                        },
                        {
                            $type: 'association_table',
                            id: 'service_ipaallowedtoperform_read_keys_host',
                            name: 'ipaallowedtoperform_read_keys_host',
                            flags: ['w_if_no_aci'],
                            add_method: 'allow_retrieve_keytab',
                            remove_method: 'disallow_retrieve_keytab',
                            add_title: '@i18n:keytab.add_hosts_retrieve',
                            remove_title: '@i18n:keytab.remove_hosts_retrieve',
                            columns: [
                                {
                                    name: 'ipaallowedtoperform_read_keys_host',
                                    label: '@mo:host.label_singular',
                                    link: true
                                }
                            ]
                        },
                        {
                            $type: 'association_table',
                            id: 'service_ipaallowedtoperform_read_keys_hostgroup',
                            name: 'ipaallowedtoperform_read_keys_hostgroup',
                            flags: ['w_if_no_aci'],
                            add_method: 'allow_retrieve_keytab',
                            remove_method: 'disallow_retrieve_keytab',
                            add_title: '@i18n:keytab.add_hostgroups_retrieve',
                            remove_title: '@i18n:keytab.remove_hostgroups_retrieve',
                            columns: [
                                {
                                    name: 'ipaallowedtoperform_read_keys_hostgroup',
                                    label: '@mo:hostgroup.label_singular',
                                    link: true
                                }
                            ]
                        }
                    ]
                },
                {
                    name: 'write',
                    label: '@i18n:keytab.allowed_to_create',
                    $factory: IPA.section,
                    fields: [
                        {
                            $type: 'association_table',
                            id: 'host_ipaallowedtoperform_write_keys_user',
                            name: 'ipaallowedtoperform_write_keys_user',
                            flags: ['w_if_no_aci'],
                            add_method: 'allow_create_keytab',
                            remove_method: 'disallow_create_keytab',
                            add_title: '@i18n:keytab.add_users_create',
                            remove_title: '@i18n:keytab.remove_users_create',
                            columns: [
                                {
                                    name: 'ipaallowedtoperform_write_keys_user',
                                    label: '@mo:user.label_singular',
                                    link: true
                                }
                            ]
                        },
                        {
                            $type: 'association_table',
                            id: 'host_ipaallowedtoperform_write_keys_group',
                            name: 'ipaallowedtoperform_write_keys_group',
                            flags: ['w_if_no_aci'],
                            add_method: 'allow_create_keytab',
                            remove_method: 'disallow_create_keytab',
                            add_title: '@i18n:keytab.add_groups_create',
                            remove_title: '@i18n:keytab.remove_groups_create',
                            columns: [
                                {
                                    name: 'ipaallowedtoperform_write_keys_group',
                                    label: '@mo:group.label_singular',
                                    link: true
                                }
                            ]
                        },
                        {
                            $type: 'association_table',
                            id: 'service_ipaallowedtoperform_write_keys_host',
                            name: 'ipaallowedtoperform_write_keys_host',
                            flags: ['w_if_no_aci'],
                            add_method: 'allow_create_keytab',
                            remove_method: 'disallow_create_keytab',
                            add_title: '@i18n:keytab.add_hosts_create',
                            remove_title: '@i18n:keytab.remove_hosts_create',
                            columns: [
                                {
                                    name: 'ipaallowedtoperform_write_keys_host',
                                    label: '@mo:host.label_singular',
                                    link: true
                                }
                            ]
                        },
                        {
                            $type: 'association_table',
                            id: 'service_ipaallowedtoperform_write_keys_hostgroup',
                            name: 'ipaallowedtoperform_write_keys_hostgroup',
                            flags: ['w_if_no_aci'],
                            add_method: 'allow_create_keytab',
                            remove_method: 'disallow_create_keytab',
                            add_title: '@i18n:keytab.add_hostgroups_create',
                            remove_title: '@i18n:keytab.remove_hostgroups_create',
                            columns: [
                                {
                                    name: 'ipaallowedtoperform_write_keys_hostgroup',
                                    label: '@mo:hostgroup.label_singular',
                                    link: true
                                }
                            ]
                        }
                    ]
                }
            ],
            actions: [
                'select',
                {
                    $type: 'automember_rebuild',
                    name: 'automember_rebuild',
                    label: '@i18n:actions.automember_rebuild'
                },
                'host_unprovision',
                {
                    $type: 'password',
                    name: 'set_otp',
                    label: '@i18n:objects.host.password_set_title',
                    dialog: {
                        title: '@i18n:objects.host.password_set_title',
                        confirm_button_label: '@i18n:objects.host.password_set_button',
                        password_name: 'userpassword',
                        success_message: '@i18n:objects.host.password_set_success'
                    },
                    enable_cond: ['userpassword_w'],
                    hide_cond: ['has_password']
                },
                {
                    $type: 'password',
                    name: 'reset_otp',
                    label: '@i18n:objects.host.password_reset_title',
                    dialog: {
                        title: '@i18n:objects.host.password_reset_title',
                        confirm_button_label: '@i18n:objects.host.password_reset_button',
                        password_name: 'userpassword',
                        success_message: '@i18n:objects.host.password_set_success'
                    },
                    enable_cond: ['userpassword_w'],
                    show_cond: ['has_password']
                },
                {
                    $type: 'cert_request',
                    title: '@i18n:objects.cert.issue_for_host'
                }
            ],
            header_actions: ['automember_rebuild', 'unprovision', 'set_otp', 'reset_otp',
                'request_cert'],
            state: {
                evaluators: [
                    {
                        $factory: IPA.host.has_password_evaluator,
                        param: 'has_password',
                        adapter: { $type: 'batch', result_index: 0 }
                    },
                    {
                        $factory: IPA.has_keytab_evaluator,
                        param: 'has_keytab',
                        adapter: { $type: 'batch', result_index: 0 }
                    },
                    IPA.host.userpassword_acl_evaluator,
                    IPA.host.krbprincipalkey_acl_evaluator,
                    IPA.cert.certificate_evaluator
                ]
            },
            policies: [
                IPA.host.enrollment_policy,
                IPA.host.certificate_policy
            ]
        },
        {
            $type: 'association',
            name: 'managedby_host',
            add_method: 'add_managedby',
            add_title: '@i18n:objects.host.add_hosts_managing',
            remove_method: 'remove_managedby',
            remove_title: '@i18n:objects.host.remove_hosts_managing'
        },
        {
            $type: 'association',
            name: 'memberof_hostgroup',
            associator: IPA.serial_associator,
            add_title: '@i18n:objects.host.add_into_groups',
            remove_title: '@i18n:objects.host.remove_from_groups'
        },
        {
            $type: 'association',
            name: 'memberof_netgroup',
            associator: IPA.serial_associator,
            add_title: '@i18n:objects.host.add_into_netgroups',
            remove_title: '@i18n:objects.host.remove_from_netgroups'
        },
        {
            $type: 'association',
            name: 'memberof_role',
            associator: IPA.serial_associator,
            add_title: '@i18n:objects.host.add_into_roles',
            remove_title: '@i18n:objects.host.remove_from_roles'
        },
        {
            $type: 'association',
            name: 'memberof_hbacrule',
            associator: IPA.serial_associator,
            add_method: 'add_host',
            add_title: '@i18n:objects.host.add_into_hbac',
            remove_method: 'remove_host',
            remove_title: '@i18n:objects.host.remove_from_hbac'
        },
        {
            $type: 'association',
            name: 'memberof_sudorule',
            associator: IPA.serial_associator,
            add_method: 'add_host',
            add_title: '@i18n:objects.host.add_into_sudo',
            remove_method: 'remove_host',
            remove_title: '@i18n:objects.host.remove_from_sudo'
        }
    ],
    standard_association_facets: true,
    adder_dialog: {
        title: '@i18n:objects.host.add',
        $factory: IPA.host_adder_dialog,
        height: 300,
        sections: [
            {
                $factory: IPA.composite_widget,
                name: 'fqdn',
                fields: [
                    {
                        $type: 'host_fqdn',
                        name: 'fqdn',
                        required: true
                    }
                ]
            },
            {
                name: 'other',
                fields: [
                    'userclass',
                    {
                        name: 'ip_address',
                        validators: [ 'ip_address' ],
                        metadata: '@mc-opt:host_add:ip_address'
                    },
                    {
                        $type: 'force_host_add_checkbox',
                        name: 'force',
                        metadata: '@mc-opt:host_add:force'
                    },
                    {
                        $type: 'checkbox',
                        name: 'random',
                        label: '@i18n:objects.host.generate_otp',
                        title: '@i18n:objects.host.generate_otp'
                    }
                ]
            }
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.host.remove',
        $factory: IPA.host_deleter_dialog
    }
};};

IPA.host.details_facet = function(spec, no_init) {

    var that = IPA.details_facet(spec, true);
    that.certificate_loaded = IPA.observer();
    that.certificate_updated = IPA.observer();

    that.create_refresh_command = function() {
        var pkey = that.get_pkey();

        var batch = rpc.batch_command({
            name: 'host_details_refresh'
        });

        var host_command = that.details_facet_create_refresh_command();
        batch.add_command(host_command);

        var certificates = rpc.command({
            entity: 'cert',
            method: 'find',
            retry: false,
            options: {
                host: [ pkey ],
                sizelimit: 0,
                all: true
            }
        });

        batch.add_command(certificates);

        return batch;

    };

    that.get_refresh_command_name = function() {
        return that.entity.name+'_show_'+that.get_pkey();
    };

    that.update_on_success = function(data, text_status, xhr) {
        that.on_update.notify();
        that.nofify_update_success();
        that.refresh();
    };

    if (!no_init) that.init_details_facet();

    return that;
};

IPA.host_fqdn_widget = function(spec) {

    spec = spec || {};

    spec.widgets = [
        {
            $type: 'text',
            name: 'hostname',
            label: '@i18n:objects.service.host',
            required: true
        },
        {
            $type: 'dnszone_select',
            name: 'dnszone',
            label: '@mo:dnszone.label_singular',
            editable: true,
            empty_option: false,
            required: true,
            searchable: true
        }
    ];

    var that = IPA.composite_widget(spec);

    that.create = function(container) {
        that.container = container;
        container.addClass('col-sm-12');

        var hostname = that.widgets.get_widget('hostname');
        var dnszone = that.widgets.get_widget('dnszone');

        var layout = IPA.fluid_layout({
            cont_cls: 'row fluid-row',
            group_cls: 'col-sm-6 form-group',
            widget_cls: 'controls',
            label_cls: 'control-label'
        });

        var html = layout.create([hostname, dnszone]);
        that.container.append(html);

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

    that.save = function() {

        var hw = that.widgets.get_widget('hostname');
        var dw = that.widgets.get_widget('dnszone');

        var hostname = hw.save()[0];
        var dnszone = dw.save()[0];

        var fqdn = hostname && dnszone ? [ hostname+'.'+dnszone ] : [];
        return fqdn;

    };

    return that;
};

IPA.host_fqdn_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);


    that.has_value = function(widget) {

        var value = widget.save();
        var has_value = !!value.length && value[0] !== '';
        return has_value;
    };

    that.validate_required = function() {

        var valid = true;

        if (!that.has_value(that.hostname_widget)) {
            that.hostname_widget.show_error(text.get('@i18n:widget.validation.required'));
            that.valid = valid = false;
        }

        if (!that.has_value(that.dns_zone_widget)) {
            that.dns_zone_widget.show_error(text.get('@i18n:widget.validation.required'));
            that.valid = valid = false;
        }

        return valid;
    };

    that.hide_error = function() {
        if (that.has_value(that.hostname_widget)) {
            that.hostname_widget.hide_error();
        }
        if (that.has_value(that.dns_zone_widget)) {
            that.dns_zone_widget.hide_error();
        }
    };

    that.reset = function() {

        that.hostname_widget.update([]);
        that.dns_zone_widget.update([]);
    };

    that.widgets_created = function() {

        that.widget = that.container.widgets.get_widget(that.widget_name);
        that.hostname_widget = that.widget.widgets.get_widget('hostname');
        that.dns_zone_widget = that.widget.widgets.get_widget('dnszone');
        that.hostname_widget.value_changed.attach(that.child_value_changed);
        that.dns_zone_widget.value_changed.attach(that.child_value_changed);
    };

    that.child_value_changed = function() {
        that.set_value(that.widget.save());
    };

    return that;
};

IPA.host_adder_dialog = function(spec) {

    spec = spec || {};
    spec.retry = spec.retry !== undefined ? spec.retry : false;

    if (!IPA.dns_enabled) {

        //When server is installed without DNS support, a use of host_fqdn_widget
        //is bad because there are no DNS zones. IP address field is useless as
        //well. Special section and IP address field should be removed and normal
        //fqdn textbox has to be added.
        spec.sections.shift();
        spec.sections[0].fields.shift();
        spec.sections[0].fields.unshift('fqdn');
        delete spec.height;
    }

    var that = IPA.entity_adder_dialog(spec);

    that.init = function() {
        that.added.attach(that.handle_random_otp);
    };

    that.create_content = function() {
        that.entity_adder_dialog_create_content();
        that.container.addClass('host-adder-dialog');
    };

    that.create_result_dialog = function() {
        spec = {
            title: text.get('@i18n:dialogs.result'),
            sections: [
                {
                    show_header: false,
                    fields: [
                        {
                            $type: 'text',
                            name: 'randompassword',
                            label: '@i18n:objects.host.generated_otp',
                            read_only: true
                        }
                    ]
                }
            ]
        };

        var dialog = IPA.dialog(spec);

        dialog.create_button({
            name: 'close',
            label: text.get('@i18n:buttons.close'),
            click: function() {
                dialog.close();
            }
        });


        return dialog;
    };

    that.handle_random_otp = function(data, method) {
        var dialog = that.create_result_dialog();
        var random_passwd = that.get_field('random').get_value()[0];

        if ((method === 'add' || method === 'add_and_edit') && random_passwd) {
            var field = dialog.get_field('randompassword');
            dialog.open();
            field.load(data);
        }
        else if (method === 'add_and_add_another' && random_passwd) {
            var message = text.get('@i18n:objects.host.generated_otp') +
                ": " + data.result.result.randompassword;
            that.show_message(message);
        }
    };

    that.on_error = rpc.create_4304_error_handler(that);

    that.init();

    return that;
};

IPA.host_deleter_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.search_deleter_dialog(spec);

    that.create_content = function() {

        that.deleter_dialog_create_content();

        var metadata = IPA.get_command_option('host_del', 'updatedns');

        var updatedns = IPA.standalone_option({
            type: 'checkbox',
            name: 'updatedns',
            title: metadata.doc
        }, that.container, metadata.doc);

        that.updatedns = updatedns[0];
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
        return rpc.command({
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

IPA.host_dnsrecord_entity_link_widget = function(spec) {

    var that = IPA.link_widget(spec);

    that.other_pkeys = function(){
        var pkey = that.facet.get_pkey();
        var first_dot = pkey.search(/\./);
        var pkeys = [];
        pkeys[1] = pkey.substring(0,first_dot);
        pkeys[0] = pkey.substring(first_dot+1);
        return pkeys;
    };

    return that;
};

IPA.force_host_add_checkbox_widget = function(spec) {
    var metadata = IPA.get_command_option('host_add', spec.name);
    spec.label = metadata.label;
    spec.title = metadata.doc;
    return IPA.checkbox_widget(spec);
};

IPA.host.enrollment_policy = function(spec) {

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

        that.missing_el = $('<label/>', {
            name: 'missing',
            style: 'display: none;'
        }).appendTo(container);

        $('<i/>', {
            'class': 'fa fa-warning'
        }).appendTo(that.missing_el);

        that.missing_el.append(' ');

        that.missing_el.append(text.get('@i18n:objects.host.keytab_missing'));

        that.present_el = $('<label/>', {
            name: 'present',
            style: 'display: none;'
        }).appendTo(container);

        $('<i/>', {
            'class': 'fa fa-check'
        }).appendTo(that.present_el);

        that.present_el.append(' ');

        that.present_el.append(text.get('@i18n:objects.host.keytab_present'));
    };

    that.update = function(values) {
        set_status(values[0] ? 'present' : 'missing');
        that.on_value_changed(values);
    };

    that.clear = function() {
        that.present_el.css('display', 'none');
        that.missing_el.css('display', 'none');
    };

    function set_status(status) {
        that.present_el.css('display', status == 'present' ? '' : 'none');
        that.missing_el.css('display', status == 'missing' ? '' : 'none');
    }

    return that;
};

IPA.host_unprovision_dialog = function(spec) {

    spec.title = spec.title || '@i18n:objects.host.unprovision_title';

    spec = spec || {};

    var that = IPA.dialog(spec);
    that.facet = spec.facet;

    that.create_content = function() {
        that.container.append(text.get('@i18n:objects.host.unprovision_confirmation'));
    };

    that.create_buttons = function() {

        that.create_button({
            name: 'unprovision',
            label: '@i18n:objects.host.unprovision',
            click: function() {
                that.unprovision(
                    function(data, text_status, xhr) {
                        that.facet.refresh();
                        that.close();
                        IPA.notify_success('@i18n:objects.host.unprovisioned');
                    },
                    function(xhr, text_status, error_thrown) {
                        that.close();
                    }
                );
            }
        });

        that.create_button({
            name: 'cancel',
            label: '@i18n:buttons.cancel',
            click: function() {
                that.close();
            }
        });
    };

    that.unprovision = function(on_success, on_error) {

        var pkey = that.facet.get_pkeys();

        var command = rpc.command({
            name: that.entity.name+'_disable_'+pkey,
            entity: that.entity.name,
            method: 'disable',
            args: pkey,
            on_success: on_success,
            on_error: on_error
        });

        command.execute();
    };

    that.create_buttons();

    return that;
};

IPA.host.unprovision_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'unprovision';
    spec.label = spec.label || '@i18n:objects.host.unprovision';
    spec.enable_cond = spec.enable_cond || ['has_keytab', 'krbprincipalkey_w'];

    var that = IPA.action(spec);

    that.execute_action = function(facet) {

        var dialog = IPA.host_unprovision_dialog({
            entity: facet.entity,
            facet: facet
        });

        dialog.open();
    };

    return that;
};

IPA.host.krbprincipalkey_acl_evaluator = function(spec) {

    spec.name = spec.name || 'unprovision_acl_evaluator';
    spec.attribute = spec.attribute || 'krbprincipalkey';

    var that = IPA.acl_state_evaluator(spec);
    return that;
};

IPA.host_password_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.create = function(container) {

        that.widget_create(container);

        that.missing_el = $('<label/>', {
            name: 'missing'
        }).appendTo(container);

        $('<i/>', {
            'class': 'fa fa-warning'
        }).appendTo(that.missing_el);

        that.missing_el.append(' ');

        that.missing_el.append(text.get('@i18n:objects.host.password_missing'));

        that.present_el = $('<label/>', {
            name: 'present',
            style: 'display: none;'
        }).appendTo(container);

        $('<i/>', {
            'class': 'fa fa-check'
        }).appendTo(that.present_el);

        that.present_el.append(' ');

        that.present_el.append(text.get('@i18n:objects.host.password_present'));
    };

    that.update = function(values) {
        set_status(values[0] ? 'present' : 'missing');
        that.on_value_changed(values);
    };

    that.clear = function() {
        that.missing_el.css('display', 'none');
        that.present_el.css('display', 'none');
    };

    function set_status(status) {

        that.status = status;

        if (status == 'missing') {
            that.missing_el.css('display', '');
            that.present_el.css('display', 'none');
        } else {
            that.missing_el.css('display', 'none');
            that.present_el.css('display', '');
        }
    }

    return that;
};

IPA.host.userpassword_acl_evaluator = function(spec) {

    spec.name = spec.name || 'userpassword_acl_evaluator';
    spec.attribute = spec.attribute || 'userpassword';

    var that = IPA.acl_state_evaluator(spec);
    return that;
};

IPA.host.has_password_evaluator = function(spec) {

    spec.name = spec.name || 'has_password_evaluator';
    spec.attribute = spec.attribute || 'has_password';
    spec.value = spec.value || [true];
    spec.representation = spec.representation || 'has_password';
    spec.param = spec.param || 'has_password';
    spec.adapter = spec.adapter || { $type: 'adapter' };

    var that = IPA.value_state_evaluator(spec);

    return that;
};

IPA.host.certificate_policy = function(spec) {

    spec = spec || {};

    spec.get_pkey = spec.get_pkey || function(result) {
        var values = result.fqdn;
        return values ? values[0] : null;
    };

    spec.get_name = spec.get_name || function(result) {
        var values = result.fqdn;
        return values ? values[0] : null;
    };

    spec.get_principal = spec.get_principal || function(result) {
        var values = result.krbprincipalname;
        return values ? values[0] : null;
    };

    spec.get_cn = spec.get_cn || spec.get_name;

    spec.get_cn_name = spec.get_cn_name || function(result) {
        return "hostname";
    };

    var that = IPA.cert.load_policy(spec);
    return that;
};

exp.entity_spec = make_spec();
exp.register = function() {
    var e = reg.entity;
    var w = reg.widget;
    var f = reg.field;
    var a = reg.action;

    e.register({type: 'host', spec: exp.entity_spec});
    f.register('host_fqdn', IPA.host_fqdn_field);
    w.register('host_fqdn', IPA.host_fqdn_widget);
    f.register('dnszone_select', IPA.field);
    w.register('dnszone_select', IPA.dnszone_select_widget);
    f.register('host_dnsrecord_entity_link', IPA.field);
    w.register('host_dnsrecord_entity_link', IPA.host_dnsrecord_entity_link_widget);
    f.register('force_host_add_checkbox', IPA.checkbox_field);
    w.register('force_host_add_checkbox', IPA.force_host_add_checkbox_widget);
    f.register('host_password', IPA.field);
    w.register('host_password', IPA.host_password_widget);

    a.register('host_unprovision', exp.unprovision_action);
};
phases.on('registration', exp.register);

return exp;
});
