/*jsl:import ipa.js */
/*jsl:import search.js */
/*jsl:import net.js */

/*  Authors:
 *    Adam Young <ayoung@redhat.com>
 *    Petr Vobornik <pvoborni@redhat.com>
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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js,
 *           net.js, widget.js */

IPA.dns = {
    zone_permission_name: 'Manage DNS zone ${dnszone}'
};

IPA.dns.config_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {

        if (!IPA.dns_enabled) {
            throw {
                expected: true
            };
        }

        that.entity_init();

        that.builder.details_facet({
            title: IPA.metadata.objects.config.label,
            sections: [
                {
                    name: 'options',
                    label: IPA.messages.objects.dnsconfig.options,
                    fields: [
                        {
                            type: 'checkbox',
                            name: 'idnsallowsyncptr'
                        },
                        {
                            type: 'multivalued',
                            name: 'idnsforwarders',
                            validators: [IPA.dnsforwarder_validator()]
                        },
                        {
                            type: 'radio',
                            name: 'idnsforwardpolicy',
                            default_value: 'first',
                            options: [
                                {
                                    value: 'first',
                                    label: IPA.messages.objects.dnsconfig.forward_first
                                },
                                {
                                    value: 'only',
                                    label: IPA.messages.objects.dnsconfig.forward_only
                                }
                            ]
                        },
                        'idnszonerefresh'
                    ]
                }
            ],
            needs_update: true
        });
    };

    return that;
};

IPA.dns.zone_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {

        if (!IPA.dns_enabled) {
            throw {
                expected: true
            };
        }

        that.entity_init();

        that.builder.facet_groups([ 'dnsrecord', 'settings' ]).
        search_facet({
            row_enabled_attribute: 'idnszoneactive',
            title: IPA.metadata.objects.dnszone.label,
            columns: [
                'idnsname',
                {
                    name: 'idnszoneactive',
                    label: IPA.messages.status.label,
                    formatter: IPA.boolean_status_formatter()
                }
            ],
            actions: [
                IPA.batch_disable_action,
                IPA.batch_enable_action
            ],
            control_buttons: [
                {
                    name: 'disable',
                    label: IPA.messages.buttons.disable,
                    icon: 'disabled-icon'
                },
                {
                    name: 'enable',
                    label: IPA.messages.buttons.enable,
                    icon: 'enabled-icon'
                }
            ]
        }).
        details_facet({
            factory: IPA.dnszone_details_facet,
            command_mode: 'info',
            sections: [
            {
                name: 'identity',
                fields: [
                    'idnsname',
                    'idnssoamname',
                    'idnssoarname',
                    'idnssoaserial',
                    'idnssoarefresh',
                    'idnssoaretry',
                    'idnssoaexpire',
                    'idnssoaminimum',
                    'dnsttl',
                    {
                        type: 'combobox',
                        name: 'dnsclass',
                        options: [
                            'IN', 'CS', 'CH', 'HS'
                        ]
                    },
                    {
                        type: 'radio',
                        name: 'idnsallowdynupdate',
                        options: [
                            { value: 'TRUE', label: IPA.get_message('true') },
                            { value: 'FALSE', label: IPA.get_message('false') }
                        ]
                    },
                    {
                        type: 'textarea',
                        name: 'idnsupdatepolicy'
                    },
                    {
                        type: 'netaddr',
                        name: 'idnsallowquery',
                        validators: [
                            IPA.network_validator({
                                specials: ['any', 'none', 'localhost', 'localnets'],
                                allow_negation: true,
                                allow_host_address: true
                        })]
                    },
                    {
                        type: 'netaddr',
                        name: 'idnsallowtransfer',
                        validators: [
                            IPA.network_validator({
                                specials: ['any', 'none', 'localhost', 'localnets'],
                                allow_negation: true,
                                allow_host_address: true
                        })]
                    },
                    {
                        type: 'multivalued',
                        name: 'idnsforwarders',
                        validators: [IPA.dnsforwarder_validator()]
                    },
                    {
                        type: 'radio',
                        name: 'idnsforwardpolicy',
                        default_value: 'first',
                        options: [
                            {
                                value: 'first',
                                label: IPA.messages.objects.dnsconfig.forward_first
                            },
                            {
                                value: 'only',
                                label: IPA.messages.objects.dnsconfig.forward_only
                            }
                        ]
                    },
                    {
                        type: 'checkbox',
                        name: 'idnsallowsyncptr'
                    }
                ]
            }],
            actions: [
                IPA.select_action,
                IPA.enable_action,
                IPA.disable_action,
                IPA.delete_action,
                IPA.dns.add_permission_action,
                IPA.dns.remove_permission_action
            ],
            header_actions: ['select_action', 'enable', 'disable', 'delete',
                'add_permission', 'remove_permission'],
            state: {
                evaluators: [
                    {
                        factory: IPA.enable_state_evaluator,
                        field: 'idnszoneactive'
                    },
                    {
                        factory: IPA.acl_state_evaluator,
                        attribute: 'managedby'
                    },
                    IPA.dns.zone_has_permission_evaluator
                ],
                summary_conditions: [
                    IPA.enabled_summary_cond(),
                    IPA.disabled_summary_cond()
                ]
            }
        }).
        nested_search_facet({
            factory: IPA.dns.record_search_facet,
            facet_group: 'dnsrecord',
            nested_entity : 'dnsrecord',
            name: 'records',
            deleter_dialog: IPA.dns.record_search_deleter_dialog,
            title: IPA.metadata.objects.dnszone.label_singular,
            label: IPA.metadata.objects.dnsrecord.label,
            tab_label: IPA.metadata.objects.dnsrecord.label,
            columns: [
                {
                    name: 'idnsname',
                    label: IPA.get_entity_param('dnsrecord', 'idnsname').label,
                    primary_key: true
                },
                {
                    name: 'type',
                    label: IPA.messages.objects.dnsrecord.type
                },
                {
                    name: 'data',
                    label: IPA.messages.objects.dnsrecord.data
                }
            ]
        }).
        standard_association_facets().
        adder_dialog({
            factory: IPA.dnszone_adder_dialog,
            height: 300,
            sections: [
                {
                    factory: IPA.dnszone_name_section,
                    name: 'name',
                    fields: [
                        {
                            type: 'dnszone_name',
                            name: 'idnsname',
                            required: false,
                            radio_name: 'dnszone_name_type'
                        },
                        {
                            type: 'dnszone_name',
                            name: 'name_from_ip',
                            radio_name: 'dnszone_name_type',
                            validators: [IPA.network_validator()]
                        }
                    ]
                },
                {
                    name: 'other',
                    fields: [
                        'idnssoamname',
                        {
                            name: 'idnssoarname',
                            required: false
                        },
                        {
                            type: 'force_dnszone_add_checkbox',
                            name: 'force',
                            metadata: IPA.get_command_option('dnszone_add', 'force')
                        }
                    ]
                }
            ],
            policies: [
                IPA.add_dns_zone_name_policy()
            ]
        });
    };

    return that;
};

IPA.dnszone_details_facet = function(spec, no_init) {

    spec = spec || {};

    var that = IPA.details_facet(spec, true);
    that.permission_load = IPA.observer();
    that.permission_status = 'unknown'; // [unknown, set, none]

    that.refresh_on_success = function(data, text_status, xhr) {
        // do not load data from batch

        that.show_content();
    };

    that.create_refresh_command = function() {

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');

        var batch = IPA.batch_command({
            name: 'dnszone_details_refresh'
        });

        var dnszone_command = that.details_facet_create_refresh_command();

        dnszone_command.on_success = function(data, text_status, xhr) {
            // create data that mimics dnszone-show output
            var dnszone_data = {};
            dnszone_data.result = data;
            that.load(dnszone_data);
        };

        batch.add_command(dnszone_command);

        var permission_name = IPA.dns.zone_permission_name.replace('${dnszone}', pkey);

        var permission_command = IPA.command({
            entity: 'permission',
            method: 'show',
            args: [permission_name],
            options: {},
            retry: false
        });

        permission_command.on_success = function(data, text_status, xhr) {
            that.permission_status = 'set';
            that.permission_load.notify([that.permission_status], that);
        };

        permission_command.on_error = function(xhr, text_status, error_thrown) {
            if (error_thrown && error_thrown.code === 4001) {
                //NotFound error
                that.permission_status = 'none';
            } else {
                that.permission_status = 'unknown';
            }

            that.permission_load.notify([that.permission_status], that);
        };

        batch.add_command(permission_command);

        return batch;
    };

    that.update_on_success = function(data, text_status, xhr) {
        that.refresh();
        that.on_update.notify();
        that.nofify_update_success();
    };

    that.update_on_error = function(xhr, text_status, error_thrown) {
        that.refresh();
    };

    if (!no_init) that.init_details_facet();

    return that;
};

IPA.dnszone_name_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_table_section(spec);

    that.create = function(container) {
        that.container = container;

        that.message_container = $('<div/>', {
            style: 'display: none',
            'class': 'dialog-message ui-state-highlight ui-corner-all'
        }).appendTo(that.container);

        var table = $('<table/>', {
            'class': 'section-table'
        }).appendTo(that.container);

        var idnsname = that.widgets.get_widget('idnsname');

        var tr = $('<tr/>').appendTo(table);

        var td = $('<td/>', {
            'class': 'section-cell-label',
            title: idnsname.label
        }).appendTo(tr);

        var label = $('<label/>', {
            name: 'idnsname',
            'class': 'field-label',
            'for': idnsname.radio_id
        }).appendTo(td);

        idnsname.create_radio(label);

        label.append(idnsname.label+':');

        idnsname.create_required(td);

        td = $('<td/>', {
            'class': 'section-cell-field',
            title: idnsname.label
        }).appendTo(tr);

        var span = $('<span/>', {
            name: 'idnsname',
            'class': 'field'
        }).appendTo(td);

        idnsname.create(span);

        var idnsname_input = $('input', span);

        var name_from_ip = that.widgets.get_widget('name_from_ip');

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>', {
            'class': 'section-cell-label',
            title: name_from_ip.label
        }).appendTo(tr);

        label = $('<label/>', {
            name: 'name_from_ip',
            'class': 'field-label',
            'for': name_from_ip.radio_id
        }).appendTo(td);

        name_from_ip.create_radio(label);

        label.append(name_from_ip.label+':');

        name_from_ip.create_required(td);

        td = $('<td/>', {
            'class': 'section-cell-field',
            title: name_from_ip.label
        }).appendTo(tr);

        span = $('<span/>', {
            name: 'name_from_ip',
            'class': 'field'
        }).appendTo(td);

        name_from_ip.create(span);

        idnsname.radio.click();
    };


    return that;
};

IPA.add_dns_zone_name_policy = function() {

    var that = IPA.facet_policy();

    that.init = function() {
        var idnsname_w = this.container.widgets.get_widget('name.idnsname');
        var name_from_ip_w = this.container.widgets.get_widget('name.name_from_ip');

        var idnsname_f = this.container.fields.get_field('idnsname');
        var name_from_ip_f = this.container.fields.get_field('name_from_ip');

        idnsname_w.radio_clicked.attach(function() {
            idnsname_w.input.prop('disabled', false);
            name_from_ip_w.input.prop('disabled', true);

            idnsname_f.set_required(true);
            name_from_ip_f.set_required(false);

            name_from_ip_f.reset();
        });

        name_from_ip_w.radio_clicked.attach(function() {
            idnsname_w.input.prop('disabled', true);
            name_from_ip_w.input.prop('disabled', false);

            idnsname_f.set_required(false);
            name_from_ip_f.set_required(true);

            idnsname_f.reset();
        });
    };

    return that;
};

IPA.dnszone_name_widget = function(spec) {

    spec = spec || {};

    var that = IPA.text_widget(spec);

    that.radio_name = spec.radio_name;
    that.radio_clicked = IPA.observer();
    that.text_save = that.save;
    that.radio_id = IPA.html_util.get_next_id(that.radio_name);

    that.save = function() {

        var values = [];

        if (that.radio.is(':checked')) {
            values = that.text_save();
        }
        return values;
    };

    that.create_radio = function(container) {

        that.radio = $('<input/>', {
            type: 'radio',
            id: that.radio_id,
            name: that.radio_name,
            value: that.name,
            click: function() {
                that.radio_clicked.notify([], that);
            }
        }).appendTo(container);
    };

    return that;
};

IPA.widget_factories['dnszone_name'] = IPA.dnszone_name_widget;

IPA.force_dnszone_add_checkbox_widget = function(spec) {
    var metadata = IPA.get_command_option('dnszone_add', spec.name);
    spec.label = metadata.label;
    spec.tooltip = metadata.doc;
    return IPA.checkbox_widget(spec);
};

IPA.widget_factories['force_dnszone_add_checkbox'] = IPA.force_dnszone_add_checkbox_widget;
IPA.field_factories['force_dnszone_add_checkbox'] = IPA.checkbox_field;

IPA.dnszone_adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.entity_adder_dialog(spec);

    that.create = function() {
        that.entity_adder_dialog_create();
        that.container.addClass('dnszone-adder-dialog');
    };

    return that;
};

IPA.dns.add_permission_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'add_permission';
    spec.label = spec.label || IPA.messages.objects.dnszone.add_permission;
    spec.enable_cond = spec.enable_cond || ['permission-none', 'managedby_w'];

    var that = IPA.action(spec);

    that.execute_action = function(facet) {

        var pkey = IPA.nav.get_state('dnszone-pkey');

         var command = IPA.command({
            entity: 'dnszone',
            method: 'add_permission',
            args: [pkey],
            options: {},
            on_success: function(data, text_status, xhr) {
                facet.refresh();
                IPA.notify_success(data.result.summary);
            }
        });

        command.execute();
    };

    return that;
};

IPA.dns.remove_permission_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'remove_permission';
    spec.label = spec.label || IPA.messages.objects.dnszone.remove_permission;
    spec.enable_cond = spec.enable_cond || ['permission-set', 'managedby_w'];

    var that = IPA.action(spec);

    that.execute_action = function(facet) {

        var pkey = IPA.nav.get_state('dnszone-pkey');

         var command = IPA.command({
            entity: 'dnszone',
            method: 'remove_permission',
            args: [pkey],
            options: {},
            on_success: function(data, text_status, xhr) {
                facet.refresh();
                IPA.notify_success(data.result.summary);
            }
        });

        command.execute();
    };

    return that;
};

IPA.dns.zone_has_permission_evaluator = function(spec) {
    spec = spec || {};

    spec.event = spec.event || 'permission_load';

    var that = IPA.state_evaluator(spec);

    that.on_event = function(permission_status) {

        var old_state = that.state;
        that.state = [
            'permission-'+permission_status
        ];

        that.notify_on_change(old_state);
    };

    return that;
};

IPA.dns.record_search_facet = function(spec) {

    var that = IPA.nested_search_facet(spec);

    that.get_records = function(pkeys, on_success, on_error) {

        var batch = IPA.batch_command({
            name: that.get_records_command_name(),
            on_success: on_success,
            on_error: on_error
        });

        var zone = IPA.nav.get_state('dnszone-pkey');

        for (var i=0; i<pkeys.length; i++) {
            var pkey = pkeys[i];

            var command = IPA.command({
                entity: that.table.entity.name,
                method: 'show',
                args: [zone, pkey],
                options: { all: true }
            });

            batch.add_command(command);
        }

        batch.execute();
    };


    that.load_records = function(records) {
        that.table.empty();

        var types = IPA.dns_record_types();

        for (var i=0; i<records.length; i++) {

            var original = records[i];
            var record = {
                idnsname: original.idnsname,
                values: []
            };

            for (var j=0; j<types.length; j++) {
                var type = types[j];
                if (!original[type.value]) continue;

                var values = original[type.value];
                for (var k=0; k<values.length; k++) {
                    record.values.push({
                        type: type.label,
                        data: values[k]
                    });
                }
            }

            that.add_record(record);
        }
        that.table.set_values(that.selected_values);
    };

    that.add_record = function(record) {

        for (var i=0; i<record.values.length; i++) {

            var value = record.values[i];

            if (i === 0) {
                value.idnsname = record.idnsname;
            }

            var tr = that.table.add_record(value);

            if (i > 0) {
                $('input[name="'+that.table.name+'"]', tr).remove();
            }
        }
    };

    return that;
};

IPA.dns.record_search_deleter_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.search_deleter_dialog(spec);

    that.create_command = function() {

        var batch = that.search_deleter_dialog_create_command();

        for (var i=0; i<batch.commands.length; i++) {
            var command = batch.commands[i];
            command.set_option('del_all', true);
        }

        return batch;
    };

    return that;
};

IPA.dns.record_metadata = null;
IPA.dns.get_record_metadata = function() {

    if (IPA.dns.record_metadata === null) {

    IPA.dns.record_metadata = [
        {
            name: 'arecord',
            attributes: [
                {
                    name: 'a_part_ip_address',
                    validators: [IPA.ip_v4_address_validator()]
                },
                {
                    type: 'checkbox',
                    name: 'a_extra_create_reverse'
                }
            ],
            columns: [
                {
                    factory: IPA.dns.ptr_redirection_column,
                    name: 'a_part_ip_address'
                }
            ]
        },
        {
            name: 'aaaarecord',
            attributes: [
                {
                    name:'aaaa_part_ip_address',
                    validators: [IPA.ip_v6_address_validator()]
                },
                {
                    type: 'checkbox',
                    name: 'aaaa_extra_create_reverse'
                }
            ],
            columns: [
                {
                    factory: IPA.dns.ptr_redirection_column,
                    name: 'aaaa_part_ip_address'
                }
            ]
        },
        {
            name: 'a6record',
            attributes: [
                'a6_part_data'
            ],
            columns: ['a6_part_data']
        },
        {
            name: 'afsdbrecord',
            attributes: [
                'afsdb_part_subtype',
                'afsdb_part_hostname'
            ],
            columns: ['afsdb_part_subtype', 'afsdb_part_hostname']
        },
        {
            name: 'certrecord',
            attributes: [
                'cert_part_type',
                'cert_part_key_tag',
                'cert_part_algorithm',
                {
                    name: 'cert_part_certificate_or_crl',
                    type: 'textarea'
                }
            ],
            columns: ['cert_part_type','cert_part_key_tag','cert_part_algorithm']
        },
        {
            name: 'cnamerecord',
            attributes: [
                'cname_part_hostname'
            ],
            columns: ['cname_part_hostname']
        },
        {
            name: 'dnamerecord',
            attributes: [
                'dname_part_target'
            ],
            columns: ['dname_part_target']
        },
        {
            name: 'dsrecord',
            attributes: [
                'ds_part_key_tag',
                'ds_part_algorithm',
                'ds_part_digest_type',
                {
                    name: 'ds_part_digest',
                    type: 'textarea'
                }
            ],
            columns: ['ds_part_key_tag', 'ds_part_algorithm',
                      'ds_part_digest_type']
        },
        {
            name: 'keyrecord',
            attributes: [
                'key_part_flags',
                'key_part_protocol',
                'key_part_algorithm',
                {
                    name: 'key_part_public_key',
                    type: 'textarea'
                }
            ],
            columns: ['key_part_flags', 'key_part_protocol',
                      'key_part_algorithm']
        },
        {
            name: 'kxrecord',
            attributes: [
                'kx_part_preference',
                'kx_part_exchanger'
            ],
            columns: ['kx_part_preference', 'kx_part_exchanger']
        },
        {
            name: 'locrecord',
            attributes: [
                'loc_part_lat_deg',
                'loc_part_lat_min',
                'loc_part_lat_sec',
                {
                    name: 'loc_part_lat_dir',
                    options: IPA.create_options(['N','S']),
                    type: 'radio',
                    widget_opt: {
                        default_value: 'N'
                    }
                },
                'loc_part_lon_deg',
                'loc_part_lon_min',
                'loc_part_lon_sec',
                {
                    name: 'loc_part_lon_dir',
                    options: IPA.create_options(['E','W']),
                    type: 'radio',
                    widget_opt: {
                        default_value: 'E'
                    }
                },
                'loc_part_altitude',
                'loc_part_size',
                'loc_part_h_precision',
                'loc_part_v_precision'
            ],
            columns: ['dnsdata']
        },
        {
            name: 'mxrecord',
            attributes: [
                'mx_part_preference',
                'mx_part_exchanger'
            ],
            columns: ['mx_part_preference', 'mx_part_exchanger']
        },
        {
            name: 'naptrrecord',
            attributes: [
                'naptr_part_order',
                'naptr_part_preference',
                {
                    name: 'naptr_part_flags',
                    type: 'select',
                    options:  IPA.create_options(['S', 'A', 'U', 'P'])
                },
                'naptr_part_service',
                'naptr_part_regexp',
                'naptr_part_replacement'
            ],
            adder_attributes: [],
            columns: ['dnsdata']
        },
        {
            name: 'nsrecord',
            attributes: [
                'ns_part_hostname'
            ],
            adder_attributes: [],
            columns: ['ns_part_hostname']
        },
        {
            name: 'nsecrecord',
            attributes: [
                'nsec_part_next',
                'nsec_part_types'
//             TODO: nsec_part_types is multivalued attribute. New selector
//             widget or at least new validator should be created.
//                 {
//                     name: 'nsec_part_types',
//                     options: IPA.create_options(['SOA', 'A', 'AAAA', 'A6', 'AFSDB',
//                         'APL', 'CERT', 'CNAME', 'DHCID', 'DLV', 'DNAME', 'DNSKEY',
//                         'DS', 'HIP', 'IPSECKEY', 'KEY', 'KX', 'LOC', 'MX', 'NAPTR',
//                         'NS', 'NSEC','NSEC3', 'NSEC3PARAM', 'PTR', 'RRSIG', 'RP',
//                         'SIG', 'SPF', 'SRV', 'SSHFP', 'TA', 'TKEY', 'TSIG', 'TXT']),
//                     type: 'select'
//                 }
            ],
            adder_attributes: [],
            columns: [ 'nsec_part_next', 'nsec_part_types']
        },
        {
            name: 'ptrrecord',
            attributes: [
                'ptr_part_hostname'
            ],
            adder_attributes: [],
            columns: [ 'ptr_part_hostname']
        },
        {
            name: 'rrsigrecord',
            attributes: [
                {
                    name: 'rrsig_part_type_covered',
                    type: 'select',
                    options:  IPA.create_options(['SOA', 'A', 'AAAA', 'A6', 'AFSDB',
                                'APL', 'CERT', 'CNAME', 'DHCID', 'DLV', 'DNAME',
                                'DNSKEY', 'DS', 'HIP', 'IPSECKEY', 'KEY', 'KX',
                                'LOC', 'MX', 'NAPTR', 'NS', 'NSEC', 'NSEC3',
                                'NSEC3PARAM', 'PTR', 'RRSIG', 'RP', 'SPF', 'SRV',
                                'SSHFP', 'TA', 'TKEY', 'TSIG', 'TXT'])
                },
                'rrsig_part_algorithm',
                'rrsig_part_labels',
                'rrsig_part_original_ttl',
                'rrsig_part_signature_expiration',
                'rrsig_part_signature_inception',
                'rrsig_part_key_tag',
                'rrsig_part_signers_name',
                {
                    name: 'rrsig_part_signature',
                    type: 'textarea'
                }
            ],
            adder_attributes: [],
            columns: ['dnsdata']
        },
        {
            name: 'sigrecord',
            attributes: [
                {
                    name: 'sig_part_type_covered',
                    type: 'select',
                    options:  IPA.create_options(['SOA', 'A', 'AAAA', 'A6', 'AFSDB',
                                'APL', 'CERT', 'CNAME', 'DHCID', 'DLV', 'DNAME',
                                'DNSKEY', 'DS', 'HIP', 'IPSECKEY', 'KEY', 'KX',
                                'LOC', 'MX', 'NAPTR', 'NS', 'NSEC', 'NSEC3',
                                'NSEC3PARAM', 'PTR', 'RRSIG', 'RP', 'SPF', 'SRV',
                                'SSHFP', 'TA', 'TKEY', 'TSIG', 'TXT'])
                },
                'sig_part_algorithm',
                'sig_part_labels',
                'sig_part_original_ttl',
                'sig_part_signature_expiration',
                'sig_part_signature_inception',
                'sig_part_key_tag',
                'sig_part_signers_name',
                {
                    name: 'sig_part_signature',
                    type: 'textarea'
                }
            ],
            adder_attributes: [],
            columns: ['dnsdata']
        },
        {
            name: 'srvrecord',
            attributes: [
                'srv_part_priority',
                'srv_part_weight',
                'srv_part_port',
                'srv_part_target'
            ],
            adder_attributes: [],
            columns: ['srv_part_priority', 'srv_part_weight', 'srv_part_port',
                      'srv_part_target']
        },
        {
            name: 'sshfprecord',
            attributes: [
                'sshfp_part_algorithm',
                'sshfp_part_fp_type',
                {
                    name: 'sshfp_part_fingerprint',
                    type: 'textarea'
                }
            ],
            adder_attributes: [],
            columns: ['sshfp_part_algorithm', 'sshfp_part_fp_type']
        },
        {
            name: 'txtrecord',
            attributes: [
                'txt_part_data'
            ],
            adder_attributes: [],
            columns: ['txt_part_data']
        }
    ];

        //set required flags for attributes based on 'dnsrecord_optional' flag
        //in param metadata

        for (var i=0; i<IPA.dns.record_metadata.length; i++) {
            var type = IPA.dns.record_metadata[i];

            for (var j=0; j<type.attributes.length; j++) {
                var attr = type.attributes[j];
                if (typeof attr === 'string') {
                    attr = {
                        name: attr
                    };
                    type.attributes[j] = attr;
                }
                var attr_meta = IPA.get_entity_param('dnsrecord', attr.name);

                if (attr_meta && attr_meta.flags.indexOf('dnsrecord_optional') === -1) {
                    attr.required = true;
                }
            }
        }

    }

    return IPA.dns.record_metadata;
};


IPA.dns.get_record_type = function(type_name) {

    var metadata = IPA.dns.get_record_metadata();

    for (var i=0; i<metadata.length; i++) {
        var type = metadata[i];
        if (type.name === type_name) return type;
    }

    return null;
};

IPA.dns.record_entity = function(spec) {

    spec = spec || {};

    spec.policies = spec.policies || [
        IPA.facet_update_policy({
            source_facet: 'details',
            dest_entity: 'dnszone',
            dest_facet: 'records'
        }),
        IPA.adder_facet_update_policy()
    ];

    var that = IPA.entity(spec);

    that.init = function() {

        if (!IPA.dns_enabled) {
            throw {
                expected: true
            };
        }

        that.entity_init();

        that.builder.containing_entity('dnszone').
        details_facet({
            factory: IPA.dns.record_details_facet,
            disable_breadcrumb: false,
            fields: [
                {
                    type: 'dnsrecord_host_link',
                    name: 'idnsname',
                    other_entity: 'host',
                    widget: 'identity.idnsname'
                }
            ],
            widgets:[
                {
                    name: 'identity',
                    label: IPA.messages.details.identity,
                    type: 'details_table_section',
                    widgets: [
                        {
                            type: 'dnsrecord_host_link',
                            name: 'idnsname',
                            other_entity: 'host',
                            label: IPA.get_entity_param(
                                'dnsrecord', 'idnsname').label
                        }
                   ]
                }
            ]
        }).
        adder_dialog({
            factory: IPA.dns.record_adder_dialog,
            fields: [
                {
                    name: 'idnsname',
                    widget: 'general.idnsname'
                },
                {
                    name: 'record_type',
                    type: 'dnsrecord_type',
                    flags: ['no_command'],
                    widget: 'general.record_type'
                }
            ],
            widgets: [
                {
                    name: 'general',
                    type: 'details_table_section_nc',
                    widgets: [
                        'idnsname',
                        {
                            type: 'dnsrecord_type',
                            name: 'record_type',
                            label: IPA.messages.objects.dnsrecord.type
                        }
                    ]
                }
            ],
            policies: [
                IPA.dnsrecord_adder_dialog_type_policy({
                    type_field: 'record_type'
                })
            ]
        });
    };

    return that;
};

IPA.dns.record_adder_dialog = function(spec) {

    spec = spec || {};
    spec.retry = spec.retry !== undefined ? spec.retry : false;

    IPA.dns.record_prepare_spec(spec, IPA.dns.record_prepare_editor_for_type);

    var that = IPA.entity_adder_dialog(spec);

    that.on_error = IPA.create_4304_error_handler(that);

    return that;
};

IPA.dns.record_details_facet = function(spec) {

    IPA.dns.record_prepare_details_spec(spec);

    var that = IPA.details_facet(spec);

    that.load = function(data) {

        if (!data.result.result.idnsname) {
            that.reset();
            var dialog = IPA.dnsrecord_redirection_dialog();
            dialog.open(that.container);
            return;
        }

        that.details_facet_load(data);
    };

    that.create_refresh_command = function() {

        var command = that.details_facet_create_refresh_command();
        command.set_option('structured', true);
        return command;
    };

    return that;
};

IPA.dnsrecord_redirection_dialog = function(spec) {
    spec = spec || {};
    spec.title = spec.title || IPA.messages.dialogs.redirection;

    var that = IPA.dialog(spec);

    that.create = function() {
        $('<p/>', {
            'text': IPA.messages.objects.dnsrecord.deleted_no_data
        }).appendTo(that.container);
        $('<p/>', {
            'text': IPA.messages.objects.dnsrecord.redirection_dnszone
        }).appendTo(that.container);
    };

    that.create_button({
        name: 'ok',
        label: IPA.messages.buttons.ok,
        click: function() {
            that.close();
            IPA.nav.show_page('dnszone','default');
        }
    });
    return that;
};

/*
 * Spec preparation methods
 */

IPA.dns.record_prepare_spec = function(spec, type_prepare_method) {

    var metadata = IPA.dns.get_record_metadata();

    var fields = [];
    var widgets = [];

    for (var i=0; i<metadata.length; i++) {

        var type = metadata[i];

        type_prepare_method(type, fields, widgets);
    }

    IPA.dns.extend_spec(spec, fields, widgets);
};

IPA.dns.extend_spec = function(spec, fields, widgets) {

    if (spec.sections) delete spec.sections;

    if (spec.fields instanceof Array) {
        spec.fields.push.apply(spec.fields, fields);
    } else {
        spec.fields = fields;
    }

    if (spec.widgets instanceof Array) {
        spec.widgets.push.apply(spec.widgets, widgets);
    } else {
        spec.widgets = widgets;
    }
};

IPA.dns.record_prepare_editor_for_type = function(type, fields, widgets, update) {

    var set_defined = function(property, object, name) {
        if (property !== undefined) {
            object[name] = property;
        }
    };

    var copy_obj = function(source, dest) {
        if (source !== null || source !== undefined) {
            $.extend(source,dest);
        }
    };

    var section = {
        name: type.name,
        type: 'details_table_section_nc',
        widgets: []
    };
    widgets.push(section);

    for (var i=0; i<type.attributes.length;i++) {
        var attribute = type.attributes[i];

        if (typeof attribute === 'string') {
            attribute = {
                name: attribute
            };
        }

        var metadata = IPA.get_entity_param('dnsrecord', attribute.name);
        if (metadata && update && metadata.flags &&
            metadata.flags.indexOf('no_update') > -1) continue;

        //create field
        var field = {};

        field.name = attribute.name;
        field.label = attribute.label ||
                        IPA.dns.record_get_attr_label(attribute.name);
        set_defined(attribute.type, field, 'type');
        set_defined(attribute.validators, field, 'validators');
        set_defined(attribute.required, field, 'required');
        copy_obj(widget, attribute.field_opt);

        field.widget = type.name+'.'+field.name;
        fields.push(field);

        //create editor widget
        var widget = {};
        if (typeof attribute === 'string') {
            widget.name = attribute;
        } else {
            widget.name = attribute.name;
            set_defined(attribute.type, widget, 'type');
            set_defined(attribute.options, widget, 'options');
            copy_obj(widget, attribute.widget_opt);
        }
        section.widgets.push(widget);
    }
};

IPA.dns.record_prepare_details_spec = function(spec, type_prepare_method) {

    var metadata = IPA.dns.get_record_metadata();

    var fields = [];
    var widgets = [];

    var standard_record_section = {
        name: 'standard_types',
        type: 'details_table_section',
        label: IPA.messages.objects.dnsrecord.standard,
        widgets: []
    };

    var other_record_section = {
        name: 'other_types',
        type: 'details_table_section',
        label: IPA.messages.objects.dnsrecord.other,
        widgets: []
    };

    widgets.push(standard_record_section);
    widgets.push(other_record_section);

    var standard_types = ['arecord', 'aaaarecord', 'ptrrecord', 'srvrecord',
        'txtrecord', 'cnamerecord', 'mxrecord', 'nsrecord'];

    for (var i=0; i<metadata.length; i++) {

        var type = metadata[i];

        if (standard_types.indexOf(type.name) > -1) {
            IPA.dns.record_prepare_details_for_type(type, fields, standard_record_section);
        } else {
            IPA.dns.record_prepare_details_for_type(type, fields, other_record_section);
        }
    }

    IPA.dns.extend_spec(spec, fields, widgets);
};

IPA.dns.record_prepare_details_for_type = function(type, fields, container) {

    var index = type.name.search('record$');
    var dnstype = type.name.substring(0, index).toUpperCase();

    var type_widget = {
        name: type.name,
        type: 'dnsrecord_type_table',
        record_type: type.name,
        value_attribute: 'dnsdata',
        dnstype: dnstype,
        columns: type.columns
    };

    container.widgets.push(type_widget);

    var field = {
        name: type.name,
        type: 'dnsrecord_type_table',
        dnstype: dnstype,
        label: dnstype,
        widget: container.name+'.'+type.name
    };

    fields.push(field);
};

/*
 * Widgets and policies
 */


IPA.dnsrecord_host_link_field = function(spec) {
    var that = IPA.link_field(spec);
    that.other_pkeys = function() {
        var pkey = that.entity.get_primary_key();
        return [pkey[0]+'.'+pkey[1]];
    };
    return that;
};

IPA.field_factories['dnsrecord_host_link'] = IPA.dnsrecord_host_link_field;
IPA.widget_factories['dnsrecord_host_link'] = IPA.link_widget;

IPA.dns_record_types = function() {

    //only supported
    var attrs = ['A', 'AAAA', 'A6', 'AFSDB', 'CERT', 'CNAME', 'DNAME',
                   'DS','KEY', 'KX', 'LOC', 'MX', 'NAPTR', 'NS', 'NSEC',
                   'PTR', 'RRSIG', 'SRV', 'SIG', 'SSHFP', 'TXT'];
    var record_types = [];
    for (var i=0; i<attrs.length; i++) {
        var attr = attrs[i];

        var rec_type = {
            label: attr,
            value: attr.toLowerCase()+'record'
        };
        record_types.push(rec_type);
    }
    return record_types;
};

IPA.dns.record_get_attr_label = function(part_name) {

    var metadata = IPA.get_entity_param('dnsrecord', part_name);

    if (!metadata) return null;

    var label = metadata.label;

    if (part_name.indexOf('_part_') > -1) {

        label = label.substring(label.indexOf(' '));
    } else if (part_name.indexOf('_extra_') > -1) {

        label = label.substring(label.indexOf(' '));
    }

    return label;
};


IPA.dnsrecord_type_field = function(spec) {

    spec = spec || {};
    var that = IPA.field(spec);

    that.type_changed = IPA.observer();

    that.get_type = function() {

        return that.widget.save()[0];
    };

    that.on_type_change = function() {

        that.type_changed.notify([], that);
    };

    that.widgets_created = function() {

        that.field_widgets_created();
        that.widget.value_changed.attach(that.on_type_change);
    };

    that.reset = function() {
        that.field_reset();
        that.on_type_change();
    };

    return that;
};

IPA.field_factories['dnsrecord_type'] = IPA.dnsrecord_type_field;


IPA.dnsrecord_type_widget = function(spec) {

    spec.options = IPA.dns_record_types();
    var that = IPA.select_widget(spec);
    return that;
};

IPA.widget_factories['dnsrecord_type'] = IPA.dnsrecord_type_widget;


IPA.dnsrecord_adder_dialog_type_policy = function(spec) {

    spec = spec || {};

    var that = IPA.facet_policy(spec);

    that.type_field_name = spec.type_field;

    that.post_create = function() {
        that.type_field = that.container.fields.get_field(that.type_field_name);
        that.type_field.type_changed.attach(that.on_type_change);
        that.on_type_change();
    };

    that.on_type_change = function() {

        var type = that.type_field.get_type();

        that.allow_fields_for_type(type);
        that.show_widgets_for_type(type);
    };

    that.allow_fields_for_type = function(type) {

        type = type.substring(0, type.indexOf('record'));

        var fields = that.container.fields.get_fields();

        for (var i=0; i<fields.length; i++) {

            var field = fields[i];
            var fieldtype;
            var attr_types = ['_part_', '_extra_', 'record'];

            for (var j=0; j<attr_types.length; j++) {
                var index = field.name.indexOf(attr_types[j]);
                if (index > -1) {
                    fieldtype = field.name.substring(0, index);
                    break;
                }
            }

            field.enabled = (field.name === 'idnsname' ||
                field.name === that.type_field_name ||
                fieldtype === type);
        }
    };

    that.show_widgets_for_type = function(type) {

        var widgets = that.container.widgets.get_widgets();

        for (var i=0; i<widgets.length; i++) {
            var widget = widgets[i];
            var visible = widget.name.indexOf(type) === 0 ||
                          widget.name === 'general';
            widget.set_visible(visible);
        }
    };

    return that;
};


IPA.dns.record_type_table_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    that.dnstype = spec.dnstype;

    that.load = function(record) {

        var data = {};

        data.idnsname = record.idnsname;
        data.dnsrecords = [];

        for (var i=0, j=0; i<record.dnsrecords.length; i++) {

            var dnsrecord = record.dnsrecords[i];
            if(dnsrecord.dnstype === that.dnstype) {

                dnsrecord.position = j;
                j++;
                data.dnsrecords.push(dnsrecord);
            }
        }

        that.values = data;

        that.load_writable(record);
        that.reset();
    };

    return that;
};

IPA.field_factories['dnsrecord_type_table'] = IPA.dns.record_type_table_field;


IPA.dns.record_type_table_widget = function(spec) {

    spec = spec || {};
    spec.columns = spec.columns || [];

    spec.columns.push({
        name: 'position',
        label: '',
        factory: IPA.dns.record_modify_column,
        width: '106px'
    });

    var that = IPA.table_widget(spec);

    that.dnstype = spec.dnstype;

    that.create_column = function(spec) {

        if (typeof spec === 'string') {
            spec = {
                name: spec
            };
        }

        spec.entity = that.entity;
        spec.label = spec.label || IPA.dns.record_get_attr_label(spec.name);

        var factory = spec.factory || IPA.column;

        var column = factory(spec);
        that.add_column(column);
        return column;
    };

    that.create_columns = function() {
        that.clear_columns();
        if (spec.columns) {
            for (var i=0; i<spec.columns.length; i++) {
                that.create_column(spec.columns[i]);
            }
        }

        var modify_column = that.columns.get('position');
        modify_column.link_handler = that.on_modify;
    };

    that.create = function(container) {

        that.create_columns();
        that.table_create(container);

        container.addClass('dnstype-table');

        that.remove_button = IPA.action_button({
            name: 'remove',
            label: IPA.messages.buttons.remove,
            icon: 'remove-icon',
            'class': 'action-button-disabled',
            click: function() {
                if (!that.remove_button.hasClass('action-button-disabled')) {
                    that.remove_handler();
                }
                return false;
            }
        }).appendTo(that.buttons);

        that.add_button = IPA.action_button({
            name: 'add',
            label: IPA.messages.buttons.add,
            icon: 'add-icon',
            click: function() {
                if (!that.add_button.hasClass('action-button-disabled')) {
                    that.add_handler();
                }
                return false;
            }
        }).appendTo(that.buttons);
    };

    that.set_enabled = function(enabled) {
        that.table_set_enabled(enabled);
        if (enabled) {
            if(that.add_button) {
                that.add_button.removeClass('action-button-disabled');
            }
        } else {
            $('.action-button', that.table).addClass('action-button-disabled');
            that.unselect_all();
        }
        that.enabled = enabled;
    };

    that.select_changed = function() {

        var values = that.get_selected_values();

        if (that.remove_button) {
            if (values.length === 0) {
                that.remove_button.addClass('action-button-disabled');
            } else {
                that.remove_button.removeClass('action-button-disabled');
            }
        }
    };

    that.add_handler = function() {
        var facet = that.entity.get_facet();

        if (facet.is_dirty()) {
            var dialog = IPA.dirty_dialog({
                entity:that.entity,
                facet: facet
            });

            dialog.callback = function() {
                that.show_add_dialog();
            };

            dialog.open(that.container);

        } else {
            that.show_add_dialog();
        }
    };

    that.remove_handler = function() {
        var facet = that.entity.get_facet();

        if (facet.is_dirty()) {
            var dialog = IPA.dirty_dialog({
                entity:that.entity,
                facet: facet
            });

            dialog.callback = function() {
                that.show_remove_dialog();
            };

            dialog.open(that.container);

        } else {
            that.show_remove_dialog();
        }
    };

    that.show_remove_dialog = function() {

        var selected_values = that.get_selected_values();

        if (!selected_values.length) {
            var message = IPA.messages.dialogs.remove_empty;
            alert(message);
            return;
        }

        var dialog = IPA.deleter_dialog({
            entity: that.entity,
            values: selected_values
        });

        dialog.execute = function() {
            that.remove(
                selected_values,
                that.idnsname[0],
                function(data) {
                    that.reload_facet(data);
                    dialog.close();
                    that.notify_facet_update();
                    that.facet.nofify_update_success();
                },
                function() {
                    that.refresh_facet();
                    dialog.close();
                }
            );
        };


        dialog.open(that.container);
    };

    that.remove = function(values, pkey, on_success, on_error) {

        var dnszone = IPA.nav.get_state('dnszone-pkey');

        var command = IPA.command({
            entity: that.entity.name,
            method: 'del',
            args: [dnszone, pkey],
            on_success: on_success,
            on_error: on_error
        });

        var record_name = that.dnstype.toLowerCase()+'record';
        command.set_option(record_name, values);
        command.set_option('structured', true);

        command.execute();
    };

    that.create_add_dialog = function() {

        var title = IPA.messages.dialogs.add_title;
        var label = that.entity.metadata.label_singular;

        var dialog_spec = {
            entity: that.entity,
            fields: [],
            widgets: [],
            retry: false,
            title: title.replace('${entity}', label)
        };

        var dnstype = that.dnstype.toLowerCase();
        var type = IPA.dns.get_record_type(dnstype+'record');

        IPA.dns.record_prepare_editor_for_type(type, dialog_spec.fields,
                                               dialog_spec.widgets);

        var dialog = IPA.entity_adder_dialog(dialog_spec);

        var cancel_button = dialog.buttons.get('cancel');
        dialog.buttons.empty();

        dialog.on_error = IPA.create_4304_error_handler(dialog);

        dialog.get_add_message = function() {
            var label = that.entity.metadata.label_singular;
            var message = IPA.messages.dialogs.add_confirmation;
            message = message.replace('${entity}', label);
            return message;
        };

        dialog.create_button({
            name: 'add',
            label: IPA.messages.buttons.add,
            click: function() {
                dialog.hide_message();
                dialog.add(
                    function(data, text_status, xhr) {

                        if (data.result.result.dnsrecords) {
                            that.reload_facet(data);
                        } else {
                            that.refresh_facet();
                        }
                        dialog.close();
                        that.notify_facet_update();
                        IPA.notify_success(dialog.get_add_message());
                    },
                    dialog.on_error);
            }
        });

        dialog.create_button({
            name: 'add_and_add_another',
            label: IPA.messages.buttons.add_and_add_another,
            click: function() {
                dialog.hide_message();
                dialog.add(
                    function(data, text_status, xhr) {

                        dialog.show_message(dialog.get_add_message());

                        if (data.result.result.dnsrecords) {
                            that.reload_facet(data);
                        } else {
                            that.refresh_facet();
                        }
                        dialog.reset();
                        that.notify_facet_update();
                    },
                    dialog.on_error);
            }
        });

        dialog.buttons.put('cancel', cancel_button);

        dialog.create_add_command = function(record) {

            var dnszone = IPA.nav.get_state('dnszone-pkey');

            var command = dialog.entity_adder_dialog_create_add_command(record);
            command.args = [dnszone, that.idnsname[0]];
            command.set_option('structured', true);

            return command;
        };

        return dialog;
    };

    that.show_add_dialog = function() {

        var dialog = that.create_add_dialog();
        dialog.open(that.container);
    };

    that.create_mod_dialog = function() {

        var title = IPA.messages.dialogs.edit_title;
        var label = that.entity.metadata.label_singular;

        var dialog_spec = {
            entity: that.entity,
            fields: [],
            widgets: [],
            title: title.replace('${entity}', label)
        };

        var dnstype = that.dnstype.toLowerCase();

        var type = IPA.dns.get_record_type(dnstype+'record');

        IPA.dns.record_prepare_editor_for_type(type, dialog_spec.fields,
                                               dialog_spec.widgets, true);

        var dialog = IPA.entity_adder_dialog(dialog_spec);

        dialog.buttons.empty();

        dialog.create_button({
            name: 'modify',
            label: IPA.messages.buttons.update,
            click: function() {
                dialog.modify();
            }
        });

        dialog.create_button({
            name: 'cancel',
            label: IPA.messages.buttons.cancel,
            click: function() {
                dialog.reset();
                dialog.close();
            }
        });

        dialog.load = function(record, full_value) {

            dialog.full_value = full_value;

            var fields = dialog.fields.get_fields();

            for (var i=0; i<fields.length; i++) {
                var field = fields[i];
                field.load(record);
            }
        };

        dialog.modify = function() {

            if (!dialog.validate()) return;

            var record = {};
            dialog.save(record);

            var command = dialog.create_add_command(record);

            command.on_success = function(data) {
                that.reload_facet(data);
                dialog.close();
                that.notify_facet_update();
                that.facet.nofify_update_success();
            };
            command.on_error = function() {
                that.refresh_facet();
                dialog.close();
            };
            command.execute();
        };

        dialog.create_add_command = function(record) {

            var dnszone = IPA.nav.get_state('dnszone-pkey');

            var command = dialog.entity_adder_dialog_create_add_command(record);

            command.method = 'mod';
            command.args = [dnszone, that.idnsname[0]];

            var record_name = that.dnstype.toLowerCase()+'record';
            command.set_option(record_name, dialog.full_value);
            command.set_option('structured', true);

            return command;
        };

        return dialog;
    };

    that.reload_facet = function(data) {

        //FIXME: seems as bad approach
        var facet = IPA.current_entity.get_facet();
        facet.load(data);
    };

    that.refresh_facet = function() {

        //FIXME: seems as bad approach
        var facet = IPA.current_entity.get_facet();
        facet.refresh();
    };

    that.notify_facet_update = function() {
        var facet = IPA.current_entity.get_facet();
        facet.on_update.notify();
    };

    that.update = function(values) {

        that.idnsname = values.idnsname;
        that.dnsrecords = values.dnsrecords;
        that.table_update(that.dnsrecords);
        that.unselect_all();
    };

    that.on_modify = function(position) {

        var values = that.values[position];

        var dialog = that.create_mod_dialog();
        dialog.open();
        dialog.load(that.records[position], values);

        return false;
    };


    return that;
};

IPA.widget_factories['dnsrecord_type_table'] = IPA.dns.record_type_table_widget;

IPA.dns.netaddr_field = function(spec) {

    spec = spec || {};

    var that = IPA.multivalued_field(spec);

    that.load = function(record) {

        that.record = record;

        that.values = that.get_value(record, that.name);
        that.values = that.values[0].split(';');

        that.load_writable(record);

        that.reset();
    };

    that.test_dirty = function() {

        if (that.read_only) return false;

        var values = that.field_save();

        //check for empty value: null, [''], '', []
        var orig_empty = IPA.is_empty(that.values);
        var new_empty= IPA.is_empty(values);
        if (orig_empty && new_empty) return false;
        if (orig_empty != new_empty) return true;

        //strict equality - checks object's ref equality, numbers, strings
        if (values === that.values) return false;

        //compare values in array
        if (values.length !== that.values.length) return true;

        for (var i=0; i<values.length; i++) {
            if (values[i] != that.values[i]) {
                return true;
            }
        }

        return that.widget.test_dirty();
    };

    that.save = function(record) {

        var values = that.field_save();
        var new_val = values.join(';');

        if (record) {
            record[that.name] = new_val;
        }

        return [new_val];
    };

    that.validate = function() {

        var values = that.field_save();

        return that.validate_core(values);
    };

    return that;
};

IPA.field_factories['netaddr'] = IPA.dns.netaddr_field;
IPA.widget_factories['netaddr'] = IPA.multivalued_widget;



IPA.dns.record_modify_column = function(spec) {

    spec = spec || {};

    var that = IPA.column(spec);

    that.text = spec.text || IPA.messages.buttons.edit;

    that.setup = function(container, record, suppress_link) {

        container.empty();

        var value = record[that.name];

        $('<a/>', {
            href: '#'+that.text,
            text: that.text,
            style: 'float: right;',
            click: function() {
                return that.link_handler(value);
            }
        }).appendTo(container);
    };

    return that;
};

IPA.dns.ptr_redirection_column = function(spec) {

    spec = spec || {};

    var that = IPA.column(spec);

    that.link = true;

    that.link_handler = function(value) {

        var address = NET.ip_address(value);

        var dialog = IPA.dns.ptr_redirection_dialog({
            address: address
        });
        dialog.open();

        return false;
    };

    return that;
};

IPA.dns.ptr_redirection_dialog = function(spec) {

    spec = spec || {};

    spec.title = IPA.messages.objects.dnsrecord.ptr_redir_title;

    var that = IPA.dialog(spec);

    that.address = spec.address;

    that.create = function() {

        that.status_div = $('<div />', {
            'class': 'redirection-status'
        }).appendTo(that.container);
    };

    that.create_buttons = function() {

        that.create_button({
            name: 'close',
            label: IPA.messages.buttons.close,
            click: function() {
                that.close();
            }
        });
    };

    that.create_add_record_button = function() {

        $('<a />', {
            text:  IPA.messages.objects.dnsrecord.ptr_redir_create,
            href: '#create_record',
            click: function() {
                that.create_record();
                return false;
            }
        }).appendTo(that.container);
    };

    that.append_status = function(message) {

        $('<div />', {
            text: message
        }).appendTo(that.status_div);
    };

    that.open = function() {

        that.dialog_open();
        that.start_redirect();
    };

    //step 0 - preparation
    that.start_redirect = function() {

        if (!that.address.valid) {
            that.append_status(IPA.messages.objects.dnsrecord.ptr_redir_address_err);
        } else {
            that.reverse_address = that.address.get_reverse().toLowerCase()+'.';

            var record = IPA.nav.get_state('dnsrecord-pkey');
            var zone = IPA.nav.get_state('dnszone-pkey');

            if (record && zone && record !== '' && zone !== '') {
                that.dns_record = {
                    name: record,
                    zone: zone
                };
            }

            that.get_zones();
        }
    };

    //1st step: get all zones
    that.get_zones = function() {

        that.append_status(IPA.messages.objects.dnsrecord.ptr_redir_zones);

        var command = IPA.command({
            entity: 'dnszone',
            method: 'find',
            options: {
                pkey_only: true
            },
            on_success: that.find_zone,
            on_error: function() {
                that.append_status(IPA.messages.objects.dnsrecord.ptr_redir_zones_err);
            }
        });

        command.execute();
    };

    //2nd step: find target zone
    that.find_zone = function(data) {
        var zones = data.result.result;
        var target_zone = null;

        for (var i=0; i<zones.length; i++) {

            var zone_name = zones[i].idnsname[0];
            if (that.reverse_address.indexOf(zone_name) > -1) {
                var msg = IPA.messages.objects.dnsrecord.ptr_redir_zone;
                msg = msg.replace('${zone}', zone_name);
                that.append_status(msg);

                if (!target_zone ||
                    (target_zone && zone_name.length > target_zone.length)) {

                    target_zone = zone_name;
                }

                break;
            }
        }

        if (target_zone) {
            that.zone = target_zone;
            that.check_record();
        } else {
            that.append_status(IPA.messages.objects.dnsrecord.ptr_redir_zone_err);
        }
    };

    //3rd step: check record existance
    that.check_record = function(zone) {

        that.append_status(IPA.messages.objects.dnsrecord.ptr_redir_record);

        var i1 = that.reverse_address.indexOf(that.zone);
        var record_name = that.reverse_address.substring(0,i1 - 1);
        that.record_keys = [that.zone, record_name];

        var command = IPA.command({
            entity: 'dnsrecord',
            method: 'show',
            args: that.record_keys,
            on_success: function() {
                that.redirect();
            },
            on_error: function() {
                that.append_status(IPA.messages.objects.dnsrecord.ptr_redir_record_err);
                if (that.dns_record) {
                    that.create_add_record_button();
                }
            },
            retry: false
        });

        command.execute();
    };

    //4th-a step: actual redirect
    that.redirect = function() {

        var entity = IPA.get_entity('dnsrecord');

        IPA.nav.show_entity_page(
            entity,
            'default',
            that.record_keys);

        that.close();
    };

    //4th-b optional step: create PTR record
    that.create_record = function() {

        that.append_status(IPA.messages.objects.dnsrecord.ptr_redir_creating);

        var ptr = that.dns_record.name +'.' + that.dns_record.zone;

        var command = IPA.command({
            entity: 'dnsrecord',
            method: 'add',
            args: that.record_keys,
            options: {
                ptrrecord: [ptr]
            },
            on_success: function() {
                that.redirect();
            },
            on_error: function() {
                that.append_status(IPA.messages.objects.dnsrecord.ptr_redir_creating_err);
            }
        });

        command.execute();
    };


    that.create_buttons();

    return that;
};

IPA.ip_address_validator = function(spec) {

    spec = spec || {};
    var that = IPA.validator(spec);

    that.address_type = spec.address_type;
    that.message = spec.message || IPA.messages.widget.validation.ip_address;

    that.validate = function(value) {

        if (IPA.is_empty(value)) return that.true_result();

        var address = NET.ip_address(value);

        if (!address.valid || !that.is_type_match(address.type)) {
            return that.false_result();
        }

        return that.true_result();
    };

    that.is_type_match = function(net_type) {

        return (!that.address_type ||

                (that.address_type === 'IPv4' &&
                    (net_type === 'v4-quads' || net_type === 'v4-int')) ||

                (that.address_type === 'IPv6' && net_type === 'v6'));
    };

    that.ip_address_validate = that.validate;

    return that;
};

IPA.ip_v4_address_validator = function(spec) {

    spec = spec || {};
    spec.address_type = 'IPv4';
    spec.message = IPA.messages.widget.validation.ip_v4_address;
    return IPA.ip_address_validator(spec);
};

IPA.ip_v6_address_validator = function(spec) {

    spec = spec || {};
    spec.address_type = 'IPv6';
    spec.message = IPA.messages.widget.validation.ip_v6_address;
    return IPA.ip_address_validator(spec);
};

IPA.dnsforwarder_validator = function(spec) {

    spec = spec || {};
    var that = IPA.ip_address_validator(spec);

    that.validate = function(value) {

        var address_part = value;

        if (value.indexOf(' ') > - 1) {
            var parts = value.split(' ');

            if (parts.length !== 3 || parts[1] !== 'port') return that.false_result();

            address_part = parts[0];
            var port = parts[2];

            if (!port.match(/^[1-9]\d*$|^0$/) || port < 0 || port > 65535) {
                var message = IPA.messages.widget.validation.port;
                message = message.replace('${port}', port);
                return that.false_result(message);
            }
        }

        return that.ip_address_validate(address_part);
    };

    return that;
};

IPA.network_validator = function(spec) {

    spec = spec || {};

    var that = IPA.validator(spec);

    that.allow_negation = spec.allow_negation;
    that.allow_host_address = spec.allow_host_address;
    that.specials = spec.specials || [];
    that.message = spec.message || IPA.messages.widget.validation.net_address;

    that.validate = function(value) {

        if (IPA.is_empty(value)) return that.true_result();

        if (typeof value !== 'string') return that.false_result();

        if (that.specials.indexOf(value) > -1) {
            return that.true_result();
        }

        var address_part, mask;

        if (value.indexOf('/') > -1) {

            var parts = value.split('/');

            if (parts.length === 2) {
                address_part = parts[0];
                mask = parts[1];

                if (mask === '') return that.false_result();

            } else {
                return that.false_result();
            }
        } else if (that.allow_host_address) {
            address_part = value;
        } else {
            return that.false_result();
        }


        if (that.allow_negation && address_part.indexOf('!') === 0) {
            address_part = address_part.substring(1);
        }

        var address = NET.ip_address(address_part);
        if (!address.valid) return that.false_result();

        if (mask) {

            var mask_length = 32;
            if (address.type === 'v6') mask_length = 128;

            if (!mask.match(/^[1-9]\d*$/) || mask < 8 || mask > mask_length) {
                return that.false_result();
            }
        }

        return that.true_result();
    };

    return that;
};

IPA.register('dnsconfig', IPA.dns.config_entity);
IPA.register('dnszone', IPA.dns.zone_entity);
IPA.register('dnsrecord', IPA.dns.record_entity);
