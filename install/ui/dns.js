/*jsl:import ipa.js */
/*jsl:import search.js */
/*jsl:import net.js */

/*  Authors:
 *    Adam Young <ayoung@redhat.com>
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

IPA.dns = {};

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
            title: IPA.metadata.objects.dnszone.label,
            columns: [ 'idnsname' ]
        }).
        details_facet({
            factory: IPA.dnszone_details_facet,
            sections: [{
                name: 'identity',
                fields: [
                    'idnsname',
                    {
                        type: 'radio',
                        name: 'idnszoneactive',
                        options: [
                            { value: 'TRUE', label: IPA.get_message('true') },
                            { value: 'FALSE', label: IPA.get_message('false') }
                        ]
                    },
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
                    }
                ]
            }]
        }).
        nested_search_facet({
            factory: IPA.dns.record_search_facet,
            facet_group: 'dnsrecord',
            nested_entity : 'dnsrecord',
            name: 'records',
            pagination: false,
            title: IPA.metadata.objects.dnszone.label_singular,
            label: IPA.metadata.objects.dnsrecord.label,
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
                            radio_name: 'dnszone_name_type'
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

IPA.dnszone_details_facet = function(spec) {

    spec = spec || {};

    var that = IPA.details_facet(spec);

    that.update = function(on_success, on_error) {

        var args = that.get_primary_key();

        var modify_operation = {
            execute: false,
            command: IPA.command({
                entity: that.entity.name,
                method: 'mod',
                args: args,
                options: { all: true, rights: true }
            })
        };

        var enable_operation = {
            execute: false,
            command: IPA.command({
                entity: that.entity.name,
                method: 'enable',
                args: args,
                options: { all: true, rights: true }
            })
        };

        var record = {};
        that.save(record);

        var fields = that.fields.get_fields();
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            if (!field.is_dirty()) continue;

            var values = record[field.name];
            if (!values) continue;

            var metadata = field.metadata;

            // skip primary key
            if (metadata && metadata.primary_key) continue;

            // check enable/disable
            if (field.name == 'idnszoneactive') {
                if (values[0] == 'FALSE') enable_operation.command.method = 'disable';
                enable_operation.execute = true;
                continue;
            }

            if (metadata) {
                if (values.length == 1) {
                    modify_operation.command.set_option(field.name, values[0]);
                } else if (field.join) {
                    modify_operation.command.set_option(field.name, values.join(','));
                } else {
                    modify_operation.command.set_option(field.name, values);
                }

            } else {
                if (values.length) {
                    modify_operation.command.set_option('setattr', field.name+'='+values[0]);
                } else {
                    modify_operation.command.set_option('setattr', field.name+'=');
                }
                for (var l=1; l<values.length; l++) {
                    modify_operation.command.set_option('addattr', field.name+'='+values[l]);
                }
            }

            modify_operation.execute = true;
        }

        var batch = IPA.batch_command({
            name: 'dnszone_details_update',
            on_success: function(data, text_status, xhr) {
                that.refresh();
                if (on_success) on_success.call(this, data, text_status, xhr);
            },
            on_error: function(xhr, text_status, error_thrown) {
                that.refresh();
                if (on_error) on_error.call(this, xhr, text_status, error_thrown);
            }
        });

        if (modify_operation.execute) batch.add_command(modify_operation.command);
        if (enable_operation.execute) batch.add_command(enable_operation.command);

        if (!batch.commands.length) {
            that.refresh();
            return;
        }

        batch.execute();
    };

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
            idnsname_w.input.attr('disabled', false);
            name_from_ip_w.input.attr('disabled', true);

            idnsname_f.set_required(true);
            name_from_ip_f.set_required(false);

            name_from_ip_f.reset();
        });

        name_from_ip_w.radio_clicked.attach(function() {
            idnsname_w.input.attr('disabled', true);
            name_from_ip_w.input.attr('disabled', false);

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

IPA.dnszone_adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.entity_adder_dialog(spec);

    that.create = function() {
        that.entity_adder_dialog_create();
        that.container.addClass('dnszone-adder-dialog');
    };

    return that;
};

IPA.dns.record_search_facet = function(spec) {

    var that = IPA.nested_search_facet(spec);

    that.load_all = function(data) {

        var types = IPA.dns_record_types();

        var result = data.result.result;
        var records = [];

        for (var i=0; i<result.length; i++) {
            var record = result[i];

            for (var j=0; j<types.length; j++) {
                var type = types[j];
                if (!record[type.value]) continue;

                var values = record[type.value];
                for (var k=0; k<values.length; k++) {
                    records.push({
                        idnsname: record.idnsname,
                        type: type.label,
                        data: values[k]
                    });
                }
            }
        }

        that.load_records(records);

        if (data.result.truncated) {
            var message = IPA.messages.search.truncated;
            message = message.replace('${counter}', data.result.count);
            that.table.summary.text(message);
        } else {
            that.table.summary.text(data.result.summary);
        }
    };

    that.get_selected_values = function() {

        var values = [];

        var records = {};
        var value;
        var record_type;

        $('input[name="idnsname"]:checked', that.table.tbody).each(function() {
            $('div', $(this).parent().parent()).each(function() {
                var div = $(this);
                var name = div.attr('name');
                var text = div.text();

                if (name === 'idnsname') {
                    value = records[text];
                    if (!value) {
                        value = { pkey: text };
                        records[text] = value;
                    }
                } else if (name === 'type') {
                    record_type = text.toLowerCase()+'record';

                } else if (name === 'data') {
                    if (!value[record_type]) {
                        value[record_type] = text;
                    } else {
                         value[record_type] += ',' + text;
                    }
                }
            });
        });

        for (var key in records) {
            values.push(records[key]);
        }

        return values;
    };

    return that;
};

IPA.dns.record_entity = function(spec) {

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
            sections: [
                {
                    name: 'identity',
                    label: IPA.messages.details.identity,
                    fields: [
                        {
                            type: 'dnsrecord_host_link',
                            name: 'idnsname',
                            other_entity: 'host',
                            label: IPA.get_entity_param(
                                'dnsrecord', 'idnsname').label
                        }
                   ]
                },
                {
                    name: 'standard',
                    label: IPA.messages.objects.dnsrecord.standard,
                    fields: [
                        {
                            type: 'multivalued',
                            name: 'arecord',
                            metadata: { primary_key: false },
                            label: 'A',
                            validators: [ IPA.ip_v4_address_validator() ]
                        },
                        {
                            type: 'multivalued',
                            name: 'aaaarecord',
                            metadata: { primary_key: false },
                            label: 'AAAA',
                            validators: [ IPA.ip_v6_address_validator() ]
                        },
                        {
                            type: 'multivalued',
                            name: 'ptrrecord',
                            metadata: { primary_key: false },
                            label: 'PTR'
                        },
                        {
                            type: 'multivalued',
                            name: 'srvrecord',
                            metadata: { primary_key: false },
                            label: 'SRV'
                        },
                        {
                            type: 'multivalued',
                            name: 'txtrecord',
                            metadata: { primary_key: false },
                            label: 'TXT'
                        },
                        {
                            type: 'multivalued',
                            name: 'cnamerecord',
                            metadata: { primary_key: false },
                            label: 'CNAME'
                        },
                        {
                            type: 'multivalued',
                            label:'MX',
                            metadata: { primary_key: false },
                            name: 'mxrecord'
                        },
                        {
                            type: 'multivalued',
                            label:'NS',
                            metadata: { primary_key: false },
                            name: 'nsrecord'
                        }
                    ]
                },
                {
                    name: 'other',
                    label: IPA.messages.objects.dnsrecord.other,
                    fields: [
                        {
                            type: 'multivalued',
                            name: 'afsdbrecord',
                            metadata: { primary_key: false },
                            label: 'AFSDB'
                        },
                        {
                            type: 'multivalued',
                            name: 'certrecord',
                            metadata: { primary_key: false },
                            label: 'CERT'
                        },
                        {
                            type: 'multivalued',
                            name: 'dnamerecord',
                            metadata: { primary_key: false },
                            label: 'DNAME'
                        },
                        {
                            type: 'multivalued',
                            name: 'dsrecord',
                            metadata: { primary_key: false },
                            label: 'DSRECORD'
                        },
                        {
                            type: 'multivalued',
                            name: 'keyrecord',
                            metadata: { primary_key: false },
                            label: 'KEY'
                        },
                        {
                            type: 'multivalued',
                            name: 'kxrecord',
                            metadata: { primary_key: false },
                            label: 'KX'
                        },
                        {
                            type: 'multivalued',
                            name: 'locrecord',
                            metadata: { primary_key: false },
                            label: 'LOC'
                        },
                        {
                            type: 'multivalued',
                            name: 'naptrrecord',
                            metadata: { primary_key: false },
                            label: 'NAPTR'
                        },
                        {
                            type: 'multivalued',
                            name: 'nsecrecord',
                            metadata: { primary_key: false },
                            label: 'NSEC'
                        },
                        {
                            type: 'multivalued',
                            name: 'rrsigrecord',
                            metadata: { primary_key: false },
                            label: 'RRSIG'
                        },
                        {
                            type: 'multivalued',
                            name: 'sigrecord',
                            metadata: { primary_key: false },
                            label: 'SIG'
                        },
                        {
                            type: 'multivalued',
                            name: 'sshfprecord',
                            metadata: { primary_key: false },
                            label: 'SSHFP'
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
                    widget: 'general.record_type'
                },
                {
                    type: 'dnsrecord',
                    name: 'record_data',
                    required: true,
                    widget: 'general.record_data',
                    type_widget: 'general.record_type'
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
                        },
                        {
                            type: 'text',
                            name: 'record_data',
                            label: IPA.messages.objects.dnsrecord.data
                        }
                    ]
                }
            ]
        });
    };

    return that;
};

IPA.dns.record_adder_dialog = function(spec) {

    var that = IPA.entity_adder_dialog(spec);

    that.create_add_command = function(record) {

        var command = that.entity_adder_dialog_create_add_command(record);

        var record_type = command.options.record_type;
        var record_data = command.options.record_data;

        delete command.options.record_type;
        delete command.options.record_data;

        command.options[record_type] = record_data;

        return command;
    };


    return that;
};

IPA.dns.record_details_facet = function(spec) {

    var that = IPA.details_facet(spec);

    that.update_on_success = function(data, text_status, xhr) {

        if (!data.result.result.idnsname) {
            that.reset();
            var dialog = IPA.dnsrecord_redirection_dialog();
            dialog.open(that.container);
            return;
        }

        that.load(data);
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
    var attrs = IPA.metadata.objects.dnsrecord.default_attributes;
    var record_types = [];
    for (var i=0; i<attrs.length; i++) {
        var attr = attrs[i];
        var index = attr.search('record$');
        if (index > -1) {
            var rec_type = {
                label: attr.substring(0, index).toUpperCase(),
                value: attr
            };
            record_types.push(rec_type);
        }
    }
    return record_types;
};

IPA.dnsrecord_type_widget = function(spec) {

    spec.options = IPA.dns_record_types();
    var that = IPA.select_widget(spec);
    return that;
};

IPA.widget_factories['dnsrecord_type'] = IPA.dnsrecord_type_widget;

IPA.dnsrecord_field = function(spec) {

    spec = spec || {};
    var that = IPA.field(spec);

    that.type_widget_name = spec.type_widget || '';

    that.normal_validators = [];
    that.a_record_validators = [
        IPA.ip_v4_address_validator()
    ];
    that.aaaa_record_validators = [
        IPA.ip_v6_address_validator()
    ];

    that.on_type_change = function() {

        var type = that.type_widget.save()[0];

        if (type === 'arecord') {
            that.validators = that.a_record_validators;
        } else if (type === 'aaaarecord') {
            that.validators = that.aaaa_record_validators;
        } else {
            that.validators = that.normal_validators;
        }

        that.validate();
    };

    that.widgets_created = function() {

        that.field_widgets_created();
        that.type_widget = that.container.widgets.get_widget(that.type_widget_name);
        that.type_widget.value_changed.attach(that.on_type_change);
    };

    that.reset = function() {
        that.field_reset();
        that.on_type_change();
    };

    return that;
};

IPA.field_factories['dnsrecord'] = IPA.dnsrecord_field;

IPA.force_dnszone_add_checkbox_widget = function(spec) {
    var metadata = IPA.get_command_option('dnszone_add', spec.name);
    spec.label = metadata.label;
    spec.tooltip = metadata.doc;
    return IPA.checkbox_widget(spec);
};

IPA.widget_factories['force_dnszone_add_checkbox'] = IPA.force_dnszone_add_checkbox_widget;
IPA.field_factories['force_dnszone_add_checkbox'] = IPA.checkbox_field;


IPA.ip_address_validator = function(spec) {

    spec = spec || {};
    var that = IPA.validator(spec);

    that.address_type = spec.address_type;
    that.message = spec.message || IPA.messages.widget.validation.ip_address;

    that.validate = function(value) {

        var address = NET.ip_address(value);

        if (!address.valid || !that.is_type_match(address.type)) {
            return {
                valid: false,
                message: that.message
            };
        }

        return { valid: true };
    };

    that.is_type_match = function(net_type) {

        return (!that.address_type ||

                (that.address_type === 'IPv4' &&
                    (net_type === 'v4-quads' || net_type === 'v4-int')) ||

                (that.address_type === 'IPv6' && net_type === 'v6'));
    };

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

IPA.register('dnszone', IPA.dns.zone_entity);
IPA.register('dnsrecord', IPA.dns.record_entity);
