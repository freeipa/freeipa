/*jsl:import ipa.js */

/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2012 Red Hat
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

IPA.automember = {};

IPA.automember.entity = function(spec) {

     //HACK: Automember takes_params is missing a cn attribute. This hack
     //copies cn from mod command. Also it is set as pkey.
    var pkey_attr = IPA.metadata.commands.automember_mod.takes_args[0];
    pkey_attr.primary_key = true;
    IPA.metadata.objects.automember.takes_params.push(pkey_attr);
    IPA.metadata.objects.automember.primary_key = pkey_attr.name;

    var that = IPA.entity(spec);

    that.init = function() {

        that.entity_init();

        that.builder.search_facet({
            factory: IPA.automember.rule_search_facet,
            name: 'searchgroup',
            group_type: 'group',
            label: 'User group rules', //TODO: translate
            details_facet: 'usergrouprule',
            columns: [
                'cn',
                'description'
            ]
        }).
        search_facet({
            factory: IPA.automember.rule_search_facet,
            name: 'searchhostgroup',
            group_type: 'hostgroup',
            label: 'Host group rules', //TODO: translate
            details_facet: 'hostgrouprule',
            columns: [
                'cn',
                'description'
            ]
        }).
        details_facet({
            factory: IPA.automember.rule_details_facet,
            name: 'usergrouprule',
            group_type: 'group',
            label: 'User group rule', //TODO: translate
            disable_facet_tabs: true,
            redirect_info: { tab: 'amgroup' }
        }).
        details_facet({
            factory: IPA.automember.rule_details_facet,
            name: 'hostgrouprule',
            group_type: 'hostgroup',
            label: 'Host group rule',//TODO: translate
            disable_facet_tabs: true,
            redirect_info: { tab: 'amhostgroup' }
        }).
        adder_dialog({
            factory: IPA.automember.rule_adder_dialog,
            fields: [
                {
                    type: 'entity_select',
                    name: 'cn',
                    other_entity: 'group',
                    other_field: 'cn'
                }
            ],
            height: '300'
        }).
        deleter_dialog({
            factory: IPA.automember.rule_deleter_dialog
        });
    };

    return that;
};


IPA.automember.rule_search_facet = function(spec) {

    spec = spec || {};

    var that = IPA.search_facet(spec);

    that.group_type = spec.group_type;

    that.get_records_command_name = function() {
        return that.managed_entity.name + that.group_type+'_get_records';
    };

    that.get_search_command_name = function() {
        var name = that.managed_entity.name + that.group_type + '_find';
        if (that.pagination && !that.search_all_entries) {
            name += '_pkeys';
        }
        return name;
    };

    that.create_get_records_command = function(pkeys, on_success, on_error) {

        var batch = that.table_facet_create_get_records_command(pkeys, on_success, on_error);

        for (var i=0; i<batch.commands.length; i++) {
            var command = batch.commands[i];
            command.set_option('type', that.group_type);
        }

        return batch;
    };

    that.create_refresh_command = function() {

        var command = that.search_facet_create_refresh_command();

        command.set_option('type', that.group_type);

        return command;
    };

    return that;
};

IPA.automember.rule_details_facet = function(spec) {

    spec = spec || {};

    spec.fields = [
        {
            name: 'cn',
            widget: 'general.cn'
        },
        {
            type: 'textarea',
            name: 'description',
            widget: 'general.description'
        },
        {
            type: 'automember_condition',
            name: 'automemberinclusiveregex',
            widget: 'inclusive.automemberinclusiveregex'
        },
        {
            type: 'automember_condition',
            name: 'automemberexclusiveregex',
            widget: 'exclusive.automemberexclusiveregex'
        }
    ];

    spec.widgets = [
            {
            type: 'details_table_section',
            name: 'general',
            label: IPA.messages.details.general,
            widgets: [
                {
                    name: 'cn'
                },
                {
                    type: 'textarea',
                    name: 'description'
                }
            ]
        },
        {
            factory: IPA.collapsible_section,
            name: 'inclusive',
            label: 'Inclusive', //TODO:translate
            widgets: [
                {
                    type: 'automember_condition',
                    name: 'automemberinclusiveregex',
                    group_type: spec.group_type,
                    add_command: 'add_condition',
                    remove_command: 'remove_condition',
                    adder_dialog: {
                        title: 'Add Condition to ${pkey}', //TODO: translate
                        fields: [
                            {
                                name: 'key',
                                type: 'select',
                                options: IPA.automember.get_condition_attributes(spec.group_type),
                                label: 'Attribute' //TODO: translate
                            },
                            {
                                name: 'automemberinclusiveregex',
                                label: 'Expression' //TODO: translate
                            }
                        ]
                    }
                }
            ]
        },
        {
            factory: IPA.collapsible_section,
            name: 'exclusive',
            label: 'Exclusive', //TODO:translate
            widgets: [
                {
                    type: 'automember_condition',
                    name: 'automemberexclusiveregex',
                    group_type: spec.group_type,
                    add_command: 'add_condition',
                    remove_command: 'remove_condition',
                    adder_dialog: {
                        title: 'Add Condition to ${pkey}', //TODO: translate
                        fields:  [
                            {
                                name: 'key',
                                type: 'select',
                                options: IPA.automember.get_condition_attributes(spec.group_type),
                                label: 'Attribute' //TODO: translate
                            },
                            {
                                name: 'automemberexclusiveregex',
                                label: 'Expression' //TODO: translate
                            }
                        ]
                    }
                }
            ]
        }
    ];

    var that = IPA.details_facet(spec);

    that.group_type = spec.group_type;

    that.get_refresh_command_name = function() {
        return that.entity.name+that.group_type+'_show';
    };

    that.create_refresh_command = function() {

        var command = that.details_facet_create_refresh_command();
        command.set_option('type', that.group_type);

        return command;
    };

    that.create_update_command = function() {

        var command = that.details_facet_create_update_command();
        command.set_option('type', that.group_type);

        return command;
    };

    return that;
};

IPA.automember.rule_adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.entity_adder_dialog(spec);

    that.reset = function() {

        var field = that.fields.get_field('cn');
        var facet = IPA.current_entity.get_facet();

        field.widget.other_entity = IPA.get_entity(facet.group_type);

        that.dialog_reset();
    };

    that.create_add_command = function(record) {

        var facet = IPA.current_entity.get_facet();
        var command = that.entity_adder_dialog_create_add_command(record);
        command.name = that.entity.name+facet.group_type+'_show';
        command.set_option('type', facet.group_type);

        return command;
    };

    return that;
};

IPA.automember.rule_deleter_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.search_deleter_dialog(spec);

    that.create_command = function() {

        var facet = IPA.current_entity.get_facet();

        var batch = that.search_deleter_dialog_create_command();

        for (var i=0; i<batch.commands.length; i++) {
            var command = batch.commands[i];
            command.set_option('type', facet.group_type);
        }

        return batch;
    };

    return that;
};

IPA.automember.get_condition_attributes = function(type) {
    var options = [];

    if (type === 'group') {
        options = IPA.metadata.objects.user.aciattrs;
    } else if (type === 'hostgroup') {
        options = IPA.metadata.objects.host.aciattrs;
    }

    var list_options = IPA.create_options(options);
    return list_options;
};

IPA.automember.parse_condition_regex = function(regex) {

    var delimeter_index = regex.indexOf('=');
    var condition = {
        condition: regex,
        attribute: regex.substring(0, delimeter_index),
        expression: regex.substring(delimeter_index+1)
    };

    return condition;
};

IPA.automember.condition_field = function(spec) {

    spec = spec || {};
    var that = IPA.field(spec);

    that.attr_name = spec.attribute || that.name;

    that.load = function(record) {

        var regexes = record[that.attr_name];
        that.values = [];

        if (regexes) {
            for (var i=0, j=0; i<regexes.length; i++) {
                var condition = IPA.automember.parse_condition_regex(regexes[i]);
                that.values.push(condition);
            }
        }

        that.load_writable(record);
        that.reset();
    };

    return that;
};

IPA.field_factories['automember_condition'] = IPA.automember.condition_field;

IPA.automember.condition_widget = function(spec) {

    spec = spec || {};

    spec.columns = $.merge(spec.columns || [], [
        {
            name: 'attribute',
            label: 'Attribute'//TODO:translate
        },
        {
            name: 'expression',
            label: 'Expression'//TODO:translate
        }
    ]);

    spec.value_attribute = 'condition';

    var that = IPA.attribute_table_widget(spec);

    that.group_type = spec.group_type;

    that.get_additional_options = function() {
        return [
            {
                name: 'type',
                value: that.group_type
            }
        ];
    };

    that.on_add = function(data) {

        if (data.result.completed === 0) {
            that.refresh_facet();
        } else {
            that.reload_facet(data);
        }
    };

    that.on_remove = function(data) {

        var results = data.result.results;

        var i = results.length - 1;
        while (i >= 0) {
            if (results[i].completed === 1){
                that.reload_facet({ result: results[i] });
                return;
            }
            i--;
        }

        that.refresh_facet();
    };

    that.create_remove_command = function(values, on_success, on_error) {

        var batch = IPA.batch_command({
            name: 'automember_remove_condition',
            on_success: on_success,
            on_error: on_error
        });

        var pkeys = that.get_pkeys();

        for (var i=0; i<values.length; i++) {
            var condition = IPA.automember.parse_condition_regex(values[i]);

            var command = that.attribute_table_create_remove_command([]);
            command.set_option('key', condition.attribute);
            command.set_option(that.attribute_name, condition.expression);

            batch.add_command(command);
        }

        return batch;
    };

    return that;
};

IPA.widget_factories['automember_condition'] = IPA.automember.condition_widget;

IPA.register('automember', IPA.automember.entity);