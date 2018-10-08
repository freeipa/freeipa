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

define([
    'dojo/_base/declare',
    './field',
    './metadata',
    './ipa',
    './jquery',
    './navigation',
    './phases',
    './reg',
    './rpc',
    './text',
    './details',
    './search',
    './association',
    './entity'],
    function(declare, field_mod, metadata_provider, IPA, $, navigation,
        phases, reg, rpc, text) {

var exp = IPA.automember = {};

var make_spec = function() {
return {

    name: 'automember',

    policies:[
        {
            $factory: IPA.facet_update_policy,
            source_facet: 'usergrouprule',
            dest_facet: 'searchgroup'
        },
        {
            $factory: IPA.facet_update_policy,
            source_facet: 'hostgrouprule',
            dest_facet: 'searchhostgroup'
        }
    ],
    facets: [
        {
            $factory: IPA.automember.rule_search_facet,
            $type: 'search',
            name: 'searchgroup',
            group_type: 'group',
            label: '@i18n:objects.automember.usergrouprules',
            details_facet: 'usergrouprule',
            pagination: false,
            columns: [
                'cn',
                'description'
            ]
        },
        {
            $factory: IPA.automember.rule_search_facet,
            $type: 'search',
            name: 'searchhostgroup',
            group_type: 'hostgroup',
            label: '@i18n:objects.automember.hostgrouprules',
            details_facet: 'hostgrouprule',
            pagination: false,
            columns: [
                'cn',
                'description'
            ]
        },
        {
            $factory: IPA.automember.rule_details_facet,
            $type: 'details',
            name: 'usergrouprule',
            group_type: 'group',
            label: '@i18n:objects.automember.usergrouprule',
            disable_facet_tabs: true,
            check_rights: false,
            redirect_info: { facet: 'searchgroup' }
        },
        {
            $factory: IPA.automember.rule_details_facet,
            $type: 'details',
            name: 'hostgrouprule',
            group_type: 'hostgroup',
            label: '@i18n:objects.automember.hostgrouprule',
            disable_facet_tabs: true,
            check_rights: false,
            redirect_info: { facet: 'searchhostgroup' }
        }
    ],
    adder_dialog: {
        $factory: IPA.automember.rule_adder_dialog,
        title: '@i18n:objects.automember.add',
        fields: [
            {
                $type: 'entity_select',
                name: 'cn',
                other_entity: 'group',
                other_field: 'cn'
            }
        ],
        height: '300'
    },
    deleter_dialog: {
        title: '@i18n:objects.automember.remove',
        $factory: IPA.automember.rule_deleter_dialog
    }
};};

exp.metadata_extension_pre_op = function(spec, context) {
    //HACK: Automember takes_params is missing a cn attribute. This hack
    //copies cn from mod command. Also it is set as pkey.
    var metadata = metadata_provider.source;
    var pkey_attr = metadata.commands.automember_mod.takes_args[0];
    pkey_attr.primary_key = true;
    metadata.objects.automember.takes_params.push(pkey_attr);
    metadata.objects.automember.primary_key = pkey_attr.name;
    return spec;
};

IPA.automember.rule_search_facet = function(spec) {

    spec = spec || {};

    var that = IPA.search_facet(spec);

    that.group_type = spec.group_type;

    var init = function() {

        that.default_group_widget = IPA.automember.default_group_widget({
            entity: that.entity,
            group_type: that.group_type
        });
    };

    that.refresh = function() {

        that.search_facet_refresh();
        that.default_group_widget.refresh();
    };


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

    that.create_get_records_command = function(records, pkeys, on_success, on_error) {

        var batch = that.table_facet_create_get_records_command(records, pkeys,
                                                        on_success, on_error);

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

    that.create_content = function(container) {

        var header = $('<div/>', {
            'class': 'automember-header'
        }).appendTo(container);

        var content = $('<div/>', {
            'class': 'automember-content'
        }).appendTo(container);

        that.default_group_widget.create(header);
        that.table.create(content);
    };

    that.show_add_dialog = function() {
        var dialog = that.managed_entity.get_dialog('add');
        if (!that.adder_dialog) {
            that.adder_dialog = dialog;
            dialog.added.attach(function() {
                that.refresh();
            });
        }
        dialog.pkey_prefix = that.managed_entity_pkey_prefix();
        dialog.group_type = that.group_type;
        dialog.open();
    };

    that.create_remove_dialog = function() {
        var dialog = that.search_facet_create_remove_dialog();
        dialog.group_type = that.group_type;
        return dialog;
    };

    init();

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
            $type: 'textarea',
            name: 'description',
            widget: 'general.description'
        },
        {
            $type: 'automember_condition',
            name: 'automemberinclusiveregex',
            widget: 'inclusive.automemberinclusiveregex'
        },
        {
            $type: 'automember_condition',
            name: 'automemberexclusiveregex',
            widget: 'exclusive.automemberexclusiveregex'
        }
    ];

    spec.widgets = [
            {
            $type: 'details_section',
            name: 'general',
            label: '@i18n:details.general',
            widgets: [
                {
                    name: 'cn'
                },
                {
                    $type: 'textarea',
                    name: 'description'
                }
            ]
        },
        {
            $factory: IPA.section,
            name: 'inclusive',
            label: '@i18n:objects.automember.inclusive',
            widgets: [
                {
                    $type: 'automember_condition',
                    name: 'automemberinclusiveregex',
                    group_type: spec.group_type,
                    add_command: 'add_condition',
                    remove_command: 'remove_condition',
                    adder_dialog: {
                        title: '@i18n:objects.automember.add_inc_condition',
                        fields: [
                            {
                                name: 'key',
                                $type: 'select',
                                options: IPA.automember.get_condition_attributes(spec.group_type),
                                label: '@i18n:objects.automember.attribute'
                            },
                            {
                                name: 'automemberinclusiveregex',
                                label: '@i18n:objects.automember.expression',
                                required: true
                            }
                        ]
                    },
                    deleter_dialog: {
                        title: '@i18n:objects.automember.remove_inc_conditions'
                    }
                }
            ]
        },
        {
            $factory: IPA.section,
            name: 'exclusive',
            label: '@i18n:objects.automember.exclusive',
            widgets: [
                {
                    $type: 'automember_condition',
                    name: 'automemberexclusiveregex',
                    group_type: spec.group_type,
                    add_command: 'add_condition',
                    remove_command: 'remove_condition',
                    adder_dialog: {
                        title: '@i18n:objects.automember.add_exc_condition',
                        fields:  [
                            {
                                name: 'key',
                                $type: 'select',
                                options: IPA.automember.get_condition_attributes(spec.group_type),
                                label: '@i18n:objects.automember.attribute'
                            },
                            {
                                name: 'automemberexclusiveregex',
                                label: '@i18n:objects.automember.expression',
                                required: true
                            }
                        ]
                    },
                    deleter_dialog: {
                        title: '@i18n:objects.automember.remove_exc_conditions'
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
    that.group_type = spec.group_type || '';

    that.show_edit_page = function (entity,result) {
        var pkey_name = entity.metadata.primary_key;
        var pkey = result[pkey_name];
        if (pkey instanceof Array) {
            pkey = pkey[0];
        }

        var facetname = that.group_type === 'group' ? 'usergrouprule' :
                            'hostgrouprule';

        navigation.show_entity(that.entity.name, facetname, [pkey]);
    };

    that.reset = function() {

        var field = that.fields.get_field('cn');

        field.widget.other_entity = IPA.get_entity(that.group_type);

        that.dialog_reset();
    };

    that.create_add_command = function(record) {

        var command = that.entity_adder_dialog_create_add_command(record);
        command.name = that.entity.name+that.group_type+'_show';
        command.set_option('type', that.group_type);

        return command;
    };


    return that;
};

IPA.automember.rule_deleter_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.search_deleter_dialog(spec);
    that.group_type = spec.group_type || '';

    that.create_command = function() {

        var batch = that.search_deleter_dialog_create_command();

        for (var i=0; i<batch.commands.length; i++) {
            var command = batch.commands[i];
            command.set_option('type', that.group_type);
        }

        return batch;
    };

    return that;
};

IPA.automember.get_condition_attributes = function(type) {
    var options = [];

    if (type === 'group') {
        options = metadata_provider.get('@mo:user.aciattrs');
    } else if (type === 'hostgroup') {
        options = metadata_provider.get('@mo:host.aciattrs');
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
    spec.adapter = spec.adapter || IPA.automember.condition_adapter;
    var that = IPA.field(spec);
    return that;
};

IPA.automember.condition_adapter = declare([field_mod.Adapter], {

    load: function(data) {
        var regexes = this.inherited(arguments);
        var values = [];
        if (regexes) {
            for (var i=0, j=0; i<regexes.length; i++) {
                if (regexes[i] === '') continue;
                var condition = IPA.automember.parse_condition_regex(regexes[i]);
                values.push(condition);
            }
        }
        return values;
    }
});

IPA.automember.condition_widget = function(spec) {

    spec = spec || {};
    spec.footer = spec.footer === undefined ? false : spec.footer;

    spec.columns = $.merge(spec.columns || [], [
        {
            name: 'attribute',
            label: '@i18n:objects.automember.attribute'
        },
        {
            name: 'expression',
            label: '@i18n:objects.automember.expression'
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
                that.reload_facet({ error: results[i].error, id: null,
                                    result: results[i] });
                return;
            }
            i--;
        }

        that.refresh_facet();
    };

    that.create_remove_command = function(values, on_success, on_error) {

        var batch = rpc.batch_command({
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

IPA.automember.default_group_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);
    that.group_type = spec.group_type;
    that.group = '';

    var init = function() {

        that.group_select = IPA.entity_select_widget({
            name: 'automemberdefaultgroup',
            other_entity: that.group_type,
            other_field: 'cn',
            show_undo: false
        });

        that.group_select.value_changed.attach(that.group_changed);
    };

    that.get_group = function() {

        var group = that.group_select.save();
        group = group.length === 0 ? '' : group[0];
        return group;
    };

    that.set_group = function(group) {

        if (group === that.group) return;

        that.group = group;
        that.group_select.update([group]);
    };

    that.group_changed = function() {

        var group = that.get_group();

        if (group === that.group) return;

        if (group === '') {
            that.remove_default_group();
        } else {
            that.set_default_group(group);
        }
    };

    that.load = function(data) {

        var group = data.result.result.automemberdefaultgroup;

        if (group) group = group[0];

        if (!group || group.indexOf('cn=') === -1) {
            group = '';
        } else {
            //extract from dn
            var i1 = group.indexOf('=');
            var i2 = group.indexOf(',');
            if (i1 > -1 && i2 > -1) {
                group = group.substring(i1 + 1,i2);
            }
        }

        that.update(group);
        that.set_visible(true);
    };

    that.update = function(group) {

        group = group || '';

        that.set_group(group);
    };

    that.create_command = function(method) {

        method = 'default_group_' + method;
        var command_name = that.entity.name + that.group_type + '_' + method;

        var command  = rpc.command({
            name: command_name,
            entity: that.entity.name,
            method: method,
            options: {
                type: that.group_type
            }
        });

        return command;
    };

    that.refresh = function() {

        var command = that.create_command('show');
        command.retry = false;
        command.on_success = that.load;
        command.on_error = function() {
            that.set_visible(false);
        };

        command.execute();
    };

    that.remove_default_group = function() {

        var command = that.create_command('remove');

        command.on_success = function() {
            that.update('');
        };
        command.on_error = that.refresh;

        command.execute();
    };

    that.set_default_group = function(group) {

        var command = that.create_command('set');
        command.on_success = that.load;
        command.on_error = that.refresh;
        command.set_option('automemberdefaultgroup', group);

        command.execute();
    };


    that.create = function(container) {

        var title = that.get_title();
        that.container = container;

        that.header = $('<div/>', {
            'class': 'automember-header-label',
            name: 'header',
            text: title,
            title: title
        }).appendTo(container);

        that.group_select_node = $('<div/>', {
            'class': 'automember-header-control',
            name: that.group_select.name
        });
        that.group_select.create(that.group_select_node);
        that.group_select_node.appendTo(container);
        that.group_select.update([]); // preload groups
        that.set_visible(false);
    };

    that.get_title = function() {
        if (that.group_type === 'group') {
            return text.get('@i18n:objects.automember.default_user_group');
        } else {
            return text.get('@i18n:objects.automember.default_host_group');
        }
    };

    init();

    return that;
};

IPA.automember.rebuild_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'automember_rebuild';
    spec.label = spec.label || '@i18n:actions.automember_rebuild';
    spec.needs_confirm = spec.needs_confirm !== undefined ? spec.needs_confirm : true;
    spec.confirm_msg = spec.confirm_msg || '@i18n:actions.automember_rebuild_confirm';

    var that = IPA.action(spec);

    that.execute_action = function(facet) {
        var entity = facet.entity.name;
        if (facet.name == 'search') {
            var entries = facet.get_selected_values();
        } else {
            entries = facet.get_pkeys();
        }

        var options = {};
        if (entries.length > 0) {
            options[entity + 's'] = entries;
        } else if (entity == 'user') {
            options['type'] = 'group';
        } else {
            options['type'] = 'hostgroup';
        }

        var command = rpc.command({
            entity: 'automember',
            method: 'rebuild',
            options: options,
            on_success: function() {
                IPA.notify_success('@i18n:actions.automember_rebuild_success');
            },
            on_error: function() {
            }
        });

        command.execute();
    };

    return that;
};

exp.entity_spec = make_spec();

exp.register = function() {
    var e = reg.entity;
    var w = reg.widget;
    var f = reg.field;
    var a = reg.action;

    e.register({
        type: 'automember',
        spec: exp.entity_spec,
        pre_ops: [ exp.metadata_extension_pre_op ]
    });
    w.register('automember_condition', IPA.automember.condition_widget);
    f.register('automember_condition', IPA.automember.condition_field);
    a.register('automember_rebuild', exp.rebuild_action);
};

phases.on('registration', exp.register);

return exp;
});
