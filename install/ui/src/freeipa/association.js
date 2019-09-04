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

/* CURRENTLY ALSO REQUIRES search.js, because it reuses it's code to create
 * the AssociationList elements; IT NEEDS IT'S OWN CODE! */

define([
    'dojo/_base/lang',
    'dojo/Deferred',
    './metadata',
    './ipa',
    './jquery',
    './metadata',
    './navigation',
    './phases',
    './reg',
    './rpc',
    './spec_util',
    './text',
    './facet',
    './search',
    './dialog'],
        function(lang, Deferred, metadata_provider, IPA, $, metadata,
                 navigation, phases, reg, rpc, su, text) {

/**
 * Association module
 * @class association
 * @singleton
 */
var exp = {};

/**
 * Associator base class
 * @class
 */
IPA.associator = function (spec) {

    spec = spec || {};

    var that = IPA.object();

    that.entity = IPA.get_entity(spec.entity);
    that.pkey = spec.pkey;

    that.other_entity = IPA.get_entity(spec.other_entity);
    that.values = spec.values;

    that.method = spec.method;

    that.on_success = spec.on_success;
    that.on_error = spec.on_error;

    that.execute = function() {
    };

    return that;
};


/**
 * Serial associator
 * This associator is built for the case where each association requires a separate rpc
 * @class
 * @extends IPA.associator
 */
IPA.serial_associator = function(spec) {

    spec = spec || {};

    var that = IPA.associator(spec);

    that.execute = function() {

        if (!that.values || !that.values.length) {
            that.on_success();
            return;
        }

        var batch = rpc.batch_command({
            on_success: that.on_success,
            on_error: that.on_error
        });

        var args, options, command;

        for(var i=0; i < that.values.length; i++) {
            args = [that.values[i]];
            options = {};
            options[that.entity.name] = that.pkey;

            command = rpc.command({
                entity: that.other_entity.name,
                method: that.method,
                args: args,
                options: options
            });

            batch.add_command(command);
        }
        //window.alert(JSON.stringify(command.to_json()));

        batch.execute();
    };

    return that;
};

/**
 * This associator is for the common case where all the asociations can be sent
 * in a single rpc
 * @class
 */
IPA.bulk_associator = function(spec) {

    spec = spec || {};

    var that = IPA.associator(spec);
    that.options = spec.options || { 'all': true };

    that.execute = function() {

        if (!that.values || !that.values.length) {
            that.on_success();
            return;
        }

        var command = rpc.command({
            entity: that.entity.name,
            method: that.method,
            args: [that.pkey],
            options: that.options,
            on_success: that.on_success,
            on_error: that.on_error
        });

        command.set_option(that.other_entity.name, that.values);

        //window.alert(JSON.stringify(command.to_json()));

        command.execute();
    };

    return that;
};

/**
 * This dialog is for adding value of multivalued attribute which behaves like
 * association attribute.
 * @class
 * @extends IPA.entity_adder_dialog
 */
IPA.attribute_adder_dialog = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'attr_adder_dialog';
    spec.method = spec.method || 'add_member';

    var metadata = IPA.get_command_option(spec.entity.name+'_'+spec.method, spec.attribute);

    spec.fields = spec.fields || [
        {
            name: spec.attribute,
            metadata: metadata,
            required: true
        }
    ];
    spec.title = spec.title || text.get('@i18n:dialogs.add_title_default');
    spec.subject = metadata.label;

    var that = IPA.entity_adder_dialog(spec);
    that.pkeys = spec.pkeys || [];

    that.create_add_command = function(record) {

        var command = that.entity_adder_dialog_create_add_command(record);

        command.add_args(that.pkeys);

        return command;
    };

    that.create_buttons = function() {

        that.buttons.remove('add_and_edit');
    };

    that.on_add = function() {

        that.hide_message();
        that.add(
            function(data, text_status, xhr) {
                if (data.result.completed > 0) {
                    that.added.notify();
                    that.close();
                    that.notify_success(data);
                }
            },
            that.on_error);
    };

    that.create_buttons();

    return that;
};

/**
 * This dialog is used for adding associations between two entities.
 * @class
 * @extends IPA.adder_dialog
 */
IPA.association_adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.adder_dialog(spec);

    that.entity = IPA.get_entity(spec.entity);
    that.pkey = spec.pkey;

    /**
     * Map of options for search method
     * @property {Object}
     */
    that.search_options = spec.search_options;

    that.other_entity = IPA.get_entity(spec.other_entity);
    that.attribute_member = spec.attribute_member;

    that.exclude = spec.exclude || [];

    var init = function() {
        if (!that.get_columns().length) {
            var pkey_name = that.other_entity.metadata.primary_key;
            that.create_column({
                entity: that.entity,
                name: pkey_name,
                label: that.other_entity.metadata.label,
                primary_key: true,
                width: '600px'
            });
        }
    };

    that.search = function() {
        function on_success(data, text_status, xhr) {

            that.clear_available_values();

            var pkey_attr = that.other_entity.metadata.primary_key;

            var selected = that.normalize_values(that.get_selected_values());
            var exclude = that.normalize_values(that.exclude);

            var results = data.result;
            var same_entity = that.entity === that.other_entity;
            for (var i=0; i<results.count; i++) {
                var result = results.result[i];
                var pkey = result[pkey_attr][0];

                if (same_entity && pkey === that.pkey) continue;
                pkey = that.normalize_values([pkey])[0];
                if (exclude.indexOf(pkey) >= 0) continue;
                if (selected.indexOf(pkey) >= 0) continue;

                that.add_available_value(result);
            }
        }

        var options = {};
        if (that.search_options) {
            lang.mixin(options, that.search_options);
        }

        var relationships = that.other_entity.metadata.relationships;

        /* TODO: better generic handling of different relationships! */
        var other_attribute_member = '';
        if (that.attribute_member == 'member')
            other_attribute_member = 'memberof';
        else if (that.attribute_member == 'memberuser')
            other_attribute_member = 'memberof';
        else if (that.attribute_member == 'memberhost')
            other_attribute_member = 'memberof';
        else if (that.attribute_member == 'memberof')
            other_attribute_member = 'member';
        else if (that.attribute_member == 'managedby')
            other_attribute_member = 'managing';

        var relationship = relationships[other_attribute_member];
        if (relationship) {
            var param_name = relationship[2] + that.entity.name;
            var cmd_opt = IPA.get_command_option(that.other_entity.name + '_find',
                                                 param_name);
            if (cmd_opt) {
                options[param_name] = that.pkey;
            }
        }

        var cmd = rpc.command({
            entity: that.other_entity.name,
            method: 'find',
            args: [that.get_filter()],
            options: options,
            on_success: on_success
        });

        var no_members = metadata.get('@mc-opt:' + cmd.get_command() + ':no_members');
        if (no_members) {
            cmd.set_option('no_members', true);
        }
        cmd.execute();
    };

    that.normalize_values = function(values) {
        var norm = [];
        for (var i=0; i<values.length;i++) {
            norm.push(values[i].toLowerCase());
        }
        return norm;
    };

    init();

    return that;
};


/**
 * This dialog is used for removing associations between two entities.
 * @class
 * @extends IPA.deleter_dialog
 */
IPA.association_deleter_dialog = function (spec) {

    spec = spec || {};

    var that = IPA.deleter_dialog(spec);

    that.entity = IPA.get_entity(spec.entity);
    that.pkey = spec.pkey;

    that.other_entity = IPA.get_entity(spec.other_entity);
    that.values = spec.values;

    that.associator = spec.associator;
    that.method = spec.method || 'remove_member';

    that.on_success = spec.on_success;
    that.on_error = spec.on_error;

    that.execute = function() {

        var associator = that.associator({
            entity: that.entity,
            pkey: that.pkey,
            other_entity: that.other_entity,
            values: that.values,
            method: that.method,
            on_success: that.on_success,
            on_error: that.on_error
        });

        associator.execute();
    };

    return that;
};

/**
 * Association config
 * @class
 */
IPA.association_config = function (spec) {

    spec = spec || {};

    var that = IPA.object();

    that.name = spec.name;
    that.associator = spec.associator;
    that.add_method = spec.add_method;
    that.remove_method = spec.remove_method;

    return that;
};

/**
 * Association table widget
 * @class
 * @extends IPA.table_widget
 */
IPA.association_table_widget = function (spec) {

    spec = spec || {};

    var index = spec.name.lastIndexOf('_');
    spec.attribute_member = spec.attribute_member || spec.name.substring(0, index);
    spec.other_entity = spec.other_entity || spec.name.substring(index+1);

    spec.managed_entity = IPA.get_entity(spec.other_entity);

    var that = IPA.table_widget(spec);

    /**
     * The value should be name of the field, which will be added to *_add_*,
     * *_del_* commands as option: {fieldname: fieldvalue}.
     *
     * @property {String} fieldname
     */
    that.additional_add_del_field = spec.additional_add_del_field;

    /**
     * Can be used in situations when the *_add_member command needs entity
     * as a parameter, but parameter has different name than entity.
     * i.e. vault_add_member --services=[values] ... this needs values from service
     * entity, but option is called services, that we can set by setting
     * this option in spec to other_option_name: 'services'
     *
     * @property {String} other_option_name
     */
    that.other_option_name = spec.other_option_name;

    /**
     * Entity which is added into member table.
     *
     * @property {String} other_entity
     */
    that.other_entity = IPA.get_entity(spec.other_entity);
    that.attribute_member = spec.attribute_member;

    that.associator = spec.associator || IPA.bulk_associator;
    that.add_method = spec.add_method || 'add_member';
    that.remove_method = spec.remove_method || 'remove_member';

    that.read_only = spec.read_only === undefined ? false : spec.read_only;
    that.add_title = text.get(spec.add_title);
    that.remove_title = text.get(spec.remove_title);

    that.adder_columns = $.ordered_map();

    that.needs_refresh = IPA.observer();

    that.get_adder_column = function(name) {
        return that.adder_columns.get(name);
    };

    that.add_adder_column = function(column) {
        that.adder_columns.put(column.name, column);
    };

    that.create_adder_column = function(spec) {
        spec.entity = that.other_entity;
        var column = IPA.column(spec);
        that.add_adder_column(column);
        return column;
    };

    that.create_columns = function() {
        // create a column if none defined
        if (!that.columns.length) {
            that.create_column({
                name: that.name,
                label: that.label,
                entity: that.other_entity,
                primary_key: true,
                link: true
            });
        }
    };

    that.init_columns = function() {
        var column;
        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++) {
            column = columns[i];
            column.entity = that.other_entity;

            if (column.link) {
                column.link_handler = function(value) {
                    navigation.show_entity(that.other_entity.name, 'default', [value]);
                    return false;
                };
            }
        }
    };

    that.init_adder_columns = function() {
        var column;
        var adder_columns = that.adder_columns.values;
        for (var j=0; j<adder_columns.length; j++) {
            column = adder_columns[j];
            column.entity = that.other_entity;
        }
    };

    that.init = function() {

        that.create_columns();
        that.init_columns();
        that.init_adder_columns();
    };

    that.create = function(container) {

        that.init();

        that.table_create(container);

        if (that.read_only) return;

        that.remove_button = IPA.button_widget({
            name: 'remove',
            label: '@i18n:buttons.remove',
            icon: 'fa-trash-o',
            enabled: false,
            button_class: 'btn btn-link',
            click: that.remove_handler
        });
        that.remove_button.create(that.buttons);

        that.add_button = IPA.button_widget({
            name: 'add',
            label: '@i18n:buttons.add',
            icon: 'fa-plus',
            button_class: 'btn btn-link',
            click: that.add_handler
        });
        that.add_button.create(that.buttons);
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

            dialog.open();

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

            dialog.open();

        } else {
            that.show_remove_dialog();
        }
    };

    that.set_enabled = function(enabled) {
        that.table_set_enabled(enabled);
        if (!enabled) {
            that.unselect_all();
        }
        if (that.add_button) {
            that.add_button.set_enabled(enabled);
            that.remove_button.set_enabled(false);
        }
    };

    that.select_changed = function() {

        var values = that.get_selected_values();

        if (that.remove_button) {
            that.remove_button.set_enabled(values.length > 0);
        }
    };

    that.load = function(result) {
        that.values = result[that.name] || [];
        that.update();
        that.unselect_all();
    };

    that.update = function(values) {

        if (values) that.values = values;

        that.empty();

        var i;
        var columns = that.columns.values;
        if (columns.length == 1) { // show pkey only
            var name = columns[0].param;
            for (i=0; i<that.values.length; i++) {
                var record = {};
                record[name] = that.values[i];
                that.add_record(record);
            }
        } else {
            for (i=0; i<that.values.length; i++) {
                that.add_record(that.values[i]);
            }
        }
    };

    that.create_add_dialog = function() {

        var pkey = that.facet.get_pkey();

        var title = that.add_title;
        title = title.replace('${primary_key}', pkey);

        return IPA.association_adder_dialog({
            title: title,
            entity: that.entity,
            pkey: pkey,
            other_entity: that.other_entity,
            attribute_member: that.attribute_member,
            method: that.add_method,
            exclude: that.values
        });
    };

    that.show_add_dialog = function() {

        var dialog = that.create_add_dialog({entity:that.entity});

        var columns = that.adder_columns.values;
        if (columns.length) {
            dialog.set_columns(columns);
        }

        dialog.execute = function() {
            that.add(
                dialog.get_selected_values(),
                function(data) {
                    that.refresh();
                    that.facet.refresh();
                    dialog.close();

                    var succeeded = IPA.get_succeeded(data);
                    var msg = text.get('@i18n:association.added').replace('${count}', succeeded);
                    IPA.notify_success(msg);
                },
                function() {
                    that.refresh();
                    that.facet.refresh();
                    dialog.close();
                }
            );
        };

        dialog.open();
    };

    that.add = function(values, on_success, on_error) {

        var pkey = that.facet.get_pkey();

        var command = rpc.command({
            entity: that.entity.name,
            method: that.add_method,
            args: [pkey],
            on_success: on_success,
            on_error: on_error
        });

        that.join_additional_option(command);
        that.handle_entity_option(command, values);

        command.execute();
    };

    that.join_additional_option = function(command) {
        var add_opt = that.additional_add_del_field;
        if (add_opt && typeof add_opt === 'string') {
            var opt_field = that.entity.facet.get_field(add_opt);
            var value;
            if (opt_field) value = opt_field.get_value()[0];

            command.set_option(add_opt, value);
        }
    };

    that.handle_entity_option = function(command, values) {
        var option_name = that.other_option_name;
        if (!option_name) {
            option_name = that.other_entity.name;
        }
        command.set_option(option_name, values);
    };

    that.show_remove_dialog = function() {

        var selected_values = that.get_selected_values();

        if (!selected_values.length) {
            var message = text.get('@i18n:dialogs.remove_empty');
            window.alert(message);
            return;
        }

        var pkey = that.facet.get_pkey();

        var title = that.remove_title;
        title = title.replace('${primary_key}', pkey);

        var dialog = IPA.association_deleter_dialog({
            title: title,
            entity: that.entity,
            pkey: pkey,
            other_entity: that.other_entity,
            values: selected_values,
            method: that.remove_method
        });

        dialog.execute = function() {
            that.remove(
                selected_values,
                function(data) {
                    that.refresh();

                    var succeeded = IPA.get_succeeded(data);
                    var msg = text.get('@i18n:association.removed').replace('${count}', succeeded);
                    IPA.notify_success(msg);
                },
                function() {
                    that.refresh();
                }
            );
        };

        dialog.open();
    };

    that.remove = function(values, on_success, on_error) {

        var pkey = that.facet.get_pkey();

        var command = rpc.command({
            entity: that.entity.name,
            method: that.remove_method,
            args: [pkey],
            on_success: on_success,
            on_error: on_error
        });

        that.join_additional_option(command);
        that.handle_entity_option(command, values);

        command.execute();
    };

    that.refresh = function() {

        that.needs_refresh.notify([], that);
    };

    /*initialization code*/
    /*this is duplicated in the facet... should be unified*/
    var i;
    if (spec.columns){
        for (i = 0; i < spec.columns.length; i+= 1){
            spec.columns[i].entity = spec.columns[i].entity || that.other_entity;
            that.create_column(spec.columns[i]);
        }
    }
    if (spec.adder_columns){
        for (i = 0; i < spec.adder_columns.length; i+= 1){
            that.create_adder_column(spec.adder_columns[i]);
        }
    }

    // methods that should be invoked by subclasses
    that.association_table_widget_create_columns = that.create_columns;
    that.association_table_widget_show_add_dialog = that.show_add_dialog;
    that.association_table_widget_show_remove_dialog = that.show_remove_dialog;

    return that;
};

/**
 * Association table field
 * @class
 * @extends IPA.field
 */
IPA.association_table_field = function (spec) {

    spec = spec || {};

    /**
     * Turn off decision whether the field is writable according to metadata.
     * The source of rights will be only ACLs.
     *
     * @property {Boolean}
     */
    spec.check_writable_from_metadata = spec.check_writable_from_metadata === undefined ?
                        false : spec.check_writable_from_metadata;

    var that = IPA.field(spec);

    /**
     * In case that facet has a state attribute set this is the way how to user
     * that attribute in refresh command as option in format:
     * {attributename: attributevalue}.
     *
     * @property {String}
     */
    that.refresh_attribute = spec.refresh_attribute || '';

    that.load = function(data) {
        that.values = that.adapter.load(data);
        that.widget.update(that.values);
        that.widget.unselect_all();

        if (!!that.acl_param) {
            var record = that.adapter.get_record(data);
            that.load_writable(record);
            that.handle_acl();
        }
    };

    that.handle_acl = function() {
        if (!that.writable) that.widget.set_enabled(false);
    };

    that.refresh = function() {

        function on_success(data, text_status, xhr) {
            that.load(data.result.result);
        }

        function on_error(xhr, text_status, error_thrown) {
            that.widget.summary.text(error_thrown.name+': '+error_thrown.message);
        }

        var pkey = that.facet.get_pkey();
        var command = rpc.command({
            entity: that.entity.name,
            method: 'show',
            args: [pkey],
            options: { all: true, rights: true },
            on_success: on_success,
            on_error: on_error
        });

        var additional_option = that.facet.state[that.refresh_attribute];
        if (additional_option) command.set_option(that.refresh_attribute, additional_option);

        command.execute();
    };

    that.widgets_created = function() {

        that.field_widgets_created();
        that.widget.needs_refresh.attach(that.refresh);
    };

    return that;
};

/**
 * Association facet pre-op
 * @member association
 */
exp.association_facet_pre_op = function(spec, context) {

    var has_indirect_attribute_member = function(spec) {

        var indirect_members = entity.metadata.attribute_members[spec.attribute_member + 'indirect'];
        var has_indirect = !!(indirect_members && indirect_members.indexOf(spec.other_entity) > -1);
        return has_indirect;
    };

    su.context_entity(spec, context);
    var entity = reg.entity.get(spec.entity);

    var index = spec.name.lastIndexOf('_');
    spec.attribute_member = spec.attribute_member ||
        spec.name.substring(0, index);
    spec.other_entity = spec.other_entity ||
        spec.name.substring(index+1);

    if (!spec.associator) {
        // batch associator (default) calls entity_command, serial associator
        // calls other_entity_command --> if entity doesn't support the command,
        // switch associators to try the other_entity
        var add_command = spec.add_method || 'add_member';
        if (!metadata_provider.get('@mc:'+entity.name+'_'+add_command)) {
            spec.associator = IPA.serial_associator;
        }
    }

    spec.add_title = spec.add_title ||
                         '@i18n:association.add_title_default';
    spec.remove_title = spec.remove_title ||
                            '@i18n:association.remove_title_default';

    spec.facet_group = spec.facet_group || spec.attribute_member;

    spec.label = spec.label || entity.metadata.label_singular;

    spec.tab_label = spec.tab_label ||
                    metadata_provider.get('@mo:'+spec.other_entity+'.label') ||
                    spec.other_entity;

    if (has_indirect_attribute_member(spec)) {

        spec.indirect_attribute_member = spec.attribute_member + 'indirect';
    }

    if (spec.facet_group === 'memberindirect' ||
        spec.facet_group === 'memberofindirect') {

        spec.read_only = true;
    }

     /*
       Link parameter is used to turn off the links in self-service mode.
       Default it to true if not set so that facets that would not otherwise
       link by default get links set.

       link must be set before the call to the base class, to affect the table.
     */
    spec.link = spec.link === undefined ? true : spec.link;
    spec.managed_entity = IPA.get_entity(spec.other_entity);


    //default buttons and their actions
    spec.actions = spec.actions || [];
    spec.actions.unshift(
        'refresh',
        {
            name: 'remove',
            hide_cond: ['read-only'],
            show_cond: ['direct'],
            enable_cond: ['item-selected'],
            enabled: false,
            handler: function(facet) {
                facet.show_remove_dialog();
            }
        },
        {
            name: 'add',
            hide_cond: ['read-only'],
            show_cond: ['direct'],
            handler: function(facet) {
                facet.show_add_dialog();
            }
        }
    );

    spec.control_buttons = spec.control_buttons || [];
    spec.control_buttons.unshift(
        {
            name: 'refresh',
            label: '@i18n:buttons.refresh',
            icon: 'fa-refresh'
        },
        {
            name: 'remove',
            label: '@i18n:buttons.remove',
            icon: 'fa-trash-o'
        },
        {
            name: 'add',
            label: '@i18n:buttons.add',
            icon: 'fa-plus'
        });

    spec.state = spec.state || {};
    spec.state.evaluators = spec.state.evaluators || [];
    spec.state.evaluators.push(
        IPA.selected_state_evaluator,
        IPA.association_type_state_evaluator,
        IPA.read_only_state_evaluator);

    entity.policies.add_policy(IPA.build({
        $factory: IPA.facet_update_policy,
        source_facet: 'search',
        dest_facet: spec.name
    }));

    return spec;
};

/**
 * Association facet
 * @class association.association_facet
 * @alternateClassName IPA.association_facet
 * @extends facet.table_facet
 */
exp.association_facet = IPA.association_facet = function (spec, no_init) {

    spec = spec || {};

    var that = IPA.table_facet(spec, true);

    that.attribute_member = spec.attribute_member;
    that.indirect_attribute_member = spec.indirect_attribute_member;

    that.other_entity = IPA.get_entity(spec.other_entity);

    that.association_type = 'direct';
    that.facet_group = spec.facet_group;

    that.read_only = spec.read_only;
    that.show_values_with_dup_key = spec.show_values_with_dup_key || false;

    that.associator = spec.associator || IPA.bulk_associator;
    that.add_method = spec.add_method || 'add_member';
    that.remove_method = spec.remove_method || 'remove_member';

    that.add_title = text.get(spec.add_title);
    that.remove_title = text.get(spec.remove_title);

    that.adder_columns = $.ordered_map();

    /**
     * Map of search options for adder dialog
     * @property {Object}
     */
    that.search_options = spec.search_options;

    that.get_adder_column = function(name) {
        return that.adder_columns.get(name);
    };

    that.add_adder_column = function(column) {
        column.entity = that.other_entity;
        that.adder_columns.put(column.name, column);
    };

    /*TODO try to reuse the association_table_widget in association_facet*/
    that.create_adder_column = function(spec) {
        var column;
        var factory;
        if (spec instanceof Object) {
            factory = spec.$factory || IPA.column;
        } else {
            factory  = IPA.column;
            spec = { name: spec };
        }
        spec.entity = that.other_entity;
        column = factory(spec);
        that.add_adder_column(column);
        return column;
    };

    var init = function() {

        var column;
        var i;

        var pkey_name;
        if (that.other_entity) {
            pkey_name = that.other_entity.metadata.primary_key;
        }

        if (!that.columns.length){
            that.create_column({
                name: pkey_name
            });
        }

        var columns = that.columns.values;
        for (i=0; i<columns.length; i++) {
            column = columns[i];
            if (column.primary_key) column.link = spec.link;
        }

        that.init_table(that.other_entity);

        var adder_columns = spec.adder_columns || [];
        for (i=0; i<adder_columns.length; i++) {
            that.create_adder_column(adder_columns[i]);
        }

        if (!that.adder_columns.length) {
            that.create_adder_column({
                name: pkey_name,
                primary_key: true
            });
        }

        adder_columns = that.adder_columns.values;
        for (i=0; i<adder_columns.length; i++) {
            column = adder_columns[i];
            column.entity = that.other_entity;
        }
    };

    that.get_records_command_name = function() {
        return that.entity.name+'_'+that.get_attribute_name();
    };

    that.create_header = function(container) {

        that.facet_create_header(container);

        if (that.indirect_attribute_member) {
            that.create_membership_radios(that.controls_right);
        }

        that.create_control_buttons(that.controls_left);
    };

    that.create_membership_radios = function(container) {

        var div = $('<div/>', { 'class': 'association-direction'}).appendTo(container);
        div.append(text.get('@i18n:association.show_results'));
        div.append(' ');

        var name = that.entity.name+'-'+that.attribute_member+'-'+that.other_entity.name+'-type-radio';
        var direct_id = name + '-direct';

        that.direct_radio = $('<input/>', {
            id: direct_id,
            type: 'radio',
            name: name,
            value: 'direct',
            click: function() {
                that.association_type = $(this).val();
                that.refresh();
                return true;
            }
        }).appendTo(div);

        $('<label/>', {
            text: text.get('@i18n:association.direct_membership'),
            'for': direct_id
        }).appendTo(div);

        div.append(' ');

        var indirect_id = name + '-indirect';

        that.indirect_radio = $('<input/>', {
            id: indirect_id,
            type: 'radio',
            name: name,
            value: 'indirect',
            click: function() {
                that.association_type = $(this).val();
                that.refresh();
                return true;
            }
        }).appendTo(div);

        $('<label/>', {
            text: text.get('@i18n:association.indirect_membership'),
            'for': indirect_id
        }).appendTo(div);
    };

    that.get_attribute_name = function() {
        if (that.association_type == 'direct') {
            return that.attribute_member+'_'+that.other_entity.name;
        } else {
            return that.indirect_attribute_member+'_'+that.other_entity.name;
        }
    };

    that.show = function() {
        that.facet_show();
        var pkey = that.get_pkey();
        that.header.set_pkey(pkey);
    };

    that.show_add_dialog = function() {

        var pkey = that.get_pkey();

        var title = that.add_title;
        title = title.replace('${primary_key}', pkey);

        var pkeys = that.data.result.result[that.get_attribute_name()];

        var dialog = IPA.association_adder_dialog({
            title: title,
            entity: that.entity,
            pkey: pkey,
            other_entity: that.other_entity,
            attribute_member: that.attribute_member,
            exclude: pkeys,
            search_options: that.search_options
        });

        var adder_columns = that.adder_columns.values;
        if (adder_columns.length) {
            dialog.set_columns(adder_columns);
        }

        dialog.execute = function() {

            var pkey = that.get_pkey();

            var associator = that.associator({
                entity: that.entity,
                pkey: pkey,
                other_entity: that.other_entity,
                values: dialog.get_selected_values(),
                method: that.add_method,
                on_success: function(data) {
                    that.refresh();
                    dialog.close();

                    var succeeded = IPA.get_succeeded(data);
                    var msg = text.get('@i18n:association.added').replace('${count}', succeeded);
                    IPA.notify_success(msg);
                },
                on_error: function() {
                    that.refresh();
                    dialog.close();
                }
            });

            associator.execute();
        };

        dialog.open();
    };

    that.show_remove_dialog = function() {

        var values = that.table.get_selected_values();

        if (!values.length) {
            var message = text.get('@i18n:dialogs.remove_empty');
            window.alert(message);
            return;
        }

        var pkey = that.get_pkey();

        var title = that.remove_title;
        title = title.replace('${primary_key}', pkey);

        var dialog = IPA.association_deleter_dialog({
            title: title,
            entity: that.entity,
            pkey: pkey,
            other_entity: that.other_entity,
            values: values
        });

        dialog.execute = function() {

            var associator = that.associator({
                entity: that.entity,
                pkey: pkey,
                other_entity: that.other_entity,
                values: values,
                method: that.remove_method,
                on_success: function(data) {
                    that.refresh();
                    that.table.unselect_all();

                    var succeeded = IPA.get_succeeded(data);
                    var msg = text.get('@i18n:association.removed').replace('${count}', succeeded);
                    IPA.notify_success(msg);
                },
                on_error: function() {
                    that.refresh();
                }
            });

            associator.execute();
        };

        dialog.open();
    };

    that.get_records_map = function(data) {

        var records_map = $.ordered_map();
        var pkeys_map = $.ordered_map();
        var association_name = that.get_attribute_name();
        var pkey_name = that.managed_entity.metadata.primary_key;

        var pkeys = data.result.result[association_name];
        for (var i=0; pkeys && i<pkeys.length; i++) {
            var pkey = pkeys[i];
            var record = {};
            record[pkey_name] = pkey;
            var compound_pkey = pkey;
            if (that.show_values_with_dup_key) {
                compound_pkey = pkey + i;
            }
            records_map.put(compound_pkey, record);
            pkeys_map.put(compound_pkey, pkey);
        }

        return {
            records_map: records_map,
            pkeys_map: pkeys_map
        };
    };

    that.refresh = function() {

        if (that.association_type == 'direct') {
            if (that.direct_radio) that.direct_radio.prop('checked', true);
        } else {
            if (that.indirect_radio) that.indirect_radio.prop('checked', true);
        }

        var pkeys = that.get_pkeys();

        var command = rpc.command({
            entity: that.entity.name,
            method: 'show',
            args: pkeys
        });

        command.on_success = function(data, text_status, xhr) {
            that.load(data);
            that.show_content();
        };

        command.on_error = function(xhr, text_status, error_thrown) {
            that.redirect_error(error_thrown);
            that.report_error(error_thrown);
        };

        command.execute();
    };

    that.clear = function() {
        that.header.clear();
        that.table.clear();
    };

    that.init_association_facet = function() {

        that.init_facet();
        that.init_table_columns();
        init();
        that.policies.init();
    };

    if (!no_init) that.init_association_facet();


    return that;
};

/**
 * Attribute facet pre-op
 * @member association
 */
exp.attribute_facet_pre_op = function(spec, context) {

    su.context_entity(spec, context);
    var entity = reg.entity.get(spec.entity);

    spec.title = spec.title || entity.metadata.label_singular;
    spec.label = spec.label || entity.metadata.label_singular;

    var attr_metadata = IPA.get_entity_param(entity.name, spec.attribute);
    spec.tab_label = spec.tab_label || attr_metadata.label;

    entity.policies.add_policy(IPA.build({
        $factory: IPA.facet_update_policy,
        source_facet: 'search',
        dest_facet: spec.name
    }));

    //default buttons and their actions
    spec.actions = spec.actions || [];
    spec.actions.unshift(
        'refresh',
        {
            name: 'remove',
            hide_cond: ['read-only'],
            enable_cond: ['item-selected'],
            handler: function(facet) {
                facet.show_remove_dialog();
            }
        },
        {
            name: 'add',
            hide_cond: ['read-only'],
            handler: function(facet) {
                facet.show_add_dialog();
            }
        }
    );

    spec.control_buttons = spec.control_buttons || [];
    spec.control_buttons.unshift(
        {
            name: 'refresh',
            label: '@i18n:buttons.refresh',
            icon: 'fa-refresh'
        },
        {
            name: 'remove',
            label: '@i18n:buttons.remove',
            icon: 'fa-trash-o'
        },
        {
            name: 'add',
            label: '@i18n:buttons.add',
            icon: 'fa-plus'
        });

    spec.state = spec.state || {};
    spec.state.evaluators = spec.state.evaluators || [];
    spec.state.evaluators.push(
        IPA.selected_state_evaluator,
        IPA.read_only_state_evaluator,
        {
            $factory: IPA.attr_read_only_evaluator,
            attribute: spec.attribute
        });

    spec.columns = spec.columns || [ spec.attribute ];
    spec.table_name = spec.table_name || spec.attribute;

    return spec;
};

/**
 * Association facet
 * @class association.attribute_facet
 * @alternateClassName IPA.attribute_facet
 * @extends facet.table_facet
 */
exp.attribute_facet = IPA.attribute_facet = function(spec, no_init) {

    spec = spec || {};

    var that = IPA.table_facet(spec, true);

    that.attribute = spec.attribute;

    that.add_method = spec.add_method || 'add_member';
    that.remove_method = spec.remove_method || 'remove_member';

    that.create_header = function(container) {

        that.facet_create_header(container);
        that.create_control_buttons(that.controls);
    };

    that.show = function() {
        that.facet_show();
        var pkey = that.get_pkey();
        that.header.set_pkey(pkey);
    };

    that.get_records_map = function(data) {

        var records_map = $.ordered_map();
        var pkeys_map = $.ordered_map();
        var pkeys = data.result.result[that.attribute];

        for (var i=0; pkeys && i<pkeys.length; i++) {
            var pkey = pkeys[i];
            var record = {};
            record[that.attribute] = pkey;
            var compound_pkey = pkey + i;
            records_map.put(compound_pkey, record);
            pkeys_map.put(compound_pkey, pkey);
        }

        return {
            records_map: records_map,
            pkeys_map: pkeys_map
        };
    };

    that.refresh = function() {

        var command = that.get_refresh_command();
        command.execute();
    };

    /**
     * Create refresh command
     */
    that.get_refresh_command = function() {

        var pkey = that.get_pkeys();

        var command = rpc.command({
            entity: that.entity.name,
            method: 'show',
            args: pkey
        });

        if (command.check_option('all')) {
            command.set_option('all', true);
        }
        if (command.check_option('rights')) {
            command.set_option('rights', true);
        }

        command.on_success = function(data, text_status, xhr) {
            that.load(data);
            that.show_content();
        };

        command.on_error = function(xhr, text_status, error_thrown) {
            that.redirect_error(error_thrown);
            that.report_error(error_thrown);
        };
        return command;
    };

    that.clear = function() {
        that.header.clear();
        that.table.clear();
    };

    that.show_add_dialog = function() {

        var dialog = IPA.attribute_adder_dialog({
            attribute: spec.attribute,
            entity: that.entity,
            pkeys: that.get_pkeys()
        });

        dialog.added.attach(function() {
            that.refresh();
        });
        dialog.open();
    };

    that.show_remove_dialog = function() {

        var selected_values = that.get_selected_values();

        if (!selected_values.length) {
            var message = text.get('@i18n:dialogs.remove_empty');
            window.alert(message);
            return;
        }

        var dialog = IPA.deleter_dialog({
            entity: that.entity,
            values: selected_values
        });

        dialog.execute = function() {
            that.remove(
                selected_values,
                function(data) {
                    that.load(data);
                    that.show_content();
                    that.table.unselect_all();

                    var succeeded = IPA.get_succeeded(data);
                    var msg = text.get('@i18n:association.removed').replace('${count}', succeeded);
                    IPA.notify_success(msg);
                },
                function() {
                    that.refresh();
                }
            );
        };


        dialog.open();
    };

    that.remove = function(values, on_success, on_error) {

        var pkey = that.get_pkeys();

        var command = rpc.command({
            entity: that.entity.name,
            method: that.remove_method,
            args: pkey,
            on_success: on_success,
            on_error: on_error
        });

        command.set_option(that.attribute, values);

        if (command.check_option('all')) {
            command.set_option('all', true);
        }
        if (command.check_option('rights')) {
            command.set_option('rights', true);
        }

        command.execute();
    };


    that.init_attribute_facet = function() {

        that.init_facet();
        that.init_table_columns();
        that.init_table(that.entity);
        that.policies.init();
    };

    if (!no_init) that.init_attribute_facet();

    that.attribute_get_refresh_command = that.get_refresh_command;

    return that;
};

/**
 * Attriute read-only evaluator
 * @class IPA.attr_read_only_evaluator
 * @extends IPA.state_evaluator
 */
IPA.attr_read_only_evaluator = function(spec) {

    spec.name = spec.name || 'attr_read_only_evaluator';
    spec.event = spec.event || 'post_load';

    var that = IPA.state_evaluator(spec);
    that.attribute = spec.attribute;

    that.on_event = function(data) {

        var old_state, record, rights, i, state;

        old_state = that.state;
        record = data.result.result;

        // ignore loads without --rights
        if (!record.attributelevelrights) return;

        that.state = [];

        rights = record.attributelevelrights[that.attribute];

        if (!rights || rights.indexOf('w') === -1) {
            that.state.push('read-only');
        }

        that.notify_on_change(old_state);
    };

    return that;
};

phases.on('registration', function() {
    var w = reg.widget;
    var f = reg.field;
    var fa = reg.facet;

    w.register('association_table', IPA.association_table_widget);
    f.register('association_table', IPA.association_table_field);

    fa.register({
        type: 'association',
        factory: exp.association_facet,
        pre_ops: [
            exp.association_facet_pre_op
        ]
    });

    fa.register({
        type: 'attribute',
        factory: exp.attribute_facet,
        pre_ops: [
            exp.attribute_facet_pre_op
        ]
    });
});

return exp;
});
