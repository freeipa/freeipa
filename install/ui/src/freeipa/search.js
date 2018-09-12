/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
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

define([
        './builder',
        './ipa',
        './jquery',
        './phases',
        './reg',
        './rpc',
        './spec_util',
        './text',
        './facet'],
    function(builder, IPA, $, phases, reg, rpc, su, text, mod_facet) {

var exp = {};

exp.search_facet_control_buttons_pre_op = function(spec, context) {

    var override_actions = function(cust_acts, def_acts) {
        if (!cust_acts) return def_acts;

        var new_default_actions = [];
        for (var i=0, l=def_acts.length; i<l; i++) {
            var d_action = def_acts[i];

            var chosen_action = d_action;

            for (var k=0, j=cust_acts.length; k<j; k++) {
                var custom_act = cust_acts[k];
                if (custom_act === d_action || (custom_act.$type && custom_act.$type === d_action)) {
                    chosen_action = custom_act;
                    break;
                }
            }

            new_default_actions.push(chosen_action);
        }

        return new_default_actions;
    };

    var default_actions = ['refresh', 'batch_remove', 'add'];
    var merged_actions = override_actions(spec.custom_actions, default_actions);

    spec.actions = merged_actions.concat(spec.actions || []);
    spec.control_buttons = spec.control_buttons || [];

    if (!spec.no_update) {
        spec.control_buttons.unshift(
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
    }
    spec.control_buttons.unshift(
        {
            name: 'refresh',
            label: '@i18n:buttons.refresh',
            icon: 'fa-refresh'
        });

    spec.state = spec.state || {};
    spec.state.evaluators = spec.state.evaluators || [];
    spec.state.evaluators.push(
        IPA.selected_state_evaluator,
        IPA.self_service_state_evaluator);
    return spec;
};

exp.search_facet_pre_op = function(spec, context) {

    su.context_entity(spec, context);
    var entity = reg.entity.get(spec.entity);

    spec.name = spec.name || 'search';
    spec.title = spec.title || entity.metadata.label;
    spec.label = spec.label || entity.metadata.label;
    spec.tab_label = spec.tab_label || '@i18n:facets.search';

    spec.managed_entity = spec.managed_entity ? IPA.get_entity(spec.managed_entity) : spec.entity;

    spec.disable_breadcrumb =
        spec.disable_breadcrumb === undefined ? true : spec.disable_breadcrumb;
    spec.disable_facet_tabs =
        spec.disable_facet_tabs === undefined ? true : spec.disable_facet_tabs;

    exp.search_facet_control_buttons_pre_op(spec, context);
    return spec;
};

/**
 * Search facet
 * @class  IPA.search_facet
 */
IPA.search_facet = function(spec, no_init) {

    spec = spec || {};

    var that = IPA.table_facet(spec, true);

    /**
     * Additional command options which are added to refresh command on
     * refresh.
     *
     * @property {Object}
     */
    that.command_options = spec.command_options || {};

    that.deleter_dialog = spec.deleter_dialog;

    that.disable_search_field = !!spec.disable_search_field;

    that.create_header = function(container) {

        that.facet_create_header(container);
        if (!that.disable_search_field) {
            that.create_search_filter(that.controls_left);
        }
        that.create_control_buttons(that.controls_right);
        that.create_action_dropdown(that.controls_right);
    };

    that.create_search_filter = function(container) {

        that.filter_container = $('<div/>', {
            'class': 'search-filter'
        }).appendTo(container);

        that.filter = $('<input/>', {
            type: 'text',
            'class': 'form-control',
            name: 'filter',
            placeholder: text.get('@i18n:search.placeholder')
        }).appendTo(that.filter_container);

        that.filter.keypress(function(e) {
            /* if the key pressed is the enter key */
            if (e.which == 13) {
                that.find();
            }
        });

        that.find_button = IPA.action_button({
            name: 'find',
            icon: 'fa-search',
            click: function() {
                that.find();
                return false;
            }
        }).appendTo(that.filter_container);
    };

    that.managed_entity_pkey_prefix = function() {

        if (that.entity !== that.managed_entity) {
            return that.get_pkeys();
        }
        return that.get_pkey_prefix();
    };

    that.show = function() {
        that.facet_show();

        var filter = that.state.filter || '';

        if (that.filter) {
            that.filter.val(filter);
        }
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
        dialog.open();
    };

    that.create_remove_dialog = function() {
        var values = that.get_selected_values();

        var title;
        if (!values.length) {
            title = text.get('@i18n:dialogs.remove_empty');
            window.alert(title);
            return null;
        }

        var dialog = builder.build('', that.deleter_dialog);
        if (!dialog) {
            dialog = that.managed_entity.get_dialog('remove');
        }
        if (!dialog) {
            dialog = IPA.search_deleter_dialog();
        }

        dialog.entity_name = that.managed_entity.name;
        dialog.entity = that.managed_entity;
        dialog.facet = that;
        dialog.pkey_prefix = that.managed_entity_pkey_prefix();

        dialog.title = dialog.title ||
                           text.get('@i18n:dialogs.remove_title_default');
        dialog.set_values(values);

        return dialog;
    };

    that.show_remove_dialog = function() {

        var dialog = that.create_remove_dialog();
        if (dialog) {
            dialog.open();
        } else {
            window.console.log("Remove dialog was not created properly.");
        }
    };

    that.find = function() {
        var filter = that.filter.val();
        var old_filter = that.state.filter;
        var state = {};
        state[that.managed_entity.name + '-filter'] = filter;

        if (filter !== old_filter) that.set_expired_flag();

        that.state.set({filter: filter});
    };

    that.get_search_command_name = function() {
        var name = that.managed_entity.name + '_find';
        if (that.pagination && !that.search_all_entries) {
            name += '_pkeys';
        }
        return name;
    };

    that.get_refresh_command_args = function() {

        var filter = that.state.filter || '';
        var args = that.managed_entity_pkey_prefix();
        args.push(filter);
        return args;
    };

    /**
     * Provide RPC options for refresh command
     * - override point
     */
    that.get_refresh_command_options = function() {

        return that.command_options;
    };

    that.create_refresh_command = function() {

        var args = that.get_refresh_command_args();

        var command = rpc.command({
            name: that.get_search_command_name(),
            entity: that.managed_entity.name,
            method: 'find',
            args: args
        });

        command.set_options(that.get_refresh_command_options());

        if (that.pagination) {
            if (!that.search_all_entries) command.set_option('pkey_only', true);
            command.set_option('sizelimit', 0);
        }

        return command;
    };

    that.refresh = function() {

        var command = that.create_refresh_command();

        command.on_success = function(data, text_status, xhr) {
            if (!IPA.opened_dialogs.dialogs.length &&
                                        !that.disable_search_field) {
                that.filter.focus();
            }
            that.load(data);
            that.show_content();
        };

        command.on_error = function(xhr, text_status, error_thrown) {
            that.report_error(error_thrown);
        };

        command.execute();
    };

    that.clear = function() {
        if (that.needs_clear()) {
            that.table.clear();
        }
    };

    that.needs_clear = function() {
        var clear = false;

        var filter = that.state.filter;
        clear = that.old_filter !== '' || that.old_filter !== filter;

        var pkeys = that.get_pkeys();
        clear = clear || IPA.array_diff(pkeys, that.old_pkeys);

        return clear;
    };

    that.init_search_facet = function() {

        that.init_facet();
        that.init_table_columns();
        that.init_table(that.managed_entity);
        that.policies.init();
    };

    if (!no_init) that.init_search_facet();

    // methods that should be invoked by subclasses
    that.search_facet_refresh = that.refresh;
    that.search_facet_create_refresh_command = that.create_refresh_command;
    that.search_facet_create_remove_dialog = that.create_remove_dialog;
    that.search_facet_create_header = that.create_header;
    that.search_facet_show = that.show;

    return that;
};

IPA.search_deleter_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.deleter_dialog(spec);
    that.pkey_prefix = spec.pkey_prefix || [];

    /**
     * List of attributes from table from search facet, which
     * are added to remove command as options. In case that there is not column
     * with this name, then the option is skipped
     *
     * @property {String}
     */
    that.additional_table_attrs = spec.additional_table_attrs || [];

    that.create_command = function() {
        var batch = rpc.batch_command({
            error_message: '@i18n:search.partial_delete',
            name: that.entity.name + '_batch_del'
        });

        for (var i=0; i<that.values.length; i++) {
            var command = rpc.command({
                entity: that.entity.name,
                method: 'del'
            });

            if (that.pkey_prefix.length) command.add_args(that.pkey_prefix);

            var value = that.values[i];
            if (value instanceof Object) {
                for (var key in value) {
                    if (value.hasOwnProperty(key)) {
                        if (key === 'pkey'){
                            value = value[key];
                            command.add_arg(value);
                        } else {
                            command.set_option(key, value[key]);
                        }
                    }
                }
            } else {
                command.add_arg(value);
            }

            var add_attrs = that.additional_table_attrs;
            if (add_attrs && add_attrs.length && add_attrs.length > 0) {
                command = that.extend_command(command, add_attrs, value);
            }

            batch.add_command(command);
        }

        return batch;
    };

    that.execute = function() {

        var batch = that.create_command();

        batch.on_success = function(data, text_status, xhr) {
            that.facet.refresh();
            that.facet.on_update.notify([],that.facet);
            that.facet.table.unselect_all();
            var succeeded = batch.commands.length - batch.errors.errors.length;
            var msg = text.get('@i18n:search.deleted').replace('${count}', succeeded);
            IPA.notify_success(msg);
        };

        batch.on_error = function() {
            that.facet.refresh();
        };

        batch.execute();
    };

    that.extend_command = function(command, add_attrs, pkey) {
        var records = that.facet.fetch_records();
        var pkey_name = that.entity.metadata.primary_key;

        for (var i=0,l=records.length; i<l; i++) {
            var record = records[i];
            var curr_pkey = record[pkey_name][0];
            if (curr_pkey && curr_pkey === pkey) {
                for (var j=0,k=add_attrs.length; j<k; j++) {
                    var attr = add_attrs[j];
                    var val = record[attr];
                    if (val) command.set_option(attr, val);
                }
            }
        }

        return command;
    };

    that.search_deleter_dialog_create_command = that.create_command;

    return that;
};

exp.nested_search_facet_preop = function(spec, context) {

    su.context_entity(spec, context);
    var entity = reg.entity.get(spec.entity);

    spec.name = spec.name || 'search';
    spec.title = spec.title || entity.metadata.label_singular;
    spec.label = spec.label || entity.metadata.label;
    spec.tab_label = spec.tab_label || '@i18n:facets.search';

    spec.managed_entity = spec.nested_entity;

    spec.disable_breadcrumb = false;
    spec.disable_facet_tabs = false;

    exp.search_facet_control_buttons_pre_op(spec, context);
    return spec;
};

/*TODO.  this has much copied code from above.  Refactor the search_facet
To either be nested or not nested. */
exp.nested_search_facet = IPA.nested_search_facet = function(spec) {

    spec = spec || {};

    var that = IPA.search_facet(spec);

    that.show = function() {
        that.facet_show();
        var pkey = that.get_pkey();
        that.header.set_pkey(pkey);
        var filter = that.state.filter || '';
        if (that.filter) {
            that.filter.val(filter);
        }
    };

    that.refresh = function() {

        var pkey = that.get_pkey();

        if ((!pkey) && (that.entity.redirect_facet)) {
            that.redirect();
            return;
        }

        that.search_facet_refresh();
    };

    return that;
};

IPA.batch_remove_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'remove';
    spec.label = spec.label || '@i18n:buttons.remove';
    spec.enable_cond = spec.enable_cond || ['item-selected'];
    spec.enabled = spec.enabled === undefined ? false : spec.enabled;
    spec.hide_cond = spec.hide_cond || ['self-service'];

    var that = IPA.action(spec);

    that.execute_action = function(facet) {
        facet.show_remove_dialog();
    };

    return that;
};

IPA.add_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'add';
    spec.label = spec.label || '@i18n:buttons.add';
    spec.hide_cond = spec.hide_cond || ['self-service'];

    var that = IPA.action(spec);

    that.execute_action = function(facet) {
        facet.show_add_dialog();
    };

    return that;
};

/*
 * Calls entity's disable command for each selected item in a batch.
 * Usable in table facets.
 */
IPA.batch_items_action = function(spec) {

    spec = spec || {};

    var that = IPA.action(spec);

    that.method = spec.method || 'disable';
    that.success_msg = text.get(spec.success_msg);
    that.options = spec.options || {};

    that.execute_action = function(facet, on_success, on_error) {

        var entity = facet.managed_entity;
        var selected_keys = facet.get_selected_values();
        var pkeys = facet.get_pkeys();
        if (!pkeys[0]) pkeys = []; // correction for search facet

        that.batch = rpc.batch_command({
            name: entity.name + '_batch_'+ that.method,
            on_success: that.get_on_success(facet, on_success)
        });

        for (var i=0; i<selected_keys.length; i++) {
            var item_keys = pkeys.splice(0);
            item_keys.push(selected_keys[i]);

            var command = that.create_action_command(facet, item_keys);
            that.batch.add_command(command);
        }

        that.batch.execute();
    };

    that.create_action_command = function(facet, keys) {
        var command = rpc.command({
            entity: facet.managed_entity.name,
            method: that.method,
            args: keys,
            options: that.options
        });
        return command;
    };

    that.on_success = function(facet, data, text_status, xhr) {
        facet.on_update.notify();
        facet.refresh();
        facet.table.unselect_all();

        if (that.success_msg) {
            var succeeded = that.batch.commands.length - that.batch.errors.errors.length;
            var msg = that.success_msg.replace('${count}', succeeded);
            IPA.notify_success(msg);
        }
    };

    that.get_on_success = function(facet, on_success) {
        return function(data, text_status, xhr) {
            that.on_success(facet, data, text_status, xhr);
            if (on_success) on_success.call(this, data, text_status, xhr);
        };
    };


    return that;
};

IPA.batch_disable_action = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'disable';
    spec.method = spec.method || 'disable';
    spec.needs_confirm = spec.needs_confirm === undefined ? true : spec.needs_confirm;
    spec.enable_cond = spec.enable_cond || ['item-selected'];
    spec.enabled = spec.enabled === undefined ? false : spec.enabled;
    spec.success_msg = spec.success_msg || '@i18n:search.disabled';
    spec.confirm_msg = spec.confirm_msg || '@i18n:search.disable_confirm';

    return IPA.batch_items_action(spec);
};

IPA.batch_enable_action = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'enable';
    spec.method = spec.method || 'enable';
    spec.needs_confirm = spec.needs_confirm === undefined ? true : spec.needs_confirm;
    spec.enabled = spec.enabled === undefined ? false : spec.enabled;
    spec.enable_cond = spec.enable_cond || ['item-selected'];
    spec.success_msg = spec.success_msg || '@i18n:search.enabled';
    spec.confirm_msg = spec.confirm_msg || '@i18n:search.enable_confirm';

    return IPA.batch_items_action(spec);
};

exp.register = function() {

    var a = reg.action;
    var f = reg.facet;

    a.register('batch_remove', IPA.batch_remove_action);
    a.register('add', IPA.add_action);
    a.register('batch_items', IPA.batch_items_action);
    a.register('batch_disable', IPA.batch_disable_action);
    a.register('batch_enable', IPA.batch_enable_action);

    f.register({
        type: 'search',
        factory: IPA.search_facet,
        pre_ops: [
            exp.search_facet_pre_op
        ],
        spec: { name: 'search' }
    });

    f.register({
        type: 'nested_search',
        factory: IPA.nested_search_facet,
        pre_ops: [
            exp.nested_search_facet_preop
        ],
        spec: { name: 'nestedsearch' }
    });
};

phases.on('registration', exp.register);

return exp;
});
