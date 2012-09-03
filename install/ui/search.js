/*jsl:import ipa.js */

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

/* REQUIRES: ipa.js */

IPA.search_facet = function(spec, no_init) {

    spec = spec || {};

    spec.name = spec.name || 'search';
    spec.managed_entity = spec.managed_entity ? IPA.get_entity(spec.managed_entity) : spec.entity;

    spec.disable_breadcrumb =
        spec.disable_breadcrumb === undefined ? true : spec.disable_breadcrumb;
    spec.disable_facet_tabs =
        spec.disable_facet_tabs === undefined ? true : spec.disable_facet_tabs;

    spec.actions = spec.actions || [];
    spec.actions.unshift(
        IPA.refresh_action,
        IPA.batch_remove_action,
        IPA.add_action);

    spec.control_buttons = spec.control_buttons || [];
    spec.control_buttons.unshift(
        {
            name: 'refresh',
            label: IPA.messages.buttons.refresh,
            icon: 'reset-icon'
        },
        {
            name: 'remove',
            label: IPA.messages.buttons.remove,
            icon: 'remove-icon'
        },
        {
            name: 'add',
            label: IPA.messages.buttons.add,
            icon: 'add-icon'
        });

    spec.state = spec.state || {};
    spec.state.evaluators = spec.state.evaluators || [];
    spec.state.evaluators.push(
        IPA.selected_state_evaluator,
        IPA.self_service_state_evaluator);

    var that = IPA.table_facet(spec, true);

    that.deleter_dialog = spec.deleter_dialog || IPA.search_deleter_dialog;

    that.create_header = function(container) {

        that.facet_create_header(container);

        var div = $('<div/>', {
            'class': 'right-aligned-facet-controls'
        }).appendTo(that.controls);

        div.append(IPA.create_network_spinner());

        var filter_container = $('<div/>', {
            'class': 'search-filter'
        }).appendTo(div);

        that.filter = $('<input/>', {
            type: 'text',
            name: 'filter'
        }).appendTo(filter_container);

        that.filter.keypress(function(e) {
            /* if the key pressed is the enter key */
            if (e.which == 13) {
                that.find();
            }
        });

        that.find_button = IPA.action_button({
            name: 'find',
            icon: 'search-icon',
            click: function() {
                that.find();
                return false;
            }
        }).appendTo(filter_container);

        that.create_control_buttons(that.controls);
    };

    that.show = function() {
        that.facet_show();

        var filter = IPA.nav.get_state(that.entity.name+'-filter');
        that.old_filter = filter || '';
        that.old_pkeys = that.managed_entity.get_primary_key_prefix();

        if (that.filter) {
            that.filter.val(filter);
        }
    };

    that.needs_update = function() {
        if (that._needs_update !== undefined) return that._needs_update;

        var needs_update = that.facet_needs_update();

        //check if state changed
        var pkeys = that.managed_entity.get_primary_key_prefix();
        needs_update = needs_update || IPA.array_diff(pkeys, that.old_pkeys);

        return needs_update;
    };

    that.show_add_dialog = function() {
        var dialog = that.managed_entity.get_dialog('add');
        dialog.open(that.container);
    };

    that.show_remove_dialog = function() {

        var values = that.get_selected_values();

        var title;
        if (!values.length) {
            title = IPA.messages.dialogs.remove_empty;
            alert(title);
            return;
        }

        var dialog = that.managed_entity.get_dialog('remove');

        if (!dialog) {
            dialog = that.deleter_dialog();
        }

        dialog.entity_name = that.managed_entity.name;
        dialog.entity = that.managed_entity;
        dialog.facet = that;

        title = IPA.messages.dialogs.remove_title;
        var label = that.managed_entity.metadata.label;
        dialog.title = title.replace('${entity}', label);

        dialog.set_values(values);

        dialog.open(that.container);
    };

    that.find = function() {
        var filter = that.filter.val();
        var old_filter = IPA.nav.get_state(that.managed_entity.name+'-filter');
        var state = {};
        state[that.managed_entity.name + '-filter'] = filter;

        if (filter !== old_filter) that.set_expired_flag();

        IPA.nav.push_state(state);
    };

    that.get_search_command_name = function() {
        var name = that.managed_entity.name + '_find';
        if (that.pagination && !that.search_all_entries) {
            name += '_pkeys';
        }
        return name;
    };

    that.create_refresh_command = function() {

        var filter = that.managed_entity.get_primary_key_prefix();
        filter.push(IPA.nav.get_state(that.managed_entity.name+'-filter'));

        var command = IPA.command({
            name: that.get_search_command_name(),
            entity: that.managed_entity.name,
            method: 'find',
            args: filter,
            options: {
                all: that.search_all_attributes
            }
        });

        if (that.pagination) {
            if (!that.search_all_entries) command.set_option('pkey_only', true);
            command.set_option('sizelimit', 0);
        }

        return command;
    };

    that.refresh = function() {

        var command = that.create_refresh_command();

        command.on_success = function(data, text_status, xhr) {
            that.filter.focus();
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
        var filter = IPA.nav.get_state(that.entity.name+'-filter') || '';
        clear = that.old_filter !== '' || that.old_filter !== filter;

        var pkeys = that.managed_entity.get_primary_key_prefix();
        clear = clear || IPA.array_diff(pkeys, that.old_pkeys);

        return clear;
    };

    that.init_search_facet = function() {

        that.init_facet();
        that.init_table_columns();
        that.init_table(that.managed_entity);
    };

    if (!no_init) that.init_search_facet();

    // methods that should be invoked by subclasses
    that.search_facet_refresh = that.refresh;
    that.search_facet_create_refresh_command = that.create_refresh_command;

    return that;
};

IPA.search_deleter_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.deleter_dialog(spec);

    that.create_command = function() {
        var batch = IPA.batch_command({
            error_message: IPA.messages.search.partial_delete
        });

        var pkeys = that.entity.get_primary_key_prefix();

        for (var i=0; i<that.values.length; i++) {
            var command = IPA.command({
                entity: that.entity.name,
                method: 'del'
            });

            for (var j=0; j<pkeys.length; j++) {
                command.add_arg(pkeys[j]);
            }

            var value = that.values[i];
            if (value instanceof Object) {
                for (var key in value) {
                    if (value.hasOwnProperty(key)) {
                        if (key === 'pkey'){
                            command.add_arg(value[key]);
                        } else {
                            command.set_option(key, value[key]);
                        }
                    }
                }
            } else {
                command.add_arg(value);
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
            that.close();
            IPA.notify_success(IPA.messages.search.deleted);
        };

        batch.on_error = function() {
            that.facet.refresh();
            that.close();
        };

        batch.execute();
    };

    that.search_deleter_dialog_create_command = that.create_command;

    return that;
};

/*TODO.  this has much copied code from above.  Refactor the search_facet
To either be nested or not nested. */
IPA.nested_search_facet = function(spec) {

    spec = spec || {};

    spec.managed_entity = IPA.get_entity(spec.nested_entity);

    spec.disable_breadcrumb = false;
    spec.disable_facet_tabs = false;

    var that = IPA.search_facet(spec);

    that.show = function() {
        that.facet_show();

        that.header.set_pkey(
            IPA.nav.get_state(IPA.current_entity.name+'-pkey'));

        var filter = IPA.nav.get_state(that.managed_entity.name+'-filter');
        that.old_filter = filter || '';
        that.old_pkeys = that.managed_entity.get_primary_key_prefix();

        if (that.filter) {
            that.filter.val(filter);
        }
    };

    that.refresh = function() {

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');

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
    spec.label = spec.label || IPA.messages.buttons.remove;
    spec.enable_cond = spec.enable_cond || ['item-selected'];
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
    spec.label = spec.label || IPA.messages.buttons.add;
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
    that.success_msg = spec.success_msg;

    that.execute_action = function(facet, on_success, on_error) {

        var entity = facet.managed_entity;
        var pkeys = facet.get_selected_values();

        that.batch = IPA.batch_command({
            name: entity.name + '_batch_'+ that.method,
            on_success: that.get_on_success(facet, on_success)
        });

        for (var i=0; i<pkeys.length; i++) {
            var pkey = pkeys[i];

            var command = IPA.command({
                entity: entity.name,
                method: that.method,
                args: [pkey]
            });

            that.batch.add_command(command);
        }

        that.batch.execute();
    };

    that.on_success = function(facet, data, text_status, xhr) {
        facet.on_update.notify();
        facet.refresh();

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
    spec.success_msg = spec.success_msg || IPA.messages.search.disabled;
    spec.confirm_msg = spec.confirm_msg || IPA.messages.search.disable_confirm;

    return IPA.batch_items_action(spec);
};

IPA.batch_enable_action = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'enable';
    spec.method = spec.method || 'enable';
    spec.needs_confirm = spec.needs_confirm === undefined ? true : spec.needs_confirm;
    spec.enable_cond = spec.enable_cond || ['item-selected'];
    spec.success_msg = spec.success_msg || IPA.messages.search.enabled;
    spec.confirm_msg = spec.confirm_msg || IPA.messages.search.enable_confirm;

    return IPA.batch_items_action(spec);
};