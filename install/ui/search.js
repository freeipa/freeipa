/*jsl:import ipa.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
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

/* REQUIRES: ipa.js */

IPA.search_facet = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'search';
    spec.managed_entity_name = spec.managed_entity_name || spec.entity.name;

    spec.disable_breadcrumb =
        spec.disable_breadcrumb === undefined ? true : spec.disable_breadcrumb;
    spec.disable_facet_tabs =
        spec.disable_facet_tabs === undefined ? true : spec.disable_facet_tabs;

    var that = IPA.table_facet(spec);

    function get_values() {
        return that.table.get_selected_values();
    }

    that.get_values = spec.get_values || get_values;

    var init = function() {

        that.managed_entity = IPA.get_entity(that.managed_entity_name);

        that.init_table(that.managed_entity);
    };

    that.create_header = function(container) {

        that.facet_create_header(container);

        var span = $('<div/>', {
            'class': 'right-aligned-facet-controls'
        }).appendTo(that.controls);

        var filter_container = $('<div/>', {
            'class': 'search-filter'
        }).appendTo(span);

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

        span.append(IPA.create_network_spinner());

        that.remove_button = IPA.action_button({
            name: 'remove',
            label: IPA.messages.buttons.remove,
            icon: 'remove-icon',
            click: function() {
                if (!that.remove_button.hasClass('action-button-disabled')) {
                    that.show_remove_dialog();
                }
                return false;
            }
        }).appendTo(that.controls);

        that.add_button = IPA.action_button({
            name: 'add',
            label: IPA.messages.buttons.add,
            icon: 'add-icon',
            click: function() {
                if (!that.add_button.hasClass('action-button-disabled')) {
                    that.show_add_dialog();
                }
                return false;
            }
        }).appendTo(that.controls);
    };

    that.show = function() {
        that.facet_show();

        var filter = IPA.nav.get_state(that.entity.name+'-filter');
        that.old_filter = filter || '';

        if (that.filter) {
            that.filter.val(filter);
        }
    };

    that.show_add_dialog = function() {
        var dialog = that.managed_entity.get_dialog('add');
        dialog.open(that.container);
    };

    that.show_remove_dialog = function() {

        var values = that.get_values();

        var title;
        if (!values.length) {
            title = IPA.messages.dialogs.remove_empty;
            alert(title);
            return;
        }

        var dialog = that.managed_entity.get_dialog('remove');

        if (!dialog) {
            dialog = IPA.search_deleter_dialog();
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
        var state = {};
        state[that.managed_entity_name + '-filter'] = filter;
        IPA.nav.push_state(state);
    };

    that.get_pkeys = function(data) {
        var result = data.result.result;
        var pkey_name = that.managed_entity.metadata.primary_key;
        var pkeys = [];
        for (var i=0; i<result.length; i++) {
            var record = result[i];
            var values = record[pkey_name];
            pkeys.push(values[0]);
        }
        return pkeys;
    };

    that.get_search_command_name = function() {
        return that.managed_entity.name + '_find' + (that.pagination ? '_pkeys' : '');
    };

    that.refresh = function() {

        var filter = [];
        var current_entity = that.managed_entity;
        filter.unshift(IPA.nav.get_state(current_entity.name+'-filter'));
        current_entity = current_entity.get_containing_entity();
        while (current_entity !== null) {
            filter.unshift(IPA.nav.get_state(current_entity.name+'-pkey'));
            current_entity = current_entity.get_containing_entity();
        }

        var command = IPA.command({
            name: that.get_search_command_name(),
            entity: that.managed_entity.name,
            method: 'find',
            args: filter,
            options: {
                all: that.search_all
            }
        });

        if (that.pagination) {
            command.set_option('pkey_only', true);
            command.set_option('sizelimit', 0);
        }

        command.on_success = function(data, text_status, xhr) {
            that.filter.focus();
            that.load(data);
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
        var filter = IPA.nav.get_state(that.entity.name+'-filter') || '';
        return that.old_filter !== '' || that.old_filter !== filter;
    };

    init();

    // methods that should be invoked by subclasses
    that.search_facet_refresh = that.refresh;

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

        batch.on_success = function() {
            that.facet.refresh();
            that.close();
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

    spec.managed_entity_name = spec.nested_entity;

    spec.disable_breadcrumb = false;
    spec.disable_facet_tabs = false;

    var that = IPA.search_facet(spec);

    that.show = function() {
        that.facet_show();

        that.header.set_pkey(
            IPA.nav.get_state(IPA.current_entity.name+'-pkey'));

        if (that.filter) {
            var filter = IPA.nav.get_state(that.managed_entity_name+'-filter');
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
