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
    spec.managed_entity_name = spec.managed_entity_name || spec.entity_name;

    spec.disable_breadcrumb = spec.disable_breadcrumb === undefined ? true : spec.disable_breadcrumb;
    spec.disable_facet_tabs = spec.disable_facet_tabs === undefined ? true : spec.disable_facet_tabs;

    var that = IPA.table_facet(spec);

    that.search_all = spec.search_all || false;
    that.selectable = spec.selectable;

    function get_values() {
        return that.table.get_selected_values();
    }

    that.get_values = spec.get_values || get_values;

    that.init = function() {
        that.facet_init();
        that.managed_entity = IPA.get_entity(that.managed_entity_name);
        that.init_table(that.managed_entity);
    };

    that.init_table = function(entity){

        that.table = IPA.table_widget({
            'class': 'content-table',
            name: 'search',
            label: entity.metadata.label,
            entity_name: entity.name,
            search_all: that.search_all,
            scrollable: true,
            selectable: that.selectable
        });

        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++) {
            var column = columns[i];

            var param_info = IPA.get_entity_param(entity.name, column.name);
            column.primary_key = param_info && param_info['primary_key'];
            column.link = column.primary_key;

            if (column.link) {
                column.link_handler = function(value) {
                    IPA.nav.show_page(entity.name, 'default', value);
                    return false;
                };
            }

            that.table.add_column(column);
        }

        that.table.select_changed = function() {
            that.select_changed();
        };

        that.table.refresh = function() {
            that.refresh();
        };

        that.table.init();
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
                if (that.remove_button.hasClass('input_link_disabled')) return false;
                that.remove();
                return false;
            }
        }).appendTo(that.controls);

        that.add_button = IPA.action_button({
            name: 'add',
            label: IPA.messages.buttons.add,
            icon: 'add-icon',
            click: function() {
                that.add();
                return false;
            }
        }).appendTo(that.controls);
    };

    that.create_content = function(container) {

        that.table.create(container);
        that.table.setup(container);
    };

    that.show = function() {
        that.facet_show();

        if (that.filter) {
            var filter = IPA.nav.get_state(that.entity_name+'-filter');
            that.filter.val(filter);
        }
    };

    that.select_changed = function() {

        var values = that.table.get_selected_values();

        if (that.remove_button) {
            if (values.length === 0) {
                that.remove_button.addClass('input_link_disabled');
            } else {
                that.remove_button.removeClass('input_link_disabled');
            }
        }
    };

    that.add = function() {
        var dialog = that.managed_entity.get_dialog('add');
        dialog.open(that.container);
    };

    that.remove = function() {
        that.remove_instances(that.managed_entity);
    };

    that.remove_instances = function(entity) {

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

        dialog.entity_name = entity.name;
        dialog.entity = entity;
        dialog.facet = that;

        title = IPA.messages.dialogs.remove_title;
        var label = entity.metadata.label;
        dialog.title = title.replace('${entity}', label);

        dialog.set_values(values);

        dialog.init();

        dialog.open(that.container);
    };

    that.find = function() {
        var filter = that.filter.val();
        var state = {};
        state[that.managed_entity_name + '-filter'] = filter;
        IPA.nav.push_state(state);
    };

    function load(result) {

        that.table.empty();

        for (var i = 0; i<result.length; i++) {
            var record = that.table.get_record(result[i], 0);
            that.table.add_record(record);
        }
    }

    that.load = spec.load || load;

    that.refresh = function() {
        that.search_refresh(that.entity);
    };

    that.on_error = function(xhr, text_status, error_thrown) {
        that.report_error(error_thrown);
    };

    that.search_refresh = function(entity){

        $('input[type=checkbox]',that.table.thead).removeAttr("checked");

        function on_success(data, text_status, xhr) {

            that.load(data.result.result);

            if (data.result.truncated) {
                var message = IPA.messages.search.truncated;
                message = message.replace('${counter}', data.result.count);
                that.table.summary.text(message);
            } else {
                that.table.summary.text(data.result.summary);
            }

            that.filter.focus();
            that.select_changed();
        }

        var filter = [];
        var current_entity = entity;
        filter.unshift(IPA.nav.get_state(current_entity.name+'-filter'));
        current_entity = current_entity.containing_entity;
        while(current_entity !== null){
            filter.unshift(
                IPA.nav.get_state(current_entity.name+'-pkey'));
            current_entity = current_entity.containing_entity;
        }

        var command = IPA.command({
            entity: entity.name,
            method: 'find',
            args: filter,
            options: {
                all: that.search_all
            },
            on_success: on_success,
            on_error: that.on_error
        });

        command.execute();
    };

    // methods that should be invoked by subclasses
    that.search_facet_init = that.init;
    that.search_facet_create_content = that.create_content;
    that.search_facet_setup = that.setup;

    return that;
};

IPA.search_deleter_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.deleter_dialog(spec);

    that.create_command = function() {
        var batch = IPA.batch_command();

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

    that.refresh = function(){

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');

        if ((!pkey) && (that.entity.redirect_facet)) {
            that.redirect();
            return;
        }

        that.search_refresh(that.managed_entity);
    };

    return that;
};
