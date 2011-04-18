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

IPA.search_widget = function (spec) {

    spec = spec || {};

    var that = IPA.table_widget(spec);

    that.entity_name = spec.entity_name;
    that.search_all = spec.search_all || false;

    that.create = function(container) {

        var search_controls = $('<div/>', {
            'class': 'search-controls'
        }).appendTo(container);

        var search_filter = $('<span/>', {
            'class': 'search-filter',
            'name': 'search-filter'
        }).appendTo(search_controls);

        search_controls.append(IPA.create_network_spinner());

        that.filter = $('<input/>', {
            'type': 'text',
            'name': 'search-' + that.entity_name + '-filter'
        }).appendTo(search_filter);

        $('<input/>', {
            'type': 'button',
            'name': 'find',
            'value': IPA.messages.buttons.find
        }).appendTo(search_filter);

        $('<div/>', {
            'class': 'search-results'
        }).appendTo(container);

        that.table_create(container);
    };

    that.setup = function(container) {

        that.table_setup(container);

        var search_filter = $('span[name=search-filter]', that.container);

        $('input[type=text]',search_filter).keypress(
            function(e) {
                /* if the key pressed is the enter key */
                if (e.which == 13) {
                    that.find();
                }
            });
        var button = $('input[name=find]', search_filter);
        that.find_button = IPA.button({
            'label': IPA.messages.buttons.find,
            'icon': 'ui-icon-search',
            'click': function() {
                that.find();
            }
        });
        button.replaceWith(that.find_button);

        var filter = $.bbq.getState(that.entity_name + '-filter', true) || '';
        that.filter.val(filter);
    };

    that.find = function() {
        var filter = that.filter.val();
        var state = {};
        state[that.entity_name + '-filter'] = filter;
        $.bbq.pushState(state);
    };

    return that;
};

IPA.search_facet = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'search';
    spec.label = spec.label ||  IPA.messages.facets.search;

    spec.display_class = 'search-facet';

    var that = IPA.facet(spec);

    that.entity_name = spec.entity_name;
    that.columns = [];
    that.columns_by_name = {};
    that.search_all = spec.search_all || false;

    that.__defineGetter__('entity_name', function() {
        return that._entity_name;
    });

    that.__defineSetter__('entity_name', function(entity_name) {
        that._entity_name = entity_name;

        for (var i=0; i<that.columns.length; i++) {
            that.columns[i].entity_name = entity_name;
        }
    });

    that.get_columns = function() {
        return that.columns;
    };

    that.get_column = function(name) {
        return that.columns_by_name[name];
    };

    that.add_column = function(column) {
        column.entity_name = that.entity_name;
        that.columns.push(column);
        that.columns_by_name[column.name] = column;
    };

    that.create_column = function(spec) {
        var column = IPA.column(spec);
        that.add_column(column);
        return column;
    };

    that.column = function(spec){
        that.create_column(spec);
        return that;
    };

    that.setup_column = function(column) {
        column.setup = function(container, record) {
            container.empty();

            var value = record[column.name];
            value = value ? value.toString() : '';

            $('<a/>', {
                'href': '#'+value,
                'html': value,
                'click': function (value) {
                    return function() {
                        var state = IPA.tab_state(that.entity_name);
                        state[that.entity_name + '-facet'] = 'details';
                        state[that.entity_name + '-pkey'] = value;
                        $.bbq.pushState(state);
                        return false;
                    };
                }(value)
            }).appendTo(container);
        };
    };

    that.init = function() {

        that.facet_init();

        that.table = IPA.search_widget({
            id: that.entity_name+'-search',
            name: 'search', 
            label: IPA.metadata.objects[that.entity_name].label,
            entity_name: that.entity_name,
            search_all: that.search_all
        });

        for (var i=0; i<that.columns.length; i++) {
            var column = that.columns[i];

            var param_info = IPA.get_entity_param(that.entity_name, column.name);
            column.primary_key = param_info && param_info['primary_key'];

            if (column.primary_key) {
                that.setup_column(column);
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

    that.create_action_panel = function(container) {

        that.facet_create_action_panel(container);

        var li = $('.action-controls', container);

        var buttons = $('<span/>', {
            'class': 'search-buttons'
        }).appendTo(li);

        $('<input/>', {
            'type': 'button',
            'name': 'remove',
            'value': IPA.messages.buttons.remove
        }).appendTo(buttons);

        $('<input/>', {
            'type': 'button',
            'name': 'add',
            'value': IPA.messages.buttons.add
        }).appendTo(buttons);
    };

    that.create_content = function(container) {

        var span = $('<span/>', { 'name': 'search' }).appendTo(container);

        that.table.create(span);
    };

    that.setup = function(container) {

        that.facet_setup(container);

        var span = $('span[name=search]', that.container);
        that.table.setup(span);

        var action_panel = that.get_action_panel();
        var search_buttons = $('.search-buttons', action_panel);

        var button = $('input[name=remove]', search_buttons);
        that.remove_button = IPA.action_button({
            'label': IPA.messages.buttons.remove,
            'icon': 'ui-icon-trash',
            'click': function() {
                if (that.remove_button.hasClass('input_link_disabled')) return;
                that.remove();
            }
        });
        button.replaceWith(that.remove_button);
        that.remove_button.addClass('input_link_disabled');

        button = $('input[name=add]', search_buttons);
        that.add_button = IPA.action_button({
            'label': IPA.messages.buttons.add,
            'icon': 'ui-icon-plus',
            'click': function() { that.add(); }
        });
        button.replaceWith(that.add_button);
    };

    that.select_changed = function() {

        var values = that.table.get_selected_values();

        var action_panel = that.get_action_panel();
        var links = $('li.entity-facet', action_panel);
        var input = $('input[id=pkey]', action_panel);

        if (values.length == 1) {
            links.removeClass('entity-facet-disabled');
            input.val(values[0]);

        } else {
            links.addClass('entity-facet-disabled');
            input.val(null);
        }

        if (values.length === 0) {
            that.remove_button.addClass('input_link_disabled');

        } else {
            that.remove_button.removeClass('input_link_disabled');
        }
    };

    that.add = function() {
        var dialog = that.entity.get_dialog('add');
        dialog.open(that.container);
    };

    that.remove = function() {

        var values = that.table.get_selected_values();

        var title;
        if (!values.length) {
            title = IPA.messages.dialogs.remove_empty;
            title = title.replace('${entity}', that.label);
            alert(title);
            return;
        }

        title = IPA.messages.dialogs.remove_title;
        title = title.replace('${entity}', that.label);

        var dialog = IPA.deleter_dialog({
            'title': title,
            'parent': that.container,
            'values': values
        });

        dialog.execute = function() {

            var batch = IPA.batch_command({
                'on_success': function() {
                    that.refresh();
                    dialog.close();
                },
                'on_error': function() {
                    that.refresh();
                    dialog.close();
                }
            });

            for (var i=0; i<values.length; i++) {
                var command = IPA.command({
                    entity: that.entity_name,
                    method: 'del'
                });
                command.add_arg(values[i]);
                batch.add_command(command);
            }

            batch.execute();
        };

        dialog.init();

        dialog.open(that.container);
    };

    that.refresh = function() {

        function on_success(data, text_status, xhr) {

            var action_panel = that.get_action_panel();
            $('li.entity-facet', action_panel).
                addClass('entity-facet-disabled');
            $('input', action_panel).val(null);

            that.table.empty();

            var result = data.result.result;
            for (var i = 0; i<result.length; i++) {
                var record = that.table.get_record(result[i], 0);
                that.table.add_record(record);
            }

            var summary = $('span[name=summary]', that.table.tfoot);
            if (data.result.truncated) {
                var message = IPA.messages.search.truncated;
                message = message.replace('${counter}', data.result.count);
                summary.text(message);
            } else {
                summary.text(data.result.summary);
            }

            $('.search-filter input[type=text]', that.container).focus();
        }

        function on_error(xhr, text_status, error_thrown) {
            var summary = $('span[name=summary]', that.table.tfoot).empty();
            summary.append('<p>Error: '+error_thrown.name+'</p>');
            summary.append('<p>'+error_thrown.title+'</p>');
            summary.append('<p>'+error_thrown.message+'</p>');
        }

        that.filter = $.bbq.getState(that.entity_name + '-filter', true) || '';

        var command = IPA.command({
            entity: that.entity_name,
            method: 'find',
            args: [that.filter],
            options: {
                all: that.search_all
            },
            on_success: on_success,
            on_error: on_error
        });

        command.execute();
    };

    // methods that should be invoked by subclasses
    that.search_facet_init = that.init;
    that.search_facet_create_content = that.create_content;
    that.search_facet_setup = that.setup;

    var columns = spec.columns || [];
    for (var i=0; i<columns.length; i++) {
        var column_spec = columns[i];
        var column;

        if (column_spec instanceof Object) {
            var factory = column_spec.factory || IPA.column;
            column = factory(column_spec);
        } else {
            column = IPA.column({ name: column_spec });
        }
        that.add_column(column);
    }

    return that;
};

