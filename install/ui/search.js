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
    spec.label = spec.label || IPA.messages.facets.search;

    spec.display_class = 'search-facet';

    var that = IPA.table_facet(spec);

    that.search_all = spec.search_all || false;

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
                        IPA.nav.show_page(that.entity_name, 'default', value);
                        return false;
                    };
                }(value)
            }).appendTo(container);
        };
    };

    that.init = function() {

        that.facet_init();

        that.table = IPA.table_widget({
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

    that.create_header = function(container) {

        that.facet_create_header(container);

        that.filter = $('<input/>', {
            type: 'text',
            name: 'filter'
        }).appendTo(that.controls);

        that.filter.keypress(function(e) {
            /* if the key pressed is the enter key */
            if (e.which == 13) {
                that.find();
            }
        });

        that.find_button = IPA.button({
            label: IPA.messages.buttons.find,
            icon: 'ui-icon-search',
            click: function() {
                that.find();
                return false;
            }
        }).appendTo(that.controls);

        that.controls.append(IPA.create_network_spinner());

        that.remove_button = IPA.action_button({
            label: IPA.messages.buttons.remove,
            icon: 'ui-icon-trash',
            'class': 'input_link_disabled',
            click: function() {
                if (that.remove_button.hasClass('input_link_disabled')) return false;
                that.remove();
                return false;
            }
        }).appendTo(that.controls);

        that.add_button = IPA.action_button({
            label: IPA.messages.buttons.add,
            icon: 'ui-icon-plus',
            click: function() {
                that.add();
                return false;
            }
        }).appendTo(that.controls);
    };

    that.create_content = function(container) {

        var span = $('<span/>', { 'name': 'search' }).appendTo(container);

        that.table.create(span);
        that.table.setup(span);
    };

    that.setup = function(container) {

        that.facet_setup(container);
    };

    that.show = function() {
        that.facet_show();

        that.entity.header.set_pkey(null);
        that.entity.header.back_link.css('visibility', 'hidden');
        that.entity.header.facet_tabs.css('visibility', 'hidden');

        if (that.filter) {
            var filter = $.bbq.getState(that.entity_name + '-filter', true) || '';
            that.filter.val(filter);
        }
    };

    that.select_changed = function() {

        var values = that.table.get_selected_values();

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

    that.find = function() {
        var filter = that.filter.val();
        var state = {};
        state[that.entity_name + '-filter'] = filter;
        IPA.nav.push_state(state);
    };

    that.refresh = function() {

        function on_success(data, text_status, xhr) {

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

        var filter = $.bbq.getState(that.entity_name + '-filter', true) || '';

        var command = IPA.command({
            entity: that.entity_name,
            method: 'find',
            args: [filter],
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

    return that;
};
