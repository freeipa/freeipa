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
            label: IPA.metadata.objects[entity.name].label,
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

        var span = $('<span/>', {
            'class': 'right-aligned-facet-controls'
        }).appendTo(that.controls);

        that.filter = $('<input/>', {
            type: 'text',
			'class': 'search-filter',
            name: 'filter'
        }).appendTo(span);

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
        }).appendTo(span);

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
            var filter = $.bbq.getState(that.entity_name+'-filter');
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
            title = title.replace('${entity}', that.label);
            alert(title);
            return;
        }

        title = IPA.messages.dialogs.remove_title;
        title = title.replace('${entity}', that.label);

        var dialog = IPA.deleter_dialog({
            'title': title,
            'parent': that.container,
            'values': values,
            entity_name: entity.name
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

            var pkeys =
                entity.get_primary_key_prefix();

            for (var i=0; i<values.length; i++) {
                var command = IPA.command({
                    entity: entity.name,
                    method: 'del'
                });

                for (var k=0; k<pkeys.length; k++) {
                    command.add_arg(pkeys[k]);
                }
                var value = values[i];
                if (value instanceof Object){
                    for (var key in value){
                        if (value.hasOwnProperty(key)){
                            command.set_option(key, value[key]);
                        }
                    }
                }else{
                    command.add_arg(value);
                }
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
        state[that.managed_entity_name + '-filter'] = filter;
        IPA.nav.push_state(state);
    };

    that.load = function(result) {

        that.table.empty();

        for (var i = 0; i<result.length; i++) {
            var record = that.table.get_record(result[i], 0);
            that.table.add_record(record);
        }
    };

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
        filter.unshift($.bbq.getState(current_entity.name+'-filter'));
        current_entity = current_entity.containing_entity;
        while(current_entity !== null){
            filter.unshift(
                $.bbq.getState(current_entity.name+'-pkey'));
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
            $.bbq.getState(IPA.current_entity.name+'-pkey'));

        if (that.filter) {
            var filter = $.bbq.getState(that.managed_entity_name+'-filter');
            that.filter.val(filter);
        }
    };

    that.refresh = function(){

        var pkey = $.bbq.getState(that.entity.name+'-pkey');

        if ((!pkey) && (that.entity.redirect_facet)) {

            var current_entity = that.entity;
            while (current_entity.containing_entity){
                current_entity = current_entity.containing_entity;
            }

            IPA.nav.show_page(
                current_entity.name,
                that.entity.redirect_facet);
            return;
        }

        that.search_refresh(that.managed_entity);
    };

    return that;
};
