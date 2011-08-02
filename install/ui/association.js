/*jsl:import ipa.js */

/*  Authors:
 *    Adam Young <ayoung@redhat.com>
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
/* CURRENTLY ALSO REQUIRES search.js, because it reuses it's code to create
 * the AssociationList elements; IT NEEDS IT'S OWN CODE! */

IPA.associator = function (spec) {

    spec = spec || {};

    var that = {};

    that.entity = spec.entity;
    that.pkey = spec.pkey;

    that.other_entity = spec.other_entity;
    that.values = spec.values;

    that.method = spec.method;

    that.on_success = spec.on_success;
    that.on_error = spec.on_error;

    that.execute = function() {
    };

    return that;
};


/**
*This associator is built for the case where each association requires a separate rpc
*/
IPA.serial_associator = function(spec) {

    spec = spec || {};

    var that = IPA.associator(spec);

    that.execute = function() {

        if (!that.values || !that.values.length) {
            that.on_success();
            return;
        }

        var value = that.values.shift();
        if (!value) {
            that.on_success();
            return;
        }

        var args = [value];
        var options = {};
        options[that.entity.name] = that.pkey;

        var command = IPA.command({
            entity: that.other_entity,
            method: that.method,
            args: args,
            options: options,
            on_success: that.execute,
            on_error: that.on_error
        });

        //alert(JSON.stringify(command.to_json()));

        command.execute();
    };

    return that;
};

/**
*This associator is for the common case where all the asociations can be sent
in a single rpc
*/
IPA.bulk_associator = function(spec) {

    spec = spec || {};

    var that = IPA.associator(spec);

    that.execute = function() {

        if (!that.values || !that.values.length) {
            that.on_success();
            return;
        }

        var value = that.values.shift();
        if (!value) {
            that.on_success();
            return;
        }

        while (that.values.length > 0) {
            value += ',' + that.values.shift();
        }

        var args = [that.pkey];
        var options = { 'all': true };
        options[that.other_entity] = value;

        var command = IPA.command({
            entity: that.entity.name,
            method: that.method,
            args: args,
            options: options,
            on_success: that.on_success,
            on_error: that.on_error
        });

        //alert(JSON.stringify(command.to_json()));

        command.execute();
    };

    return that;
};

/**
 * This dialog is used for adding associations between two entities.
 */
IPA.association_adder_dialog = function (spec) {

    spec = spec || {};
    /*
      TODO: columns map in IPA.adder_dialog should be removed and add_column()
      should be modified to add the column directly into the available_table
      and selected_table. This way IPA.association_adder_dialog can call
      create_column() from the initialization area, no need to modify the
      parameters.
    */
    default_columns(spec);

    var that = IPA.adder_dialog(spec);

    that.entity = spec.entity;
    that.pkey = spec.pkey;
    that.other_entity = spec.other_entity;
    that.attribute_member = spec.attribute_member;

    that.search = function() {
        function on_success(data, text_status, xhr) {
            var results = data.result;
            that.clear_available_values();

            var pkey_attr = that.entity.metadata.primary_key;

            for (var i=0; i<results.count; i++){
                var result = results.result[i];
                if (result[pkey_attr] != spec.pkey){
                    that.add_available_value(result);
                }
            }
        }

        var hide_checkbox = $('input[name=hidememb]', that.container);

        var options = {'all': true};
        if (hide_checkbox.attr('checked')) {
            var relationships = IPA.metadata.objects[that.other_entity].relationships;

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

            var relationship = relationships[other_attribute_member];
            if (relationship) {
                var param_name = relationship[2] + that.entity.name;
                options[param_name] = that.pkey;
            }
        }

        IPA.command({
            entity: that.other_entity,
            method: 'find',
            args: [that.get_filter()],
            options: options,
            on_success: on_success
        }).execute();
    };

    /*initialization*/
    function default_columns(spec){
        if (!spec.columns) {
            var pkey_name = IPA.metadata.objects[spec.other_entity].primary_key;
            spec.columns = [{
                name: pkey_name,
                label: IPA.metadata.objects[spec.other_entity].label,
                primary_key: true,
                width: '600px'
            }];
        }
    }

    return that;
};


/**
 * This dialog is used for removing associations between two entities.
 */
IPA.association_deleter_dialog = function (spec) {

    spec = spec || {};

    var that = IPA.deleter_dialog(spec);

    that.entity = spec.entity;
    that.pkey = spec.pkey;
    that.other_entity = spec.other_entity;
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


IPA.association_config = function (spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.associator = spec.associator;
    that.add_method = spec.add_method;
    that.remove_method = spec.remove_method;

    return that;
};

IPA.association_table_widget = function (spec) {

    spec = spec || {};
    spec.managed_entity_name = spec.other_entity;

    var that = IPA.table_widget(spec);

    that.other_entity = spec.other_entity;
    that.attribute_member = spec.attribute_member;

    that.associator = spec.associator || IPA.bulk_associator;
    that.add_method = spec.add_method || 'add_member';
    that.remove_method = spec.remove_method || 'remove_member';

    that.adder_columns = $.ordered_map();

    that.get_adder_column = function(name) {
        return that.adder_columns.get(name);
    };

    that.add_adder_column = function(column) {
        that.adder_columns.put(column.name, column);
    };

    that.create_adder_column = function(spec) {
        spec.entity_name = that.other_entity;
        var column = IPA.column(spec);
        that.add_adder_column(column);
        return column;
    };

    that.create = function(container) {

        var column;

        // create a column if none defined
        if (!that.columns.length) {
            that.create_column({
                name: that.name,
                label: IPA.metadata.objects[that.other_entity].label,
                entity_name: that.other_entity,
                primary_key: true
            });
        }

        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++) {
            column = columns[i];
            column.entity = IPA.get_entity(that.other_entity);

            if (column.link) {
                column.link_handler = function(value) {
                    IPA.nav.show_page(that.other_entity, 'default', value);
                    return false;
                };
            }
        }

        var adder_columns = that.adder_columns.values;
        for (var j=0; j<adder_columns.length; j++) {
            column = adder_columns[j];
            column.entity_name = that.other_entity;
        }

        that.table_create(container);

        var button = IPA.action_button({
            name: 'remove',
            label: IPA.messages.buttons.remove,
            icon: 'remove-icon',
            click: function() {
                that.remove_handler();
                return false;
            }
        }).appendTo(that.buttons);

        button = IPA.action_button({
            name: 'add',
            label: IPA.messages.buttons.add,
            icon: 'add-icon',
            click: function() {
                that.add_handler();
                return false;
            }
        }).appendTo(that.buttons);
    };

    that.add_handler = function() {
        if ($(this).hasClass('action-button-disabled')) {
            return;
        }

        var facet = that.entity.get_facet();

        if (facet.is_dirty()) {
            var dialog = IPA.dirty_dialog({
                entity:that.entity,
                facet: facet
            });

            dialog.callback = function() {
                that.show_add_dialog();
            };

            dialog.open(that.container);

        } else {
            that.show_add_dialog();
        }
    };

    that.remove_handler = function() {
        if ($(this).hasClass('action-button-disabled')) {
            return;
        }

        var facet = that.entity.get_facet();

        if (facet.is_dirty()) {
            var dialog = IPA.dirty_dialog({
                entity:that.entity,
                facet: facet
            });

            dialog.callback = function() {
                that.show_remove_dialog();
            };

            dialog.open(that.container);

        } else {
            that.show_remove_dialog();
        }
    };

    that.set_enabled = function(enabled) {
        that.table_set_enabled(enabled);
        if (enabled) {
            $('.action-button', that.table).removeClass('action-button-disabled');
        } else {
            $('.action-button', that.table).addClass('action-button-disabled');
        }
    };

    that.get_records = function(on_success, on_error) {

        var length = that.values.length;
        if (!length) return;

        if (length > 100) {
            length = 100;
        }

        var batch = IPA.batch_command({
            'name': that.entity.name+'_'+that.name,
            'on_success': on_success,
            'on_error': on_error
        });

        for (var i=0; i<length; i++) {
            var value = that.values[i];

            var command = IPA.command({
                entity: that.other_entity,
                method: 'show',
                args: [value],
                options: {
                    all: true,
                    rights: true
                }
            });

            batch.add_command(command);
        }

        batch.execute();
    };

    that.load = function(result) {
        that.values = result[that.name] || [];
        that.reset();
    };

    that.update = function() {

        that.empty();

        var columns = that.columns.values;
        if (columns.length == 1) { // show pkey only
            var name = columns[0].name;
            for (var i=0; i<that.values.length; i++) {
                var record = {};
                record[name] = that.values[i];
                that.add_record(record);
            }

        } else { // get and show additional fields
            that.get_records(
                function(data, text_status, xhr) {
                    var results = data.result.results;
                    for (var i=0; i<results.length; i++) {
                        var record = results[i].result;
                        that.add_record(record);
                    }
                }
            );
        }
    };

    that.create_add_dialog = function() {
        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        var label = IPA.metadata.objects[that.other_entity].label;
        var title = IPA.messages.association.add;

        title = title.replace(
            '${entity}',
            that.entity.metadata.label_singular);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', label);

        return IPA.association_adder_dialog({
            title: title,
            entity: that.entity,
            pkey: pkey,
            other_entity: that.other_entity,
            attribute_member: that.attribute_member,
            method: that.add_method
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
                function() {
                    that.refresh();
                    dialog.close();
                },
                function() {
                    that.refresh();
                    dialog.close();
                }
            );
        };

        dialog.open(that.container);
    };

    that.add = function(values, on_success, on_error) {

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');

        var command = IPA.command({
            entity: that.entity.name,
            method: that.add_method,
            args: [pkey],
            on_success: on_success,
            on_error: on_error
        });
        command.set_option(that.other_entity, values.join(','));

        command.execute();
    };

    that.show_remove_dialog = function() {

        var selected_values = that.get_selected_values();

        if (!selected_values.length) {
            var message = IPA.messages.dialogs.remove_empty;
            alert(message);
            return;
        }

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        var label = IPA.metadata.objects[that.other_entity].label;
        var title = IPA.messages.association.remove;

        title = title.replace(
            '${entity}',
            that.entity.metadata.label_singular);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', label);

        var dialog = IPA.association_deleter_dialog({
            'title': title,
            'entity': that.entity,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'values': selected_values,
            method: that.remove_method
        });

        dialog.execute = function() {
            that.remove(
                selected_values,
                function() {
                    that.refresh();
                    dialog.close();
                },
                function() {
                    that.refresh();
                    dialog.close();
                }
            );
        };


        dialog.open(that.container);
    };

    that.remove = function(values, on_success, on_error) {

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');

        var command = IPA.command({
            entity: that.entity.name,
            method: that.remove_method,
            args: [pkey],
            on_success: on_success,
            on_error: on_error
        });

        command.set_option(that.other_entity, values.join(','));

        command.execute();
    };

    that.refresh = function() {

        function on_success(data, text_status, xhr) {
            that.load(data.result.result);
        }

        function on_error(xhr, text_status, error_thrown) {
            var summary = $('span[name=summary]', that.tfoot).empty();
            summary.append(error_thrown.name+': '+error_thrown.message);
        }

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        IPA.command({
            entity: that.entity.name,
            method: 'show',
            args: [pkey],
            options: {'all': true, 'rights': true},
            on_success: on_success,
            on_error: on_error
        }).execute();
    };

    /*initialization code*/
    /*this is duplicated in the facet... should be unified*/
    var i;
    if (spec.columns){
        for (i = 0; i < spec.columns.length; i+= 1){
            spec.columns[i].entity_name = spec.columns[i].entity_name ||
                that.other_entity;
            that.create_column(spec.columns[i]);
        }
    }
    if (spec.adder_columns){
        for (i = 0; i < spec.adder_columns.length; i+= 1){
            that.create_adder_column(spec.adder_columns[i]);
        }
    }

    // methods that should be invoked by subclasses
    that.association_table_widget_show_add_dialog = that.show_add_dialog;
    that.association_table_widget_show_remove_dialog = that.show_remove_dialog;

    return that;
};


IPA.association_facet = function (spec) {

    spec = spec || {};

    /*
       Link parameter is used to turn off the links in selfservice mode.
       Default it to true if not set so that facets that would not otherwise
       link by default get links set.

       link must be set before the call to the base class, to affect the  table.
     */
    spec.link = spec.link === undefined ? true : spec.link;

    spec.managed_entity_name = spec.other_entity;
    var that = IPA.table_facet(spec);

    that.entity = spec.entity;
    that.attribute_member = spec.attribute_member;
    that.indirect_attribute_member = spec.indirect_attribute_member;

    that.other_entity = spec.other_entity;

    that.association_type = 'direct';
    that.facet_group = spec.facet_group;

    that.read_only = spec.read_only;

    that.associator = spec.associator || IPA.bulk_associator;
    that.add_method = spec.add_method || 'add_member';
    that.remove_method = spec.remove_method || 'remove_member';

    that.adder_columns = $.ordered_map();

    that.page_length = spec.page_length === undefined ? 20 : spec.page_length;

    that.get_adder_column = function(name) {
        return that.adder_columns.get(name);
    };

    that.add_adder_column = function(column) {
        column.entity_name = that.managed_entity_name;
        that.adder_columns.put(column.name, column);
    };

    /*TODO try to reuse the association_table_widget in association_facet*/
    that.create_adder_column = function(spec) {
        var column;
        var factory;
        if (spec instanceof Object) {
            factory = spec.factory || IPA.column;
        } else {
            factory  = IPA.column;
            spec = { name: spec };
        }
        spec.entity_name = that.other_entity;
        column = factory(spec);
        that.add_adder_column(column);
        return column;
    };

    function setup_columns(){
        var column;
        var i;

        var pkey_name;
        if (that.other_entity){
            pkey_name = IPA.metadata.objects[that.other_entity].primary_key;
        }

        if (!that.columns.length){
            that.create_column({
                name: pkey_name,
                primary_key: true,
                link: spec.link
            });
        }


        var label = IPA.metadata.objects[that.other_entity] ?
            IPA.metadata.objects[that.other_entity].label : that.other_entity;

        that.table = IPA.table_widget({
            id: that.entity.name+'-'+that.other_entity,
            'class': 'content-table',
            name: pkey_name,
            label: label,
            entity: that.entity,
            other_entity: that.other_entity,
            page_length: that.page_length,
            scrollable: true,
            selectable: !that.read_only
        });

        var columns = that.columns.values;

        that.table.set_columns(columns);

        for (i=0; i<columns.length; i++) {
            column = columns[i];
            column.entity_name = that.other_entity;

            if (column.link) {
                column.link_handler = function(value) {
                    IPA.nav.show_page(that.other_entity, 'default', value);
                    return false;
                };
            }
        }

        var adder_columns = that.adder_columns.values;
        for (i=0; i<adder_columns.length; i++) {
            column = adder_columns[i];
            column.entity_name = that.other_entity;
        }

        that.table.prev_page = function() {
            if (that.table.current_page > 1) {
                var state = {};
                state[that.entity_name+'-page'] = that.table.current_page - 1;
                IPA.nav.push_state(state);
            }
        };

        that.table.next_page = function() {
            if (that.table.current_page < that.table.total_pages) {
                var state = {};
                state[that.entity_name+'-page'] = that.table.current_page + 1;
                IPA.nav.push_state(state);
            }
        };

        that.table.set_page = function(page) {
            if (page < 1) {
                page = 1;
            } else if (page > that.total_pages) {
                page = that.total_pages;
            }
            var state = {};
            state[that.entity_name+'-page'] = page;
            IPA.nav.push_state(state);
        };

        that.table.refresh = function() {
            var state = {};
            var page = parseInt(IPA.nav.get_state(that.entity_name+'-page'), 10) || 1;
            if (page < 1) {
                state[that.entity_name+'-page'] = 1;
                IPA.nav.push_state(state);
                return;
            } else if (page > that.table.total_pages) {
                state[that.entity_name+'-page'] = that.table.total_pages;
                IPA.nav.push_state(state);
                return;
            }
            that.table.current_page = page;
            that.table.current_page_input.val(page);
            that.refresh_table();
        };

    }

    that.create_header = function(container) {

        that.facet_create_header(container);

        that.pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        var other_label = IPA.metadata.objects[that.other_entity].label;

        if (!that.read_only) {
            that.remove_button = IPA.action_button({
                name: 'remove',
                label: IPA.messages.buttons.remove,
                icon: 'remove-icon',
                click: function() {
                    that.show_remove_dialog();
                    return false;
                }
            }).appendTo(that.controls);

            that.add_button = IPA.action_button({
                name: 'add',
                label: IPA.messages.buttons.enroll,
                icon: 'add-icon',
                click: function() {
                    that.show_add_dialog();
                    return false;
                }
            }).appendTo(that.controls);
        }

        if (that.indirect_attribute_member) {
            var span = $('<span/>', {
                'class': 'right-aligned-facet-controls'
            }).appendTo(that.controls);

            span.append(IPA.messages.association.show_results);
            span.append(' ');

            that.direct_radio = $('<input/>', {
                type: 'radio',
                name: 'type',
                value: 'direct',
                click: function() {
                    that.association_type = $(this).val();
                    that.refresh();
                    return true;
                }
            }).appendTo(span);

            span.append(' ');
            span.append(IPA.messages.association.direct_enrollment);
            span.append(' ');

            that.indirect_radio = $('<input/>', {
                type: 'radio',
                name: 'type',
                value: 'indirect',
                click: function() {
                    that.association_type = $(this).val();
                    that.refresh();
                    return true;
                }
            }).appendTo(span);

            span.append(' ');
            span.append(IPA.messages.association.indirect_enrollment);
        }
    };

    that.get_attribute_name = function() {
        if (that.association_type == 'direct') {
            return that.attribute_member+'_'+that.other_entity;
        } else {
            return that.indirect_attribute_member+'_'+that.other_entity;
        }
    };

    that.create_content = function(container) {
        that.table.create(container);
    };

    that.show = function() {
        that.facet_show();

        that.pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        that.header.set_pkey(that.pkey);
    };

    that.show_add_dialog = function() {

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        var label = IPA.metadata.objects[that.other_entity] ? IPA.metadata.objects[that.other_entity].label : that.other_entity;
        var title = IPA.messages.association.add;

        title = title.replace(
            '${entity}',
            that.entity.metadata.label_singular);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', label);

        var dialog = IPA.association_adder_dialog({
            'title': title,
            'entity': that.entity,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'attribute_member': that.attribute_member
        });

        var adder_columns = that.adder_columns.values;
        if (adder_columns.length) {
            dialog.set_columns(adder_columns);
        }

        dialog.execute = function() {

            var pkey = IPA.nav.get_state(that.entity.name+'-pkey');

            var associator = that.associator({
                'entity': that.entity,
                'pkey': pkey,
                'other_entity': that.other_entity,
                'values': dialog.get_selected_values(),
                'method': that.add_method,
                'on_success': function() {
                    that.refresh();
                    dialog.close();
                },
                'on_error': function() {
                    that.refresh();
                    dialog.close();
                }
            });

            associator.execute();
        };

        dialog.open(that.container);
    };

    that.show_remove_dialog = function() {

        var label = IPA.metadata.objects[that.other_entity] ? IPA.metadata.objects[that.other_entity].label : that.other_entity;
        var values = that.table.get_selected_values();

        if (!values.length) {
            var message = IPA.messages.dialogs.remove_empty;
            alert(message);
            return;
        }

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        var title = IPA.messages.association.remove;

        title = title.replace(
            '${entity}',
            that.entity.metadata.label_singular);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', label);

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
                on_success: function() {
                    that.refresh();
                    dialog.close();
                },
                on_error: function() {
                    that.refresh();
                    dialog.close();
                }
            });

            associator.execute();
        };

        dialog.open(that.container);
    };

    that.refresh_table = function() {

        that.table.current_page_input.val(that.table.current_page);
        that.table.total_pages_span.text(that.table.total_pages);

        var pkeys = that.data[that.get_attribute_name()];
        if (!pkeys || !pkeys.length) {
            that.table.empty();
            that.table.summary.text(IPA.messages.association.no_entries);
            return;
        }

        pkeys.sort();
        var total = pkeys.length;

        var start = (that.table.current_page - 1) * that.table.page_length + 1;
        var end = that.table.current_page * that.table.page_length;
        end = end > total ? total : end;

        var summary = IPA.messages.association.paging;
        summary = summary.replace('${start}', start);
        summary = summary.replace('${end}', end);
        summary = summary.replace('${total}', total);
        that.table.summary.text(summary);

        var list = pkeys.slice(start-1, end);

        var columns = that.table.columns.values;
        if (columns.length == 1) { // show pkey only
            var name = columns[0].name;
            that.table.empty();
            for (var i=0; i<list.length; i++) {
                var entry = {};
                entry[name] = list[i];
                that.table.add_record(entry);
            }

        } else { // get and show additional fields
            that.get_records(
                list,
                function(data, text_status, xhr) {
                    var results = data.result.results;
                    that.table.empty();
                    for (var i=0; i<results.length; i++) {
                        var record = results[i].result;
                        that.table.add_record(record);
                    }
                },
                function(xhr, text_status, error_thrown) {
                    that.table.empty();
                    var summary = that.table.summary.empty();
                    summary.append(error_thrown.name+': '+error_thrown.message);
                }
            );
        }
    };

    that.get_records = function(pkeys, on_success, on_error) {

        var length = pkeys.length;
        if (!length) return;

        var batch = IPA.batch_command({
            'name': that.entity.name+'_'+that.get_attribute_name(),
            'on_success': on_success,
            'on_error': on_error
        });

        for (var i=0; i<length; i++) {
            var pkey = pkeys[i];

            var command = IPA.command({
                entity: that.other_entity,
                method: 'show',
                args: [pkey],
                options: { all: true }
            });

            batch.add_command(command);
        }

        batch.execute();
    };

    that.load = function(data) {
        that.facet_load(data);

        var pkeys = that.data[that.get_attribute_name()];
        if (pkeys) {
            that.table.total_pages =
                Math.ceil(pkeys.length / that.table.page_length);
        } else {
            that.table.total_pages = 1;
        }

        that.table.current_page = 1;

        that.table.refresh();
    };

    that.refresh = function() {

        if (that.association_type == 'direct') {
            if (that.direct_radio) that.direct_radio.attr('checked', true);
            if (that.add_button) that.add_button.css('display', 'inline');
            if (that.remove_button) that.remove_button.css('display', 'inline');
        } else {
            if (that.indirect_radio) that.indirect_radio.attr('checked', true);
            if (that.add_button) that.add_button.css('display', 'none');
            if (that.remove_button) that.remove_button.css('display', 'none');
        }

        var pkey = IPA.get_entity(that.entity.name).get_primary_key();

        var command = IPA.command({
            entity: that.entity.name,
            method: 'show',
            args: pkey
        });

        command.on_success = function(data, text_status, xhr) {
            that.load(data.result.result);
        };

        command.on_error = that.on_error;

        command.execute();
    };

    /*initialization*/
    var adder_columns = spec.adder_columns || [];
    for (var i=0; i<adder_columns.length; i++) {
        that.create_adder_column(adder_columns[i]);
    }
    setup_columns();
    return that;
};
