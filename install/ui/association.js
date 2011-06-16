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

    that.entity_name = spec.entity_name;
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
        options[that.entity_name] = that.pkey;

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
            entity: that.entity_name,
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

    var that = IPA.adder_dialog(spec);

    that.entity_name = spec.entity_name;
    that.pkey = spec.pkey;
    that.other_entity = spec.other_entity;
    that.attribute_member = spec.attribute_member;

    that.init = function() {
        if (!that.columns.length) {
            var pkey_name = IPA.metadata.objects[that.other_entity].primary_key;
            that.create_column({
                name: pkey_name,
                label: IPA.metadata.objects[that.other_entity].label,
                primary_key: true,
                width: '200px'
            });
        }

        /* FIXME: event not firing? */
        $('input[name=hidememb]', that.container).click(that.search);

        that.adder_dialog_init();
    };

    that.search = function() {
        function on_success(data, text_status, xhr) {
            var results = data.result;
            that.clear_available_values();

            var pkey_attr = IPA.metadata.objects[that.entity_name].primary_key;

            for (var i=0; i<results.count; i++){
                var result = results.result[i];
                if (result[pkey_attr] != spec.pkey)
                    that.add_available_value(result);
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
                var param_name = relationship[2] + that.entity_name;
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

    that.association_adder_dialog_init = that.init;
    that.association_adder_dialog_setup = that.setup;

    return that;
};


/**
 * This dialog is used for removing associations between two entities.
 */
IPA.association_deleter_dialog = function (spec) {

    spec = spec || {};

    var that = IPA.deleter_dialog(spec);

    that.entity_name = spec.entity_name;
    that.pkey = spec.pkey;
    that.other_entity = spec.other_entity;
    that.values = spec.values;

    that.associator = spec.associator;
    that.method = spec.method || 'remove_member';

    that.on_success = spec.on_success;
    that.on_error = spec.on_error;

    that.execute = function() {

        var associator = that.associator({
            'entity_name': that.entity_name,
            'pkey': that.pkey,
            'other_entity': that.other_entity,
            'values': that.values,
            'method': that.method,
            'on_success': that.on_success,
            'on_error': that.on_error
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
        var column = IPA.column(spec);
        that.add_adder_column(column);
        return column;
    };

    /*this is duplicated in the facet... should be unified*/
    var i;
    if (spec.columns){
        for (i = 0; i < spec.columns.length; i+= 1){
            that.create_column(spec.columns[i]);
        }
    }
    if (spec.adder_columns){
        for (i = 0; i < spec.adder_columns.length; i+= 1){
            that.create_adder_column(spec.adder_columns[i]);
        }
    }

    that.create = function(container) {

        var column;

        // create a column if none defined
        if (!that.columns.length) {
            that.create_column({
                'name': that.name,
                'label': IPA.metadata.objects[that.other_entity].label,
                'primary_key': true
            });
        }

        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++) {
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
        for (var j=0; j<adder_columns.length; j++) {
            column = adder_columns[j];
            column.entity_name = that.other_entity;
        }

        that.table_init();

        that.table_create(container);

        var buttons = $('span[name=buttons]', container);

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

    that.setup = function(container) {

        that.table_setup(container);

        var entity = IPA.get_entity(that.entity_name);
        var facet_name = IPA.current_facet(entity);
        var facet = entity.get_facet(facet_name);

        var button = $('input[name=remove]', container);
        button.replaceWith(IPA.action_button({
            'label': button.val(),
            'icon': 'ui-icon-trash',
            'click': function() {
                if ($(this).hasClass('action-button-disabled')) {
                    return false;
                }

                if (facet.is_dirty()) {
                    var dialog = IPA.dirty_dialog({
                        facet: facet
                    });

                    dialog.callback = function() {
                        that.show_remove_dialog();
                    };

                    dialog.init();
                    dialog.open(that.container);

                } else {
                    that.show_remove_dialog();
                }

                return false;
            }
        }));

        button = $('input[name=add]', container);
        button.replaceWith(IPA.action_button({
            'label': button.val(),
            'icon': 'ui-icon-plus',
            'click': function() {
                if ($(this).hasClass('action-button-disabled')) {
                    return false;
                }

                if (facet.is_dirty()) {
                    var dialog = IPA.dirty_dialog({
                        facet: facet
                    });

                    dialog.callback = function() {
                        that.show_add_dialog();
                    };

                    dialog.init();
                    dialog.open(that.container);

                } else {
                    that.show_add_dialog();
                }

                return false;
            }
        }));
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
            'name': that.entity_name+'_'+that.name,
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
        var pkey = $.bbq.getState(that.entity_name+'-pkey');
        var label = IPA.metadata.objects[that.other_entity].label;
        var title = IPA.messages.association.add;

        title = title.replace('${entity}', that.entity_name);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', label);

        return IPA.association_adder_dialog({
            'title': title,
            'entity_name': that.entity_name,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'attribute_member': that.attribute_member,
            method: that.add_method
        });
    };

    that.show_add_dialog = function() {

        var dialog = that.create_add_dialog();

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

        dialog.init();

        dialog.open(that.container);
    };

    that.add = function(values, on_success, on_error) {

        var pkey = $.bbq.getState(that.entity_name+'-pkey');

        var command = IPA.command({
            entity: that.entity_name,
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
            message = message.replace('${entity}', that.label);
            alert(message);
            return;
        }

        var pkey = $.bbq.getState(that.entity_name+'-pkey');
        var label = IPA.metadata.objects[that.other_entity].label;
        var title = IPA.messages.association.remove;

        title = title.replace('${entity}', that.entity_name);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', label);

        var dialog = IPA.association_deleter_dialog({
            'title': title,
            'entity_name': that.entity_name,
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

        dialog.init();

        dialog.open(that.container);
    };

    that.remove = function(values, on_success, on_error) {

        var pkey = $.bbq.getState(that.entity_name+'-pkey');

        var command = IPA.command({
            entity: that.entity_name,
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

        var pkey = $.bbq.getState(that.entity_name+'-pkey');
        IPA.command({
            entity: that.entity_name,
            method: 'show',
            args: [pkey],
            options: {'all': true, 'rights': true},
            on_success: on_success,
            on_error: on_error
        }).execute();
    };

    // methods that should be invoked by subclasses
    that.association_table_widget_init = that.init;

    return that;
};


IPA.association_facet = function (spec) {

    spec = spec || {};

    var that = IPA.facet(spec);

    that.attribute_member = spec.attribute_member;
    that.indirect_attribute_member = spec.indirect_attribute_member;

    that.other_entity = spec.other_entity;

    that.association_type = 'direct';
    that.facet_group = spec.facet_group;

    that.read_only = spec.read_only;
    that.link = spec.link === undefined ? true : spec.link;

    that.associator = spec.associator || IPA.bulk_associator;
    that.add_method = spec.add_method || 'add_member';
    that.remove_method = spec.remove_method || 'remove_member';

    that.columns = $.ordered_map();
    that.adder_columns = $.ordered_map();

    that.page_length = spec.page_length === undefined ? 20 : spec.page_length;

    that.get_column = function(name) {
        return that.columns.get(name);
    };

    that.add_column = function(column) {
        that.columns.put(column.name, column);
    };

    that.create_column = function(spec) {
        var column = IPA.column(spec);
        that.add_column(column);
        return column;
    };

    that.get_adder_column = function(name) {
        return that.adder_columns.get(name);
    };

    that.add_adder_column = function(column) {
        that.adder_columns.put(column.name, column);
    };

    that.create_adder_column = function(spec) {
        var column = IPA.column(spec);
        that.add_adder_column(column);
        return column;
    };

    var i;
    if (spec.columns){
        for (i = 0; i < spec.columns.length; i+= 1){
            that.create_column(spec.columns[i]);
        }
    }
    if (spec.adder_columns){
        for (i = 0; i < spec.adder_columns.length; i+= 1){
            that.create_adder_column(spec.adder_columns[i]);
        }
    }

    that.init = function() {

        that.facet_init();

        var entity = IPA.get_entity(that.entity_name);
        var column;
        var i;

        var label = IPA.metadata.objects[that.other_entity] ? IPA.metadata.objects[that.other_entity].label : that.other_entity;
        var pkey_name = IPA.metadata.objects[that.other_entity].primary_key;

        that.table = IPA.table_widget({
            id: that.entity_name+'-'+that.other_entity,
            'class': 'content-table',
            name: pkey_name,
            label: label,
            entity_name: that.entity_name,
            other_entity: that.other_entity,
            page_length: that.page_length,
            scrollable: true,
            selectable: !that.read_only
        });

        var columns = that.columns.values;
        if (!columns.length) {
            that.create_column({
                name: pkey_name,
                primary_key: true,
                link: that.link
            });
        }

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

        that.table.refresh = function() {
            that.refresh_table();
        };

        that.table.init();
    };

    that.create_header = function(container) {

        that.facet_create_header(container);

        that.pkey = $.bbq.getState(that.entity_name+'-pkey');
        var other_label = IPA.metadata.objects[that.other_entity].label;

        var title = that.title;
        title = title.replace('${entity}', that.entity_name);
        title = title.replace('${primary_key}', that.pkey);
        title = title.replace('${other_entity}', other_label);

        that.set_title(container, title);

        if (!that.read_only) {
            that.remove_button = IPA.action_button({
                label: IPA.messages.buttons.remove,
                icon: 'ui-icon-trash',
                click: function() {
                    that.show_remove_dialog();
                    return false;
                }
            }).appendTo(that.controls);

            that.add_button = IPA.action_button({
                label: IPA.messages.buttons.enroll,
                icon: 'ui-icon-plus',
                click: function() {
                    that.show_add_dialog();
                    return false;
                }
            }).appendTo(that.controls);
        }

        if (that.indirect_attribute_member) {
            var span = $('<span/>', {
                'class': 'right-aligned-controls'
            }).appendTo(that.controls);

            span.append('Show Results ');

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

            span.append(' Direct Enrollment ');

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

            span.append(' Indirect Enrollment');
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
        that.table.setup(container);
    };

    that.show = function() {
        that.facet_show();

        that.pkey = $.bbq.getState(that.entity_name+'-pkey');
        that.entity.header.set_pkey(that.pkey);

        that.entity.header.back_link.css('visibility', 'visible');
        that.entity.header.facet_tabs.css('visibility', 'visible');
    };

    that.show_add_dialog = function() {

        var pkey = $.bbq.getState(that.entity_name+'-pkey');
        var label = IPA.metadata.objects[that.other_entity] ? IPA.metadata.objects[that.other_entity].label : that.other_entity;
        var title = IPA.messages.association.add;

        title = title.replace('${entity}', that.entity_name);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', label);

        var dialog = IPA.association_adder_dialog({
            'title': title,
            'entity_name': that.entity_name,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'attribute_member': that.attribute_member
        });

        var adder_columns = that.adder_columns.values;
        if (adder_columns.length) {
            dialog.set_columns(adder_columns);
        }

        dialog.execute = function() {

            var pkey = $.bbq.getState(that.entity_name+'-pkey');

            var associator = that.associator({
                'entity_name': that.entity_name,
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

        dialog.init();

        dialog.open(that.container);
    };

    that.show_remove_dialog = function() {

        var label = IPA.metadata.objects[that.other_entity] ? IPA.metadata.objects[that.other_entity].label : that.other_entity;
        var values = that.table.get_selected_values();

        if (!values.length) {
            var message = IPA.messages.dialogs.remove_empty;
            message = message.replace('${entity}', label);
            alert(message);
            return;
        }

        var pkey = $.bbq.getState(that.entity_name+'-pkey');
        var title = IPA.messages.association.remove;

        title = title.replace('${entity}', that.entity_name);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', label);

        var dialog = IPA.association_deleter_dialog({
            title: title,
            entity_name: that.entity_name,
            pkey: pkey,
            other_entity: that.other_entity,
            values: values
        });

        dialog.execute = function() {

            var associator = that.associator({
                entity_name: that.entity_name,
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

        dialog.init();

        dialog.open(that.container);
    };

    that.refresh_table = function() {

        that.table.current_page_input.val(that.table.current_page);
        that.table.total_pages_span.text(that.table.total_pages);

        var pkeys = that.record[that.get_attribute_name()];
        if (!pkeys || !pkeys.length) {
            that.table.empty();
            that.table.summary.text('No entries.');
            return;
        }

        pkeys.sort();
        var total = pkeys.length;

        var start = (that.table.current_page - 1) * that.table.page_length + 1;
        var end = that.table.current_page * that.table.page_length;
        end = end > total ? total : end;

        var summary = 'Showing '+start+' to '+end+' of '+total+' entries.';
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
            'name': that.entity_name+'_'+that.get_attribute_name(),
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

        function on_success(data, text_status, xhr) {
            that.record = data.result.result;

            that.table.current_page = 1;

            var pkeys = that.record[that.get_attribute_name()];
            if (pkeys) {
                that.table.total_pages =
                    Math.ceil(pkeys.length / that.table.page_length);
            } else {
                that.table.total_pages = 1;
            }

            that.refresh_table();
        }

        var pkey = IPA.get_entity(that.entity_name).get_primary_key();

        IPA.command({
            entity: that.entity_name,
            method: 'show',
            args: pkey,
            on_success: on_success,
            on_error: that.on_error
        }).execute();
    };

    that.association_facet_init = that.init;

    return that;
};
