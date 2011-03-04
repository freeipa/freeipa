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
            method: that.other_entity+'_'+that.method,
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
            method: that.entity_name+'_'+that.method,
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

        IPA.cmd('find', [that.get_filter()], options, on_success, null, that.other_entity);
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

    that.adder_columns = [];
    that.adder_columns_by_name = {};

    that.get_adder_column = function(name) {
        return that.adder_columns_by_name[name];
    };

    that.add_adder_column = function(column) {
        that.adder_columns.push(column);
        that.adder_columns_by_name[column.name] = column;
    };

    that.create_adder_column = function(spec) {
        var column = IPA.column(spec);
        that.add_adder_column(column);
        return column;
    };

    that.init = function() {

        var entity = IPA.get_entity(that.entity_name);
        var column;

        // create a column if none defined
        if (!that.columns.length) {
            that.create_column({
                'name': that.name,
                'label': IPA.metadata.objects[that.other_entity].label,
                'primary_key': true
            });
        }

        for (var i=0; i<that.columns.length; i++) {
            column = that.columns[i];
            column.entity_name = that.other_entity;
        }

        for (var j=0; j<that.adder_columns.length; j++) {
            column = that.adder_columns[j];
            column.entity_name = that.other_entity;
        }

        that.table_init();
    };

    that.create = function(container) {

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

        var dialog = IPA.dialog({
            title: IPA.messages.dialogs.dirty_title,
            width: '20em'
        });

        dialog.create = function() {
            dialog.container.append(IPA.messages.dialogs.dirty_message);
        };

        dialog.add_button(IPA.messages.buttons.ok, function() {
            dialog.close();
        });

        dialog.init();

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

        if (!that.values.length) return;

        var batch = IPA.batch_command({
            'name': that.entity_name+'_'+that.name,
            'on_success': on_success,
            'on_error': on_error
        });
        var length = that.values.length;
        if (length > 100){
            length = 100;
        }

        for (var i=0; i< length; i++) {
            var value = that.values[i];

            var command = IPA.command({
                'method': that.other_entity+'_show',
                'args': [value],
                'options': {
                    'all': true,
                    'rights': true
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

        if (that.columns.length == 1) { // show pkey only
            var name = that.columns[0].name;
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
        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
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

        if (that.adder_columns.length) {
            dialog.set_columns(that.adder_columns);
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

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var command = IPA.command({
            'method': that.entity_name+'_'+that.add_method,
            'args': [pkey],
            'on_success': on_success,
            'on_error': on_error
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

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
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

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var command = IPA.command({
            'method': that.entity_name+'_'+that.remove_method,
            'args': [pkey],
            'on_success': on_success,
            'on_error': on_error
        });

        command.set_option(that.other_entity, values.join(','));

        command.execute();
    };

    // methods that should be invoked by subclasses
    that.association_table_widget_init = that.init;

    return that;
};


IPA.association_facet = function (spec) {

    spec = spec || {};

    var that = IPA.facet(spec);

    var index = that.name.indexOf('_');
    that.attribute_member = spec.attribute_member || that.name.substring(0, index);
    that.other_entity = spec.other_entity || that.name.substring(index+1);

    that.facet_group = spec.facet_group;
    that.label = that.label ? that.label : (IPA.metadata.objects[that.other_entity] ? IPA.metadata.objects[that.other_entity].label : that.other_entity);

    that.associator = spec.associator || IPA.bulk_associator;
    that.add_method = spec.add_method || 'add_member';
    that.remove_method = spec.remove_method || 'remove_member';

    that.columns = [];
    that.columns_by_name = {};

    that.adder_columns = [];
    that.adder_columns_by_name = {};

    that.get_column = function(name) {
        return that.columns_by_name[name];
    };

    that.add_column = function(column) {
        that.columns.push(column);
        that.columns_by_name[column.name] = column;
    };

    that.create_column = function(spec) {
        var column = IPA.column(spec);
        that.add_column(column);
        return column;
    };

    that.get_adder_column = function(name) {
        return that.adder_columns_by_name[name];
    };

    that.add_adder_column = function(column) {
        that.adder_columns.push(column);
        that.adder_columns_by_name[column.name] = column;
    };

    that.create_adder_column = function(spec) {
        var column = IPA.column(spec);
        that.add_adder_column(column);
        return column;
    };

    that.init = function() {

        that.facet_init();

        var entity = IPA.get_entity(that.entity_name);
        var column;
        var i;

        var label = IPA.metadata.objects[that.other_entity] ? IPA.metadata.objects[that.other_entity].label : that.other_entity;
        var pkey_name = IPA.metadata.objects[that.other_entity].primary_key;

        that.table = IPA.table_widget({
            'id': that.entity_name+'-'+that.other_entity,
            'name': pkey_name,
            'label': label,
            'entity_name': that.entity_name,
            'other_entity': that.other_entity
        });

        if (that.columns.length) {
            that.table.set_columns(that.columns);

        } else {

            column = that.table.create_column({
                name: that.table.name,
                label: IPA.metadata.objects[that.other_entity].label,
                primary_key: true
            });

            column.setup = function(container, record) {
                container.empty();

                var value = record[column.name];
                value = value ? value.toString() : '';

                $('<a/>', {
                    'href': '#'+value,
                    'html': value,
                    'click': function (value) {
                        return function() {
                            var state = IPA.tab_state(that.other_entity);
                            state[that.other_entity + '-facet'] = 'details';
                            state[that.other_entity + '-pkey'] = value;
                            $.bbq.pushState(state);
                            return false;
                        };
                    }(value)
                }).appendTo(container);
            };
        }

        for (i=0; i<that.columns.length; i++) {
            column = that.columns[i];
            column.entity_name = that.other_entity;
        }

        for (i=0; i<that.adder_columns.length; i++) {
            column = that.adder_columns[i];
            column.entity_name = that.other_entity;
        }

        that.table.init();
    };

    that.is_dirty = function() {
        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        return pkey != that.pkey;
    };

    that.create = function(container) {

        that.pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var relationships = IPA.metadata.objects[that.entity_name].relationships;
        var relationship = relationships[that.attribute_member];
        if (!relationship) {
            relationship = ['', '', ''];
        }

        var other_label = IPA.metadata.objects[that.other_entity].label;

        /* TODO: generic handling of different relationships */
        var header_message = '';
        if (relationship[0] == 'Member') {
            header_message = IPA.messages.association.member;

        } else if (relationship[0] == 'Parent') {
            header_message = IPA.messages.association.parent;
        }

        header_message = header_message.replace('${entity}', that.entity_name);
        header_message = header_message.replace('${primary_key}', that.pkey);
        header_message = header_message.replace('${other_entity}', other_label);

        $('<div/>', {
            'id': that.entity_name+'-'+that.other_entity,
            html: $('<h2/>',{ html:  header_message })
        }).appendTo(container);

        var span = $('<span/>', { 'name': 'association' }).appendTo(container);

        that.table.create(span);

        var action_panel = that.get_action_panel();
        var li = $('.action-controls', action_panel);

        // creating generic buttons for layout
        $('<input/>', {
            'type': 'button',
            'name': 'remove',
            'value': IPA.messages.buttons.remove
        }).appendTo(li);

        $('<input/>', {
            'type': 'button',
            'name': 'add',
            'value': IPA.messages.buttons.enroll
        }).appendTo(li);
    };

    that.setup = function(container) {

        that.facet_setup(container);

        var span = $('span[name=association]', that.container);

        that.table.setup(span);

        // replacing generic buttons with IPA.button and setting click handler
        var action_panel = that.get_action_panel();

        var button = $('input[name=remove]', action_panel);
        button.replaceWith(IPA.action_button({
            'label': button.val(),
            'icon': 'ui-icon-trash',
            'click': function() { that.show_remove_dialog(); }
        }));

        button = $('input[name=add]', action_panel);
        button.replaceWith(IPA.action_button({
            'label': button.val(),
            'icon': 'ui-icon-plus',
            'click': function() { that.show_add_dialog(); }
        }));
    };

    that.show_add_dialog = function() {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
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

        if (that.adder_columns.length) {
            dialog.set_columns(that.adder_columns);
        }

        dialog.execute = function() {

            var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

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

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
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

    that.get_records = function(pkeys, on_success, on_error) {

        if (!pkeys.length) return;


        var options = {
            'all': true,
            'rights': true
        };

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var args =[];
        /* TODO: make a general solution to generate this value */
        var relationship_filter = 'in_' + that.entity_name;
        options[relationship_filter] = pkey;

        var command = IPA.command({
            'on_success': on_success,
            'on_error': on_error,
            'method': that.other_entity+'_find',
            'args': args,
            options: options
        });

        command.execute();


    };

    that.refresh = function() {

        function on_success(data, text_status, xhr) {

            that.table.empty();

            var pkeys = data.result.result[that.name];
            if (!pkeys) return;

            if (that.table.columns.length == 1) { // show pkey only
                var name = that.table.columns[0].name;
                for (var i=0; i<pkeys.length; i++) {
                    var record = {};
                    record[name] = pkeys[i];
                    that.table.add_record(record);
                }

            } else { // get and show additional fields
                that.get_records(
                    pkeys,
                    function(data, text_status, xhr) {
                        var results = data.result.result;
                        for (var i=0; i<results.length; i++) {
                            var record = results[i];
                            that.table.add_record(record);
                        }
                    }
                );
            }
        }

        function on_error(xhr, text_status, error_thrown) {
            var summary = $('span[name=summary]', that.table.tfoot).empty();
            summary.append('<p>Error: '+error_thrown.name+'</p>');
            summary.append('<p>'+error_thrown.title+'</p>');
            summary.append('<p>'+error_thrown.message+'</p>');
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        IPA.cmd('show', [pkey], {'all': true, 'rights': true}, on_success, on_error, that.entity_name);
    };

    that.association_facet_init = that.init;

    return that;
};


IPA.deleter_dialog_setup = function () {

    var that = this;

    var ul = $('<ul/>');
    ul.appendTo(that.dialog);

    for (var i=0; i<that.values.length; i++) {
        $('<li/>',{
            'text': that.values[i]
        }).appendTo(ul);
    }

    $('<p/>', {
        'text': IPA.messages.search.delete_confirm
    }).appendTo(that.dialog);
};
