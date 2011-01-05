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

function ipa_associator(spec) {

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
}

/**
*This associator is built for the case where each association requires a separate rpc
*/
function serial_associator(spec) {

    spec = spec || {};

    var that = ipa_associator(spec);

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

        ipa_cmd(
            that.method,
            args,
            options,
            that.execute,
            that.on_error,
            that.other_entity
        );
    };

    return that;
}

/**
*This associator is for the common case where all the asociations can be sent
in a single rpc
*/
function bulk_associator(spec) {

    spec = spec || {};

    var that = ipa_associator(spec);

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

        ipa_cmd(
            that.method,
            args,
            options,
            that.on_success,
            that.on_error,
            that.entity_name
        );
    };

    return that;
}

/**
 * This dialog is used for adding associations between two entities.
 */
function ipa_association_adder_dialog(spec) {

    spec = spec || {};

    var that = ipa_adder_dialog(spec);

    that.entity_name = spec.entity_name;
    that.pkey = spec.pkey;
    that.other_entity = spec.other_entity;
    that.attribute_member = spec.attribute_member;

    that.init = function() {
        if (!that.columns.length) {
            var pkey_name = IPA.metadata[that.other_entity].primary_key;
            that.create_column({
                name: pkey_name,
                label: IPA.metadata[that.other_entity].label,
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

            var pkey_attr = IPA.metadata[that.entity_name].primary_key;

            for (var i=0; i<results.count; i++){
                var result = results.result[i];
                if (result[pkey_attr] != spec.pkey)
                    that.add_available_value(result);
            }
        }

        var hide_checkbox = $('input[name=hidememb]', that.container);

        var options = {'all': true};
        if (hide_checkbox.attr('checked')) {
            var relationships = IPA.metadata[that.other_entity].relationships;

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

        ipa_cmd('find', [that.get_filter()], options, on_success, null, that.other_entity);
    };

    that.association_adder_dialog_init = that.init;
    that.association_adder_dialog_setup = that.setup;

    return that;
}

/**
 * This dialog is used for removing associations between two entities.
 */
function ipa_association_deleter_dialog(spec) {

    spec = spec || {};

    var that = ipa_deleter_dialog(spec);

    that.entity_name = spec.entity_name;
    that.pkey = spec.pkey;
    that.other_entity = spec.other_entity;
    that.values = spec.values;

    that.associator = spec.associator;
    that.method = spec.method || 'remove_member';

    that.on_success = spec.on_success;
    that.on_error = spec.on_error;

    that.remove = function() {

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
}

function ipa_association_config(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.associator = spec.associator;
    that.add_method = spec.add_method;
    that.remove_method = spec.remove_method;

    return that;
}

function ipa_association_table_widget(spec) {

    spec = spec || {};

    var that = ipa_table_widget(spec);

    that.other_entity = spec.other_entity;
    that.attribute_member = spec.attribute_member;

    that.associator = spec.associator || bulk_associator;
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
        var column = ipa_column(spec);
        that.add_adder_column(column);
        return column;
    };

    that.init = function() {

        var entity = IPA.get_entity(that.entity_name);
        var association = entity.get_association(that.other_entity);

        if (association) {
            if (association.associator) {
                that.associator = association.associator == 'serial' ? serial_associator : bulk_associator;
            }

            if (association.add_method) that.add_method = association.add_method;
            if (association.remove_method) that.remove_method = association.remove_method;
        }

        // create a column if none defined
        if (!that.columns.length) {
            that.create_column({
                'name': that.name,
                'label': IPA.metadata[that.other_entity].label,
                'primary_key': true
            });
        }

        for (var i=0; i<that.columns.length; i++) {
            var column = that.columns[i];
            column.entity_name = that.other_entity;
        }

        for (var i=0; i<that.adder_columns.length; i++) {
            var column = that.adder_columns[i];
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
            'value': 'Remove'
        }).appendTo(buttons);

        $('<input/>', {
            'type': 'button',
            'name': 'add',
            'value': 'Add'
        }).appendTo(buttons);
    };

    that.setup = function(container) {

        that.table_setup(container);

        var button = $('input[name=remove]', container);
        button.replaceWith(IPA.action_button({
            'label': button.val(),
            'icon': 'ui-icon-trash',
            'click': function() { that.show_remove_dialog(); }
        }));

        button = $('input[name=add]', container);
        button.replaceWith(IPA.action_button({
            'label': button.val(),
            'icon': 'ui-icon-plus',
            'click': function() { that.show_add_dialog() }
        }));
    };

    that.get_records = function(on_success, on_error) {

        if (!that.values.length) return;

        var batch = ipa_batch_command({
            'name': that.entity_name+'_'+that.name,
            'on_success': on_success,
            'on_error': on_error
        });

        for (var i=0; i<that.values.length; i++) {
            var value = that.values[i];

            var command = ipa_command({
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
        var label = IPA.metadata[that.other_entity].label;
        var title = 'Add '+label+' to '+that.entity_name+' '+pkey;

        return ipa_association_adder_dialog({
            'title': title,
            'entity_name': that.entity_name,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'attribute_member': that.attribute_member,
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

        var command = ipa_command({
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
            alert('Select '+that.label+' to be removed.');
            return;
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var label = IPA.metadata[that.other_entity].label;
        var title = 'Remove '+label+' from '+that.entity_name+' '+pkey;

        var dialog = ipa_association_deleter_dialog({
            'title': title,
            'entity_name': that.entity_name,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'values': selected_values
        });

        dialog.remove = function() {
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

        var command = ipa_command({
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
}

function ipa_association_facet(spec) {

    spec = spec || {};

    var that = ipa_facet(spec);

    that.other_entity = spec.other_entity;
    that.facet_group = spec.facet_group;
    that.attribute_member = spec.attribute_member;

    that.associator = spec.associator || bulk_associator;
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
        var column = ipa_column(spec);
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
        var column = ipa_column(spec);
        that.add_adder_column(column);
        return column;
    };

    that.init = function() {

        that.facet_init();

        var entity = IPA.get_entity(that.entity_name);
        var association = entity.get_association(that.other_entity);

        if (association) {
            if (association.associator) {
                that.associator = association.associator == 'serial' ? serial_associator : bulk_associator;
            }

            if (association.add_method) that.add_method = association.add_method;
            if (association.remove_method) that.remove_method = association.remove_method;
        }

        var label = IPA.metadata[that.other_entity] ? IPA.metadata[that.other_entity].label : that.other_entity;
        var pkey_name = IPA.metadata[that.other_entity].primary_key;

        that.table = ipa_table_widget({
            'id': that.entity_name+'-'+that.other_entity,
            'name': pkey_name,
            'label': label,
            'entity_name': that.entity_name,
            'other_entity': that.other_entity
        });

        if (that.columns.length) {
            that.table.set_columns(that.columns);

        } else {

            var column = that.table.create_column({
                name: that.table.name,
                label: IPA.metadata[that.other_entity].label,
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
                        }
                    }(value)
                }).appendTo(container);
            };
        }

        for (var i=0; i<that.columns.length; i++) {
            var column = that.columns[i];
            column.entity_name = that.other_entity;
        }

        for (var i=0; i<that.adder_columns.length; i++) {
            var column = that.adder_columns[i];
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

        var relationships = IPA.metadata[that.entity_name].relationships;
        var relationship = relationships[that.attribute_member];
        if (!relationship)
            relationship = ['', '', ''];

        /* TODO: I18N and some generic handling of different relationships */
        var header_message = '';
        if (relationship[0] == 'Member') {
            header_message = that.other_entity + '(s) enrolled in ' +
                that.entity_name + ' ' + that.pkey;
        } else if (relationship[0] == 'Parent') {
            header_message = that.entity_name + ' ' + that.pkey +
                ' is enrolled in the following ' + that.other_entity + '(s)';
        }

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
            'value': IPA.messages.button.remove
        }).appendTo(li);

        /* TODO: genering handling of different relationships */
        if (relationship[0] == 'Member') {
            $('<input/>', {
                'type': 'button',
                'name': 'add',
                'value': IPA.messages.button.enroll
            }).appendTo(li);
        }
    };

    that.setup = function(container) {

        that.facet_setup(container);

        var span = $('span[name=association]', that.container);

        that.table.setup(span);

        // replacing generic buttons with ipa_button and setting click handler
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
            'click': function() { that.show_add_dialog() }
        }));
    };

    that.show_add_dialog = function() {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var label = IPA.metadata[that.other_entity] ? IPA.metadata[that.other_entity].label : that.other_entity;
        var title = 'Enroll ' + label + ' in ' + that.entity_name + ' ' + pkey;

        var dialog = ipa_association_adder_dialog({
            'title': title,
            'entity_name': that.entity_name,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'attribute_member': that.attribute_member,
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

        var label = IPA.metadata[that.other_entity] ? IPA.metadata[that.other_entity].label : that.other_entity;
        var values = that.table.get_selected_values();

        if (!values.length) {
            alert('Select '+label+' to be removed.');
            return;
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var title = 'Remove '+label+' from '+that.entity_name+' '+pkey;

        var dialog = ipa_association_deleter_dialog({
            'title': title,
            'entity_name': that.entity_name,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'values': values,
            'associator': that.associator,
            'method': that.remove_method,
            'on_success': function() {
                that.refresh();
                dialog.close();
            },
            'on_error': function() {
                that.refresh();
                dialog.close();
            }
        });

        dialog.init();

        dialog.open(that.container);
    };

    that.get_records = function(pkeys, on_success, on_error) {

        if (!pkeys.length) return;

        var batch = ipa_batch_command({
            'name': that.entity_name+'_'+that.name,
            'on_success': on_success,
            'on_error': on_error
        });

        for (var i=0; i<pkeys.length; i++) {
            var pkey = pkeys[i];

            var command = ipa_command({
                'method': that.other_entity+'_show',
                'args': [pkey],
                'options': {
                    'all': true,
                    'rights': true
                }
            });

            batch.add_command(command);
        }

        batch.execute();
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
                        var results = data.result.results;
                        for (var i=0; i<results.length; i++) {
                            var record = results[i].result;
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
        ipa_cmd('show', [pkey], {'rights': true}, on_success, on_error, that.entity_name);
    };

    that.association_facet_init = that.init;

    return that;
}

function ipa_deleter_dialog_setup() {

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
}
