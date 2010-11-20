/*  Authors:
 *    Adam Young <ayoung@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
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

    that.associator = spec.associator;
    that.method = spec.method || 'add_member';

    that.on_success = spec.on_success;
    that.on_error = spec.on_error;

    that.init = function() {
        if (!that.columns.length) {
            var pkey_name = IPA.metadata[that.other_entity].primary_key;
            that.create_column({
                name: pkey_name,
                primary_key: true
            });
        }
    };

    that.search = function() {

        function on_success(data, text_status, xhr) {
            var results = data.result;
            that.clear_available_values();

            for (var i=0; i<results.count; i++){
                var result = results.result[i];
                that.add_available_value(result);
            }
        }

        var filter = that.get_filter();
        ipa_cmd('find', [filter], {}, on_success, null, that.other_entity);
    };

    that.add = function() {

        var associator = that.associator({
            'entity_name': that.entity_name,
            'pkey': that.pkey,
            'other_entity': that.other_entity,
            'values': that.get_selected_values(),
            'method': that.method,
            'on_success': that.on_success,
            'on_error': that.on_error
        });

        associator.execute();
    };

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
    that.delete_method = spec.delete_method;

    return that;
}

function ipa_association_table_widget(spec) {

    spec = spec || {};

    var that = ipa_table_widget(spec);

    that.facet = spec.facet;
    that.other_entity = spec.other_entity;

    that.superior_create = that.superior('create');

    that.create = function(container) {

        that.member_attribute = ipa_get_member_attribute(
            that.entity_name, that.other_entity);

        if (!that.columns.length) {
            var pkey_name = IPA.metadata[that.other_entity].primary_key;

            var column = that.create_column({
                name: pkey_name,
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

        that.superior_create(container);

        var action_panel = that.facet.get_action_panel();
        var li = $('.action-controls', action_panel);

        // creating generic buttons for layout
        $('<input/>', {
            'type': 'button',
            'name': 'remove',
            'value': IPA.messages.button.remove
        }).appendTo(li);

        $('<input/>', {
            'type': 'button',
            'name': 'add',
            'value': IPA.messages.button.enroll
        }).appendTo(li);
    };

    that.setup = function(container) {

        that.table_setup(container);

        // replacing generic buttons with ipa_button and setting click handler
        var action_panel = that.facet.get_action_panel();

        var button = $('input[name=remove]', action_panel);
        button.replaceWith(ipa_button({
            'label': button.val(),
            'icon': 'ui-icon-trash',
            'click': function() { that.remove(that.container); }
        }));

        button = $('input[name=add]', action_panel);
        button.replaceWith(ipa_button({
            'label': button.val(),
            'icon': 'ui-icon-plus',
            'click': function() { that.add(that.container) }
        }));

        var entity = IPA.get_entity(that.entity_name);
        var association = entity.get_association(that.other_entity);

        if (association && association.associator == 'serial') {
            that.associator = serial_associator;
        } else {
            that.associator = bulk_associator;
        }

        that.add_method = association ? association.add_method : null;
        that.delete_method = association ? association.delete_method : null;

        that.add_method = that.add_method || "add_member";
        that.delete_method = that.delete_method || "remove_member";
    };

    that.add = function(container) {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var label = IPA.metadata[that.other_entity].label;
        var title = 'Enroll '+that.entity_name+' '+pkey+' in '+label;

        var dialog = ipa_association_adder_dialog({
            'title': title,
            'entity_name': that.entity_name,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'associator': that.associator,
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

        dialog.init();

        dialog.open(that.container);
    };

    that.remove = function(container) {

        var values = that.get_selected_values();

        if (!values.length) {
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
            'values': values,
            'associator': that.associator,
            'method': that.delete_method,
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

            that.tbody.empty();

            var pkeys = data.result.result[that.name];

            if (that.columns.length == 1) { // show pkey only
                var name = that.columns[0].name;
                for (var i=0; i<pkeys.length; i++) {
                    var record = {};
                    record[name] = pkeys[i];
                    that.add_row(record);
                }

            } else { // get and show additional fields
                that.get_records(
                    pkeys,
                    function(data, text_status, xhr) {
                        var results = data.result.results;
                        for (var i=0; i<results.length; i++) {
                            var record = results[i].result;
                            that.add_row(record);
                        }
                    }
                );
            }
        }

        function on_error(xhr, text_status, error_thrown) {
            var summary = $('span[name=summary]', that.tfoot).empty();
            summary.append('<p>Error: '+error_thrown.name+'</p>');
            summary.append('<p>'+error_thrown.title+'</p>');
            summary.append('<p>'+error_thrown.message+'</p>');
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        ipa_cmd('show', [pkey], {'rights': true}, on_success, on_error, that.entity_name);
    };

    return that;
}

function ipa_association_facet(spec) {

    spec = spec || {};

    var that = ipa_facet(spec);

    that.other_entity = spec.other_entity;

    that.columns = [];
    that.columns_by_name = {};

    that.get_column = function(name) {
        return that.columns_by_name[name];
    };

    that.add_column = function(column) {
        column.entity_name = that.entity_name;
        that.columns.push(column);
        that.columns_by_name[column.name] = column;
    };

    that.create_column = function(spec) {
        var column = ipa_column(spec);
        that.add_column(column);
        return column;
    };

    that.is_dirty = function() {
        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        return pkey != that.pkey || other_entity != that.other_entity;
    };

    that.create = function(container) {

        that.pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var label = IPA.metadata[that.other_entity] ? IPA.metadata[that.other_entity].label : that.other_entity;

        //TODO I18N
        var header_message = that.other_entity + '(s) enrolled in '  +
            that.entity_name + ' ' + that.pkey;

        $('<div/>', {
            'id': that.entity_name+'-'+that.other_entity,
            html: $('<h2/>',{ html:  header_message })
        }).appendTo(container);

        that.table = ipa_association_table_widget({
            'id': that.entity_name+'-'+that.other_entity,
            'name': that.name,
            'label': label,
            'entity_name': that.entity_name,
            'other_entity': that.other_entity,
            'facet': that
        });

        if (that.columns.length) {
            that.table.set_columns(that.columns);
        }

        var span = $('<span/>', { 'name': 'association' }).appendTo(container);

        that.table.create(span);
    };

    that.setup = function(container) {

        that.facet_setup(container);

        var span = $('span[name=association]', that.container);

        that.table.setup(span);
    };

    that.refresh = function(){
        that.table.refresh();
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
