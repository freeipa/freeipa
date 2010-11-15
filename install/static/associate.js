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

    that.search = function() {

        function on_success(data, text_status, xhr) {
            var results = data.result;
            that.clear_available_values();

            var pkey = IPA.metadata[that.other_entity].primary_key;

            for (var i=0; i<results.count; i++){
                var result = results.result[i];
                that.add_available_value(result[pkey][0]);
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

function ipa_association_widget(spec) {

    spec = spec || {};

    var that = ipa_table_widget(spec);

    that.other_entity = spec.other_entity;

    that.superior_create = that.superior('create');

    that.create = function(container) {

        that.member_attribute = ipa_get_member_attribute(that.entity_name, that.other_entity);

        that.create_column({
            'name': that.member_attribute + '_' + that.other_entity,
            'label': IPA.metadata[that.other_entity].label,
            'primary_key': true
        });

        that.superior_create(container);

        var ul = $('.action-panel ul');
        var li = $('<li/>').appendTo(ul);

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
        var action_panel = $('.action-panel');
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
                that.refresh(that.container);
                dialog.close();
            },
            'on_error': function() {
                that.refresh(that.container);
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
                that.refresh(that.container);
                dialog.close();
            },
            'on_error': function() {
                that.refresh(that.container);
                dialog.close();
            }
        });

        dialog.init();

        dialog.open(that.container);
    };

    that.refresh = function(container) {

        function on_success(data, text_status, xhr) {

            that.tbody.empty();

            var column_name = that.columns[0].name;
            var values = data.result.result[column_name];
            //TODO, this is masking an error where the wrong
            //direction association is presented upon page reload.
            //if the values is unset, it is because
            //form.associationColumns[0] doesn't exist in the results
            if (!values) return;

            for (var i = 0; i<values.length; i++){
                var record = that.get_record(data.result.result, i);
                that.add_row(that.container, record);
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

    that.other_entity = null;

    that.is_dirty = function() {
        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var other_entity = $.bbq.getState(that.entity_name + '-enroll', true) || '';
        return pkey != that.pkey || other_entity != that.other_entity;
    };

    that.create = function(container) {

        that.pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        that.other_entity =
            $.bbq.getState(that.entity_name + '-enroll', true) || '';

        var label = IPA.metadata[that.other_entity] ? IPA.metadata[that.other_entity].label : that.other_entity;

        that.table = ipa_association_widget({
            'id': that.entity_name+'-'+that.other_entity,
            'name': 'association',
            'label': label,
            'entity_name': that.entity_name,
            'other_entity': that.other_entity
        });

        //TODO I18N
        var header_message = that.other_entity + '(s) enrolled in '  +
            that.entity_name + ' ' + that.pkey;

        $('<div/>', {
            'id': that.entity_name+'-'+that.other_entity,
            html: $('<h2/>',{ html:  header_message })
        }).appendTo(container);
        that.table = ipa_association_widget({
            'id': that.entity_name+'-'+that.other_entity,
            'name': that.other_entity,
            'label': IPA.metadata[that.other_entity].label,
            'entity_name': that.entity_name,
            'other_entity': that.other_entity
        });

        var span = $('<span/>', { 'name': 'association' }).appendTo(container);

        that.table.create(span);
    };

    that.setup = function(container) {

        var span = $('span[name=association]', container);

        that.table.setup(span);
        that.table.refresh();
    };

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
