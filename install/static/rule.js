/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */

function ipa_rule_details_section(spec){

    spec = spec || {};

    var that = ipa_details_section(spec);

    that.text = spec.text;
    that.field_name = spec.field_name;
    that.options = spec.options || [];
    that.tables = spec.tables || [];
    that.columns = spec.columns;

    that.create = function(container) {

        if (that.template) return;

        if (that.text) container.append(that.text);

        var span = $('<span/>', { 'name': that.field_name }).appendTo(container);

        if (that.options.length) {
            for (var i=0; i<that.options.length; i++) {
                var option = that.options[i];

                $('<input/>', {
                    'type': 'radio',
                    'name': that.field_name,
                    'value': option.value
                }).appendTo(span);

                span.append(option.label);
            }

            span.append(' ');

            $('<span/>', {
                'name': 'undo',
                'class': 'ui-state-highlight ui-corner-all',
                'style': 'display: none;',
                'html': 'undo'
            }).appendTo(span);

            span.append('<br/>');
        }

        for (var i=0; i<that.tables.length; i++) {
            var table = that.tables[i];

            var table_span = $('<span/>', { 'name': table.field_name }).appendTo(span);

            var field = that.get_field(table.field_name);
            field.create(table_span);
        }
    };

    return that;
}

function ipa_rule_association_widget(spec) {

    spec = spec || {};

    var that = ipa_table_widget(spec);

    that.other_entity = spec.other_entity;

    that.add_method = spec.add_method;
    that.remove_method = spec.remove_method;

    that.init = function() {
        // create a column if none defined
        if (!that.columns.length) {
            that.create_column({
                'name': that.name,
                'label': IPA.metadata[that.other_entity].label,
                'primary_key': true
            });
        }

        that.table_init();
    };

    that.create = function(container) {

        that.table_create(container);

        var buttons = $('span[name=buttons]', container);

        $('<input/>', {
            'type': 'button',
            'name': 'remove',
            'value': 'Remove '+that.label
        }).appendTo(buttons);

        $('<input/>', {
            'type': 'button',
            'name': 'add',
            'value': 'Add '+that.label
        }).appendTo(buttons);
    };

    that.setup = function(container) {

        that.table_setup(container);

        var button = $('input[name=remove]', that.table);
        button.replaceWith(ipa_button({
            'label': button.val(),
            'icon': 'ui-icon-trash',
            'click': function() { that.show_remove_dialog(); }
        }));

        button = $('input[name=add]', that.table);
        button.replaceWith(ipa_button({
            'label': button.val(),
            'icon': 'ui-icon-plus',
            'click': function() { that.show_add_dialog() }
        }));

        var entity = IPA.get_entity(that.entity_name);
        var association = entity.get_association(that.other_entity);

        if (association && association.associator == 'serial') {
            that.associator = serial_associator;
        } else {
            that.associator = bulk_associator;
        }
    };

    that.load = function(result) {
        that.values = result[that.name] || [];
        that.reset();
    };

    that.set_values = function(values) {

        that.tbody.empty();
        for (var i=0; values && i<values.length; i++) {
            var record = {};
            record[that.name] = values[i];
            that.add_row(record);
        }
    };

    that.show_add_dialog = function() {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var label = IPA.metadata[that.other_entity].label;
        var title = 'Add '+label+' to '+that.entity_name+' '+pkey;

        var dialog = ipa_association_adder_dialog({
            'title': title,
            'entity_name': that.entity_name,
            'pkey': pkey,
            'other_entity': that.other_entity
        });

        dialog.add = function() {
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
    };

    return that;
}
