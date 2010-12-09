/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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

function ipa_rule_association_table_widget(spec) {

    spec = spec || {};

    var that = ipa_association_table_widget(spec);

    that.category = spec.category;

    that.add = function(values, on_success, on_error) {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var batch = ipa_batch_command({
            'on_success': on_success,
            'on_error': on_error
        });

        var command;

        if (that.category.save() != '') {
            command = ipa_command({
                'method': that.entity_name+'_mod',
                'args': [pkey],
                'options': {'all': true, 'rights': true},
                'on_success': function() {
                    var record = {};
                    record[that.category.name] = [''];
                    that.category.load(['']);
                }
            });
            command.set_option(that.category.name, '');
            batch.add_command(command);
        }

        command = ipa_command({
            'method': that.entity_name+'_'+that.add_method,
            'args': [pkey]
        });
        command.set_option(that.other_entity, values.join(','));
        batch.add_command(command);

        batch.execute();
    };

    return that;
}
