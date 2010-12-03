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
