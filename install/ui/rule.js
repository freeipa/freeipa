/*jsl:import ipa.js */

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

IPA.rule_details_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_section(spec);

    that.field_name = spec.field_name;
    that.options = spec.options || [];
    that.tables = spec.tables || [];
    that.columns = spec.columns;

    that.create = function(container) {

        that.container = container;

        var field = that.get_field(that.field_name);
        var param_info = IPA.get_entity_param(that.entity.name, that.field_name);

        container.append(param_info.doc+':');

        var span = $('<span/>', {
            name: that.field_name,
            title: param_info.doc,
            'class': 'details-field'
        }).appendTo(container);



        function update_tables(value) {
            var enabled = ('' === value);
            for (var i=0; i<that.tables.length; i++) {
                var table = that.tables[i];

                var field = that.get_field(table.field_name);
                field.set_enabled(enabled);
            }
        }

        if (that.options.length) {
            var category = that.get_field(that.field_name);
            category.options=that.options;
            category.reset = function() {
                category.widget_reset();
                var values = category.save();
                if (values.length === 0){
                    return;
                }
                var value = values[0];
                update_tables(value);
            };
            category.create(span);

            var inputs = $('input[name='+that.field_name+']', container);
            inputs.change(function() {
                var input = $(this);
                var value = input.val();
                update_tables(value);
            });
        }



        for (var j=0; j<that.tables.length; j++) {
            var table = that.tables[j];

            param_info = IPA.get_entity_param(that.entity.name, table.field_name);

            var table_span = $('<span/>', {
                name: table.field_name,
                title: param_info ? param_info.doc : table.field_name,
                'class': 'details-field'
            }).appendTo(span);

            field = that.get_field(table.field_name);
            field.create(table_span);
        }


    };

    return that;
};
