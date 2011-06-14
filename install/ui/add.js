/*jsl:import ipa.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
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

/* REQUIRES: ipa.js */

IPA.add_dialog = function (spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.name = spec.name;
    that.title = spec.title;
    that._entity_name = spec.entity_name;
    that.method = spec.method || 'add';
    that.init = function() {

        that.add_button(IPA.messages.buttons.add, function() {
            var record = {};
            that.save(record);
            that.add(
                record,
                function(data, text_status, xhr) {
                    var facet_name =   IPA.current_facet(IPA.current_entity);
                    var facet = IPA.current_entity.get_facet(facet_name);
                    var table = facet.table;
                    table.refresh();
                    that.close();
                }
            );
        });


        that.add_button(IPA.messages.buttons.add_and_add_another, function() {
            var record = {};
            that.save(record);
            that.add(
                record,
                function(data, text_status, xhr) {
                    var facet_name =   IPA.current_facet(IPA.current_entity);
                    var facet = IPA.current_entity.get_facet(facet_name);
                    var table = facet.table;
                    table.refresh();
                    that.reset();
                }
            );
        });

        that.add_button(IPA.messages.buttons.add_and_edit, function() {
            var record = {};
            that.save(record);
            that.add(
                record,
                function(data, text_status, xhr) {
                    that.close();

                    var pkey_name = IPA.metadata.objects[that.entity_name].primary_key;

                    var result = data.result.result;
                    var pkey = result[pkey_name];

                    if (pkey instanceof Array) {
                        pkey = pkey[0];
                    }

                    IPA.nav.show_page(that.entity_name, 'default', pkey);
                }
            );
        });

        that.add_button(IPA.messages.buttons.cancel, function() {
            that.close();
        });

        that.dialog_init();
    };

    that.add = function(record, on_success, on_error) {

        var field, value, pkey_prefix;
        var pkey_name = IPA.metadata.objects[that.entity_name].primary_key;

        var command = IPA.command({
            entity: that.entity_name,
            method: that.method,
            on_success: on_success,
            on_error: on_error
        });

        pkey_prefix = IPA.get_entity(that.entity_name).get_primary_key_prefix();

        for (var h=0; h<pkey_prefix.length; h++) {
            command.add_arg(pkey_prefix[h]);
        }

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            field = fields[i];
            if (!field.valid) return;

            value = record[field.name];
            if (!value) continue;

            if (field.name == pkey_name) {
                command.add_arg(value);
            } else {
                command.set_option(field.name, value);
            }
        }

        var sections = that.sections.values;
        for (var j=0; j<sections.length; j++) {
            var section = sections[j];

            var section_fields = section.fields.values;
            for (var k=0; k<section_fields.length; k++) {
                field = section_fields[k];
                if (!field.valid) return;

                value = record[field.name];
                if (!value) continue;

                if (field.name == pkey_name) {
                    command.add_arg(value);
                } else {
                    command.set_option(field.name, value);
                }
            }
        }

        //alert(JSON.stringify(command.to_json()));

        command.execute();
    };

    that.add_dialog_init = that.init;

    return that;
};

