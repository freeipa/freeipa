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

    that.method = spec.method || 'add';
    that.pre_execute_hook = spec.pre_execute_hook;
    that.on_error = spec.on_error ;
    that.retry = typeof spec.retry !== 'undefined' ? spec.retry : true;
    that.command = null;

    function show_edit_page(entity,result){
        var pkey_name = entity.metadata.primary_key;
        var pkey = result[pkey_name];
        if (pkey instanceof Array) {
            pkey = pkey[0];
        }
        IPA.nav.show_entity_page(that.entity, 'default', pkey);
    }

    that.show_edit_page = spec.show_edit_page || show_edit_page;

    that.add = function(record, on_success, on_error) {

        var field, value, pkey_prefix;
        var pkey_name = that.entity.metadata.primary_key;

        var command = IPA.command({
            entity: that.entity.name,
            method: that.method,
            retry: that.retry,
            on_success: on_success,
            on_error: on_error
        });
        that.command = command;

        pkey_prefix = that.entity.get_primary_key_prefix();

        for (var h=0; h<pkey_prefix.length; h++) {
            command.add_arg(pkey_prefix[h]);
        }

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            fields[i].validate();
        }
        var required_fields_filled = true;
        for (i=0; i<fields.length; i++) {
            field = fields[i];
            if (!field.valid) return;

            required_fields_filled = field.check_required() &&
                required_fields_filled;

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
                required_fields_filled = field.check_required()  &&
                    required_fields_filled;

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

        if (that.pre_execute_hook){
            that.pre_execute_hook(command);
        }
        if (required_fields_filled){
            command.execute();
        }

    };

    /*dialog initialization*/
    that.add_button(IPA.messages.buttons.add, function() {
        var record = {};
        that.save(record);
        that.add(
            record,
            function(data, text_status, xhr) {
                var facet = IPA.current_entity.get_facet();
                var table = facet.table;
                table.refresh();
                that.close();
            },
            that.on_error);
    });

    that.add_button(IPA.messages.buttons.add_and_add_another, function() {
        var record = {};
        that.save(record);
        that.add(
            record,
            function(data, text_status, xhr) {
                var facet = IPA.current_entity.get_facet();
                var table = facet.table;
                table.refresh();
                that.reset();
            },
            that.on_error);
    });

    that.add_button(IPA.messages.buttons.add_and_edit, function() {
        var record = {};
        that.save(record);
        that.add(
            record,
            function(data, text_status, xhr) {
                that.close();
                var result = data.result.result;
                that.show_edit_page(that.entity,result);
            },
            that.on_error);
    });

    that.add_button(IPA.messages.buttons.cancel, function() {
        that.close();
    });


    return that;
};

