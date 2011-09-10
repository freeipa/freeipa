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

    that.add = function(on_success, on_error) {

        var pkey_name = that.entity.metadata.primary_key;

        var command = IPA.command({
            entity: that.entity.name,
            method: that.method,
            retry: that.retry,
            on_success: on_success,
            on_error: on_error
        });
        that.command = command;

        command.add_args(that.entity.get_primary_key_prefix());

        var record = {};
        that.save(record);

        var fields = that.get_fields();
        for (var i=0; i<fields.length; i++) {
            fields[i].validate();
        }

        var valid = true;

        var sections = that.sections.values;
        for (i=0; i<sections.length; i++) {
            var section = sections[i];

            if (!section.is_valid() || !valid) {
                valid = false;
                continue;
            }

            var section_fields = section.fields.values;
            for (var j=0; j<section_fields.length; j++) {
                var field = section_fields[j];

                var values = record[field.name];
                if (!values) continue;

                // TODO: Handle multi-valued attributes like in detail facet's update()
                var value = values.join(',');
                if (!value) continue;

                if (field.name == pkey_name) {
                    command.add_arg(value);
                } else {
                    command.set_option(field.name, value);
                }
            }
        }

        if (!valid) return;

        //alert(JSON.stringify(command.to_json()));

        if (that.pre_execute_hook) {
            that.pre_execute_hook(command);
        }

        command.execute();
    };

    /*dialog initialization*/
    that.add_button(IPA.messages.buttons.add, function() {
        that.add(
            function(data, text_status, xhr) {
                var facet = IPA.current_entity.get_facet();
                var table = facet.table;
                table.refresh();
                that.close();
            },
            that.on_error);
    });

    that.add_button(IPA.messages.buttons.add_and_add_another, function() {
        that.add(
            function(data, text_status, xhr) {
                var facet = IPA.current_entity.get_facet();
                var table = facet.table;
                table.refresh();
                that.reset();
            },
            that.on_error);
    });

    that.add_button(IPA.messages.buttons.add_and_edit, function() {
        that.add(
            function(data, text_status, xhr) {
                that.close();
                var result = data.result.result;
                that.show_edit_page(that.entity, result);
            },
            that.on_error);
    });

    that.add_button(IPA.messages.buttons.cancel, function() {
        that.close();
    });

    return that;
};

