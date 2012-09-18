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

IPA.entity_adder_dialog = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'entity_adder_dialog';

    var that = IPA.dialog(spec);

    that.method = spec.method || 'add';
    that.on_error = spec.on_error ;
    that.retry = typeof spec.retry !== 'undefined' ? spec.retry : true;
    that.command = null;
    that.added = IPA.observer();
    that.subject = spec.subject || that.entity.metadata.label_singular;

    that.show_edit_page = spec.show_edit_page || show_edit_page;

    var init = function() {
        that.create_button({
            name: 'add',
            label: IPA.messages.buttons.add,
            click: function() {
                that.hide_message();
                that.add(
                    function(data, text_status, xhr) {
                        that.added.notify();
                        var facet = IPA.current_entity.get_facet();
                        facet.refresh();
                        that.close();
                        that.notify_success(data);
                    },
                    that.on_error);
            }
        });

        that.create_button({
            name: 'add_and_add_another',
            label: IPA.messages.buttons.add_and_add_another,
            click: function() {
                that.hide_message();
                that.add(
                    function(data, text_status, xhr) {
                        that.added.notify();
                        that.show_message(that.get_success_message(data));
                        var facet = IPA.current_entity.get_facet();
                        facet.refresh();
                        that.reset();
                    },
                    that.on_error);
            }
        });

        that.create_button({
            name: 'add_and_edit',
            label: IPA.messages.buttons.add_and_edit,
            click: function() {
                that.hide_message();
                that.add(
                    function(data, text_status, xhr) {
                        that.added.notify();
                        that.close();
                        var result = data.result.result;
                        that.show_edit_page(that.entity, result);
                        that.notify_success(data);
                    },
                    that.on_error);
            }
        });

        that.create_button({
            name: 'cancel',
            label: IPA.messages.buttons.cancel,
            click: function() {
                that.hide_message();
                that.close();
            }
        });
    };

    that.get_success_message = function(data) {
        var message = IPA.messages.dialogs.add_confirmation;
        return  message.replace('${entity}', that.subject);
    };

    that.notify_success = function(data) {
        IPA.notify_success(that.get_success_message(data));
    };

    function show_edit_page(entity,result) {
        var pkey_name = entity.metadata.primary_key;
        var pkey = result[pkey_name];
        if (pkey instanceof Array) {
            pkey = pkey[0];
        }
        IPA.nav.show_entity_page(that.entity, 'default', pkey);
    }

    that.create_add_command = function(record) {

        var pkey_name = that.entity.metadata.primary_key;

        var command = IPA.command({
            entity: that.entity.name,
            method: that.method,
            retry: that.retry
        });

        command.add_args(that.entity.get_primary_key_prefix());

        var fields = that.fields.get_fields();
        for (var j=0; j<fields.length; j++) {
            var field = fields[j];

            var values = record[field.param];
            if (!values || values.length === 0) continue;
            if (field.flags.indexOf('no_command') > -1) continue;

            if (field.param === pkey_name) {
                command.add_arg(values[0]);
            } else if (values.length === 1) {
                command.set_option(field.param, values[0]);
            } else {
                command.set_option(field.param, values);
            }
        }

        return command;
    };

    that.add = function(on_success, on_error) {

        if (!that.validate()) return;

        var record = {};
        that.save(record);

        that.command = that.create_add_command(record);
        that.command.on_success = on_success;
        that.command.on_error = on_error;

        that.command.execute();
    };

    that.create = function() {
        that.dialog_create();

        var div = $('<div/>', {
        }).appendTo(that.container);

        $('<span/>', {
            'class': 'required-indicator',
            text: IPA.required_indicator
        }).appendTo(div);

        div.append(' ');

        $('<span/>', {
            text: IPA.messages.widget.validation.required
        }).appendTo(div);
    };

    // methods that should be invoked by subclasses
    that.entity_adder_dialog_create = that.create;
    that.entity_adder_dialog_create_add_command = that.create_add_command;
    that.entity_adder_dialog_get_success_message = that.get_success_message;

    init();

    return that;
};
