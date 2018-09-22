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

define(['./ipa', './jquery', './navigation', './rpc', './text', './field', './widget', './dialog'],
       function(IPA, $, navigation, rpc, text, field_mod, widget_mod) {

/**
 * Entity adder dialog
 * @class
 * @extends IPA.dialog
 * @mixins IPA.confirm_mixin
 */
IPA.entity_adder_dialog = function(spec) {

    spec = spec || {};

    spec.title = spec.title || '@i18n:buttons.add';
    spec.name = spec.name || 'entity_adder_dialog';

    var that = IPA.dialog(spec);

    that.on_cancel = that.close;

    IPA.confirm_mixin().apply(that);

    /** @property {string} method="add" API method for add command */
    that.method = spec.method || 'add';
    /** @property {Function} on_error Custom add error handler */
    that.on_error = spec.on_error ;
    /** @property {boolean} retry=true Allow retry on error (same as in rpc.command)*/
    that.retry = typeof spec.retry !== 'undefined' ? spec.retry : true;
    /**
     * Add command
     * @property {rpc.command}
     * @protected
     */
    that.command = null;
    /** @property {IPA.observer} added Added event */
    that.added = IPA.observer();
    /** @property {string} subject Name of added subject (usually entity label) */
    that.subject = spec.subject || that.entity.metadata.label_singular;
    /**
     * Pkeys of containing entities to use in add command when adding nested entity
     * @property {string[]}
     */
    that.pkey_prefix = spec.pkey_prefix || [];

    /**
     * Custom logic for navigation to edit page in case of 'Add and Edit'
     * @property {Function}
     * @param {entity.entity} entity
     * @param {Object} result
     */
    that.show_edit_page = spec.show_edit_page || show_edit_page;

    var init = function() {
        that.create_button({
            name: 'add',
            label: '@i18n:buttons.add',
            click: function() {
                that.on_add();
            }
        });

        that.create_button({
            name: 'add_and_add_another',
            label: '@i18n:buttons.add_and_add_another',
            click: function() {
                that.hide_message();
                that.add(
                    function(data, text_status, xhr) {
                        that.added.notify([data, 'add_and_add_another'], that);
                        that.show_message(that.get_success_message(data), 'success');
                        that.reset();
                        that.focus_first_element();
                    },
                    that.on_error);
            }
        });

        that.create_button({
            name: 'add_and_edit',
            label: '@i18n:buttons.add_and_edit',
            click: function() {
                that.hide_message();
                that.add(
                    function(data, text_status, xhr) {
                        that.added.notify([data, 'add_and_edit'], that);
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
            label: '@i18n:buttons.cancel',
            click: function() {
                that.hide_message();
                that.close();
            }
        });
    };

    /**
     * Invokes simple add
     * @protected
     */
    that.on_add = function() {

        that.hide_message();
        that.add(
            function(data, text_status, xhr) {
                that.added.notify([data, 'add'], that);
                that.close();
                that.notify_success(data);
            },
            that.on_error);
    };

    /**
     * Confirm handler
     * @protected
     */
    that.on_confirm = function() {
        that.on_add();
    };

    /**
     * Get success notification message text
     * @protected
     * @param {Object} data Add command result
     */
    that.get_success_message = function(data) {
        var message = text.get('@i18n:dialogs.add_confirmation');
        return  message.replace('${entity}', that.subject);
    };

    /**
     * Show success notification
     * @protected
     * @param {Object} data Add command result
     */
    that.notify_success = function(data) {
        IPA.notify_success(that.get_success_message(data));
    };

    function show_edit_page(entity,result) {
        var pkey_name = entity.metadata.primary_key;
        var pkey = result[pkey_name];
        if (!(pkey instanceof Array)) {
            pkey = [pkey];
        }
        rpc.extract_objects(pkey);

        var pkeys = that.pkey_prefix.slice(0);
        pkeys.push(pkey[0]);
        navigation.show_entity(that.entity.name, 'default', pkeys);
    }

    /**
     * Create add command
     * @protected
     * @param {Object} record Saved data
     */
    that.create_add_command = function(record) {

        var pkey_name = that.entity.metadata.primary_key;

        var command = rpc.command({
            entity: that.entity.name,
            method: that.method,
            retry: that.retry
        });

        command.add_args(that.pkey_prefix.slice(0));

        var fields = that.fields.get_fields();
        for (var j=0; j<fields.length; j++) {
            var field = fields[j];

            var values = record[field.param];
            if (!values || values.length === 0 || !field.enabled) continue;
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

    /**
     * Execute add command
     * @param {Function} on_success
     * @param {Function} on_error
     */
    that.add = function(on_success, on_error) {

        if (!that.validate()) {
            widget_mod.focus_invalid(that);
            return;
        }

        var record = {};
        that.save(record);

        that.command = that.create_add_command(record);
        that.command.on_success = on_success;
        that.command.on_error = on_error;

        that.command.execute();
    };

    /** @inheritDoc */
    that.create_content = function() {
        that.dialog_create_content();

        var div = $('<div/>', {
        }).appendTo(that.container);

        $('<span/>', {
            'class': 'required-indicator',
            text: IPA.required_indicator
        }).appendTo(div);

        div.append(' ');

        $('<span/>', {
            text: text.get('@i18n:widget.validation.required')
        }).appendTo(div);
    };

    // methods that should be invoked by subclasses
    that.entity_adder_dialog_create_content = that.create_content;
    that.entity_adder_dialog_create_add_command = that.create_add_command;
    that.entity_adder_dialog_get_success_message = that.get_success_message;

    init();

    return that;
};

return IPA.entity_adder_dialog;
});
