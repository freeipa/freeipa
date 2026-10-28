/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2013 Red Hat
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

define(['dojo/_base/declare',
        'dojo/_base/lang',
        'dojo/on',
        './util'
       ],
       function(declare, lang, on, util) {

    /**
     * Field binder
     *
     * Binds input widget with field - defines standard communication logic
     * between widget and a field.
     *
     * Usage:
     *
     *      var binder = new FieldBinder(widget, field).bind();
     *
     *      // or
     *      var binder = new FieldBinder({
     *          field: field,
     *          widget: widget
     *      });
     *      binder.bind()
     *
     * @class FieldBinder
     */
    var FieldBinder = declare([], {

        /**
         * Field
         * @property {IPA.field}
         */
        field: null,

        /**
         * Widget
         * @property {IPA.input_widget}
         */
        widget: null,

        /**
         * Binder is enabled
         *
         * Handlers are not be called when set to false.
         *
         * @property {boolean}
         */
        enabled: true,

        /**
         * Handlers
         * @protected
         * @property {Function[]}
         */
        handlers: null,

        /**
         * Value update is in progress
         *
         * When set, binder should not react to field's nor widget's value-change
         * event.
         *
         * @property {boolean}
         */
        updating: false,

        /**
         * Bind widget with field
         *
         * Listens for field's:
         *
         * - enable-change
         * - valid-change
         * - value-change
         * - dirty-change
         * - require-change
         * - writable-change
         * - readonly-change
         * - reset
         *
         * Listens for widget's:
         *
         * - value-change
         * - undo-click
         *
         * @param {boolean} hard
         *                       Hard binding. Sets `field.widget` to `this.widget`.
         *                       This option is for backward compatibility.
         */
        bind: function(hard) {

            var field = this.field;
            var widget = this.widget;

            if (hard) field.widget = widget;

            this.handle(field, 'enable-change', this.on_field_enable_change);
            this.handle(field, 'valid-change', this.on_field_valid_change);
            this.handle(field, 'value-change', this.on_field_value_change);
            this.handle(field, 'dirty-change', this.on_field_dirty_change);
            this.handle(field, 'require-change', this.on_field_require_change);
            this.handle(field, 'writable-change', this.on_field_writable_change);
            this.handle(field, 'readonly-change', this.on_field_readonly_change);
            this.handle(field, 'acl-rights-change', this.on_field_acl_rights_change);
            this.handle(field, 'reset', this.on_field_reset);

            this.handle(widget, 'value-change', this.on_widget_value_change);
            this.handle(widget, 'undo-click', this.on_widget_undo_click);

            return this;
        },

        /**
         * Unbind all handlers
         */
        unbind: function() {

            var handler;
            while ((handler = this.handlers.pop())) {
                handler.remove();
            }
        },

        /**
         * Creates and registers the handler.
         * Handler will be called in binder context and only if
         * `this.enabled === true`.
         *
         * Do not use `on(target, type, handler)` directly.
         *
         * @param {Function} handler
         * @return {Function} context bound handler
         * @protected
         */
        handle: function(target, type, handler) {

            var _this = this;

            var hndlr = function() {
                if (_this.enabled !== true) return;
                else {
                    handler.apply(_this, Array.prototype.slice.call(arguments, 0));
                }
            };

            var reg_hndl = on(target, type, hndlr);
            this.handlers.push(reg_hndl);

            return hndlr;
        },

        /**
         * Field enable change handler
         *
         * Reflect enabled state to widget
         *
         * @protected
         */
        on_field_enable_change: function(event) {
            this.widget.set_enabled(event.enabled);
        },

        /**
         * Field valid change handler
         * @protected
         */
        on_field_valid_change: function(event) {
            this.widget.set_valid(event.result);
        },

        /**
         * Field dirty change handler
         *
         * Controls showing of widget's undo button
         *
         * @protected
         */
        on_field_dirty_change: function(event) {

            if (!this.field.undo) return;
            if (event.dirty) {
                this.widget.show_undo();
            } else {
                this.widget.hide_undo();
            }
        },

        /**
         * Field require change handler
         *
         * Updates widget's require state
         *
         * @protected
         */
        on_field_require_change: function(event) {

            this.widget.set_required(event.required);
        },

        /**
         * Field require change handler
         *
         * Updates widget's require state
         *
         * @protected
         */
        on_field_writable_change: function(event) {

            this.widget.set_writable(event.writable);
        },

        /**
         * Field require change handler
         *
         * Updates widget's require state
         *
         * @protected
         */
        on_field_readonly_change: function(event) {

            this.widget.set_read_only(event.read_only);
        },

        /**
         * Field acl rights change handler
         * @protected
         */
        on_field_acl_rights_change: function(event) {

            var readable= event.rights.indexOf('r') > -1;
            if (this.widget.set_readable) {
                this.widget.set_readable(readable);
            }
        },

        /**
         * Field reset handler
         *
         * @param {Object} event
         * @protected
         */
        on_field_reset: function(event) {
            this.copy_properties();
        },

        /**
         * Field value change handler
         * @protected
         */
        on_field_value_change: function(event) {

            if (this.updating) return;

            var format_result = util.format(this.field.ui_formatter, event.value);
            if (format_result.ok) {
                this.updating = true;
                this.widget.update(format_result.value);
                this.updating = false;
            } else {
                // this should not happen in ideal world
                window.console.warn('field format error: '+this.field.name);
            }
        },

        /**
         * Widget value change handler
         * @protected
         */
        on_widget_value_change: function(event) {

            if (this.updating) return;

            var val = this.widget.save();
            var format_result = util.parse(this.field.ui_parser, val);
            if (format_result.ok) {
                this.updating = true;
                this.field.set_value(format_result.value);
                this.updating = false;
            } else {
                this.field.set_valid(format_result);
            }
        },

        /**
         * Widget undo click handler
         * @protected
         */
        on_widget_undo_click: function(event) {

            this.field.reset();
        },

        /**
         * Copies `label`, `tooltip`, `measurement_unit`, `undo`, `writable`,
        * `read_only` from field to widget
         */
        copy_properties: function() {

            var field = this.field;
            var widget = this.widget;

            if (field.label) widget.label = field.label;
            if (field.tooltip) widget.tooltip = field.tooltip;
            if (field.measurement_unit) widget.measurement_unit = field.measurement_unit;
            widget.undo = field.undo;
            widget.set_writable(field.writable);
            widget.set_read_only(field.read_only);
            widget.set_required(field.is_required());

            return this;
        },

        constructor: function(arg1, arg2) {

            this.handlers = [];

            if (arg2) {
                this.field = arg1;
                this.widget = arg2;
            } else {
                arg1 = arg1 || {};
                this.field = arg1.field;
                this.widget = arg1.widget;
            }
        }
    });

    return FieldBinder;
});
