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
        '../builder',
        '../ordered-map',
        '../widget'
       ],
       function(declare, lang, on, builder, ordered_map, widget_mod) {

    /**
     * Container Mixin
     *
     * Manages child widgets.
     *
     * @class widgets.ContainerMixin
     */
    var ContainerMixin = declare([], {

        /**
         * Childs
         * @property {ordered_map}
         */
        widgets: null,

        /**
         * Builds widgets on add if not already built
         *
         * @property {widget.widget_builder}
         */
        widget_builder: null,

        /**
         * Raised after `create`
         * @event create
         */

        /**
         * Raised after 'clear_widgets`
         * @event clear
         */

        /**
         * Raised before `clear_widgets`
         *
         * - `clear_widgets` can be aborted by setting `event.abort=true`
         *
         * @event pre-clear
         */

        /**
         * Get widget by name
         * @param {string} name
         */
        get_widget: function(name) {
            return this.widgets.get(name);
        },

        /**
         * Get all widgets
         * @return {Array.<IPA.widget>}
         */
        get_widgets: function() {
            return this.widgets.values;
        },

        /**
         * Add widget
         * @param {IPA.widget|Object|String} widget
         *                           Field or widget spec
         */
        add_widget: function(widget) {
            widget.container = this;
            var built = this.widget_builder.build_widget(widget);

            this.register_widget_listeners(widget);
            this.widgets.put(widget.name, built);
            return built;
        },

        /**
         * Add multiple widgets
         * @param {Array} widgets
         */
        add_widgets: function(widgets) {

            if (!widgets) return [];

            var built = [];
            for (var i=0; i<widgets.length; i++) {
                var w = this.add_widget(widgets[i]);
                built.push(w);
            }
            return built;
        },

        /**
         * Registers listeners for widget events
         * @param {IPA.widget} widget
         * @protected
         */
        register_widget_listeners: function(widget) {
            this.emit('register-widget', { source: this, widget: widget });
        },

        /**
         * Clear all widgets
         * @fires reset
         */
        clear_widgets: function() {

            var event = { source: this };
            this.emit('pre_clear', event);
            if (event.abort) return;

            var widgets = this.get_widgets();
            for (var i=0; i<widgets.length; i++) {
                var widget = widgets[i];
                widget.clear();
            }

            this.emit('clear', { source: this });
        },

        /** Constructor */
        constructor: function(spec) {

            this.widgets = ordered_map();
            var builder_spec = spec.widget_builder || widget_mod.widget_builder;
            this.widget_builder = builder.build(null, builder_spec);
            this.widget_builder.widget_options =  this.widget_builder.widget_options || {};
            this.widget_builder.widget_options.parent = this;
        }
    });

    return ContainerMixin;
});