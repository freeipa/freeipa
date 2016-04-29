/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2014 Red Hat
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
        'dojo/on',
        '../jquery',
        './DropdownWidget'], function(declare, on, $,  DropdownWidget) {

    return declare([DropdownWidget], {
        /**
         * Represents and creates a dropdown widget for executing facet actions
         *
         * @class widgets.ActionDropdownWidget
         */

        /**
         * Facet which contains actions
         * @type {facet.facet|facets.Facet}
         */
        facet: null,

        /**
         * Names of actions, which should be later obtained from facet
         * @property {Array.<string>}
         */
        action_names: [],

        /**
         * Actions
         * @property {ordered_map}
         */
        actions: [],

        on_item_click: function(event, item) {

            if (item.click) item.click();
            this.emit('item-click', item);
        },

        /**
         * Initializes action list
         *
         * - set facet
         * - get actions from facet
         * - init child widgets
         *
         * @param {facet.facet} facet
         */
        init: function(facet) {

            var options, actions, action, name, i;

            this.facet = facet;

            if (!this.action_names) return;

            for (i=0; i<this.action_names.length; i++) {
                name = this.action_names[i];
                action = this.facet.actions.get(name);
                if (!action) {
                    window.console.error(
                        "ActionDropDown: cannot find action: " + name +
                        "\nFacet: "+facet.name);
                    continue;
                }
                this.add_action(action, true);
            }
            this.recreate_options();
        },

        /**
         * Add action
         * @param {facet.action} action
         * @param {boolean} [batch] Set to `true` when adding multiple actions to
         *                          prevent unnecessary option initialization and
         *                          recreation. Set it back to `false` when adding
         *                          last option.
         */
        add_action: function(action, batch) {
            this.actions.put(action.name, action);
            action.enabled_changed.attach(this.action_enabled_changed.bind(this));
            action.visible_changed.attach(this.action_visible_changed.bind(this));

            if (!batch) {
                this.recreate_options();
            }
        },

        /**
         * Create and set select options from actions
         */
        recreate_options: function() {

            var items, actions, action, i;

            items = [];
            actions = this.actions.values;

            for (i=0; i< actions.length; i++) {
                action = actions[i];
                if (!action.visible) continue;
                items.push({
                    label: action.label,
                    value: action.name,
                    name: action.name,
                    disabled: !action.enabled,
                    action: action
                });
            }

            this.set('items', items);
        },

        on_item_click: function(event, item) {

            this.inherited(arguments);
            if (item.action) {
                this.execute_action(item.action);
            }
        },


        /**
         * Execute action if enabled
         *
         * @protected
         */
        execute_action: function(action) {

            if (action.enabled) {
                action.execute(this.facet,
                               this.on_action_success.bind(this),
                               this.on_action_error.bind(this));
            }
        },

        /**
         * Global action success handler
         *
         * @localdoc - override point
         * @protected
         * @abstract
         */
        on_action_success: function() {
        },

        /**
         * Global action error handler
         *
         * @localdoc - override point
         * @protected
         * @abstract
         */
        on_action_error: function() {
        },

        /**
         * Handle action's `enabled_changed` event.
         * @protected
         * @param {boolean} enabled
         */
        action_enabled_changed: function(enabled) {
            this.recreate_options();
        },

        /**
         * Handle action's `visible_changed` event.
         * @protected
         * @param {boolean} visible
         */
        action_visible_changed: function(visible) {
            this.recreate_options();
        },

        constructor: function(spec) {
            declare.safeMixin(this, spec);
            this.actions = $.ordered_map();
        }
    });
});
