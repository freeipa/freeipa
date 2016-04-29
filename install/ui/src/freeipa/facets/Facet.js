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
        'dojo/Evented',
        'dojo/dom-construct',
        'dojo/dom-class',
        'dojo/on',
        '../builder',
        '../facet',
        '../ipa', // for util functions
        '../jquery',
        '../text',
        '../widgets/ContainerMixin'
       ],
       function(declare, lang, Evented, construct, dom_class,
                on, builder, mod_facet, IPA, $, text, ContainerMixin) {

    /**
     * Base class of Facet
     *
     * A future replacement/base class for `facet.facet`
     *
     * @class facets.Facet
     * @mixins widgets.ContainerMixin
     */
    var Facet = declare([Evented, ContainerMixin], {

        /**
         * Name of preferred facet container
         *
         * Leave unset to use default container.
         * @property {string}
         */
        preferred_container: null,

        /**
         * Facet name
         * @property {string}
         */
        name: null,

        /**
         * Facet label
         * @property {string}
         */
        label: null,

        /**
         * Facet title
         * @property {string}
         */
        title: null,

        /**
         * Facet tab label
         * @property {string}
         */
        tab_label: null,

        /**
         * Facet element's CSS class
         * @property {string}
         */
        'class': null,

        /**
         * Class which tells that the facet should be visible
         * @property {string}
         */
        active_class: 'active',

        /**
         * dom_node of container
         * Suppose to contain dom_node of this and other facets.
         * @property {jQuery}
         */
        container_node: null,

        /**
         * dom_node which contains all content of this Facet.
         * @property {HTMLElement}
         * @readonly
         */
        dom_node: null,

        /**
         * DOM node which serves as container for child widgets
         * @property {HTMLElement}
         */
        children_node: null,

        /**
         * Redirection target information.
         *
         * Can be facet and/or entity name.
         * @property {Object}
         * @param {string} entity entity name
         * @param {string} facet facet name
         */
        redirect_info: null,

        /**
         * Facet requires authenticated user
         * @type {Boolean}
         */
        requires_auth: true,

        /**
         * Public state
         * @property {facet.FacetState}
         * @protected
         */
        state: null,

        get_full_name: function() {
            return this.name;
        },

        /**
         * Checks if two objects has the same properties with equal values.
         *
         * @param {Object} a
         * @param {Object} b
         * @return {boolean} `a` and `b` are value-equal
         * @protected
         */
        state_diff: function(a, b) {
            var diff = false;
            var checked = {};

            var check_diff = function(a, b, skip) {

                var same = true;
                skip = skip || {};

                for (var key in a) {
                    if (a.hasOwnProperty(key) && !(key in skip)) {
                        var va = a[key];
                        var vb = b[key];
                        if (lang.isArray(va)) {
                            if (IPA.array_diff(va,vb)) {
                                same = false;
                                skip[a] = true;
                                break;
                            }
                        } else {
                            if (va != vb) {
                                same = false;
                                skip[a] = true;
                                break;
                            }
                        }
                    }
                }
                return !same;
            };

            diff = check_diff(a,b, checked);
            diff = diff || check_diff(b,a, checked);
            return diff;
        },

        /**
         * Reset facet state to supplied
         *
         * @param {Object} state state to set
         */
        reset_state: function(state) {
            this.state.reset(state);
        },

        /**
         * Get copy of current state
         *
         * @return {Object} state
         */
        get_state: function() {
            return this.state.clone();
        },

        /**
         * Merges state into current and notifies it.
         *
         * @param {Object} state object to merge into current state
         */
        set_state: function(state) {
            this.state.set(state);
        },

        /**
         * Handle state set
         * @param {Object} old_state
         * @param {Object} state
         * @protected
         */
        on_state_set: function(old_state, state) {
            this.on_state_change(state);
        },

        /**
         * Handle state change
         * @param {Object} state
         * @protected
         */
        on_state_change: function(state) {

            this._notify_state_change(state);
        },

        /**
         * Fires `facet-state-change` event with given state as event parameter.
         *
         * @fires facet-state-change
         * @protected
         * @param {Object} state
         */
        _notify_state_change:  function(state) {
            this.emit('facet-state-change', {
                facet: this,
                state: state
            });
        },

        /**
         * Create facet's HTML representation
         * NOTE: may be renamed to render
         */
        create: function() {

            if (this.dom_node) {
                construct.empty(this.dom_node);
            } else {
                this.dom_node = construct.create('div', {
                    'class': 'facet',
                    name: this.name,
                    'data-name': this.name
                });
            }
            if (this['class']) {
                dom_class.add(this.dom_node, this['class']);
            }
            if (this.container_node) {
                construct.place(this.dom_node, this.container_node);
            }
            this.children_node = this.dom_node;
            return this.dom_node;
        },

        /**
         * Render child widgets
         */
        render_children: function() {
            var widgets = this.get_widgets();

            for (var i=0;i<widgets.length; i++) {
                var widget = widgets[i];
                var modern = typeof widget.render === 'function';

                if (modern) {
                    widget.container_node = this.children_node;
                    widget.render();
                } else {
                    var container = $('<div/>').appendTo(this.children_node);
                    widget.create(container);
                }
            }
        },

        /**
         * Show facet
         *
         * - mark itself as active facet
         */
        show: function() {

            if (!this.dom_node) {
                this.create();
                this.render_children();
            } else if (!this.dom_node.parentElement) {
                construct.place(this.dom_node, this.container_node);
            }

            dom_class.add(this.dom_node, 'active-facet');
            this.emit('show', { source: this });
        },

        /**
         * Un-mark itself as active facet
         */
        hide: function() {
            if (this.dom_node.parentElement) {
                this.container_node.removeChild(this.dom_node);
            }
            dom_class.remove(this.dom_node, 'active-facet');
            this.emit('hide', { source: this });
        },

        /**
         * Initializes facet
         *
         * Facet builder should run this method after instantiation.
         * @param {Object} spec
         */
        init: function(spec) {

            this.add_widgets(spec.widgets || []);
        },

        can_leave: function() {
            return true;
        },

        show_leave_dialog: function(callback) {
            window.console.warning('Unimplemented');
        },

        /** Constructor */
        constructor: function(spec) {

            this.preferred_container = spec.preferred_container;
            this.name = spec.name;
            this.label = text.get(spec.label);
            this.tab_label = text.get(spec.tab_label || spec.label);
            this.title = text.get(spec.title || spec.label);
            this['class'] = spec['class'];
            this.container_node = spec.container_node;
            this.dom_node = spec.dom_node;
            this.redirect_info = spec.redirect_info;
            if (spec.requires_auth !== undefined) {
                this.requires_auth = spec.requires_auth;
            }
            this.state = new mod_facet.FacetState();
            on(this.state, 'set', this.on_state_set.bind(this));
        }
    });

    return Facet;
});
