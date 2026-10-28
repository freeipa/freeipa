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
        'dojo/dom-construct',
        'dojo/dom-style',
        'dojo/Evented',
        'dojo/Stateful',
        'dojo/NodeList-dom'
       ],
       function(declare, lang,  construct, dom_style,
                Evented, Stateful) {

    /**
     * Container for standalone facets
     *
     * Main feature is that this container doesn't produce any
     * surroundings. Therefore facets can occupy the entire page.
     *
     * @class widgets.FacetContainer
     */
    var FacetContainer = declare([Stateful, Evented], {

        id: 'simple-container',

        'class': 'app-container',

        //nodes:
        dom_node: null,

        container_node: null,

        content_node: null,

        render: function() {

            this.dom_node = construct.create('div', {
                id: this.id,
                'class': this['class']
            });

            if (this.container_node) {
                construct.place(this.dom_node, this.container_node);
            }

            this.content_node = construct.create('div', {
                'class': 'content'
            }, this.dom_node);

            return this.dom_node;
        },

        show: function() {
            if (!this.dom_node) return;

            dom_style.set(this.dom_node, 'display', '');
        },

        hide: function() {
            if (!this.dom_node) return;

            dom_style.set(this.dom_node, 'display', 'none');
        },

        constructor: function(spec) {
            spec = spec || {};
            declare.safeMixin(this, spec);
        }
    });

    return FacetContainer;
});