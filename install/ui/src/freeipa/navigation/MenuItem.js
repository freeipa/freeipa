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

/**
 * This is a virtual object which serves only for documentation purposes. It
 * describes what properties has the created menu item and what can be part
 * of menu item object specification.
 *
 * Following properties are not in created in menu item:
 *
 * - children
 *
 * Following properties may be part of menu item at runtime:
 *
 * - selected
 * - parent
 * - selected_child
 *
 * @class navigation.MenuItem
 * @abstract
 */
var MenuItem = {
    /**
     * Name - menu item identifier
     */
    name: '',

    /**
     * Visible text
     */
    label: '',

    /**
     * Title
     */
    title: '',

    /**
     * Position for ordering
     */
    position: 0,

    /**
     * Children
     *
     * - next navigation level
     * @property {Array.<navigation.MenuItem>}
     */
    children: null,

    /**
     * Entity name
     */
    entity: '',

    /**
     * Facet name
     */
    facet: '',

    /**
     * Control item visibility but can serve for other evaluations (nested entities)
     */
    hidden: '',

    /**
     * Runtime property
     * Should not be set by hand. Indicates whether item is selected.
     */
    selected: false,

    /**
     * Parent menu item's name
     */
    parent: null,

    /**
     * Some child is selectd. Runtime property.
     */
    selected_child: null
};
