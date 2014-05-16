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

define([
    'dojo/_base/lang',
    './jquery',
    './phases',
    './app_container',
    'exports'
],function(lang, $, phases, app, extend) {

/**
 * Extension interface
 *
 * This class provides interface for plugins and tries to hide underlying functionality
 *
 * @class extend
 * @singleton
 */
lang.mixin(extend, {
    /**
     * Adds element to utility section
     *
     * This method doesn't do any correction. Expended root node type to add is
     * by default `<li>`.
     *
     * Preferred phase: any after `init`
     *
     * @param {HTMLElement|jQuery} element Element to add to utility section
     * @return {HTMLElement} Utility node
     */
    add_menu_utility: function(element) {

        // Should we check if we are in good stage or atleast report that app doesn't exist yet?

        var $utility = $(app.app.app_widget.nav_util_tool_node);
        $utility.prepend(element);
        return $utility.eq(0);
    }
});

    return extend;
});