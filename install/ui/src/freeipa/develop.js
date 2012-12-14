/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2012 Red Hat
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
 *
*/

define(['./ipa'], function(IPA) {

    //polute global namespace - easy usage in browser console
    window.IPA = IPA;
    var console = window.console; // avoid  jsl error

    var tools = window.ipadev = IPA.dev = {

        // map of loaded modules
        modules: {},

        get: function (mid,name) {
            /* loads module into ipa dev modules property */

            var self = this;
            var mid_parts = mid.split('/');
            name = name || mid_parts[mid_parts.length-1];

            require([mid], function(module) {
                self.modules[name] = module;
                console.log('Module '+mid+' loaded.');
            });
        }
    };

    console.log('Dev tools loaded.');

    return tools;

}); //define