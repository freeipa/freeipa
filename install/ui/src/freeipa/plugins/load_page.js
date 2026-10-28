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

define([
    'dojo/_base/declare',
    'dojo/_base/lang',
    'dojo/on',
    '../facets/Facet',
    '../phases',
    '../reg',
    '../text'
   ],
   function(declare, lang, on, Facet, phases, reg, text) {

    /**
     * Load Facet plugin
     *
     * @class plugins.load
     * @singleton
     */
    var load = {};

    load.facet_spec = {
        name: 'load',
        preferred_container: 'simple',
        requires_auth: false,
        'class': 'login-pf-body',
        widgets: [
            {
                $type: 'activity',
                name: 'activity',
                text: text.get('@i18n:login.loading', 'Loading'),
                visible: true
            }
        ]
    };

    phases.on('registration', function() {

        var fa = reg.facet;

        fa.register({
            type: 'load',
            factory: Facet,
            spec: load.facet_spec
        });
    });

    return load;
});
