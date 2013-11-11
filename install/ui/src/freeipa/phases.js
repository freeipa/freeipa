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
*/

define([
    './_base/Phase_controller'
], function(Phase_controller) {

    /**
     * Phases specification object.
     * @ignore
     * @property {string[]}
     */
    var spec = {
        phases: [
            //'resource-load', // implicit phase
            'customization',
            'registration',
            'login',
            'init',
            'metadata',
            'post-metadata',
            'profile',
            'runtime',
            'shutdown'
        ]
    };

    /**
     * Phases module
     *
     * Provides access mainly serves as an registration point for
     * phase tasks. It also provides access to Phase controller.
     *
     * @class phases
     * @singleton
     */
    var phases = {
        /**
         * Phases controller
         */
        controller: new Phase_controller(spec),

        /**
         * Registers a phase task
         *
         * @param {string} phase_name
         * @param {Function} handler Task handler. Should return promise if async.
         * @param {number} [priority=10]
         */
        on: function(phase_name, handler, priority) {
            this.controller.add_task(phase_name, handler, priority);
        },

       /**
         * Adds a phase
         *
         * Possible options:
         *   before: 'name-of-phase'
         *   after: 'name-of-phase'
         *   position: 'position for new phase'
         *
         * @param {string} phase_name
         * @param {Object} options
         */
        add: function(phase_name, options) {
            this.controller.add_phase(phase_name, null, options);
        },

        /**
         * Checks if phases with given name exists
         *
         * @param {string} name
         * @return {boolean}
         */
        exists: function(name) {
            return this.controller.exists(name);
        }
    };

    return phases;
});