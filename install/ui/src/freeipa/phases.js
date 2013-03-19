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

/**
 * Phases module provides access mainly serves as an registration point for
 * phase tasks. It also provides access to Phase controller.
 */
define([
    './_base/Phase_controller'
], function(Phase_controller) {

    /**
     * Phases specification object.
     *
     * @type String[]
     */
    var spec = {
        phases: [
            //'resource-load', // implicit phase
            'registration',
            'alternation',
            'init',
            'metadata',
            'profile',
            'runtime',
            'shutdown'
        ]
    };

    /**
     * Phases module
     */
    var phases = {
        /**
         * Phases controller
         */
        controller: new Phase_controller(spec),

        /**
         * Registers phase task
         */
        on: function(phase_name, handler, priority) {
            this.controller.add_task(phase_name, handler, priority);
        }
    };

    return phases;
});