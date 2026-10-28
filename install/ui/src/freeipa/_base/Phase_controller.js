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
    'dojo/_base/array',
    'dojo/_base/declare',
    'dojo/Deferred',
    'dojo/promise/all',
    'dojo/topic',
    '../ordered-map'
], function(array, declare, Deferred, all, topic, ordered_map) {


    /**
     * Phase
     *
     * This class does not exist, it's only for documentation purposes.
     *
     * @class _base.Phase_controller.phase
     * @abstract
     */
    /**
     * Name
     * @property {string} name
     */
    /**
     * Tasks
     * @property {Array.<_base.Phase_controller.task>} tasks
     */

    /**
     * Phase task
     *
     * This class does not exist, it's only for documentation purposes.
     *
     * @class _base.Phase_controller.task
     * @abstract
     */
    /**
     * Name
     * @property {number} priority
     */
    /**
     * Tasks
     * @property {Function} handler
     */

    /**
     * Phase Controller
     *
     * Creates synchronization points - phases - in application life cycle.
     *
     * Phases:
     *
     * - are ordered
     * - consist of task
     * - phase finishes when all task finishes
     * - new phases can be added at runtime
     *
     * @class _base.Phase_controller
     */
    var Phase_controller = declare(null, {

        /**
         * Phases
         * @property {ordered_map.<string, _base.Phase_controller.phase>}
         */
        phases: null,

        /**
         * Current phase name
         * @property {string}
         */
        current: null,

        /**
         * Run all phases in a row starting from current, or the first when
         * current is not set.
         */
        run: function() {
            if (this.current !== null) {
                var phase = this.phases.get(this.current);
                this._run_phase(phase);
            } else {
                this.next_phase(true);
            }
        },

        /**
         * Runs phase
         *
         * 1. Sorts tasks of the phase based on their priority.
         * 2. Runs all task sequentially.
         * 3. Waits for all tasks to complete (in case of asynchronous ones)
         * 4. Optionally runs next phase
         *
         * @param {_base.Phase_controller.phase} phase Phase to run
         * @param {boolean} next_phase Whether to run next phase when current finishes
         */
        _run_phase: function(phase, next_phase) {

            if (!phase) return;
            this.current = phase.name;
            topic.publish('phase-start', { phase: phase.name });
            var promises = [];

            var tasks = phase.tasks.sort(function(a,b) {
                return a.priority-b.priority;
            });

            array.forEach(tasks, function(task) {
                var promise;
                try {
                    promise = task.handler();
                } catch (e) {
                    var fail = new Deferred();
                    fail.reject(e, true);
                    promise = fail.promise;
                }
                promises.push(promise);
            });

            all(promises).then(function(results) {
                topic.publish('phase-finished',
                              { phase: phase.name, results: results });
                if (next_phase) {
                    this.next_phase(next_phase);
                }
            }.bind(this), function(results) {
                topic.publish('phase-error',
                              { phase: phase.name, results: results });
                // don't go for next phase on error, let app decide what to do
            });
        },

        /**
         * Selects next phase and then runs it.
         *
         * @param {boolean} continuous Whether to run phases continuously
         */
        next_phase: function(continuous) {
            var phase;

            if (this.current === null) {
                phase = this.phases.get_value_by_index(0);
            } else {
                var index = this.phases.get_key_index(this.current);
                phase = this.phases.get_value_by_index(index + 1);
            }

            this._run_phase(phase, continuous);
        },

        /**
         * Adds task for a phase.
         *
         * At phase execution, tasks are sorted by priority and executed in
         * that order.
         *
         * @param {string} phase_name Name of associated phase
         * @param {Function} handler Task handler. Should return promise if async.
         * @param {number} [priority=10] Priority of task.
         */
        add_task: function(phase_name, handler, priority) {

            var phase = this.phases.get(phase_name);

            if (!phase) {
                window.console.warn('no such phase: ' + phase_name);
                return;
            }

            if (typeof priority !== 'number') priority = 10;

            phase.tasks.push({
                priority: priority,
                handler: handler
            });
        },

        /**
         * Adds a phase
         *
         * Possible options:
         *
         * - before: 'name-of-phase'
         * - after: 'name-of-phase'
         * - position: 'position for new phase'
         *
         * @param {string} phase name
         * @param {Array.<_base.Phase_controller.task>} tasks
         * @param {Object} options
         */
        add_phase: function(name, tasks, options) {

            var phase = {
                name: name,
                tasks: tasks || []
            };

            var position;
            if (options) {
                if (options.before) {
                    position = this.phases.get_key_index(options.before);
                } else if (options.after) {
                    position = this.phases.get_key_index(options.after);
                    if (position === -1) position = this.phases.length;
                    else position++;
                } else if (options.position) {
                    position = options.position;
                }
            }

            this.phases.put(name, phase, position);
        },

        /**
         * Checks if phases with given name exists
         *
         * @param {string} name
         * @return {boolean}
         */
        exists: function(name) {
            return !!this.phases.get(name);
        },

        constructor: function(spec) {
            spec = spec || {};

            this.phases = ordered_map();

            var phases = spec.phases || [];
            array.forEach(phases, function(phase) {
                this.add_phase(phase);
            }.bind(this));
        }
    });

    return Phase_controller;

});
