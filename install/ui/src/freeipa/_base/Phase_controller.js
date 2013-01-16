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
    'dojo/_base/lang',
    'dojo/_base/array',
    'dojo/_base/declare',
    'dojo/promise/all',
    'dojo/topic',
    '../ordered-map'
], function(lang, array, declare, all, topic, ordered_map) {

    var Phase_controller = declare(null, {

        /**
         * Phases
         * @type ordered_map[name, phase]
         */
        phases: null,

        /**
         * Current phase name
         * @type String
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
         * 1) Sorts tasks of the phase based on their priority.
         * 2) Runs all task sequentially.
         * 3) Waits for all tasks to complete (in case of asynchronous ones)
         * 4) Optionally runs next phase
         *
         * @param {phase} Phase to runs
         * @param {Boolean} Whether to run next phase when current finishes
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
                var promise = task.handler();
                promises.push(promise);
            });

            all(promises).then(lang.hitch(this, function(results) {
                topic.publish('phase-finished',
                              { phase: phase.name, results: results });
                if (next_phase) {
                    this.next_phase(next_phase);
                }
            }), function(results) {
                topic.publish('phase-error',
                              { phase: phase.name, results: results });
                // don't go for next phase on error, let app decide what to do
            });
        },

        /**
         * Selects next phase and then runs it.
         *
         * @param {Boolen} Whether to run phases continuously
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
         * Add task for a phase.
         *
         * At phase execution, tasks are sorted by priority and executed in
         * that order.
         *
         * @param {String} Name of associated phase
         * @param {Function} Task handler. Should return promise if async.
         * @param {Number} Priority of task. Default 10.
         */
        add_task: function(phase_name, handler, priority) {

            var phase = this.phases.get(phase_name);

            if (typeof priority !== 'number') priority = 10;

            phase.tasks.push({
                priority: priority,
                handler: handler
            });
        },

        /**
         * Adds a phase.
         * @param {String} phase name
         */
        add_phase: function(name, tasks) {

            var phase = {
                name: name,
                tasks: tasks || []
            };

            this.phases.put(name, phase);
        },

        constructor: function(spec) {
            spec = spec || {};

            this.phases = ordered_map();

            var phases = spec.phases || [];
            array.forEach(phases, lang.hitch(this, function(phase) {
                this.add_phase(phase);
            }));
        }
    });

    return Phase_controller;

});