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
        'dojo/_base/lang'
        ], function(declare, lang) {

    var Spec_mod = declare(null, {

        /**
         * Modifies spec according to rules defined in diff object.
         *
         * Diff should have following structure: {
         *      $add: array of add rules
         *      $del: array of del rules
         *      $set: array of set rules
         * }
         *
         * The order of modification is del, add, set.
         *
         * @param {Object} spec
         * @param {Object} diff
         */
        mod: function(spec, diff) {

            if (!diff) return spec;

            this.del(spec, diff.$del);
            this.add(spec, diff.$add);
            this.set(spec, diff.$set);

            return spec;
        },


        /**
         * Adds objects according to rules to array.
         *
         * A rule is a triple of path and a object and position to add:
         *      ['path.to.spec.array', {}, position]
         *
         */
        add: function(spec, rules) {

            return this._apply_rules(spec, rules, this._add);
        },

        /**
         * Deletes objects according to rules from an array.
         *
         * A rule is a pair of path and delete conditions:
         *      ['path.to.spec.array', [ { name: 'foo'}, { name: 'baz'} ]]
         *
         *      Deletes all objects with name 'baz' or 'foo'.
         */
        del: function(spec, rules) {

            return this._apply_rules(spec, rules, this._del);
        },

        /**
         * A rule is a pair of path and a object to set.
         *      ['path.to.spec.property', {}]
         */
        set: function(spec, rules) {

            return this._apply_rules(spec, rules, this._set);
        },

        /**
         * Removes all rule props
         */
        del_rules: function(diff) {
            delete diff.$add;
            delete diff.$del;
            delete diff.$set;
        },

        _apply_rules: function(spec, rules, method) {
            if (!lang.isArrayLike(rules)) return spec;

            for (var i=0; i<rules.length; i++) {
                method.call(this, spec, rules[i]);
            }

            return spec;
        },

        _add: function(spec, rule) {

            var path = rule[0];
            var value = rule[1];
            var pos = rule[2];
            var arr = lang.getObject(path, false, spec);

            if (!arr) {
                arr = [];
                lang.setObject(path, arr, spec);
            }

            if (typeof pos !== 'number') pos = arr.length;
            else if (pos < 0) pos = 0;
            else if (pos > arr.length) pos = arr.length;

            arr.splice(pos, 0, value);
            return spec;
        },

        _del: function(spec, rule) {

            var path = rule[0];
            var conds = rule[1];
            var arr = lang.getObject(path, false, spec);

            if (!arr) return spec;

            var del = [];
            var i,j;

            for (i=0; i<arr.length; i++) {
                for (j=0; j<conds.length; j++) {
                    if (this._match(arr[i], conds[j])) {
                        del.push(i);
                        break;
                    }
                }
            }

            del.sort(function(a,b) {return b-a;});
            for (i=0; i<del.length;i++) {
                arr.splice(del[i], 1);
            }
            return spec;
        },

        _match: function(value, cond) {
            var match = true;

            if (typeof cond !== 'object') {
                match = cond === value;
            } else {
                for (var prop in cond) {
                    if (cond.hasOwnProperty(prop) && cond[prop] !== value[prop]) {
                        match = false;
                        break;
                    }
                }
            }

            return match;
        },

        _set: function(spec, rule) {
            lang.setObject(rule[0], rule[1], spec);
            return spec;
        }
    });

    return Spec_mod;
});