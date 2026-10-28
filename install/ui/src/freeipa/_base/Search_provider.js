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
 * Search value provider
 *
 * Serves for searching for values within an array in a source object.
 *
 * Path has input formats as follows:
 *
 *    * key1:key2:key3
 *    * key1:key2
 *    * key2
 *
 * With:
 *
 *    * base_query: `%1.takes_params`
 *    * array_attr: `name`
 *
 * Such path is translates into query:
 *
 *    * `%key1.takes_params[name=%key2].$key3`
 *
 * In a future we should support defining generic queries and thus not be
 * limited to simple search.
 *
 * @class _base.Search_provider
 * @extends _base.Provider
 */
define(['dojo/_base/declare','dojo/_base/lang', './Provider'],
       function(declare, lang, Provider) {

    var Search_provider = declare([Provider], {

        base_query: null,
        array_attr: null,

        /**
         * @inheritDoc
         * @protected
         */
        _get: function(key) {
            var search_keys = key.substring(this._code_length);
            search_keys = search_keys.split(':');
            var count = search_keys.length;
            if (count < 1 || count > 3) return null;

            var key1, key2, key3;
            if (count === 1) {
                key2 = search_keys[0];
            } else if (count === 2) {
                key1 = search_keys[0];
                key2 = search_keys[1];
            } else {
                key1 = search_keys[0];
                key2 = search_keys[1];
                key3 = search_keys[2];
            }

            var arr;
            var source = arr = this._get_source();

            if (key1) {
                var property = this.base_query.replace('%1', search_keys[0]);
                arr = lang.getObject(property, false, source);
            }
            var ret = this._find(arr, this.array_attr, key2, false);
            if (ret && key3) {
                ret = lang.getObject(key3, false, ret);
            }
            return ret;
        },

        /**
         * Finds object with attr_name === value in array defined by key.
         * @protected
         */
        _find: function(array, attr, value, all) {

            var vals = [];

            if (!lang.isArrayLike(array)) return null;

            for (var i=0; i<array.length; i++) {
                if (array[i][attr] === value) {
                    vals.push(array[i]);
                    if (!all) break;
                }
            }

            if (!all) return vals[0] || null;

            return vals;
        },

        constructor: function(spec) {

            spec = spec || {};
            this.base_query = spec.base_query || '%1';
            this.array_attr = spec.array_attr || 'name';
        }
    });

    return Search_provider;
});