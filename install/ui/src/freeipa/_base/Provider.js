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
 * Value provider.
 *
 * It search source or child providers for value defined by key.
 *
 * Key consists of code and path.
 *
 * Code defines the type of resource. Provider's handles() method tells whether
 * it can handle this type of resource.
 *
 * Path is a plain object path within a source.
 *
 *      // if source is
 *      {
 *          foo: {
 *              bar: {
 *                  a: 'val'
 *              }
 *          }
 *      }
 *
 *      // path: `foo.bar.a` would return `val`
 *
 * @class _base.Provider
 *
 */
define([
    'dojo/_base/declare',
    'dojo/_base/lang',
    './debug'],
    function(declare, lang, debug) {

    var undefined;
    var Provider = declare(null, {

        /**
         * Array of other providers
         * @property {_base.Provider[]}
         */
        providers: null,

        /**
         * Source object or a function which returns source object.
         * @property {Function|Object|_base.Provider}
         */
        source: null,

        /**
         * Path within a source.
         *
         * When defined, all lookups in source are based on the object
         * defined by this path within a source.
         * @property {string}
         */
        path: null,

        /**
         * Value which is returned if no value nor alternative is found
         * @property {Mixed}
         */
        null_value: null,

        /**
         * Specifies which type should be returned. Limited to output of
         * typeof operator.
         * @property {string}
         */
        required_type: null,

        _code: null,
        _code_length: null,
        _handling_provider: null,

        _set_code: function(code) {
            this._code = code;
            if (code) this._code_length = code.length;
        },

        _get_source: function() {
            var source;
            var type = typeof this.source;
            if (type === 'function') {
                source = this.source.call(this);
            } else if (type === 'object') {
                source = this.source;

                // if source is another provider, use its source as this source
                if (source.isInstanceOf && source.isInstanceOf(Provider) &&
                        source.source) {
                    source = source._get_source();
                }
            }
            if (this.path) {
                source = lang.getObject(this.path, false, source);
            }
            return source;
        },


        _handles: function(key) {
            if (!this._code) return false;
            if (typeof key !== 'string') return false;
            if (key[0] !== '@') return false;
            var code = key.substring(0, this._code_length);
            var handles = code === this._code;
            return handles;
        },

        _handle_children: function(key) {
            var handles = false;
            this._handling_provider = null;
            for (var i=0; i< this.providers.length; i++) {
                handles = this.providers[i].handles(key);
                if (handles) {
                    this._handling_provider = this.providers[i];
                    break;
                }
            }
            return handles;
        },

        /**
         * Get's value from this provider's source
         * @protected
         */
        _get: function(key) {
            var property = key.substring(this._code_length);
            var value = lang.getObject(property, false, this._get_source());
            return value;
        },

        /**
         * Finds out whether this or some of its children handles given key.
         */
        handles: function(key) {
            var handles = this._handles(key);
            handles = handles || this._handle_children(key);
            return handles;
        },

        /**
         * Gets value.
         *
         * @param {string|Object} Key or value
         * @param {Object} Alternate value
         */
        get: function(key, alternate) {

            var value = key;
            if (key !== undefined) {
                if (this._handles(key)) {
                    value = this._get(key);
                } else if(this._handle_children(key)) {
                    value = this._handling_provider.get(key);
                } else {
                    // Report invalid keys
                    if (typeof key === 'string' && key[0] === '@') {
                        window.console.warn('Using key as value:'+key);
                    }
                }
            }

            var ret = value || alternate;
            if (!ret && key && debug.provider_missing_value) {
                window.console.log('No value for:'+key);
            }

            if ((this.required_type && typeof ret !== this.required_type) ||
                    ret === null ||
                    ret === undefined){
                ret = this.null_value;
            }

            return ret;
        },

        /**
         * Finds object with attr_name === value in array defined by key.
         */
        find: function(key, attr_name, value) {

            var arr = this.get(key);
            if (!lang.isArrayLike(arr)) return null;

            for (var i=0; i<arr.length; i++) {
                if (arr[i][attr_name] === value) {
                    return arr[i];
                }
            }

            return null;
        },

        constructor: function(spec) {
            spec = spec || {};
            this.source = spec.source || {};
            this.path = spec.path || null;
            this.providers = spec.providers || [];
            if (spec.null_value !== undefined) {
                this.null_value = spec.null_value;
            }
            this.required_type = spec.required_type;
            if (spec.code) {
                this._set_code(spec.code);
            }
        }
    });

    return Provider;
});