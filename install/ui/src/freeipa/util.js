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
        './text'
    ],
    function(lang, text) {

    function equals_obj_def(a, b, options) {
        var same = true;
        var checked = {};

        var check_same = function(a, b, skip) {

            var same = true;
            skip = skip || {};

            for (var key in a) {
                if (a.hasOwnProperty(key) && !(key in skip)) {

                    var va = a[key];
                    var vb = b[key];

                    if (!equals(va, vb, options)) {
                        same = false;
                        skip[a] = true;
                        break;
                    }
                }
            }
            return same;
        };

        same = check_same(a,b, checked);
        same = same && check_same(b,a, checked);
        return same;
    }

    function equals_obj(a, b, options) {

        if (options.comparator) {
            return options.comparator(a, b, options);
        } else {
            return equals_obj_def(a, b, options);
        }
    }

    function equals_array(a1, b1, options) {

        var a = a1,
            b = b1;

        if (!a || !b) return false;

        if (a1.length !== b1.length) return false;

        if (options.unordered) {
            a = a1.slice(0);
            b = b1.slice(0);
            a.sort();
            b.sort();
        }

        for (var i=0; i<a.length; i++) {
            if (!equals(a[i], b[i], options)) return false;
        }

        return true;
    }

    function equals(a, b, options) {
        var a_t = typeof a;
        var b_t = typeof b;
        options = options || {};

        if (a_t !== b_t) return false;
        if (a === b) return true;

        if (['string', 'number', 'function', 'boolean',
             'undefined'].indexOf(a_t) > -1) {
              return false;
        } else if (a === null || b === null) {
            return false;
        } else if (lang.isArray(a)) {
            return equals_array(a, b, options);
        } else if (a instanceof Date) {
            return a.getTime() === b.getTime();
        } else { // objects
            return equals_obj(a, b, options);
        }
    }

    function is_empty(value) {
        var empty = false;

        if (value === null || value === undefined) empty = true;

        if (lang.isArray(value)) {
            empty = empty || value.length === 0 ||
                    (value.length === 1) && (value[0] === '');
        } else if (typeof value === 'object') {
            var has_p = false;
            for (var p in value) {
                if (value.hasOwnProperty(p)) {
                    has_p = true;
                    break;
                }
            }
            empty = !has_p;
        } else  if (value === '') empty = true;

        return empty;
    }

    function dirty(value, pristine, options) {

        // check for empty value: null, [''], '', []
        var orig_empty = is_empty(pristine);
        var new_empty= is_empty(value);
        if (orig_empty && new_empty) return false;
        if (orig_empty != new_empty) return true;

        // strict equality - checks object's ref equality, numbers, strings
        if (value === pristine) return false;

        return !equals(value, pristine, options);
    }

    function format_single(formatter, value, error_text, method) {
        var val = value,
            ok = true,
            msg = null;
        try {
            if (method === 'format') {
                val = formatter.format(val);
            } else {
                val = formatter.parse(val);
            }
        } catch (e) {
            if (e.reason !== method) throw e;
            ok = false;
            value = e.value;
            msg = e.message || error_text;
        }
        return {
            ok: ok,
            value: val,
            message: msg
        };
    }

    function format_core(formatter, value, error_text, method) {

        if (!formatter) return { ok: true, value: value };
        if (lang.isArray(value)) {
            var res = {
                ok: true,
                value: [],
                messages: []
            };
            for (var i=0, l=value.length; i<l; i++) {
                var single_res = format_single(formatter, value[i], error_text, method);
                res.ok = res.ok && single_res.ok;
                res.value[i] =single_res.value;
                res.messages[i] = single_res.message;
                if (!res.ok) {
                    if (l > 1) res.message = error_text;
                    else res.message = res.messages[0];
                }
            }
            return res;
        } else {
            return format_single(formatter, value, error_text, method);
        }
    }

    function format(formatter, value, error_text) {

        var err = error_text || text.get('@i18n:widget.validation.format');
        return format_core(formatter, value, err, 'format');
    }

    function parse(formatter, value, error_text) {

        var err = error_text || text.get('@i18n:widget.validation.parse');
        return format_core(formatter, value, err, 'parse');
    }

    function normalize_value(value) {

        if (!(value instanceof Array)) {
            value = value !== undefined ? [value] : [];
        }
        return value;
    }

    function emit_delayed(target, type, event, delay) {

        delay = delay || 0;
        window.setTimeout(function() {
            target.emit(type, event);
        }, 0);
    }

    function beautify_message(message) {
        var els = [];
        var lines = message.split(/\n/g);
        var line_span;
        for (var i=0,l=lines.length; i<l; i++) {
            if (lines[i].charAt(0) == '\t') {
                line_span = $('<p />', {
                    'class': 'error-message-hinted',
                    text: lines[i].substr(1)
                });
                els.push(line_span);
            } else {
                line_span = $('<p />', {
                    text: lines[i]
                });
                els.push(line_span);
            }
        }
        return els;
    }

    function get_val_from_dn(dn, pos) {
        if (!dn) return '';
        pos = pos === undefined ? 0 : pos;
        var val = dn.split(',')[pos].split('=')[1];
        return val;
    }

    /**
     * Module with utility functions
     * @class
     * @singleton
     */
    var util = {

        /**
         * Checks if two variables have equal value
         *
         * - `string`, `number`, `function`, `boolean`, `null`,
         *   `undefined` are compared with strict equality
         * - 'object' and arrays are compared by values
         *
         * Available options:
         *
         * - `unordered` - boolean, sort arrays before value comparison. Does
         *                 not modify original values.
         * - `comparator`- function(a,b), returns bool - custom object comparator
         *
         * @param {Mixed} a
         * @param {Mixed} b
         * @param {String[]} [options]
         * @return {boolean} `a` and `b` are value-equal
         */
        equals: equals,

        /**
         * Check if value is empty.
         *
         * True when:
         *
         * - value is undefined or `null` or `''`
         * - value is empty Array
         * - value is Array with an empty string (`''`)
         * - value is empty Object- `{}`
         * @param value - value to check
         * @return {boolean}
         */
        is_empty: is_empty,

        /**
         * Special kind of negative `equals` where variants of `empty_value` are
         * considered same.
         *
         * @param {Mixed} value New value
         * @param {Mixed} pristine Pristine value
         * @param {String[]} [options] control options, same as in `equals`
         * @return {boolean} `value` and `pristine` differs
         */
        dirty: dirty,

        /**
         * Format value or values using a formatter
         *
         * Output format for single values:
         *
         *      {
         *          ok: true|false,
         *          value: null | formatted value,
         *          message: null | string
         *      }
         *
         * Output form for array:
         *
         *      {
         *          ok: true|false,
         *          value: array of formatted values,
         *          messages: array of error messages
         *          message: null | string
         *      }
         *
         * @param {IPA.formatter} formatter
         * @param {Mixed} value
         * @param {string} error Default error message
         * @return {Object}
         */
        format: format,

        /**
         * Basically the same as format method, just uses formatter's `parse`
         * method instead of `format` method.
         *
         * @param {IPA.formatter} formatter
         * @param {Mixed} value
         * @param {string} error Default error message
         * @return {Object}
         */
        parse: parse,

        /**
         * Encapsulates value into array if it's not already an array.
         *
         * @param {Mixed} value
         * @returns {Array} normalized value
         */
        normalize_value: normalize_value,

        /**
         * Emit delayed event
         *
         * Uses timer in order to wait for current processing to finish.
         *
         * @param {Evented} object Source object which emits the event
         * @param {String} type Name of the event to emit
         * @param {Object} event Event object
         * @param {Number} [delay=0]
         */
        emit_delayed: emit_delayed,

        /**
         * Beautify message
         *
         * Converts text value into array of HTML <p> elements. One additional
         * paragraph for each line break.
         *
         * Multi-lined text may contain TAB character as first char of the line
         * to hint at marking the whole line differently.
         * @param {string} text
         * @return {Array} array of jQuery elements
         */
        beautify_message: beautify_message,

        /**
         * Return value of part of DN on specified position
         * @param {string} dn Distinguished name
         * @param {Number} [position=0] Zero-based DN part position
         * @return {string}
         */
        get_val_from_dn: get_val_from_dn
    };

    return util;
});
