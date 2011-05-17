/*  Authors:
 *    Endi Dewata <edewata@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
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

jQuery.ordered_map = jQuery.fn.ordered_map = function() {

    var that = {};

    /**
     * These variables can be read directly but should not be
     * modified directly. Use the provided methods instead.
     */
    that.keys = [];
    that.values = [];
    that.map = {};

    that.__defineGetter__('length', function() {
        return that.keys.length;
    });

    that.get = function(key) {
        return that.map[key];
    };

    that.put = function(key, value) {
        that.keys.push(key);
        that.values.push(value);
        that.map[key] = value;
    };

    that.remove = function(key) {

        var i = that.keys.indexOf(key);
        if (i<0) return null;

        that.keys.splice(i, 1);
        that.values.splice(i, 1);

        var value = that.map[key];
        delete that.map[key];

        return value;
    };

    that.empty = function() {
        that.keys = [];
        that.values = [];
        that.map = {};
    };

    return that;
};
