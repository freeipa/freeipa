/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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

module('ordered_map');

test("Testing $.ordered_map constructor.", function() {

    var test = $.ordered_map();

    strictEqual(test.length, 0, "Checking length.");
    deepEqual(test.keys, [], "Checking keys.");
    deepEqual(test.values, [], "Checking values.");
    deepEqual(test.map, {}, "Checking map.");
});

test("Testing $.ordered_map.put().", function() {

    var test = $.ordered_map();

    var key1 = 'key1';
    var value1 = 'value1';

    var key2 = 'key2';
    var value2 = 'value2';

    var map = {};
    map[key1] = value1;
    map[key2] = value2;

    test.put(key1, value1);
    test.put(key2, value2);

    strictEqual(test.length, 2, 'Checking length.');
    deepEqual(test.keys, [key1, key2], 'Checking keys.');
    deepEqual(test.values, [value1, value2], 'Checking values.');
    deepEqual(test.map, map, 'Checking map.');
});

test("Testing $.ordered_map.get().", function() {

    var test = $.ordered_map();

    var key1 = 'key1';
    var value1 = 'value1';

    var key2 = 'key2';
    var value2 = 'value2';

    var map = {};
    map[key1] = value1;
    map[key2] = value2;

    test.put(key1, value1);
    test.put(key2, value2);

    var result1 = test.get(key1);
    var result2 = test.get(key2);

    strictEqual(test.length, 2, 'Checking length.');
    deepEqual(test.keys, [key1, key2], 'Checking keys.');
    deepEqual(test.values, [value1, value2], 'Checking values.');
    deepEqual(test.map, map, 'Checking map.');
    strictEqual(result1, value1, 'Checking result 1.');
    strictEqual(result2, value2, 'Checking result 2.');
});

test("Testing $.ordered_map.remove().", function() {

    var test = $.ordered_map();

    var key1 = 'key1';
    var value1 = 'value1';

    var key2 = 'key2';
    var value2 = 'value2';

    var map = {};
    map[key2] = value2;

    test.put(key1, value1);
    test.put(key2, value2);

    var result1 = test.remove(key1);

    strictEqual(test.length, 1, 'Checking length.');
    deepEqual(test.keys, [key2], 'Checking keys.');
    deepEqual(test.values, [value2], 'Checking values.');
    deepEqual(test.map, map, 'Checking map.');
    strictEqual(result1, value1, 'Checking result.');
});

test("Testing $.ordered_map.empty().", function() {

    var test = $.ordered_map();

    var key1 = 'key1';
    var value1 = 'value1';

    var key2 = 'key2';
    var value2 = 'value2';

    test.put(key1, value1);
    test.put(key2, value2);

    test.empty();

    strictEqual(test.length, 0, 'Checking length.');
    deepEqual(test.keys, [], 'Checking keys.');
    deepEqual(test.values, [], 'Checking values.');
    deepEqual(test.map, {}, 'Checking map.');
});
