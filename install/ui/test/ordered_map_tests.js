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

 define(['freeipa/jquery'], function($) {
    return function() {
QUnit.module('ordered_map');

QUnit.test("Testing $.ordered_map constructor.", function(assert) {

    var test = $.ordered_map();

    assert.strictEqual(test.length, 0, "Checking length.");
    assert.deepEqual(test.keys, [], "Checking keys.");
    assert.deepEqual(test.values, [], "Checking values.");
});

QUnit.test("Testing $.ordered_map.put().", function(assert) {

    var test = $.ordered_map();

    var key1 = 'key1';
    var value1 = 'value1';

    var key2 = 'key2';
    var value2 = 'value2';

    var key3 = 'key3';
    var value3 = 'value3';

    var key4 = 'key4';
    var value4 = 'value4';

    var key5 = 'key5';
    var value5 = 'value5';

    var key6 = 'key6';
    var value6 = 'value6';

    var key7 = 'key7';
    var value7 = 'value7';

    var key8 = 'key8';
    var value8 = 'value8';

    var map = {};
    map[key1] = value1;
    map[key2] = value2;
    map[key3] = value3;
    map[key4] = value4;
    map[key5] = value5;
    map[key6] = value6;
    map[key7] = value7;
    map[key8] = value8;

    test.put(key1, value1);
    test.put(key2, value2);

    test.put(key3, value3, 1); //put before key2
    test.put(key4, value4, 0); //put at beginning
    test.put(key5, value5, -2); //put at beginning
    test.put(key6, value6, 5); //put at end
    test.put(key7, value7, 100); //put at end
    test.put(key8, value8, 'foobar'); //put at end

    assert.strictEqual(test.length, 8, 'Checking length.');
    assert.deepEqual(test.keys, [key5, key4, key1, key3, key2, key6, key7, key8], 'Checking keys.');
    assert.deepEqual(test.values, [value5, value4, value1, value3, value2, value6, value7, value8], 'Checking values.');
});

QUnit.test("Testing $.ordered_map.get().", function(assert) {

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

    assert.strictEqual(test.length, 2, 'Checking length.');
    assert.deepEqual(test.keys, [key1, key2], 'Checking keys.');
    assert.deepEqual(test.values, [value1, value2], 'Checking values.');
    assert.strictEqual(result1, value1, 'Checking result 1.');
    assert.strictEqual(result2, value2, 'Checking result 2.');
});

QUnit.test("Testing $.ordered_map.remove().", function(assert) {

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

    assert.strictEqual(test.length, 1, 'Checking length.');
    assert.deepEqual(test.keys, [key2], 'Checking keys.');
    assert.deepEqual(test.values, [value2], 'Checking values.');
    assert.strictEqual(result1, value1, 'Checking result.');
});

QUnit.test("Testing $.ordered_map.empty().", function(assert) {

    var test = $.ordered_map();

    var key1 = 'key1';
    var value1 = 'value1';

    var key2 = 'key2';
    var value2 = 'value2';

    test.put(key1, value1);
    test.put(key2, value2);

    test.empty();

    assert.strictEqual(test.length, 0, 'Checking length.');
    assert.deepEqual(test.keys, [], 'Checking keys.');
    assert.deepEqual(test.values, [], 'Checking values.');
});

};});
