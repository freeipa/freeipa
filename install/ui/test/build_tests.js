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

define([
        'freeipa/_base/Spec_mod'],
       function(Spec_mod) {  return function() {


module('build',{

    setup: function() {
    },
    teardown: function() {
    }
});

test('Testing builder', function() {
});

test('Testing Spec_mod', function() {

    var sm = new Spec_mod();

    var spec = {
        foo: {
            arr1: [
                { name: 'i1', a: 'b' },
                { name: 'i2', a: 'b' },
                { name: 'i3', a: 'c' },
                { name: 'i4', a: 'c' },
                { name: 'i5', a: 'a' }
            ],
            arr2: ['item1']
        },
        baz: {
            bar: 'a'
        },
        bar: 'b'
    };

    var diff = {
        $add: [
            ['foo.arr1', { name: 'foo', a: 'c' }],
            ['foo.arr2', 'item2'],
            ['foo.arr2', { name: 'foo' }],
            ['arr3', 'a'] //creates new array
        ],
        $del: [
            [
                'foo.arr1',
                [
                    { name: 'i1' }, //match
                    { a: 'c'}, // 2 matches
                    { name: 'i2', a:'c' }, //no match
                    { name: 'i5', a:'a' } // match
                ]
            ],
            [ 'foo.arr2', ['item1'] ] //match
        ],
        $set: [
            [ 'arr4', ['b'] ], // new array in spec
            [ 'baz.bar', 'c'], //overwrite 'a'
            [ 'baz.baz.baz', 'a'], // new property
            [ 'bar', { foo: 'baz' }] // replace string by object
        ]
    };

    var ref = {
        foo: {
            arr1: [
                { name: 'i2', a: 'b' },
                { name: 'foo', a: 'c'}
            ],
            arr2: [
                'item2', { name: 'foo' }
            ]
        },
        arr3: [ 'a' ],
        baz: {
            bar: 'c',
            baz: { baz: 'a' }
        },
        bar: { foo: 'baz' },
        arr4: ['b']
    };

    sm.mod(spec, diff);

    deepEqual(spec, ref, 'Complex Modification');

    spec = {
        a: [ 'a1', 'a2', 'a3' ]
    };
    var rules = [[ 'a', 'new', 1]];
    sm.add(spec, rules);

    deepEqual(spec, { a: ['a1', 'new', 'a2', 'a3'] }, 'Add on position');
});



};});