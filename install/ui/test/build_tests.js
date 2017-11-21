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
        'dojo/_base/declare',
        'freeipa/_base/Builder',
        'freeipa/_base/Construct_registry',
        'freeipa/_base/Spec_mod',
        'freeipa/ipa',
        'freeipa/spec_util'
       ],
       function(declare, Builder, C_reg, Spec_mod, IPA, su) {  return function() {


QUnit.module('build');

QUnit.test('Testing builder', function(assert) {

    var simple_factory = function(spec) {

        var that = IPA.object();
        su.set(that, spec, 'foo', 'bar');
        return that;
    };

    var Simple_class = declare(null, {
        foo: 'bar',
        constructor: function(spec) {
            su.set(this, spec, 'foo');
        }
    });

    var b1 = new Builder({factory: simple_factory});
    var b2 = new Builder({ctor: Simple_class});

    var o1 = b1.build({});
    var o11 = b1.build({ foo: 'baz'});
    var o12 = b1.build(o11);

    var o2 = b2.build({});
    var o21 = b2.build({ foo: 'baz'});
    var o22 = b2.build(o21);

    var r1 = simple_factory({});
    var r11 = simple_factory({ foo: 'baz' });
    var r2 = new Simple_class({});
    var r21 = new Simple_class({ foo:'baz'});

    assert.deepEqual(o1, r1, 'Factory, default');
    assert.deepEqual(o11, r11, 'Factory, spec use');

    assert.deepEqual(o2, r2, 'Constructor, default');
    assert.deepEqual(o21, r21, 'Constructor, spec use');

    assert.strictEqual(o11, o12, 'Don\'t build built object - factory');
    assert.strictEqual(o21, o22, 'Don\'t build built object - constructor');

});

QUnit.test('Testing Spec_mod', function(assert) {

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

    assert.deepEqual(spec, ref, 'Complex Modification');

    spec = {
        a: [ 'a1', 'a2', 'a3' ]
    };
    var rules = [[ 'a', 'new', 1]];
    sm.add(spec, rules);

    assert.deepEqual(spec, { a: ['a1', 'new', 'a2', 'a3'] }, 'Add on position');
});

QUnit.test('Testing Construct registry', function(assert) {

    var undefined;

    var cr = new C_reg();

    // test simple ctor registration
    var ctor = declare([], {});
    cr.register('ctor', ctor);

    var ctor_cs = cr.get('ctor');
    assert.equal(ctor_cs.type, 'ctor', 'Ctor: Match type');
    assert.equal(ctor_cs.ctor, ctor, 'Ctor: Match ctor');
    assert.equal(ctor_cs.factory, undefined, 'Ctor: Match factory');
    assert.equal(ctor_cs.pre_ops.length, 0, 'Ctor: No pre_ops');
    assert.equal(ctor_cs.post_ops.length, 0, 'Ctor: No post_ops');

    // test simple factory registration
    var fac = function(){};
    cr.register('fac', fac);

    var fac_cs = cr.get('fac');
    assert.equal(fac_cs.type, 'fac', 'Factory: Match type');
    assert.equal(fac_cs.ctor, undefined, 'Factory: Match ctor');
    assert.equal(fac_cs.factory, fac, 'Factory: Match factory');
    assert.equal(fac_cs.pre_ops.length, 0, 'Factory: No pre_ops');
    assert.equal(fac_cs.post_ops.length, 0, 'Factory: No post_ops');


    // test complex registration

    var spec = { name: 'spec' };

    var cs = {
        type: 'complex',
        ctor: ctor,
        factory: fac, // for next test
        spec: spec
    };
    cr.register(cs);
    var complex_cs = cr.get('complex');
    assert.equal(complex_cs.type, 'complex', 'Complex: Match type');
    assert.equal(complex_cs.ctor, ctor, 'Complex: Match ctor');
    assert.equal(complex_cs.factory, fac, 'Complex: Match factory');
    assert.equal(complex_cs.pre_ops.length, 0, 'Complex: No pre_ops');
    assert.equal(complex_cs.post_ops.length, 0, 'Complex: No post_ops');
    assert.deepEqual(complex_cs.spec, spec, 'Complex: Match spec');

    // copy: new cs based on existing
    cr.copy('complex', 'copy', {}); // pure copy
    var copy_cs = cr.get('copy');
    assert.equal(copy_cs.type, 'copy', 'Copy: Match type');
    assert.equal(copy_cs.ctor, ctor, 'Copy: Match ctor');
    assert.equal(copy_cs.factory, fac, 'Copy: Match factory');
    assert.equal(copy_cs.pre_ops.length, 0, 'Copy: No pre_ops');
    assert.equal(copy_cs.post_ops.length, 0, 'Copy: No post_ops');
    assert.deepEqual(copy_cs.spec, spec, 'Copy: Match spec');

    // add post op and pre op to complex
    var op1 = function() {};
    var op2 = function() {};
    var op3 = function() {};
    var op4 = function() {};

    cr.register_pre_op('complex', op1);
    cr.register_pre_op('complex', op2, true /* first*/);
    assert.deepEqual(complex_cs.pre_ops, [op2, op1], 'Adding pre_ops');

    cr.register_post_op('complex', op3);
    cr.register_post_op('complex', op4, true);
    assert.deepEqual(complex_cs.post_ops, [op4, op3], 'Adding post_ops');


    // copy: altered
    var ctor2 = declare([], {});
    var fac2 = function() {};
    var op5 = function() {};
    var op6 = function() {};
    cr.copy('complex', 'copy2', {
        ctor: ctor2,
        factory: fac2,
        spec: {
            foo: 'bar'
        },
        pre_ops: [op5],
        post_ops: [op6]
    });
    var a_copy_cs = cr.get('copy2');

    assert.equal(a_copy_cs.type, 'copy2', 'Altered copy: Match type');
    assert.equal(a_copy_cs.ctor, ctor2, 'Altered copy: Match ctor');
    assert.equal(a_copy_cs.factory, fac2, 'Altered copy: Match factory');
    assert.deepEqual(a_copy_cs.spec, {
        name: 'spec',
        foo: 'bar'
    }, 'Altered copy: Match spec');
    assert.deepEqual(a_copy_cs.pre_ops, [op2, op1, op5], 'Altered copy: Match pre_ops');
    assert.deepEqual(a_copy_cs.post_ops, [op4, op3, op6], 'Altered copy: Match post_ops');
});


};});
