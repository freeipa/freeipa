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
        'freeipa/builder',
        'freeipa/FieldBinder',
        'freeipa/widget',
        'freeipa/field',
        'freeipa/entity'
       ],
       function(builder, FieldBinder, mod_widget, mod_field) {  return function() {


QUnit.module('binding');


/**
 * This test tests two-way binding between one field and two widgets
 *
 * All three have to have the same value.
 */
QUnit.test('Testing two way bindings', function(assert) {

    function test_same_value(value, dirty) {
        if (dirty) {
            assert.ok(field.dirty, "Field is dirty")
        } else {
            assert.ok(!field.dirty, "Field is not dirty")
        }
        assert.deepEqual(widget1.get_value(), value, 'Testing Widget 1 value');
        assert.deepEqual(widget2.get_value(), value, 'Testing Widget 2 value');
        assert.deepEqual(field.get_value(), value, 'Testing Field value');
    }

    mod_widget.register();
    mod_field.register();

    var field = builder.build('field', 'f1');
    var widget1 = builder.build('widget', 'w1');
    var widget2 = builder.build('widget', 'w2');

    // is it a bug that widgets needs to be created?
    var c1 = $("<div/>");
    var c2 = $("<div/>");
    widget1.create(c1);
    widget2.create(c2);

    var b1 = new FieldBinder(field, widget1);
    b1.bind();

    var b2 = new FieldBinder(field, widget2);
    b2.bind();

    test_same_value([], false); // initial is empty

    // set pristine value to field
    var value = ['val1'];
    field.set_value(value, true); // pristine  = true
    test_same_value(value, false);

    // set value from widget 1
    var value2 = ['val2'];
    widget1.set_value(value2);
    test_same_value(value2, true);

    // set value from widget 2
    var value3 = ['val3'];
    widget1.set_value(value3);
    test_same_value(value3, true);

    // reset the field, all should have original value
    field.reset();
    test_same_value(value, false);

    // make the field dirty again and click on undo button
    widget1.set_value(value2);
    test_same_value(value2, true);
    widget1.get_undo().click();
    test_same_value(value, false);

    // set new value to field
    field.set_value(value2);
    test_same_value(value2, true);

    // unbind the fields, set different value to each
    b1.unbind();
    b2.unbind();
    field.reset();
    widget2.set_value(value3);
    assert.deepEqual(widget1.get_value(), value2, 'Testing Widget 1 value');
    assert.deepEqual(widget2.get_value(), value3, 'Testing Widget 2 value');
    assert.deepEqual(field.get_value(), value, 'Testing Field value');

    // bind again
    b1.bind();
    b2.bind();
    field.set_value(value2);
    test_same_value(value2, true);
});


};});
