/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2012 Red Hat
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

var old;

module('utils',{

    setup: function() {
        old = IPA.messages;
        IPA.messages = {
            widget: {
                validation: {
                    integer: "",
                    decimal: "",
                    min_value: "",
                    max_value: "",
                    pattern_errmsg: ""
                }
            }
        };
    },
    teardown: function() {
        IPA.messages = old;
    }
});

test('Testing metadata validator', function() {

    // using strings as values because it is an output of inputs

    var validator = IPA.build({
        factory: IPA.metadata_validator
    });

    var metadata = {
        type: 'int',
        maxvalue: 300,
        minvalue: 30
    };

    var context = { metadata: metadata };

    var value;

    value = "50";
    ok(validator.validate(value, context).valid, 'Checking lower maximun, alphabetically higher');

    value = "200";
    ok(validator.validate(value, context).valid, 'Checking higher minimum, alphabetically lower');

    value = "29";
    ok(!validator.validate(value, context).valid, 'Checking below minimum');

    value = "301";
    ok(!validator.validate(value, context).valid, 'Checking above maximum');

    context.metadata.minvalue = 0;
    value = "-1";
    ok(!validator.validate(value, context).valid, 'Checking zero minimum - below');
    value = "0";
    ok(validator.validate(value, context).valid, 'Checking zero minimum - above');
    value = "1";
    ok(validator.validate(value, context).valid, 'Checking zero minimum - same');

    context.metadata = {
        type: 'int',
        maxvalue: "",
        minvalue: ""
    };

    ok(validator.validate(value, context).valid, 'Checking empty strings as boundaries');

    context.metadata = {
        type: 'int',
        maxvalue: null,
        minvalue: null
    };
    ok(validator.validate(value, context).valid, 'Checking null as boundaries');

    context.metadata = {
        type: 'int',
        maxvalue: undefined,
        minvalue: undefined
    };
    ok(validator.validate(value, context).valid, 'Checking undefined as boundaries');

    context.metadata = {
        type: 'Decimal',
        maxvalue: "10.333",
        minvalue: "-10.333"
    };

    value = "10.333";
    ok(validator.validate(value, context).valid, 'Decimal: checking maximum');
    value = "10.3331";
    ok(!validator.validate(value, context).valid, 'Decimal: checking maximum - invalid');

    value = "-10.333";
    ok(validator.validate(value, context).valid, 'Decimal: checking minimum');
    value = "-10.3331";
    ok(!validator.validate(value, context).valid, 'Decimal: checking minimum - invalid');
});

test('Testing IPA.defined', function() {

    // positive
    same(IPA.defined({}), true, 'Object');
    same(IPA.defined(0), true, 'Zero number');
    same(IPA.defined(1), true, 'Some number');
    same(IPA.defined(false), true, 'false');
    same(IPA.defined(true), true, 'true');
    same(IPA.defined(function(){}), true, 'function');
    same(IPA.defined(''), true, 'Empty string - not checking');

    // negative
    same(IPA.defined('', true), false, 'Empty string - checking');
    same(IPA.defined(undefined), false, 'undefined');
    same(IPA.defined(null), false, 'null');
});