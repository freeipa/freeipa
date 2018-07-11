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

define([
        'freeipa/ipa',
        'freeipa/jquery',
        'freeipa/datetime',
        'freeipa/util',
        'freeipa/field',
        'freeipa/widget'],
       function(IPA, $, datetime, util) {  return function() {

var old;

QUnit.module('utils');

QUnit.test('Testing metadata validator', function(assert) {

    // using strings as values because it is an output of inputs

    var validator = IPA.build({
        $factory: IPA.metadata_validator
    });

    var metadata = {
        type: 'int',
        maxvalue: 300,
        minvalue: 30
    };

    var context = { metadata: metadata };

    var value;

    value = "50";
    assert.ok(validator.validate(value, context).valid, 'Checking lower maximun, alphabetically higher');

    value = "200";
    assert.ok(validator.validate(value, context).valid, 'Checking higher minimum, alphabetically lower');

    value = "29";
    assert.ok(!validator.validate(value, context).valid, 'Checking below minimum');

    value = "301";
    assert.ok(!validator.validate(value, context).valid, 'Checking above maximum');

    context.metadata.minvalue = 0;
    value = "-1";
    assert.ok(!validator.validate(value, context).valid, 'Checking zero minimum - below');
    value = "0";
    assert.ok(validator.validate(value, context).valid, 'Checking zero minimum - above');
    value = "1";
    assert.ok(validator.validate(value, context).valid, 'Checking zero minimum - same');

    context.metadata = {
        type: 'int',
        maxvalue: "",
        minvalue: ""
    };

    assert.ok(validator.validate(value, context).valid, 'Checking empty strings as boundaries');

    context.metadata = {
        type: 'int',
        maxvalue: null,
        minvalue: null
    };
    assert.ok(validator.validate(value, context).valid, 'Checking null as boundaries');

    context.metadata = {
        type: 'int',
        maxvalue: undefined,
        minvalue: undefined
    };
    assert.ok(validator.validate(value, context).valid, 'Checking undefined as boundaries');

    context.metadata = {
        type: 'Decimal',
        maxvalue: "10.333",
        minvalue: "-10.333"
    };

    value = "10.333";
    assert.ok(validator.validate(value, context).valid, 'Decimal: checking maximum');
    value = "10.3331";
    assert.ok(!validator.validate(value, context).valid, 'Decimal: checking maximum - invalid');

    value = "-10.333";
    assert.ok(validator.validate(value, context).valid, 'Decimal: checking minimum');
    value = "-10.3331";
    assert.ok(!validator.validate(value, context).valid, 'Decimal: checking minimum - invalid');
});

QUnit.test('Testing IPA.defined', function(assert) {

    // positive
    assert.deepEqual(IPA.defined({}), true, 'Object');
    assert.deepEqual(IPA.defined(0), true, 'Zero number');
    assert.deepEqual(IPA.defined(1), true, 'Some number');
    assert.deepEqual(IPA.defined(false), true, 'false');
    assert.deepEqual(IPA.defined(true), true, 'true');
    assert.deepEqual(IPA.defined(function(){}), true, 'function');
    assert.deepEqual(IPA.defined(''), true, 'Empty string - not checking');

    // negative
    assert.deepEqual(IPA.defined('', true), false, 'Empty string - checking');
    assert.deepEqual(IPA.defined(undefined), false, 'undefined');
    assert.deepEqual(IPA.defined(null), false, 'null');
});

QUnit.test('Testing util.equals', function(assert) {

    assert.ok(util.equals([], []), 'Empty Arrays');
    assert.ok(util.equals([1, "a", false, true], [1, "a", false, true]), 'Arrays');
    assert.ok(util.equals(true, true), 'Boolean: true');
    assert.ok(util.equals(false, false), 'Boolean: false');
    assert.ok(!util.equals(true, false), 'Negative: boolean');
    assert.ok(!util.equals(false, true), 'Negative: boolean');
    assert.ok(util.equals("abc", "abc"), 'Positive: strings');
    assert.ok(!util.equals("abc", "aBC"), 'Negative: string casing');
    assert.ok(util.equals(1, 1), 'Positive: number');
    assert.ok(util.equals(1.0, 1), 'Positive: number');
    assert.ok(util.equals(2.2, 2.2), 'Positive: number');

    assert.ok(!util.equals([], [""]), 'Negative: empty array');
});

QUnit.test('Testing datetime', function(assert) {

    var valid = [
        // [format, str, data, utc, output]
        [ '${YYYY}${MM}${DD}${HH}${mm}${ss}Z', '20140114175402Z', [ 2014, 1, 14, 17, 54, 2], true ],
        [ '${YYYY}-${MM}-${DD}T${HH}:${mm}:${ss}Z', '2014-01-14T17:54:02Z', [ 2014, 1, 14, 17, 54, 2], true ],
        [ '${YYYY}-${MM}-${DD} ${HH}:${mm}:${ss}Z', '2014-01-14 17:54:02Z', [ 2014, 1, 14, 17, 54, 2], true ],
        [ '${YYYY}-${MM}-${DD}T${HH}:${mm}Z', '2014-01-14T17:54Z', [ 2014, 1, 14, 17, 54, 0], true ],
        [ '${YYYY}-${MM}-${DD} ${HH}:${mm}Z', '2014-01-14 17:54Z', [ 2014, 1, 14, 17, 54, 0], true ],
        [ '${YYYY}-${MM}-${DD}', '2014-01-14', [ 2014, 1, 14, 0, 0, 0], true ],

        // allow overflows?
        // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/setUTCFullYear
        [ '${YYYY}-${MM}-${DD}', '2014-01-32', [ 2014, 2, 1, 0, 0, 0], true, '2014-02-01' ],
        [ '${YYYY}-${MM}-${DD}', '2014-02-30', [ 2014, 3, 2, 0, 0, 0], true, '2014-03-02' ],
        [ '${YYYY}-${MM}-${DD}', '2014-15-10', [ 2015, 3, 10, 0, 0, 0], true, '2015-03-10' ],

        // local time
        [ '${YYYY}-${MM}-${DD}T${HH}:${mm}:${ss}', '2014-01-14T17:54:13', [ 2014, 1, 14, 17, 54, 13], false ],
        [ '${YYYY}-${MM}-${DD} ${HH}:${mm}:${ss}', '2014-01-14 17:54:13', [ 2014, 1, 14, 17, 54, 13], false ],
        [ '${YYYY}-${MM}-${DD}T${HH}:${mm}', '2014-01-14T17:54', [ 2014, 1, 14, 17, 54, 0], false ],
        [ '${YYYY}-${MM}-${DD} ${HH}:${mm}', '2014-01-14 17:54', [ 2014, 1, 14, 17, 54, 0], false ]
    ];
    var invalid = [
        // [str, utc]
        ['2014-01-14T12:01:00', true],
        ['2014-01-14T12:01', true],
        ['2014-01-14T12', true],
        ['2014-01-14T12Z', true],
        ['2014-01-14TZ', true],


        ['2014-01-14 17:54:00', true],
        ['2014-01-14 17:54', true],
        ['2014-01-14 17', true],
        ['2014-01-14 17Z', true],
        ['2014-01-14Z', true],

        ['2014-01-14X17:54:00Z', true],
        ['20140114175400', false]
    ];
    var i, l;

    function test_valid(format, str, data, utc, output) {
        datetime.allow_local = !utc;
        var d = data;

        var expected = new Date();
        if (utc) {
            expected.setUTCFullYear(d[0], d[1]-1, d[2]);
            expected.setUTCHours(d[3], d[4], d[5], 0); // set ms to 0
        } else {
            expected.setFullYear(d[0], d[1]-1, d[2]);
            expected.setHours(d[3], d[4], d[5], 0); // set ms to 0
        }

        var parsed = datetime.parse(str);

        assert.ok(parsed, "Parse successful: "+str);
        if (!parsed) return; // don't die for other tests
        assert.strictEqual(parsed.getTime(), expected.getTime(), "Valid date: "+str);

        var formatted = datetime.format(parsed, format, !utc);
        expected = output || str;
        assert.strictEqual(formatted, expected, "Format: "+format);
    }

    function test_invalid(str, utc) {
        datetime.allow_local = !utc;
        var parsed = datetime.parse(str);
        assert.strictEqual(parsed, null, "Parse invalid date: "+str);
    }

    for (i=0, l=valid.length; i < l; i++) {
        test_valid(valid[i][0], valid[i][1], valid[i][2], valid[i][3], valid[i][4]);
    }

    for (i=0, l=invalid.length; i < l; i++) {
        test_invalid(invalid[i][0], invalid[i][1]);
    }
});

};});
