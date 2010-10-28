/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

test("Testing serial_associate().", function() {

    expect(10);

    var orig_ipa_cmd = ipa_cmd;

    var counter = 0;

    var form = {
        method: "add_member",
        pkey: "test",
        oneObj: "user",
        manyObj: "group"
    };

    var manyObjPkeys = ['user1', 'user2', 'user3'];

    ipa_cmd = function(name, args, options, win_callback, fail_callback, objname) {
        counter++;

        equals(
            name, form.method,
            "Checking ipa_cmd() parameter: method"
        );

        equals(
            objname, form.manyObj,
            "Checking ipa_cmd() parameter: object name"
        );

        equals(
            args[0], "user"+counter,
            "Checking ipa_cmd() parameter: primary key"
        );

        var response = {};
        win_callback(response);
        return 0;
    };

    var on_success = function() {
        ok(true, "on_success() is invoked.");
    };

    var associator = serial_associate(form, manyObjPkeys, on_success);
    //associator.associateNext();

    ipa_cmd = orig_ipa_cmd;
});

test("Testing BulkAssociator().", function() {

    expect(5);

    var orig_ipa_cmd = ipa_cmd;

    var counter = 0;

    var form = {
        method: "add_member",
        pkey: "test",
        oneObj: "user",
        manyObj: "group"
    };

    var manyObjPkeys = ['user1', 'user2', 'user3'];

    ipa_cmd = function(name, args, options, win_callback, fail_callback, objname) {
        counter++;

        equals(
            name, form.method,
            "Checking ipa_cmd() parameter: method"
        );

        equals(
            objname, form.oneObj,
            "Checking ipa_cmd() parameter: object name"
        );

        equals(
            args[0], form.pkey,
            "Checking ipa_cmd() parameter: primary key"
        );

        equals(
            options[form.manyObj], "user1,user2,user3",
            "Checking ipa_cmd() parameter: options[\""+form.manyObj+"\"]"
        );

        var response = {};
        win_callback(response);
        return 0;
    };

    var on_success = function() {
        ok(true, "on_success() is invoked.");
    };

    var associator = bulk_associate(form, manyObjPkeys, on_success);
    //associator.associateNext();

    ipa_cmd = orig_ipa_cmd;
});
