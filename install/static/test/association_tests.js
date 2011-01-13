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

module('associate');


test("Testing serial_associator().", function() {

    expect(10);

    var orig_ipa_cmd = IPA.cmd;

    var counter = 0;

    var params = {
        method: "add_member",
        pkey: "test",
        entity_name: "user",
        other_entity: "group"
    };

    params.values = ['user1', 'user2', 'user3'];

    IPA.cmd = function(name, args, options, win_callback, fail_callback, objname) {
        counter++;

        equals(
            name, params.method,
            "Checking IPA.cmd() parameter: method"
        );

        equals(
            objname, params.other_entity,
            "Checking IPA.cmd() parameter: object name"
        );

        equals(
            args[0], "user"+counter,
            "Checking IPA.cmd() parameter: primary key"
        );

        var response = {};
        win_callback(response);
        return 0;
    };

    params.on_success = function() {
        ok(true, "on_success() is invoked.");
    };

    var associator = serial_associator(params);
    associator.execute();

    IPA.cmd = orig_ipa_cmd;
});

test("Testing bulk_associator().", function() {

    expect(5);

    var orig_ipa_cmd = IPA.cmd;

    var counter = 0;

    var params = {
        method: "add_member",
        pkey: "test",
        entity_name: "user",
        other_entity: "group"
    };

    params.values = ['user1', 'user2', 'user3'];

    IPA.cmd = function(name, args, options, win_callback, fail_callback, objname) {
        counter++;

        equals(
            name, params.method,
            "Checking IPA.cmd() parameter: method"
        );

        equals(
            objname, params.entity_name,
            "Checking IPA.cmd() parameter: object name"
        );

        equals(
            args[0], params.pkey,
            "Checking IPA.cmd() parameter: primary key"
        );

        equals(
            options[params.other_entity], "user1,user2,user3",
            "Checking IPA.cmd() parameter: options[\""+params.other_entity+"\"]"
        );

        var response = {};
        win_callback(response);
        return 0;
    };

    params.on_success = function() {
        ok(true, "on_success() is invoked.");
    };

    var associator = bulk_associator(params);
    associator.execute();

    IPA.cmd = orig_ipa_cmd;
});
