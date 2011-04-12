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

    var orig_ipa_command = IPA.command;

    var counter = 0;

    var params = {
        method: 'add_member',
        pkey: 'test',
        entity_name: 'user',
        other_entity: 'group'
    };

    params.values = ['user1', 'user2', 'user3'];

    IPA.command = function(spec) {

        var that = orig_ipa_command(spec);

        that.execute = function() {
            counter++;

            equals(
                that.entity, params.other_entity,
                'Checking IPA.command() parameter: entity'
            );

            equals(
                that.method, params.method,
                'Checking IPA.command() parameter: method'
            );

            equals(
                that.args[0], 'user'+counter,
                'Checking IPA.command() parameter: primary key'
            );

            that.on_success();
        };

        return that;
    };

    params.on_success = function() {
        ok(true, "on_success() is invoked.");
    };

    var associator = IPA.serial_associator(params);
    associator.execute();

    IPA.command = orig_ipa_command;
});

test("Testing bulk_associator().", function() {

    expect(5);

    var orig_ipa_command = IPA.command;

    var counter = 0;

    var params = {
        method: "add_member",
        pkey: "test",
        entity_name: "user",
        other_entity: "group"
    };

    params.values = ['user1', 'user2', 'user3'];

    IPA.command = function(spec) {

        var that = orig_ipa_command(spec);

        that.execute = function() {
            counter++;

            equals(
                that.entity, params.entity_name,
                'Checking IPA.command() parameter: entity'
            );

            equals(
                that.method, params.method,
                'Checking IPA.command() parameter: method'
            );

            equals(
                that.args[0], params.pkey,
                'Checking IPA.command() parameter: primary key'
            );

            equals(
                that.options[params.other_entity], 'user1,user2,user3',
                'Checking IPA.command() parameter: options[\""+params.other_entity+"\"]'
            );

            that.on_success();
        };

        return that;
    };

    params.on_success = function() {
        ok(true, "on_success() is invoked.");
    };

    var associator = IPA.bulk_associator(params);
    associator.execute();

    IPA.command = orig_ipa_command;
});
