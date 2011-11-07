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

module('association');


test("Testing serial_associator().", function() {

    expect(11);

    var orig_ipa_batch_command = IPA.batch_command;

    var user = IPA.entity({ name: 'user' });
    var group = IPA.entity({ name: 'group' });

    var params = {
        method: 'add_member',
        pkey: 'test',
        entity: user,
        other_entity: group
    };

    params.values = ['user1', 'user2', 'user3'];

    IPA.batch_command = function(spec) {

        var that = orig_ipa_batch_command(spec);

        that.execute = function() {
            equals(that.commands.length, params.values.length,
                   'Checking IPA.batch_command command count');

            var i, command;

            for(i=0; i < params.values.length; i++) {
                command = that.commands[i];

                equals(
                    command.entity, params.other_entity.name,
                    'Checking IPA.command() parameter: entity');

                equals(
                    command.method, params.method,
                    'Checking IPA.command() parameter: method');

                equals(
                    command.args[0], 'user'+(i+1),
                    'Checking IPA.command() parameter: primary key');
            }

            that.on_success({});
        };

        return that;
    };

    params.on_success = function() {
        ok(true, "on_success() is invoked.");
    };

    var associator = IPA.serial_associator(params);
    associator.execute();

    IPA.batch_command = orig_ipa_batch_command;
});

test("Testing bulk_associator().", function() {

    expect(4);

    var orig_ipa_command = IPA.command;

    var counter = 0;

    var user = IPA.entity({ name: 'user' });
    var group = IPA.entity({ name: 'group' });

    var params = {
        method: 'add_member',
        pkey: 'test',
        entity: user,
        other_entity: group
    };

    params.values = ['user1', 'user2', 'user3'];

    IPA.command = function(spec) {

        var that = orig_ipa_command(spec);

        that.execute = function() {
            counter++;

            equals(
                that.method, params.method,
                'Checking IPA.command() parameter: method');

            equals(
                that.args[0], params.pkey,
                'Checking IPA.command() parameter: primary key');

            equals(
                that.options[params.other_entity.name], 'user1,user2,user3',
                'Checking IPA.command() parameter: options[\""+params.other_entity+"\"]');

            that.on_success({});
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
