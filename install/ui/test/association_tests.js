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


define([
    'freeipa/ipa',
    'freeipa/jquery',
    'freeipa/rpc',
    'freeipa/association',
    'freeipa/entity'
], function(IPA, $, rpc)
    { return function() {

QUnit.module('association');


QUnit.test("Testing serial_associator().", function(assert) {

    assert.expect(11);

    var orig_ipa_batch_command = rpc.batch_command;

    var user = IPA.entity({ name: 'user' });
    var group = IPA.entity({ name: 'group' });

    var params = {
        method: 'add_member',
        pkey: 'test',
        entity: user,
        other_entity: group
    };

    params.values = ['user1', 'user2', 'user3'];

    rpc.batch_command = function(spec) {

        var that = orig_ipa_batch_command(spec);

        that.execute = function() {
            assert.equal(that.commands.length, params.values.length,
                   'Checking rpc.batch_command command count');

            var i, command;

            for(i=0; i < params.values.length; i++) {
                command = that.commands[i];

                assert.equal(
                    command.entity, params.other_entity.name,
                    'Checking rpc.command() parameter: entity');

                assert.equal(
                    command.method, params.method,
                    'Checking rpc.command() parameter: method');

                assert.equal(
                    command.args[0], 'user'+(i+1),
                    'Checking rpc.command() parameter: primary key');
            }

            that.on_success({});
        };

        return that;
    };

    params.on_success = function() {
        assert.ok(true, "on_success() is invoked.");
    };

    var associator = IPA.serial_associator(params);
    associator.execute();

    rpc.batch_command = orig_ipa_batch_command;
});

QUnit.test("Testing bulk_associator().", function(assert) {

    assert.expect(4);

    var orig_ipa_command = rpc.command;

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

    rpc.command = function(spec) {

        var that = orig_ipa_command(spec);

        that.execute = function() {
            counter++;

            assert.equal(
                that.method, params.method,
                'Checking rpc.command() parameter: method');

            assert.equal(
                that.args[0], params.pkey,
                'Checking rpc.command() parameter: primary key');

            assert.equal(
                that.options[params.other_entity.name], 'user1,user2,user3',
                'Checking rpc.command() parameter: options[\""+params.other_entity+"\"]');

            that.on_success({});
        };

        return that;
    };

    params.on_success = function() {
        assert.ok(true, "on_success() is invoked.");
    };

    var associator = IPA.bulk_associator(params);
    associator.execute();

    rpc.command = orig_ipa_command;
});

};});
