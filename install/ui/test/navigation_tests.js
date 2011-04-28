/*  Authors:
 *    Adam Young <ayoung@redhat.com>
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


module('navigation', {
    setup: function() {
        IPA.ajax_options.async = false;
        IPA.init(
            'data',
            true,
            function(data, text_status, xhr) {
            },
            function(xhr, text_status, error_thrown) {
                ok(false, 'ipa_init() failed: '+error_thrown);
            }
        );
    }
});

test("Testing IPA.navigation.create().", function() {

    var entity;

    IPA.entity_factories.user =  function() {
        var that = IPA.entity({name: 'user',
                               metadata:IPA.metadata.objects.user});
        that.setup = function(container){
            user_mock_called = true;
            same(container[0].id,'user','user id');
            same(container[0].nodeName,'DIV','user div');
        };
        return that;
    };
    IPA.entity_factories.group = function(){
        var that  = IPA.entity({name: 'group',
                               metadata:IPA.metadata.objects.group});
        that.setup = function(container){
            group_mock_called = true;
            same(container[0].id,'group','group id');
            same(container[0].nodeName,'DIV','group Div');
        };
        return that;
    };

    IPA.start_entities();

    IPA.metadata = {};
    var container = $('<div id="navigation"/>').appendTo(document.body);
    var user_mock_called = false;
    var group_mock_called = false;

    var navigation = IPA.navigation({
        container: container,
        tabs: [
            { name:'identity', label:'IDENTITY', children: [
                {name:'user', entity:'user'},
                {name:'group', entity:'group'}
            ]}
        ]
    });

    navigation.create();
    navigation.update();

    ok(user_mock_called, "mock user setup was called");
    ok(!group_mock_called, "mock group setup was not called because the tab is inactive");
    same( container[0].children.length, 2, "Two Child tabs");
    same( container[0].children[1].id, 'identity', "Identity Tab");
    same( container[0].children[1].children[1].id, 'user', "User Tab");
    same( container[0].children[1].children[2].id, 'group', "User Tab");
    container.remove();
});

test("Testing IPA.navigation.update() with valid index.", function() {

    var container = $('<div id="navigation"/>').appendTo(document.body);

    var navigation = IPA.navigation({
        container: container,
        tabs: [
            { name:'identity', label:'IDENTITY', children: [
                {name:'one', label:'One', setup: function (){}},
                {name:'two', label:'Two', setup: function (){}}
            ]}
        ]
    });

    var state = {};

    navigation.push_state = function(params) {
        $.extend(state, params);
    };

    navigation.get_state = function(key) {
        return state[key];
    };

    navigation.remove_state = function(key) {
        delete state[key];
    };

    navigation.create();
    navigation.push_state({'identity': 'two'});
    navigation.update();

    same(
        container.tabs('option', 'selected'), 0,
        "Active tab at level 1"
    );

    same(
        $('#identity').tabs('option', 'selected'), 1,
        "Active tab at level 2"
    );

    navigation.remove_state("identity");

    container.remove();
});

test("Testing IPA.navigation.update() with out-of-range index.", function() {

    var container = $('<div id="navigation"/>').appendTo(document.body);

    var navigation = IPA.navigation({
        container: container,
        tabs: [
            { name:'identity', label:'IDENTITY', children: [
                {name:'one', label:'One', setup: function (){}},
                {name:'two', label:'Two', setup: function (){}}
            ]}
        ]
    });

    var state = {};

    navigation.push_state = function(params) {
        $.extend(state, params);
    };

    navigation.get_state = function(key) {
        return state[key];
    };

    navigation.remove_state = function(key) {
        delete state[key];
    };

    navigation.create();
    navigation.push_state({'identity': 'three'});
    navigation.update();

    same(
        container.tabs('option', 'selected'), 0,
        "Active tab at level 1"
    );

    same(
        $('#identity').tabs('option', 'selected'), 0,
        "Active tab at level 2"
    );

    navigation.remove_state("identity");

    container.remove();
});
