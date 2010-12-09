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




test("Testing nav_create().", function() {

    var mock_tabs_lists =
        [
            { name:'identity', label:'IDENTITY', children: [
                {name:'user', entity:'user'},
                {name:'group', entity:'group'}
            ]}];

    var entity = ipa_entity({name: 'user'});
    entity.setup = function(container){
        user_mock_called = true;
        same(container[0].id,'user','user id');
        same(container[0].nodeName,'DIV','user div');
    };
    IPA.add_entity(entity);

    entity = ipa_entity({name: 'group'});
    entity.setup = function(container){
        group_mock_called = true;
        same(container[0].id,'group','group id');
        same(container[0].nodeName,'DIV','group Div');
    };
    IPA.add_entity(entity);

    IPA.metadata = {};
    var navigation = $('<div id="navigation"/>').appendTo(document.body);
    var user_mock_called = false;
    var group_mock_called = false;
    nav_create(mock_tabs_lists, navigation, 'tabs');
    ok(user_mock_called, "mock user setup was called");
    ok(!group_mock_called, "mock group setup was not called because the tab is inactive");
    same( navigation[0].children.length, 2, "Two Child tabs");
    same( navigation[0].children[1].id, 'identity', "Identity Tab");
    same( navigation[0].children[1].children[1].id, 'user', "User Tab");
    same( navigation[0].children[1].children[2].id, 'group', "User Tab");
    navigation.remove();
});

test("Testing nav_update_tabs() with valid index.", function() {

    var orig_push_state = nav_push_state;
    var orig_get_state = nav_get_state;
    var orig_remove_state = nav_remove_state;

    var state = {};

    nav_push_state = function(params) {
        $.extend(state, params);
    };
    nav_get_state = function(key) {
        return state[key];
    };
    nav_remove_state = function(key) {
        delete state[key];
    };

    var mock_tabs_lists =
        [
            { name:'identity', label:'IDENTITY', children: [
                {name:'one', label:'One', setup: function (){}},
                {name:'two', label:'Two', setup: function (){}}
            ]}];

    var navigation = $('<div id="navigation"/>').appendTo(document.body);

    nav_create(mock_tabs_lists, navigation, 'tabs');

    nav_push_state({"identity":1});
    nav_update_tabs();

    same(
        navigation.tabs('option', 'selected'), 0,
        "Active tab at level 1"
    );

    same(
        $('#identity').tabs('option', 'selected'), 1,
        "Active tab at level 2"
    );

    nav_remove_state("identity");

    navigation.remove();

    nav_push_state = orig_push_state;
    nav_get_state = orig_get_state;
    nav_remove_state = orig_remove_state;
});

test("Testing nav_update_tabs() with out-of-range index.", function() {

    var orig_push_state = nav_push_state;
    var orig_get_state = nav_get_state;
    var orig_remove_state = nav_remove_state;

    var state = {};

    nav_push_state = function(params) {
        $.extend(state, params);
    };
    nav_get_state = function(key) {
        return state[key];
    };
    nav_remove_state = function(key) {
        delete state[key];
    };

    var mock_tabs_lists =
        [
            { name:'identity', label:'IDENTITY', children: [
                {name:'one', label:'One', setup: function (){}},
                {name:'two', label:'Two', setup: function (){}}
            ]}];

    var navigation = $('<div id="navigation"/>').appendTo(document.body);

    nav_create(mock_tabs_lists, navigation, 'tabs');

    nav_push_state({"identity":2});
    nav_update_tabs();

    same(
        navigation.tabs('option', 'selected'), 0,
        "Active tab at level 1"
    );

    same(
        $('#identity').tabs('option', 'selected'), 0,
        "Active tab at level 2"
    );

    nav_remove_state("identity");

    navigation.remove();

    nav_push_state = orig_push_state;
    nav_get_state = orig_get_state;
    nav_remove_state = orig_remove_state;
});
