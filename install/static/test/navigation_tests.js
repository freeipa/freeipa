/*  Authors:
 *    Adam Young <ayoung@redhat.com>
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




test("Testing nav_create().", function() {

    var mock_tabs_lists =
        [
            { name:'identity', label:'IDENTITY', children: [
                {name:'user', label:'Users', setup:mock_setup_user},
                {name:'group', label:'Users', setup:mock_setup_group},
            ]}];
    function  mock_setup_user (jobj){
        user_mock_called = true;
        same(jobj[0].id,'user','user id');
        same(jobj[0].nodeName,'DIV','user div');
    }
    function  mock_setup_group (jobj){
        group_mock_called = true;
        same(jobj[0].id,'group','group id');
        same(jobj[0].nodeName,'DIV','group Div');

    }
    ipa_objs= {};
    var navigation = $('<div id="navigation"/>').appendTo(document.body);
    var user_mock_called = false;
    var group_mock_called = false;
    nav_create(mock_tabs_lists, navigation, 'tabs')
    ok(user_mock_called, "mock user setup was called");
    ok(!group_mock_called, "mock group setup was not called because the tab is inactive");
    same( navigation[0].children.length, 2, "Two Child tabs");
    same( navigation[0].children[1].id, 'identity', "Identity Tab");
    same( navigation[0].children[1].children[1].id, 'user', "User Tab");
    same( navigation[0].children[1].children[2].id, 'group', "User Tab");
    navigation.remove();
});

test("Testing  nav_select_tabs().", function() {


    var mock_tabs_lists =
        [
            { name:'identity', label:'IDENTITY', children: [
                {name:'one', label:'One', setup: function (){}},
                {name:'two', label:'Two', setup: function (){}},
            ]}];

    var navigation = $('<div id="navigation"/>').appendTo(document.body);

    nav_create(mock_tabs_lists, navigation, 'tabs')

    $.bbq.pushState({"identity":2});
    nav_select_tabs(mock_tabs_lists, navigation);
    same( navigation[0].children[1].children[2].id, 'two', "Tab two");
    $.bbq.removeState(["identity"]);

    navigation.remove();
});
