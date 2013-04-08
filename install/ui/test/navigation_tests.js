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

define(['freeipa/ipa', 'freeipa/jquery', 'freeipa/navigation', 'freeipa/entity'],
       function(IPA, $) {
    return function() {

module('navigation', {

//     setup: function() {
//         IPA.ajax_options.async = false;
//         IPA.init({
//             url: 'data',
//             on_error: function(xhr, text_status, error_thrown) {
//                 ok(false, 'ipa_init() failed: '+error_thrown);
//             }
//         });
//     }

});

test("Testing IPA.navigation.create().", function() {

//     var entity;
//     var user_mock_called = false;
//     var group_mock_called = false;
//     //Force reset of entities
//     IPA.entities = $.ordered_map();
//
//     IPA.register('user', function(spec) {
//
//         var that = IPA.entity({
//             name: 'user',
//             metadata: IPA.metadata.objects.user,
//             facets: [
//                 {
//                     type: 'search'
//                 }
//             ]
//         });
//
//         that.display = function(container){
//             user_mock_called = true;
//             same(container.attr('name'), 'user', 'user container name');
//             same(container[0].nodeName, 'DIV', 'user container element');
//         };
//
//         return that;
//     });
//
//     IPA.register('group', function(spec) {
//
//         var that = IPA.entity({
//             name: 'group',
//             metadata: IPA.metadata.objects.group
//         });
//
//         that.display = function(container){
//             group_mock_called = true;
//             same(container.attr('name'), 'group','user container name');
//             same(container[0].nodeName, 'DIV', 'user container element');
//         };
//
//         return that;
//     });
//
//     var navigation_container = $('<div id="navigation"/>').appendTo(document.body);
//     var entity_container = $('<div id="content"/>').appendTo(document.body);
//
//     var navigation = IPA.navigation({
//         container: navigation_container,
//         content: entity_container,
//         tabs: [
//             { name:'identity', label:'IDENTITY', children: [
//                 {name:'user', entity:'user'},
//                 {name:'group', entity:'group'}
//             ]}
//         ]
//     });
//
//     navigation.create();
//     navigation.update();
//
//     ok(user_mock_called, "mock user setup was called");
//     ok(!group_mock_called, "mock group setup was not called because the tab is inactive");
//
//     var tabs_container = navigation_container.children('div');
//
//     var level1_tabs = tabs_container.children('div');
//     same(level1_tabs.length, 1, "One level 1 tab");
//
//     var identity_tab = level1_tabs.first();
//     same(identity_tab.attr('name'), 'identity', "Identity Tab");
//
//     var level2_tabs = identity_tab.children('div');
//     same(level2_tabs.length, 2, "Two level 2 tabs");
//
//     var user_tab = level2_tabs.first();
//     same(user_tab.attr('name'), 'user', "User Tab");
//
//     var group_tab = user_tab.next();
//     same(group_tab.attr('name'), 'group', "Group Tab");
//
//     entity_container.remove();
//     navigation_container.remove();
});

test("Testing IPA.navigation.update() with valid index.", function() {

//     var navigation_container = $('<div id="navigation"/>').appendTo(document.body);
//     var entity_container = $('<div id="content"/>').appendTo(document.body);
//
//     var navigation = IPA.navigation({
//         container: navigation_container,
//         content: entity_container,
//         tabs: [
//             { name:'identity', label:'IDENTITY', children: [
//                 {name:'one', label:'One'},
//                 {name:'two', label:'Two'}
//             ]}
//         ]
//     });
//
//     var state = {};
//
//     navigation.push_state = function(params) {
//         $.extend(state, params);
//     };
//
//     navigation.get_state = function(key) {
//         return key ? state[key] : {};
//     };
//
//     navigation.remove_state = function(key) {
//         delete state[key];
//     };
//
//     navigation.create();
//     navigation.push_state({'identity': 'two'});
//     navigation.update();
//
//     var tabs_container = navigation_container.children('div');
//
//     same(
//         tabs_container.tabs('option', 'selected'), 0,
//         "Active tab at level 1");
//
//     same(
//         $('.tabs[name=identity]', tabs_container).tabs('option', 'selected'), 1,
//         "Active tab at level 2");
//
//     navigation.remove_state("identity");
//
//     entity_container.remove();
//     navigation_container.remove();
// });
//
// test("Testing IPA.navigation.update() with out-of-range index.", function() {
//
//     var navigation_container = $('<div id="navigation"/>').appendTo(document.body);
//     var entity_container = $('<div id="content"/>').appendTo(document.body);
//
//     var navigation = IPA.navigation({
//         container: navigation_container,
//         content: entity_container,
//         tabs: [
//             { name:'identity', label:'IDENTITY', children: [
//                 {name:'one', label:'One', setup: function (){}},
//                 {name:'two', label:'Two', setup: function (){}}
//             ]}
//         ]
//     });
//
//     var state = {};
//
//     navigation.push_state = function(params) {
//         $.extend(state, params);
//     };
//
//     navigation.get_state = function(key) {
//         return key ? state[key] : {};
//     };
//
//     navigation.remove_state = function(key) {
//         delete state[key];
//     };
//
//     navigation.create();
//     navigation.push_state({'identity': 'three'});
//     navigation.update();
//
//     var tabs_container = navigation_container.children('div');
//
//     same(
//         tabs_container.tabs('option', 'selected'), 0,
//         "Active tab at level 1");
//
//     same(
//         $('.tabs[name=identity]', tabs_container).tabs('option', 'selected'), 0,
//         "Active tab at level 2");
//
//     navigation.remove_state("identity");
//
//     entity_container.remove();
//     navigation_container.remove();
});

};});