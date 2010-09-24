/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
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

/* REQUIRES: everything, this file puts it all togheter */

/* tabs definition for IPA webUI */
var admin_tabs_lists = [
    ['identity', 'IDENTITY', [
        ['user', 'Users', ipa_entity_setup],
        ['group', 'Groups', ipa_entity_setup],
        ['host', 'Hosts', ipa_entity_setup],
        ['hostgroup', 'Hostgroups', ipa_entity_setup],
        ['netgroup', 'Netgroups', ipa_entity_setup],
        ['service', 'Services', ipa_entity_setup],
    ]],
    ['policy', 'POLICY', unimplemented_tab],
    ['config', 'CONFIG', [
        ['rolegroup', 'Rolegroups', ipa_entity_setup]
    ]]
];


var self_serv_tabs_lists =
    [
    ['identity', 'IDENTITY', [
        ['user', 'Users', ipa_entity_setup]]]];

var nav_tabs_lists;

/* main (document onready event handler) */
$(function() {

    var whoami_pkey;

    function whoami_on_win(data, text_status, xhr) {
        $(window).bind('hashchange', window_hashchange);
        if (!data.error){
            var whoami = data.result.result[0];
            whoami_pkey=whoami.uid[0];
            $('#loggedinas').find('strong').text(whoami.krbprincipalname[0]);
            $('#loggedinas a').fragment(
                {'user-facet':'details', 'user-pkey':whoami_pkey},2);
            if (whoami.hasOwnProperty('memberof_rolegroup') &&
                whoami.memberof_rolegroup.length > 0){
                nav_tabs_lists = admin_tabs_lists;
                window_hashchange(null);
            }else{
                nav_tabs_lists = self_serv_tabs_lists;

                var state = {'user-pkey':whoami_pkey ,
                             'user-facet': jQuery.bbq.getState('user-facet') ||
                             'details'};
                $.bbq.pushState(state);
            }
            nav_create(nav_tabs_lists, $('#navigation'), 'tabs');

        }else{
            alert("Unable to find prinicpal for logged in user");
        }
    };

    function init_on_win(data, text_status, xhr) {
        ipa_cmd('user_find', [], {"whoami":"true","all":"true"}, whoami_on_win,
            function(xhr, options, thrownError) {
                alert("Error: "+thrownError);
            },
            null
        );
    };

    ipa_init(null, null, init_on_win,
        function(xhr, options, thrownError) {
            alert("Error: "+thrownError);
        }
    );
});

/* use this to track individual changes between two hashchange events */
var window_hash_cache = {};

/* main loop (hashchange event handler) */
function window_hashchange(evt)
{
    $('.tabs').each(function () {
        var jobj = $(this);
        var index = $.bbq.getState(jobj.attr('id'), true) || 0;
        jobj.find('ul.ui-tabs-nav a').eq(index).triggerHandler('change');
    });

    for (var i = 0; i < nav_tabs_lists.length; ++i) {
        var t = nav_tabs_lists[i];
        if (typeof t[2] != 'function' && t[2].length) {
            for (var j = 0; j < t[2].length; ++j) {
                var tt = t[2][j];
                var obj_name = tt[0];
                var entity_setup = tt[2];
                var div = $('#' + t[0] + ' div[title=' + obj_name + ']');

                var state = obj_name + '-facet';
                var facet = $.bbq.getState(state, true) || 'search';
                var last_facet = window_hash_cache[state] || 'search';
                if (facet != last_facet) {
                    entity_setup(div);
                    continue;
                }

                if (facet == 'search') {
                    state = obj_name + '-filter';
                    var filter = $.bbq.getState(state, true);
                    var last_filter = window_hash_cache[state];
                    if (filter != last_filter)
                        entity_setup(div);
                } else if (facet == 'details') {
                    state = obj_name + '-pkey';
                    var pkey = $.bbq.getState(state, true);
                    var last_pkey = window_hash_cache[state];
                    if (pkey != last_pkey)
                        entity_setup(div);
                } else if (facet == 'associate' || facet == 'enroll') {
                    state = obj_name + '-enroll';
                    var enroll = $.bbq.getState(state, true);
                    var last_enroll = window_hash_cache[state];
                    if (enroll != last_enroll)
                        entity_setup(div);
                }
            }
        }
    }

    window_hash_cache = $.bbq.getState();
}

/* builder function for unimplemented tab content */
function unimplemented_tab(jobj)
{
    jobj.text('Not implemented yet!');
}

