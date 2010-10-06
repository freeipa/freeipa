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


var admin_tab_set = [
    {name:'identity', children:[
        {name:'user', label:'Users', setup: ipa_entity_setup},
        {name:'group', label:'Groups', setup: ipa_entity_setup},
        {name:'host', label:'Hosts', setup: ipa_entity_setup},
        {name:'hostgroup', label:'Hostgroups', setup: ipa_entity_setup},
        {name:'netgroup', label:'Netgroups', setup: ipa_entity_setup},
        {name:'service', label:'Services', setup: ipa_entity_setup}
    ]},
    {name:'policy', children:[
        {name:'hbac', setup: ipa_entity_setup},
        {name:'dns', setup: ipa_entity_setup},
        {name:'automountlocation',  setup: ipa_entity_setup},
        {name:'pwpolicy', setup: ipa_entity_setup},
        {name:'krbtpolicy', setup:ipa_details_only_setup}
    ]},
    {name:'ipaserver', children: [
//        {name:'aci', setup: ipa_entity_setup},
        {name:'taskgroup', setup: ipa_entity_setup},
        {name:'rolegroup', label:'Rolegroups', setup: ipa_entity_setup},
        {name:'config', setup: ipa_details_only_setup}
    ]}
];

var self_serv_tab_set =
    [
        { name:'identity', label:'IDENTITY', children: [
            {name:'user', label:'Users', setup:ipa_entity_setup}]}];

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

            var navigation = $('#navigation');

            if (whoami.hasOwnProperty('memberof_rolegroup') &&
                whoami.memberof_rolegroup.length > 0){
                nav_create(admin_tab_set, navigation, 'tabs');

            }else{
                nav_create(self_serv_tab_set, navigation, 'tabs');

                var state = {'user-pkey':whoami_pkey ,
                             'user-facet': jQuery.bbq.getState('user-facet') ||
                             'details'};
                $.bbq.pushState(state);
            }


            $('#login_header').html(ipa_messages.login.header);
        }else{
            alert("Unable to find prinicpal for logged in user");
        }
    };

    function init_on_win(data, text_status, xhr) {
        ipa_cmd('user_find', [], {"whoami":"true","all":"true"}, whoami_on_win, init_on_error, null);
    };

    function init_on_error(xhr, text_status, error_thrown) {
        var navigation = $('#navigation').empty();
        navigation.append('<p>Error: '+error_thrown.name+'</p>');
        navigation.append('<p>URL: '+this.url+'</p>');
        navigation.append('<p>'+error_thrown.message+'</p>');
    }

    ipa_init(null, null, init_on_win, init_on_error);
});

/* main loop (hashchange event handler) */
function window_hashchange(evt)
{
    nav_update_tabs();
}

/* builder function for unimplemented tab content */
function unimplemented_tab(jobj)
{
    jobj.text('Not implemented yet!');
}

