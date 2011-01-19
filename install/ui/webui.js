/*jsl:import ipa.js */
/*jsl:import navigation.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
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

/* REQUIRES: everything, this file puts it all togheter */

/* tabs definition for IPA webUI */


var admin_tab_set = [
    {name:'identity', children:[
        {name:'user', entity:'user'},
        {name:'group', entity:'group'},
        {name:'host', entity:'host'},
        {name:'hostgroup', entity:'hostgroup'},
        {name:'netgroup', entity:'netgroup'},
        {name:'service', entity:'service'}
    ]},
    {name:'policy', children:[
        {name:'dnszone', entity:'dnszone'},
        {name:'hbacrule', entity:'hbacrule', children:[
            {name:'hbacsvc', entity:'hbacsvc'},
            {name:'hbacsvcgroup', entity:'hbacsvcgroup'}
        ]},
        {name:'sudorule', entity:'sudorule',children:[
            {name:'sudocmd', entity:'sudocmd'},
            {name:'sudocmdgroup', entity:'sudocmdgroup'}
        ]},
        {name:'pwpolicy', entity:'pwpolicy'},
        {name:'krbtpolicy', entity:'krbtpolicy'}
    ]},
    {name:'ipaserver', children: [
        {name:'role',entity:'role'  ,children:[
            {name:'privilege',entity:'privilege' },
            {name:'permission', entity:'permission'}
        ]},
        {name:'selfservice'  ,entity:'selfservice'},
        {name:'delegation'  ,entity:'delegation'},
        {name:'config', entity:'config'}
    ]}
];

var self_serv_tab_set =
    [
        { name:'identity', children: [
            {name:'user', entity:'user'}]}];


IPA.tab_state = function(entity_name){

    var state = {};

    for (var top_tab_index = 0;
         top_tab_index < IPA.tab_set.length;
         top_tab_index += 1){
        var top_tab =  IPA.tab_set[top_tab_index];
        for (var subtab_index = 0;
             subtab_index < top_tab.children.length;
             subtab_index += 1){
            if(top_tab.children[subtab_index].name){
                if (top_tab.children[subtab_index].name === entity_name){
                    state.navigation =  top_tab_index;
                    state[top_tab.name] =  subtab_index;
                    return state;
                }else if (top_tab.children[subtab_index].children){
                    var  nested_entities = top_tab.children[subtab_index].children;
                    for (var nested_index = 0;
                         nested_index < nested_entities.length;
                         nested_index += 1){
                        if (nested_entities[nested_index].name === entity_name){
                            state.navigation =  top_tab_index;
                             state[top_tab.name] =  subtab_index;
                             state[ top_tab.children[subtab_index].name+'-entity'] =  entity_name;
                             return state;
                        }
                    }
                }
            }
        }
    }
    /*should never reach here*/
    return null;
};


/* main (document onready event handler) */
$(function() {

    function should_show_all_ui(){
        var whoami = IPA.whoami;

        if (whoami.hasOwnProperty('memberof_group') &&
            whoami.memberof_group.indexOf('admins')  !== -1) return true;

        return whoami.hasOwnProperty('memberof_rolegroup') &&
            whoami.memberof_rolegroup.length > 0;
    }


    function init_on_win(data, text_status, xhr) {
        $(window).bind('hashchange', window_hashchange);

        var whoami = IPA.whoami;
        IPA.whoami_pkey=whoami.uid[0];
        $('#loggedinas').find('strong').text(whoami.cn[0]);
        $('#loggedinas a').fragment(
            {'user-facet':'details', 'user-pkey':IPA.whoami_pkey},2);

        for (var i=0; i<IPA.entities.length; i++) {
            var entity = IPA.entities[i];
            entity.init();
        }

        var navigation = $('#navigation');

        if (should_show_all_ui()){
            IPA.tab_set = admin_tab_set;
            nav_create(admin_tab_set, navigation, 'tabs');
        } else {
            IPA.tab_set = self_serv_tab_set;
            nav_create(self_serv_tab_set, navigation, 'tabs');

            var state = {'user-pkey':IPA.whoami_pkey ,
                         'user-facet': $.bbq.getState('user-facet') ||
                         'details'};
            $.bbq.pushState(state);
        }


        $('#login_header').html(IPA.messages.login.header);
    }


    function init_on_error(xhr, text_status, error_thrown) {
        var navigation = $('#navigation').empty();
        navigation.append('<p>Error: '+error_thrown.name+'</p>');
        navigation.append('<p>'+error_thrown.title+'</p>');
        navigation.append('<p>'+error_thrown.message+'</p>');
    }

    IPA.init(null, null, init_on_win, init_on_error);
});

/* main loop (hashchange event handler) */
function window_hashchange(evt){
    nav_update_tabs();
}

/* builder function for unimplemented tab content */
function unimplemented_tab(jobj){
    jobj.text('Not implemented yet!');
}

