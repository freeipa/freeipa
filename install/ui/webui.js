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


IPA.admin_tab_set = function () {
    var tabset = [
        {name:'identity', label: IPA.messages.tabs.identity,  children:[
            {entity:'user'},
            {entity:'group'},
            {entity:'host'},
            {entity:'hostgroup'},
            {entity:'netgroup'},
            {entity:'service'}
        ]},
        {name:'policy', label: IPA.messages.tabs.policy, children:[
            {entity:'dnszone'},
            {name:'hbac', label: IPA.messages.tabs.hbac ,
             children:[
                 {entity:'hbacrule'},
                 {entity:'hbacsvc'},
                 {entity:'hbacsvcgroup'}
            ]},
            {name:'sudo', label: IPA.messages.tabs.sudo,
             children:[
                 {entity:'sudorule'},
                 {entity:'sudocmd'},
                 {entity:'sudocmdgroup'}
            ]},
//            {entity:'automountlocation'},
            {entity:'pwpolicy'},
            {entity:'krbtpolicy'}
        ]},
        {name:'ipaserver', label: IPA.messages.tabs.ipaserver, children: [
            {name:'rolebased', label: IPA.messages.tabs.role,
             children:[
                 {entity:'role'},
                 {entity:'privilege'},
                 {entity:'permission'}
             ]},
            {entity:'selfservice'},
            {entity:'delegation'},
            {entity:'entitle'},
            {entity:'config'}
        ]}];

    return tabset;
};

IPA.self_serv_tab_set = function(){
    return [ { name:'identity',
               children:
               [
                   {entity:'user'},
                   {entity:'group'}
               ]
             }
           ];
};




/* main (document onready event handler) */
$(function() {

    /* main loop (hashchange event handler) */
    function window_hashchange(evt){
        IPA.nav.update_tabs();
    }


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

        IPA.start_entities();

        var navigation = $('#navigation');

        if (should_show_all_ui()){
            IPA.tab_set = IPA.admin_tab_set();
            IPA.nav.create(IPA.tab_set, navigation, 'tabs');
            IPA.nav.update_tabs();

        } else {
            IPA.tab_set = IPA.self_serv_tab_set();
            IPA.nav.create(IPA.tab_set, navigation, 'tabs');

            var pkey = $.bbq.getState('user-pkey');
            var facet = $.bbq.getState('user-facet');

            if (pkey && facet) {
                IPA.nav.update_tabs();

            } else {
                var state = {
                    'user-pkey': pkey || IPA.whoami_pkey,
                    'user-facet': facet || 'details'
                };
                $.bbq.pushState(state);
            }
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
