/*jsl:import ipa.js */
/*jsl:import navigation.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
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

IPA.admin_navigation = function(spec) {

    spec = spec || {};

    spec.name = 'admin';

    spec.tabs = [
        {name: 'identity', label: IPA.messages.tabs.identity, children: [
            {entity: 'user'},
            {entity: 'group'},
            {entity: 'host'},
            {entity: 'hostgroup'},
            {entity: 'netgroup'},
            {entity: 'service'},
            {name:'dns', label: IPA.messages.tabs.dns, children:[
                 {entity: 'dnszone'},
                 {entity: 'dnsconfig'},
                 {entity: 'dnsrecord', hidden:true}
             ]
            }
        ]},
        {name: 'policy', label: IPA.messages.tabs.policy, children: [
            {name: 'hbac', label: IPA.messages.tabs.hbac, children: [
                 {entity: 'hbacrule'},
                 {entity: 'hbacsvc'},
                 {entity: 'hbacsvcgroup'},
                 {entity: 'hbactest'}
            ]},
            {name: 'sudo', label: IPA.messages.tabs.sudo, children: [
                 {entity: 'sudorule'},
                 {entity: 'sudocmd'},
                 {entity: 'sudocmdgroup'}
            ]},
            {name:'automount',
             label: IPA.messages.tabs.automount,
             children:[
                {entity: 'automountlocation', hidden:true, depth: -1},
                {entity: 'automountmap', hidden: true, depth: -1},
                {entity: 'automountkey', hidden: true, depth: -1}]},
            {entity: 'pwpolicy'},
            {entity: 'krbtpolicy'},
            {entity: 'selinuxusermap'},
            {name: 'automember', label: IPA.messages.tabs.automember,
             children: [
                { name: 'amgroup', entity: 'automember',
                  facet: 'searchgroup', label: IPA.messages.objects.automember.usergrouprules},
                { name: 'amhostgroup', entity: 'automember',
                  facet: 'searchhostgroup', label: IPA.messages.objects.automember.hostgrouprules}
            ]}
        ]},
        {name: 'ipaserver', label: IPA.messages.tabs.ipaserver, children: [
            {name: 'rolebased', label: IPA.messages.tabs.role, children: [
                 {entity: 'role'},
                 {entity: 'privilege'},
                 {entity: 'permission'}
             ]},
            {entity: 'selfservice'},
            {entity: 'delegation'},
            {entity: 'idrange'},
            {entity: 'trust'},
            {entity: 'config'}
        ]}];

    var that = IPA.navigation(spec);

    return that;
};

IPA.self_serv_navigation = function(spec) {

    spec = spec || {};

    spec.name = 'self-service';

    spec.tabs = [
        {name: 'identity', label: IPA.messages.tabs.identity, children: [
            {entity: 'user'}
        ]}];

    var that = IPA.navigation(spec);

    that.update = function() {
        var pkey = that.get_state('user-pkey');
        var facet = that.get_state('user-facet');

        if (pkey && facet) {
            that.navigation_update();

        } else {
            var state = {
                'navigation': 'identity',
                'identity': 'user',
                'user-pkey': pkey || IPA.whoami_pkey,
                'user-facet': facet || 'details'
            };
            that.push_state(state);
        }
    };

    return that;
};

/* main (document onready event handler) */
$(function() {



    /* main loop (hashchange event handler) */
    function window_hashchange(evt){
        IPA.nav.update();
    }

    function create_navigation() {
        var whoami = IPA.whoami;
        var factory;


        if (whoami.hasOwnProperty('memberof_group') &&
            whoami.memberof_group.indexOf('admins') !== -1) {
            factory = IPA.admin_navigation;
        } else if (whoami.hasOwnProperty('memberofindirect_group')&&
                   whoami.memberofindirect_group.indexOf('admins') !== -1) {
            factory = IPA.admin_navigation;
        } else if (whoami.hasOwnProperty('memberof_role') &&
                   whoami.memberof_role.length > 0) {
            factory = IPA.admin_navigation;
        } else if (whoami.hasOwnProperty('memberofindirect_role') &&
                   whoami.memberofindirect_role.length > 0) {
            factory = IPA.admin_navigation;
        } else {
            factory = IPA.self_serv_navigation;
        }

        return factory({
            container: $('#navigation'),
            content: $('#content')
        });
    }


    function init_on_success(data, text_status, xhr) {
        $(window).bind('hashchange', window_hashchange);

        var whoami = IPA.whoami;
        IPA.whoami_pkey = whoami.uid[0];
        $('#loggedinas .login').text(whoami.cn[0]);
        $('#loggedinas a').fragment(
            {'user-facet': 'details', 'user-pkey': IPA.whoami_pkey}, 2);

        $('#logout').click(function() {
            IPA.logout();
            return false;
        }).text(IPA.messages.login.logout);

        $('.header-loggedinas').css('visibility','visible');
        IPA.update_password_expiration();

        IPA.nav = create_navigation();
        IPA.nav.create();
        IPA.nav.update();

        $('#login_header').html(IPA.messages.login.header);
    }


    function init_on_error(xhr, text_status, error_thrown) {
        var container = $('#content').empty();
        container.append('<p>Error: '+error_thrown.name+'</p>');
        container.append('<p>'+error_thrown.message+'</p>');
    }

    IPA.init({
        on_success: init_on_success,
        on_error: init_on_error
    });
});
