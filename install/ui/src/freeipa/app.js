/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2012 Red Hat
 * see file 'COPYING'./for use and warranty information
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

//
// AMD Wrapper for json2 library
//

define([
    //core
    './ipa',
    './jquery',
    './navigation',
    './webui',
    //only entities
    './aci',
    './automember',
    './automount',
    './dns',
    './group',
    './hbac',
    './hbactest',
    './hostgroup',
    './host',
    './idrange',
    './netgroup',
    './policy',
    './realmdomains',
    './rule',
    './selinux',
    './serverconfig',
    './service',
    './sudo',
    './trust',
    './user',
    'dojo/domReady!'
],function(IPA, $) {

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

    return {
        run: function() {
            IPA.init({
                on_success: init_on_success,
                on_error: init_on_error
            });
        }
    };
});