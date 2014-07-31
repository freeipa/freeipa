/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2012 Red Hat
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



define([], function() {

    /**
     * Application configuration
     * @class config
     * @singleton
     */
    var config = {

        /**
         * Selector for application container node
         */
        app_container: 'body',

        /**
         * Live server path
         */
        url: '/ipa/ui/',

        /**
         * RPC url
         */
        json_url: '/ipa/session/json',

        /**
         * Kerberos authentication url
         */
        krb_login_url: '/ipa/session/login_kerberos',

        /**
         * Forms based login url
         */
        frms_login_url: '/ipa/session/login_password',

        //logout_url: '/ipa/session/json',

        /**
         * Password reset url
         */
        reset_psw_url: '/ipa/session/change_password',

        /**
         * Ajax options for RPC commands
         */
        ajax_options: {
            type: 'POST',
            contentType: 'application/json',
            dataType: 'json',
            async: true,
            processData: false
        },

        /**
         * Hide read-only widgets without value
         * @property {boolean}
         */
        hide_empty_widgets: false,

        /**
         * Hide sections without any visible widget
         * @property {boolean}
         */
        hide_empty_sections: true
    };

    return config;
});