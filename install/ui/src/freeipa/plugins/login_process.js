/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2014 Red Hat
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

define([
    'dojo/_base/lang',
    'dojo/on',
    '../ipa',
    '../app_container',
    '../reg',
    '../phases',
    'exports',
    './login',
    './sync_otp'], function(lang, on, IPA, app, reg, phases, login_process) {

/**
 * Defines switching between Sync OTP facet and Login facet.
 * @singleton
 * @class plugins.login_process
 */
lang.mixin(login_process, {

    bind_login_process: function() {

        var sync_facet = reg.facet.get('sync-otp');
        var login_facet = reg.facet.get('login');

        on(sync_facet, 'sync-success, sync-cancel', function(args) {
            app.app.show_facet(login_facet);
            IPA.notify_success(args.message);
        });
        on(login_facet, 'require-otp-sync', function(args) {
            sync_facet.set_user(args.user);
            app.app.show_facet(sync_facet);
        });
    }
});

phases.on('init', function() {
    login_process.bind_login_process();
}, 15);


return login_process;
});
