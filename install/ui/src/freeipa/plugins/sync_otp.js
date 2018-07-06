/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2013 Red Hat
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

define(['dojo/_base/declare',
        'dojo/_base/lang',
        'dojo/on',
        '../facets/Facet',
        '../auth',
        '../navigation',
        '../phases',
        '../reg',
        '../text',
        '../widget',
        '../widgets/SyncOTPScreen'
       ],
       function(declare, lang, on, Facet, auth, navigation, phases, reg, text,
           widget, SyncOTPScreen) {

    /**
     * Sync OTP Facet plugin
     *
     * Creates and registers a facet with sync otp page.
     *
     * @class plugins.sync_otp
     * @singleton
     */
    var sync_otp = {};

    sync_otp.facet_spec = {
        name: 'sync-otp',
        'class': 'login-pf-body',
        preferred_container: 'simple',
        requires_auth: false,
        widgets: [
            {
                $type: 'activity',
                name: 'activity',
                text: text.get('@i18n:login.synchronizing', 'Synchronizing'),
                visible: false
            },
            {
                $type: 'sync_otp_screen',
                name: 'sync_screen'
            }
        ]
    };

    sync_otp.SyncOTPFacet = declare([Facet], {

        init: function() {
            this.inherited(arguments);
            var sync_screen = this.get_widget('sync_screen');
            var self = this;
            on(sync_screen, 'sync-success', function(args) {
                self.emit('sync-success', args);
            });

            on(sync_screen, 'sync-cancel', function(args) {
                self.emit('sync-cancel', args);
            });

            on(this, 'show', function(args) {
                sync_screen.refresh();
            });
        },

        set_user: function(user) {
            var sync_screen = this.get_widget('sync_screen');
            sync_screen.set('user', user);
        }
    });

    phases.on('registration', function() {

        var fa = reg.facet;
        var w = reg.widget;

        w.register('sync_otp_screen', SyncOTPScreen);

        fa.register({
            type: 'sync-otp',
            factory: sync_otp.SyncOTPFacet,
            spec: sync_otp.facet_spec
        });
    });

    return sync_otp;
});
