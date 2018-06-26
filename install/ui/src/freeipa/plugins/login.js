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
        '../phases',
        '../reg',
        '../widget',
        '../widgets/LoginScreen',
        '../text'
       ],
       function(declare, lang, on, Facet, auth, phases, reg, widget, LoginScreen, text) {

    /**
     * Login Facet plugin
     *
     * Creates and registers a facet with login page.
     *
     * @class plugins.login
     * @singleton
     */
    var login = {};

    login.facet_spec = {
        name: 'login',
        preferred_container: 'simple',
        requires_auth: false,
        widgets: [
            {
                $type: 'activity',
                name: 'activity',
                text: text.get('@i18n:login.authenticating', 'Authenticating'),
                visible: false
            },
            {
                $type: 'login_screen',
                name: 'login_screen'
            }
        ]
    };

    login.LoginFacet = declare([Facet], {

        can_leave: function() {
            return auth.current.authenticated;
        },

        init: function() {
            this.inherited(arguments);
            var login_screen = this.get_widget('login_screen');
            var self = this;
            on(login_screen, 'logged_in', function(args) {
                self.emit('logged_in', args);
            });

            on(this, 'show', function(args) {
                login_screen.refresh();
            });

            on(login_screen, 'require-otp-sync', function(args) {
                self.emit('require-otp-sync', args);
            });
        }
    });

    phases.on('registration', function() {

        var fa = reg.facet;
        var w = reg.widget;

        w.register('login_screen', LoginScreen);

        fa.register({
            type: 'login',
            factory: login.LoginFacet,
            spec: login.facet_spec
        });
    });

    return login;
});
