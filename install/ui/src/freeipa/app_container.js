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

define([
    'dojo/_base/lang',
    'dojo/Deferred',
    'dojo/on',
    'dojo/when',
    './plugin_loader',
    './phases',
    './reg',
    './Application_controller',
    'exports'
],function(lang, Deferred, on, when, plugin_loader, phases, reg, Application_controller, app) {

    /**
     * Application wrapper
     *
     * Prepares application controller and registers phases.
     *
     * @class app
     * @singleton
     */
    lang.mixin(app, {

        /**
         * Application instance
         */
        app: null,

        /**
         * Application class
         */
        App_class: Application_controller,

        /**
         * Phases registration
         */
        register_phases: function() {

            phases.on('init', function() {
                var app = this.app = new this.App_class();
                app.init();
                return app;
            }.bind(this));

            phases.on('init', function() {
                var deferred = new Deferred();

                function reject(item) {
                    var msg = "Web UI requires " + item + " enabled. " +
                              "Possible cause: too strict browser " +
                              "configuration.";
                    deferred.reject({ message: msg });
                    return deferred.promise;
                }

                function testStorage(storage) {
                    try {
                        if (!window[storage]) return false;
                    } catch(e) {
                        return false;
                    }
                    return true;
                }

                if (!window.navigator.cookieEnabled) return reject('cookies');
                if (!testStorage('sessionStorage')) return reject('sessionStorage');
                if (!testStorage('localStorage')) return reject('localStorage');

                if (window.sessionStorage.getItem('logout')) {
                    window.sessionStorage.removeItem('logout');
                    var login_facet = reg.facet.get('login');
                    this.app.show_facet(login_facet);
                    on.once(login_facet, "logged_in", function() {
                        deferred.resolve();
                    });
                } else {
                    deferred.resolve();
                }
                return deferred.promise;
            }.bind(this));

            phases.on('metadata', function() {
                var deferred = new Deferred();

                this.app.get_configuration(function(success) {
                    deferred.resolve(success);
                }, function(error) {
                    deferred.reject(error);
                });

                return deferred.promise;
            }.bind(this));

            phases.on('profile', function() {
                this.app.choose_profile();
            }.bind(this));

            phases.on('runtime', function() {
                return this.app.start_runtime();
            }.bind(this));

            phases.on('shutdown', function() {
                return this.app.start_logout();
            }.bind(this));
        },

        simple_mode_phases: function() {

            phases.on('init', function() {
                var app = this.app = new this.App_class();
                app.init();
                return app;
            }.bind(this));

            phases.on('runtime', function() {
                var d = new Deferred();
                var facet = reg.facet.get(this.target_facet);
                if (!facet) {
                    window.console.error('Target facet not found: '+this.target_facet);
                } else {
                    this.app.show_facet(facet);
                }
                return d.promise;
            }.bind(this));
        },

        run: function() {
            when(plugin_loader.load_plugins(), function() {
                this.register_phases();
                phases.controller.run();
            }.bind(this));
        },

        run_simple: function(facet) {
            this.target_facet = facet;
            when(plugin_loader.load_plugins(), function() {
                this.simple_mode_phases();
                phases.controller.run();
            }.bind(this));
        }
    });

    return app;
});
