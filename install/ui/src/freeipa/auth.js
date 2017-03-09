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
    'dojo/_base/declare',
    'dojo/_base/lang',
    'dojo/Deferred',
    'dojo/Evented',
    'dojo/Stateful',
    'dojo/topic',
    'dojo/when'
   ],
   function(declare, lang, Deferred, Evented, Stateful, topic, when) {

/**
 * Authentication module
 * @class auth
 * @singleton
 */
var auth = {
    /**
     * Current authentication state
     * @property {auth.Auth}
     */
    current: null
};

/**
 * Authentication interface and state.
 *
 * Can be used for checking whether user is authenticated, by what method or
 * what methods can be used for authentication. Actual authentication is
 * done by separate object - authentication provider.
 *
 * Communication with authentication providers is done through global messages
 * (`dojo/topic`).
 *
 * Some component can initiate the authentication process by calling:
 *
 *      var auth_promise = auth.current.authenticate();
 *
 * `auth_promise` is a promise which is resolve on auth success and rejected
 *  on auth failure.
 *
 * Logout works in similar fashion:
 *
 *      var logout_promise = auth.current.logout();
 *
 * The communication with authentication providers works as follows:
 *
 * 1. `auth.current.authenticate();` publishes `authenticate` topic
 * 2. provider starts the authentication process
 * 3. if it finishes with a success provider publishes `auth-successful`, if not
 *    it publishes `auth-failed`
 * 4. the promise is resolved or rejected
 *
 * Logout works in similar fashion, only the topic names are `log-out`,
 * `logout-successful` and `logout-failed`.
 *
 * New `authenticate` or `log-out` topics are not published if there is
 * already authentication or logout in progress. The promises from subsequent
 * `authenticate()` or `logout()` calls are resolved as expected.
 *
 * `login`, `principal`, `whoami`, `fullname` properties are supposed to be
 * set by authentication providers.
 *
 * @class
 */
auth.Auth = declare([Stateful, Evented], {
    /**
     * Raw User information
     *
     * @property {Object}
     */
    whoami: {},

    /**
     * User is authenticated
     *
     * Use `set_authenticated(state, method)` for setting it.
     *
     * @property {boolean}
     * @readonly
     */
    authenticated: false,

    /**
     * Method used for authentication
     * @property {string}
     */
    authenticated_by: "",

    /**
     * Enabled auth methods
     * @property {string[]}
     */
    auth_methods: ['kerberos', 'password', 'certificate'],

    /**
     * Authenticated user's Kerberos principal
     * @property {string}
     */
    principal: "",

    /**
     * Authenticated user's login
     * @property {string}
     */
    login: "",

    /**
     * Authenticated user's fullname
     * @property {string}
     */
    fullname: "",

    /**
     * Authentication is in progress
     * @property {boolean}
     */
    authenticating: false,

    /**
     * Logging out is in progress
     * @property {boolean}
     */
    logging_out: false,

    /**
     * Indicates whether user was previously authenticated
     * @property {boolean}
     */
    expired: false,

    /**
     * Update authenticated state
     * @param {boolean} state User is authenticated
     * @param {string} method used for authentication
     */
    set_authenticated: function(state, method) {

        if (this.authenticated && !state) {
            this.set('expired', true);
        }

        this.set('authenticated', state);
        this.set('authenticated_by', method);

        if (this.authenticated) {
            this.set('expired', false);
        }
    },

    /**
     * Initiate authentication process (if not already initiated)
     *
     * Returns promise which is fulfilled when user is authenticated. It's
     * rejected when authentication is canceled.
     * @returns {Promise}
     */
    authenticate: function() {
        var authenticated = new Deferred();
        var ok_handler = topic.subscribe('auth-successful', function(info) {
            authenticated.resolve(true);
            ok_handler.remove();
            fail_handler.remove();
        });
        var fail_handler = topic.subscribe('auth-failed', function(info) {
            authenticated.reject();
            ok_handler.remove();
            fail_handler.remove();
        });
        if (!this.authenticating) {
            topic.publish('authenticate', this);
        }
        return authenticated.promise;
    },

    /**
     * Initiate logout process (if not already initiated)
     *
     * Returns promise which is fulfilled when user is logged-out. It's
     * rejected when logout failed.
     * @returns {Promise}
     */
    logout: function() {
        var loggedout = new Deferred();
        var ok_handler = topic.subscribe('logout-successful', function(info) {
            loggedout.resolve(true);
            ok_handler.remove();
            fail_handler.remove();
        });
        var fail_handler = topic.subscribe('logout-failed', function(info) {
            loggedout.reject();
            ok_handler.remove();
            fail_handler.remove();
        });
        if (!this.logging_out) {
            topic.publish('log-out', this);
        }
        return loggedout.promise;
    },

    /**
     * Initializes instance
     *
     * @private
     */
    postscript: function() {
        var self = this;
        var auth_true =  function() {
            self.set('authenticating', true);
        };
        var auth_false =  function() {
            self.set('authenticating', false);
        };
        var out_true =  function() {
            self.set('logging_out', true);
        };
        var out_false =  function() {
            self.set('logging_out', false);
        };

        topic.subscribe('auth-successful', auth_false);
        topic.subscribe('auth-failed', auth_false);
        topic.subscribe('authenticate', auth_true);
        topic.subscribe('logout-successful', out_true);
        topic.subscribe('logout-failed', out_true);
        topic.subscribe('log-out', out_false);
    }
});

auth.current = new auth.Auth();
return auth;
});
