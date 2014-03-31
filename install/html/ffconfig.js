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

var IPA = IPA || {};

IPA.browser_config = {

    configure_firefox: function(domain) {

        var self = this;

        domain = domain || self.get_domain();

        self.send_message({
            method: 'configure',
            predefined: 'ipa',
            trusted_uris: domain
        });
    },


    get_configure_result: function() {

        var self = this;

        var el = self.get_data_element();

        var answer = el.getAttribute('answer');

        return answer;
    },

    get_domain: function() {
        return "."+IPA_DOMAIN;
    },

    send_message: function(options) {

        options = options || {};

        var self = this;

        self.clear_data_element();
        var opt_element = self.get_data_element();

        for (var opt in options) {
            opt_element.setAttribute(opt, options[opt]);
        }

        var msg_evt = document.createEvent('HTMLEvents');
        msg_evt.initEvent('kerberos-auth-config', true, false);
        opt_element.dispatchEvent(msg_evt);
    },

    get_data_element: function() {

        var els = document.getElementsByTagName('kerberosauthdataelement');
        var element;

        if (els.length === 0) {
            element = document.createElement('kerberosauthdataelement');
            document.documentElement.appendChild(element);
        } else {
            element = els[0];
        }

        return element;
    },

    clear_data_element: function() {

        var self = this;

        var el = self.get_data_element();
        var to_remove = [];

        for (var i=0; i<el.attributes.length; i++) {
            to_remove.push(el.attributes[i].name);
        }

        for (i=0; i<to_remove.length; i++) {
            el.removeAttribute(to_remove[i]);
        }
    },

    extension_installed: function() {

        var self = this;

        self.send_message({
            method: 'can_configure'
        });

        var element = self.get_data_element();
        var ext_installed = element.getAttribute('answer') === 'true';
        return ext_installed;
    },

    get_browser: function() {

        var ua = window.navigator.userAgent.toLowerCase();

        var match = (/(chrome)[ \/]([\w.]+)/.exec(ua)) ||
            (/(webkit)[ \/]([\w.]+)/.exec(ua)) ||
            (/(opera)(?:.*version|)[ \/]([\w.]+)/.exec(ua)) ||
            (/(msie) ([\w.]+)/.exec(ua)) ||
            ua.indexOf("compatible") < 0 && (/(mozilla)(?:.*? rv:([\w.]+)|)/.exec(ua)) ||
            [];

        var matched = {
            browser: match[ 1 ] || "",
            version: match[ 2 ] || "0"
        };
        var browser = {};

        if (matched.browser) {
            browser[matched.browser] = true;
            browser.version = matched.version;
        }

        // Chrome is Webkit, but Webkit is also Safari.
        if (browser.chrome) {
           browser.webkit = true;
        } else if ( browser.webkit ) {
            browser.safari = true;
        }
        return browser;
    }
};