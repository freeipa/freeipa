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

var EXPORTED_SYMBOLS = ["kerberosauth", "kerberosauth_listener"];

var Cc = Components.classes;
var Ci = Components.interfaces;

var kerberosauth = {

    // Dictionary of configuration options this extension can configure.
    // An alias (key) is set for each options. Using a set of aliases limits
    // configuration pages from supplying potential malicious options.
    config_options: {
        referer: ['network.http.sendRefererHeader', 'int'],
        native_gss_lib: ['network.negotiate-auth.using-native-gsslib', 'bool'],
        trusted_uris: ['network.negotiate-auth.trusted-uris', 'str'],
        allow_proxies: ['network.negotiate-auth.allow-proxies', 'bool']
    },

    // Some preconfigurations to make things easier. Can be good if UI is added
    // (mostly for future usage).
    predefined_configurations: {
        ipa: {
            referer: '2',
            native_gss_lib: 'true',
            trusted_uris: '',
            allow_proxies: 'true'
        }
    },

    page_listener: function(event, dom_window) {

        var self = this;

        var conf = {
            event: event,
            window: dom_window || window,
            element: event.target
        };

        if (!conf.element.hasAttribute('method')) return;

        var method = conf.element.getAttribute('method');

        if (method === 'configure') self.configure(conf);
        if (method === 'can_configure') self.send_response(conf.element, { answer: 'true' });
    },

    send_response: function(element, options) {

        options = options || {};

        var doc = element.ownerDocument;

        for (var opt in options) {
            element.setAttribute(opt, options[opt]);
        }

        var answer_event = doc.createEvent("HTMLEvents");
        answer_event.initEvent("kerberos-auth-answer", true, false);
        element.dispatchEvent(answer_event);
    },

    notify_installed: function(window) {
        var doc = window.document;
        var event = doc.createEvent("HTMLEvents");
        event.initEvent("kerberos-auth-installed", true, false);
        doc.dispatchEvent(event);
    },

    configure: function(conf) {
        var self = this;

        var options = {}; // options to be configured
        var opt;

        // use predefined configuration if supplied
        if (conf.element.hasAttribute('predefined')) {
            var predefined = conf.element.getAttribute('predefined');

            var pconfig = self.predefined_configurations[predefined];
            if (pconfig) {
                for (opt in pconfig) {
                    options[opt] = pconfig[opt];
                }
            }
        }

        // overwrite predefined with supplied and only supported options
        for (var i=0; i < conf.element.attributes.length; i++) {
            var attr = conf.element.attributes[i].name;
            if (attr in self.config_options) {
                options[attr] =  conf.element.getAttribute(attr);
            }
        }

        if (self.prompt(conf, options)) {
            self.configure_core(conf, options);
            self.send_response(conf.element, { answer: 'configured' });
        } else {
            self.send_response(conf.element, { answer: 'aborted' });
        }
    },

    configure_core: function(conf, options) {

        var self = this;

        var prefs = Cc["@mozilla.org/preferences-service;1"].getService(Ci.nsIPrefBranch);

        for (var opt in options) {

            var name = self.config_options[opt][0];
            var type = self.config_options[opt][1];
            var value = options[opt];

            if (type === 'str') {
                prefs.setCharPref(name, value);
            } else if (type ==='int') {
                prefs.setIntPref(name, Number(value));
            } else if (type === 'bool') {
                prefs.setBoolPref(name, value === 'true');
            }
        }
    },

    prompt: function(conf, options) {
        var strs = Cc["@mozilla.org/intl/stringbundle;1"].
                        getService(Ci.nsIStringBundleService).
                        createBundle("chrome://kerberosauth/locale/kerberosauth.properties");

        var prompts = Cc["@mozilla.org/embedcomp/prompt-service;1"].
                        getService(Ci.nsIPromptService);

        var title = strs.GetStringFromName('prompt_title');
        var text = strs.GetStringFromName('prompt_topic');

        if (options.trusted_uris) {
            text += strs.GetStringFromName('prompt_domain').replace('${domain}', options.trusted_uris);
        }
        text +=  strs.GetStringFromName('prompt_question');

        var flags = prompts.STD_YES_NO_BUTTONS;

        var confirmed = prompts.confirmEx(conf.window, title, text, flags, "","","",
                                        null,{value: false}) === 0;
        return confirmed;
    }
};

var kerberosauth_listener = function(window) {

    return function(event) {

        kerberosauth.page_listener(event, window);
    };
};