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

define(['dojo/_base/lang', '../ipa'], function(lang, IPA) {

    var i18n = {

        /**
         * Gets translated message.
         *
         * If a message starts with @i18n: it tries to get the message from
         * IPA.messages. If IPA messages doesn't contain a string with
         * the key it returns alternate string or the part after @i18n.
         *
         * When IPA.messages doesn't exist alternate string is returned.
         * It all other cases the message itself is returned.
         *
         * @param {String} Message key
         * @param {String} Alternate message.
         * @returns {String} Translated message
         */
        message: function(message, alternate) {

            if (!message) return '';

            if (message.substring(0, 6) === '@i18n:') {
                var key = message.substring(6);
                if(!IPA.messages) return alternate || key;
                var string = lang.getObject(key, false, IPA.messages);
                // don't return objecs
                if (typeof string !== 'string') string = null;
                return string || alternate || key;
            }

            return alternate || message;
        }
    };

    return i18n;
});