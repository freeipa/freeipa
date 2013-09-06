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

/**
* Gets translated message.
*
* If a message starts with `@i18n`: it tries to get the message from
* message object. If it doesn't contain a string with
* the key it returns alternate string.
*
* It all other cases the message itself or empty string is returned.
* @class _base.i18n
* @extends _base.Provider
* @singleton
*/
define(['dojo/_base/lang', './Provider'], function(lang, Provider) {

    var i18n = new Provider({
        code: '@i18n:',
        null_value: '',
        required_type: 'string'
    });

    return i18n;
});