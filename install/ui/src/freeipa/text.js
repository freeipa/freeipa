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

define([ './_base/Provider', './_base/i18n', './metadata', './translations'],
       function(Provider, i18n, metadata) {

    /**
     * Text provider
     *
     * Serves for returning labels, titles, messages from:
     *
     * - {@link _base.i18n} provider
     * - and {@link metadata} provider
     *
     * Other providers can extends its functionality.
     *
     * @class text
     * @singleton
     * @extends _base.Provider
     */
    var text = new Provider({
        providers: [
            i18n,
            metadata
        ],
        null_value: '',
        required_type: 'string'
    });

    return text;
});
