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
define([], function() {

    /**
     * Debug module
     *
     * One can set flags to enable console output of various messages.
     *
     * """
     * var debug = require('freeipa._base.debug');
     * debug.provider_missing_value = true;
     * """
     *
     * Currently used flags
     *
     * - provider_missing_value
     *
     * @class _base.debug
     */
    return {
        provider_missing_value: false
    };
});