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

define([
        'dojo/_base/lang',
        './_base/Provider',
        './_base/Search_provider'
    ], function(lang, Provider, Search_provider) {

    var metadata = new Provider({
        code: '@m:'
    });
    var objects = new Provider({
        code: '@mo:',
        source: metadata,
        path: 'objects'
    });
    var commands = new Provider({
        code: '@mc:',
        source: metadata,
        path: 'commands'
    });
    var object_param = new Search_provider({
        code: '@mo-param:',
        source: metadata,
        path: 'objects',
        base_query: '%1.takes_params',
        array_attr: 'name'
    });
    var cmd_arg = new Search_provider({
        code: '@mc-arg:',
        source: metadata,
        path: 'commands',
        base_query: '%1.takes_args',
        array_attr: 'name'
    });
    var cmd_option = new Search_provider({
        code: '@mc-opt:',
        source: metadata,
        path: 'commands',
        base_query: '%1.takes_options',
        array_attr: 'name'
    });

    metadata.providers.push(objects, commands, object_param, cmd_arg, cmd_option);

    return metadata;
});