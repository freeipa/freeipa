/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
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
        './ipa',
        './jquery',
        './phases',
        './reg',
        './details',
        './search',
        './association',
        './entity'],
            function(IPA, $, phases, reg) {

var exp = IPA.hostgroup = {};

var make_spec = function() {
return {
    name: 'hostgroup',
    facets: [
        {
            $type: 'search',
            tab_label: '@i18n:objects.hostgroup.host_group',
            facet_groups: [IPA.group.search_facet_group],
            tabs_in_sidebar: true,
            disable_facet_tabs: false,
            columns: [
                'cn',
                'description'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'identity',
                    label: '@i18n:objects.hostgroup.identity',
                    fields: [
                        'cn',
                        {
                            $type: 'textarea',
                            name: 'description'
                        }
                    ]
                }
            ]
        },
        {
            $type: 'association',
            name: 'memberof_hostgroup',
            associator: IPA.serial_associator
        },
        {
            $type: 'association',
            name: 'memberof_netgroup',
            associator: IPA.serial_associator
        },
        {
            $type: 'association',
            name: 'memberof_hbacrule',
            associator: IPA.serial_associator,
            add_method: 'add_host',
            remove_method: 'remove_host'
        },
        {
            $type: 'association',
            name: 'memberof_sudorule',
            associator: IPA.serial_associator,
            add_method: 'add_host',
            remove_method: 'remove_host'
        }
    ],
    standard_association_facets: true,
    adder_dialog: {
        fields: [
            'cn',
            {
                $type: 'textarea',
                name: 'description'
            }
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.hostgroup.remove',
    },
};};


exp.entity_spec = make_spec();
exp.register = function() {
    var e = reg.entity;
    e.register({type: 'hostgroup', spec: exp.entity_spec});
};
phases.on('registration', exp.register);

return exp;
});
