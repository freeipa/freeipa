/*  Authors:
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

var exp = IPA.idrange = {};

var make_spec = function() {
return {
    name: 'idrange',
    facets: [
        {
            $type: 'search',
            columns: [
                'cn',
                'ipabaseid',
                'ipaidrangesize',
                'iparangetype'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'details',
                    fields: [
                        'cn',
                        'iparangetype',
                        {
                            name: 'ipabaseid',
                            label: '@i18n:objects.idrange.ipabaseid',
                            tooltip: '@mo-param:idrange:ipabaseid:label'
                        },
                        {
                            name: 'ipaidrangesize',
                            label: '@i18n:objects.idrange.ipaidrangesize',
                            tooltip: '@mo-param:idrange:ipaidrangesize:label'
                        },
                        {
                            name: 'ipabaserid',
                            label: '@i18n:objects.idrange.ipabaserid',
                            tooltip: '@mo-param:idrange:ipabaserid:label'
                        },
                        {
                            name: 'ipasecondarybaserid',
                            label: '@i18n:objects.idrange.ipasecondarybaserid',
                            tooltip: '@mo-param:idrange:ipasecondarybaserid:label'
                        },
                        {
                            name: 'ipanttrusteddomainsid',
                            label: '@i18n:objects.idrange.ipanttrusteddomainsid',
                            tooltip: '@mo-param:idrange:ipanttrusteddomainsid:label'
                        }
                    ]
                }
            ]
        }
    ],
    adder_dialog: {
        fields: [
            {
                name: 'cn',
                widget: 'idrange.cn'
            },
            {
                name: 'ipabaseid',
                label: '@i18n:objects.idrange.ipabaseid',
                tooltip: '@mo-param:idrange:ipabaseid:label',
                widget: 'idrange.ipabaseid'
            },
            {
                name: 'ipaidrangesize',
                label: '@i18n:objects.idrange.ipaidrangesize',
                tooltip: '@mo-param:idrange:ipaidrangesize:label',
                widget: 'idrange.ipaidrangesize'
            },
            {
                name: 'ipabaserid',
                label: '@i18n:objects.idrange.ipabaserid',
                tooltip: '@mo-param:idrange:ipabaserid:label',
                widget: 'idrange.ipabaserid'
            },
            {
                name: 'ipasecondarybaserid',
                label: '@i18n:objects.idrange.ipasecondarybaserid',
                tooltip: '@mo-param:idrange:ipasecondarybaserid:label',
                widget: 'type.ipasecondarybaserid'
            },
            {
                name: 'ipanttrusteddomainsid',
                label: '@i18n:objects.idrange.ipanttrusteddomainsid',
                tooltip: '@mo-param:idrange:ipanttrusteddomainsid:label',
                widget: 'type.ipanttrusteddomainsid'
            }
        ],
        widgets: [
            {
                $type: 'details_table_section_nc',
                name: 'idrange',
                widgets: [
                    'cn',
                    'ipabaseid',
                    'ipaidrangesize',
                    'ipabaserid'
                ]
            },
            {
                $type: 'multiple_choice_section',
                name: 'type',
                label: '@i18n:objects.idrange.type',
                choices: [
                    {
                        name: 'local',
                        label: '@i18n:objects.idrange.type_local',
                        fields: ['ipasecondarybaserid'],
                        required: ['ipasecondarybaserid'],
                        enabled: true
                    },
                    {
                        name: 'ad',
                        label: '@i18n:objects.idrange.type_ad',
                        fields: ['ipanttrusteddomainsid'],
                        required: ['ipanttrusteddomainsid']
                    }
                ],
                widgets: [
                    'ipasecondarybaserid',
                    'ipanttrusteddomainsid'
                ]
            }
        ],
        policies: [
            {
                $factory: IPA.multiple_choice_section_policy,
                widget: 'type'
            }
        ]
    }
};};

exp.entity_spec = make_spec();
exp.register = function() {
    var e = reg.entity;
    e.register({type: 'idrange', spec: exp.entity_spec});
};
phases.on('registration', exp.register);

return {};
});