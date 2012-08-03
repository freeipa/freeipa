/*jsl:import ipa.js */

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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.range = {};

IPA.range.entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.search_facet({
            columns: [
                'cn',
                'ipabaseid',
                'ipaidrangesize',
                'iparangetype'
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'details',
                    fields: [
                        'cn',
                        'iparangetype',
                        {
                            name: 'ipabaseid',
                            label: IPA.messages.objects.range.ipabaseid,
                            tooltip: IPA.get_entity_param('range', 'ipabaseid').label
                        },
                        {
                            name: 'ipaidrangesize',
                            label: IPA.messages.objects.range.ipaidrangesize,
                            tooltip: IPA.get_entity_param('range', 'ipaidrangesize').label
                        },
                        {
                            name: 'ipabaserid',
                            label: IPA.messages.objects.range.ipabaserid,
                            tooltip: IPA.get_entity_param('range', 'ipabaserid').label
                        },
                        {
                            name: 'ipasecondarybaserid',
                            label: IPA.messages.objects.range.ipasecondarybaserid,
                            tooltip: IPA.get_entity_param('range', 'ipasecondarybaserid').label
                        },
                        {
                            name: 'ipanttrusteddomainsid',
                            label: IPA.messages.objects.range.ipanttrusteddomainsid,
                            tooltip: IPA.get_entity_param('range', 'ipanttrusteddomainsid').label
                        }
                    ]
                }
            ]
        }).
        adder_dialog({
            fields: [
                {
                    name: 'cn',
                    widget: 'range.cn'
                },
                {
                    name: 'ipabaseid',
                    label: IPA.messages.objects.range.ipabaseid,
                    tooltip: IPA.get_entity_param('range', 'ipabaseid').label,
                    widget: 'range.ipabaseid'
                },
                {
                    name: 'ipaidrangesize',
                    label: IPA.messages.objects.range.ipaidrangesize,
                    tooltip: IPA.get_entity_param('range', 'ipaidrangesize').label,
                    widget: 'range.ipaidrangesize'
                },
                {
                    name: 'ipabaserid',
                    label: IPA.messages.objects.range.ipabaserid,
                    tooltip: IPA.get_entity_param('range', 'ipabaserid').label,
                    widget: 'range.ipabaserid'
                },
                {
                    name: 'ipasecondarybaserid',
                    label: IPA.messages.objects.range.ipasecondarybaserid,
                    tooltip: IPA.get_entity_param('range', 'ipasecondarybaserid').label,
                    widget: 'type.ipasecondarybaserid'
                },
                {
                    name: 'ipanttrusteddomainsid',
                    label: IPA.messages.objects.range.ipanttrusteddomainsid,
                    tooltip: IPA.get_entity_param('range', 'ipanttrusteddomainsid').label,
                    widget: 'type.ipanttrusteddomainsid'
                }
            ],
            widgets: [
                {
                    type: 'details_table_section_nc',
                    name: 'range',
                    widgets: [
                        'cn',
                        'ipabaseid',
                        'ipaidrangesize',
                        'ipabaserid'
                    ]
                },
                {
                    type: 'multiple_choice_section',
                    name: 'type',
                    label: IPA.messages.objects.range.type,
                    choices: [
                        {
                            name: 'local',
                            label: IPA.messages.objects.range.type_local,
                            fields: ['ipasecondarybaserid'],
                            required: ['ipasecondarybaserid'],
                            enabled: true
                        },
                        {
                            name: 'ad',
                            label: IPA.messages.objects.range.type_ad,
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
                IPA.multiple_choice_section_policy({
                    widget: 'type'
                })
            ]
        });
    };

    return that;
};

IPA.register('range', IPA.range.entity);
