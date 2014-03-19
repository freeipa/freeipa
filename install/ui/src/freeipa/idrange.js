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
                name: 'cn'
            },
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
                name: 'iparangetype',
                $type: 'radio',
                label: '@i18n:objects.idrange.type',
                layout: 'vertical',
                default_value: 'ipa-local',
                options: [
                    {
                        value: 'ipa-local',
                        label: '@i18n:objects.idrange.type_local'
                    },
                    {
                        value: 'ipa-ad-trust',
                        label: '@i18n:objects.idrange.type_ad'
                    },
                    {
                        value: 'ipa-ad-trust-posix',
                        label: '@i18n:objects.idrange.type_ad_posix'
                    },
                    {
                        value: 'ipa-ad-winsync',
                        label: '@i18n:objects.idrange.type_winsync'
                    },
                    {
                        value: 'ipa-ipa-trust',
                        label: '@i18n:objects.idrange.type_ipa'
                    }
                ]
            },
            {
                name: 'ipasecondarybaserid',
                label: '@i18n:objects.idrange.ipasecondarybaserid',
                tooltip: '@mo-param:idrange:ipasecondarybaserid:label'
            },
            {
                name: 'ipanttrusteddomainsid',
                label: '@i18n:objects.idrange.ipanttrusteddomainsid',
                tooltip: '@mo-param:idrange:ipanttrusteddomainsid:label',
                enabled: false
            }
        ],
        policies: [
                IPA.idrange_adder_policy
        ]
    }
};};

IPA.idrange_adder_policy = function(spec) {
    /*
    The logic for enabling/requiring ipabaserid, ipasecondarybaserid and
    ipanttrusteddomainsid is as follows:
        1) for AD ranges (range type is ipa-ad-trust or ipa-ad-trust-posix):
           * ipabaserid and ipanttrusteddomainsid are requred
           * ipasecondarybaserid is disabled
        2) for local ranges
           *  ipanttrusteddomainsid is disabled
           A) if server has AD trust support:
              * both ipabaserid and ipasecondarybaserid are required
           B) if server does not have AD trust support:
              * ipabaserid and ipasecondarybaserid may only be used together
                (if one is set, other is required and vice versa)
     */

    function require(field) {
        field.set_enabled(true);
        field.set_required(true);
    }

    function disable(field) {
        field.reset();
        field.set_required(false);
        field.set_enabled(false);
    }

    function enable(field) {
        field.set_enabled(true);
        field.set_required(false);
    }

    spec = spec || {};

    var that = IPA.facet_policy(spec);

    that.init = function() {
        var type_f = that.container.fields.get_field('iparangetype');
        var baserid_f = that.container.fields.get_field('ipabaserid');
        var secondarybaserid_f = that.container.fields.get_field('ipasecondarybaserid');

        if (IPA.trust_enabled) {
            require(baserid_f);
            require(secondarybaserid_f);
        }

        type_f.widget.value_changed.attach(that.on_input_change);
        baserid_f.widget.value_changed.attach(that.on_input_change);
        secondarybaserid_f.widget.value_changed.attach(that.on_input_change);
    };

    that.on_input_change = function() {
        var type_f = that.container.fields.get_field('iparangetype');
        var baserid_f = that.container.fields.get_field('ipabaserid');
        var secondarybaserid_f = that.container.fields.get_field('ipasecondarybaserid');
        var trusteddomainsid_f = that.container.fields.get_field('ipanttrusteddomainsid');

        var type_v = type_f.save()[0];
        var baserid_v = baserid_f.save()[0] || '';
        var secondarybaserid_v = secondarybaserid_f.save()[0] || '';

        var is_ad_range = (type_v === 'ipa-ad-trust' || type_v === 'ipa-ad-trust-posix');

        if (is_ad_range) {
            require(baserid_f);
            require(trusteddomainsid_f);
            disable(secondarybaserid_f);
        } else {
            disable(trusteddomainsid_f);

            if (IPA.trust_enabled) {
                require(baserid_f);
                require(secondarybaserid_f);
            } else {
                if (baserid_v || secondarybaserid_v) {
                    require(baserid_f);
                    require(secondarybaserid_f);
                } else {
                    enable(baserid_f);
                    enable(secondarybaserid_f);
                }
            }
        }
    };

    return that;
};

exp.entity_spec = make_spec();
exp.register = function() {
    var e = reg.entity;
    e.register({type: 'idrange', spec: exp.entity_spec});
};
phases.on('registration', exp.register);

return {};
});