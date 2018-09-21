/*  Authors:
 *    Adam Young <ayoung@redhat.com>
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

var exp = {};
exp.pwpolicy = IPA.pwpolicy = {};

var make_pwpolicy_spec = function() {
return {
    name: 'pwpolicy',
    facets: [
        {
            $type: 'search',
            sort_enabled: false,
            columns:['cn','cospriority']
        },
        {
            $type: 'details',
            sections:[
                {
                    name : 'identity',
                    fields:[
                        {
                            $type: 'link',
                            name: 'cn',
                            other_entity: 'group'
                        },
                        'krbmaxpwdlife',
                        'krbminpwdlife',
                        {
                            name: 'krbpwdhistorylength',
                            measurement_unit: 'number_of_passwords'
                        },
                        'krbpwdmindiffchars',
                        'krbpwdminlength',
                        'krbpwdmaxfailure',
                        {
                            name: 'krbpwdfailurecountinterval',
                            measurement_unit: 'seconds'
                        },
                        {
                            name: 'krbpwdlockoutduration',
                            measurement_unit: 'seconds'
                        },
                        {
                            name: 'cospriority',
                            required: true
                        }
                    ]
                }]
        }
    ],
    standard_association_facets: true,
    adder_dialog: {
        title: '@i18n:objects.pwpolicy.add',
        fields: [
            {
                $type: 'entity_select',
                name: 'cn',
                other_entity: 'group',
                other_field: 'cn',
                required: true
            },
            {
                name: 'cospriority',
                required: true
            }
        ],
        height: 300
    },
    deleter_dialog: {
        title: '@i18n:objects.pwpolicy.remove'
    }
};};

exp.krbtpolicy = IPA.krbtpolicy = {};

var make_krbtpolicy_spec = function() {
return {
    name: 'krbtpolicy',
    facets: [
        {
            $type: 'details',
            title: '@mo:krbtpolicy.label',
            sections: [
                {
                    name: 'identity',
                    fields: [
                        {
                            name: 'krbmaxrenewableage',
                            measurement_unit: 'seconds'
                        },
                        {
                            name: 'krbmaxticketlife',
                            measurement_unit: 'seconds'
                        }
                    ]
                }
            ],
            needs_update: true
        }
    ]
};};

exp.pwpolicy_spec = make_pwpolicy_spec();
exp.krbtpolicy_spec = make_krbtpolicy_spec();
exp.register = function() {
    var e = reg.entity;
    e.register({type: 'pwpolicy', spec: exp.pwpolicy_spec});
    e.register({type: 'krbtpolicy', spec: exp.krbtpolicy_spec});
};
phases.on('registration', exp.register);

return exp;
});
