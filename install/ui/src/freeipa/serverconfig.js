/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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

var exp = IPA.serverconfig = {};

var make_spec = function() {
return {
    name: 'config',
    defines_key: false,
    facets: [
        {
            $type: 'details',
            title: '@mo:config.label',
            sections: [
                {
                    name: 'search',
                    label: '@i18n:objects.config.search',
                    fields: [
                        'ipasearchrecordslimit',
                        'ipasearchtimelimit'
                    ]
                },
                {
                    name: 'server',
                    label: '@i18n:objects.config.server',
                    fields: [
                        {
                            $type: 'entity_select',
                            name: 'ca_renewal_master_server',
                            other_entity: 'server',
                            other_field: 'cn',
                            flags: ['w_if_no_aci']
                        },
                        {
                            $type: 'multivalued',
                            name: 'pkinit_server_server',
                            read_only: true
                        }
                    ]
                },
                {
                    name: 'user',
                    label: '@i18n:objects.config.user',
                    fields: [
                        'ipausersearchfields',
                        'ipadefaultemaildomain',
                        {
                            name: 'ipadomainresolutionorder',
                            tooltip: '@mc-opt:config_mod:ipadomainresolutionorder:doc'
                        },
                        {
                            $type: 'entity_select',
                            name: 'ipadefaultprimarygroup',
                            other_entity: 'group',
                            other_field: 'cn'
                        },
                        'ipahomesrootdir',
                        'ipadefaultloginshell',
                        'ipamaxusernamelength',
                        'ipapwdexpadvnotify',
                        {
                            name: 'ipaconfigstring',
                            $type: 'checkboxes',
                            options: IPA.create_options([
                                'AllowNThash',
                                'KDC:Disable Last Success', 'KDC:Disable Lockout'
                            ])
                        },
                        {
                            $type: 'checkboxes',
                            name: 'ipauserauthtype',
                            flags: ['w_if_no_aci'],
                            options: [
                                { label: '@i18n:authtype.type_disabled', value: 'disabled' },
                                { label: '@i18n:authtype.type_password', value: 'password' },
                                { label: '@i18n:authtype.type_radius', value: 'radius' },
                                { label: '@i18n:authtype.type_otp', value: 'otp' },
                                { label: '@i18n:authtype.type_pkinit', value: 'pkinit' },
                                { label: '@i18n:authtype.type_hardened', value: 'hardened' }
                            ],
                            tooltip: {
                                title: '@i18n:authtype.config_tooltip',
                                html: true
                            }
                        },
                        {
                            $type: 'checkbox',
                            name: 'ipamigrationenabled'
                        },
                        {
                            $type: 'multivalued',
                            name: 'ipauserobjectclasses'
                        }
                    ]
                },
                {
                    name: 'group',
                    label: '@i18n:objects.config.group',
                    fields: [
                        'ipagroupsearchfields',
                        {
                            $type: 'multivalued',
                            name: 'ipagroupobjectclasses'
                        }
                    ]
                },
                {
                    name: 'selinux',
                    label: '@i18n:objects.config.selinux',
                    fields: [
                        'ipaselinuxusermaporder',
                        'ipaselinuxusermapdefault'
                    ]
                },
                {
                    name: 'service',
                    label: '@i18n:objects.config.service',
                    fields: [
                        {
                            name: 'ipakrbauthzdata',
                            $type: 'checkboxes',
                            options: IPA.create_options(['MS-PAC', 'PAD', 'nfs:NONE'])
                        }
                    ]
                }
            ],
            needs_update: true
        }
    ]
};};

exp.entity_spec = make_spec();
exp.register = function() {
    var e = reg.entity;
    e.register({type: 'config', spec: exp.entity_spec});
};
phases.on('registration', exp.register);

return {};
});
