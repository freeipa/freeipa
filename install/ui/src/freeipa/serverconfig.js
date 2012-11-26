/*jsl:import ipa.js */

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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.serverconfig = {};

IPA.serverconfig.entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.details_facet({
            title: IPA.metadata.objects.config.label,
            sections: [
                {
                    name: 'search',
                    label: IPA.messages.objects.config.search,
                    fields: [
                        'ipasearchrecordslimit',
                        'ipasearchtimelimit'
                    ]
                },
                {
                    name: 'user',
                    label: IPA.messages.objects.config.user,
                    fields: [
                        'ipausersearchfields',
                        'ipadefaultemaildomain',
                        {
                            type: 'entity_select',
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
                            type: 'checkboxes',
                            options: IPA.create_options([
                                'AllowLMhash', 'AllowNThash',
                                'KDC:Disable Last Success', 'KDC:Disable Lockout'
                            ])
                        },
                        {
                            type: 'checkbox',
                            name: 'ipamigrationenabled'
                        },
                        {
                            type: 'multivalued',
                            name: 'ipauserobjectclasses'
                        }
                    ]
                },
                {
                    name: 'group',
                    label: IPA.messages.objects.config.group,
                    fields: [
                        'ipagroupsearchfields',
                        {
                            type: 'multivalued',
                            name: 'ipagroupobjectclasses'
                        }
                    ]
                },
                {
                    name: 'selinux',
                    label: IPA.messages.objects.config.selinux,
                    fields: [
                        'ipaselinuxusermaporder',
                        'ipaselinuxusermapdefault'
                    ]
                },
                {
                    name: 'service',
                    label: IPA.messages.objects.config.service,
                    fields: [
                        {
                            name: 'ipakrbauthzdata',
                            type: 'checkboxes',
                            options: IPA.create_options(['MS-PAC', 'PAD'])
                        }
                    ]
                }
            ],
            needs_update: true
        });
    };

    return that;
};

IPA.register('config', IPA.serverconfig.entity);
