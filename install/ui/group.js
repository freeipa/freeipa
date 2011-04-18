/*jsl:import ipa.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Endi Dewata <edewata@redhat.com>
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

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */

IPA.entity_factories.group =  function () {

    return IPA.entity_builder().
        entity('group').
        search_facet({
            columns:['cn','gidnumber','description']
        }).
        details_facet({sections:
            [{
                name:'details',
                fields:['cn','description','gidnumber']
            }]}).
        association_facet({
            name: 'member_user',
            columns:[
                {
                    name: 'uid',
                    primary_key: true,
                    link_entity: true
                },
                {name: 'uidnumber'},
                {name: 'mail'},
                {name: 'telephonenumber'},
                {name: 'title'}
            ],
            adder_columns:[
                {
                    name: 'cn',
                    width: '100px'
                },
                {
                    name: 'uid',
                    primary_key: true,
                    width: '100px'
                }
            ]

        }).
        association_facet({
                name: 'memberof_group',
                associator: IPA.serial_associator
        }).
        association_facet({
            name: 'memberof_netgroup',
            associator: IPA.serial_associator
        }).
        association_facet({
            name: 'memberof_role',
            associator: IPA.serial_associator
        }).
        standard_association_facets().
        adder_dialog({
            fields: [
                'cn',
                'description',
                {
                    factory:IPA.checkbox_widget,
                    name: 'posix',
                    label: IPA.messages.objects.group.posix,
                    undo: false,
                    checked: 'checked'
                },
                'gidnumber']
        }).
        build();
};
