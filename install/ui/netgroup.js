/*jsl:import ipa.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
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

IPA.entity_factories.netgroup = function() {

    return IPA.entity_builder().
        entity('netgroup').
        search_facet({
            columns:[
                'cn',
                'description'
            ]
        }).
        details_facet({
            sections:[{
                name:'identity',
                fields:[
                    'cn',
                    'description',
                    'nisdomainname']
            }]
        }).
        association_facet({
            name: 'memberhost_host',
            facet_group: 'member'
        }).
        association_facet({
            name: 'memberhost_hostgroup',
            facet_group: 'member'
        }).
        association_facet({
            name: 'memberuser_user',
            facet_group: 'member'
        }).
        association_facet({
            name: 'memberuser_group',
            facet_group: 'member'
        }).
        association_facet({
            name: 'memberof_netgroup',
            associator: IPA.serial_associator
        }).
        standard_association_facets().
        adder_dialog({
            fields:[
                'cn',
                'description'
            ]
        }).
        build();
};
