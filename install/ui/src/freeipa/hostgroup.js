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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.hostgroup = {};

IPA.hostgroup.entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.search_facet({
            columns: [
                'cn',
                'description'
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'identity',
                    label: IPA.messages.objects.hostgroup.identity,
                    fields: [
                        'cn',
                        {
                            type: 'textarea',
                            name: 'description'
                        }
                    ]
                }
            ]
        }).
        association_facet({
            name: 'memberof_hostgroup',
            associator: IPA.serial_associator
        }).
        association_facet({
            name: 'memberof_netgroup',
            associator: IPA.serial_associator
        }).
        association_facet({
            name: 'memberof_hbacrule',
            associator: IPA.serial_associator,
            add_method: 'add_host',
            remove_method: 'remove_host'
        }).
        association_facet({
            name: 'memberof_sudorule',
            associator: IPA.serial_associator,
            add_method: 'add_host',
            remove_method: 'remove_host'
        }).
        standard_association_facets().
        adder_dialog({
            fields: [
                'cn',
                {
                    type: 'textarea',
                    name: 'description'
                }
            ]
        });
    };

    return that;
};

IPA.register('hostgroup', IPA.hostgroup.entity);
