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


IPA.entity_factories.hostgroup = function() {

    var that = IPA.entity({
        'name': 'hostgroup'
    });

    that.init = function() {

        that.facet(
            IPA.search_facet({
                name: 'search',
                label: IPA.messages.facets.search,
                entity_name: that.name
            }).
                column({name:'cn'}).
                column({name:'description'}).
                dialog(
                    IPA.add_dialog({
                        name: 'add',
                        title: IPA.messages.objects.hostgroup.add
                    }).
                        field(IPA.text_widget({name: 'cn', undo: false})).
                        field(IPA.text_widget({name: 'description', undo: false}))));

        that.facet(
            IPA.details_facet({name:'details'}).
                section(
                    IPA.stanza({
                        name: 'identity',
                        label: IPA.messages.objects.hostgroup.identity
                    }).
                        input({name:'cn'}).
                        input({name: 'description'})));

        that.facet(
            IPA.association_facet({
                name: 'memberof_hostgroup',
                associator: IPA.serial_associator
            }));

        that.create_association_facets();
        that.entity_init();
    };

    return that;
};



