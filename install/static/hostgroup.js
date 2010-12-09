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


IPA.add_entity( function() {
    var that = ipa_entity({
        'name': 'hostgroup'
    });
    that.init = function() {
        var search_facet = ipa_search_facet({
            name: 'search',
            label: 'Search',
            entity_name: that.name
        });
        search_facet.create_column({name:'cn'});
        search_facet.create_column({name:'description'});
        that.add_facet(search_facet);

        that.add_facet(function() {
            var that = ipa_details_facet({name:'details',label:'Details'});
            that.add_section(
                ipa_stanza({name:'identity', label:'Hostgroup Details'}).
                    input({name:'cn'}).
                    input({name: 'description'}));
            return that;
        }());


        var dialog = ipa_add_dialog({
            name: 'add',
            title: 'Add Hostgroup'
        });
        that.add_dialog(dialog);

        dialog.add_field(ipa_text_widget({name: 'cn', undo: false}));
        dialog.add_field(ipa_text_widget({name: 'description', undo: false}));
        dialog.init();

        that.create_association_facets();
        that.entity_init();
    };
    return that;
}());



