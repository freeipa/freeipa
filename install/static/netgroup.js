/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */

IPA.add_entity( function() {
    var that = ipa_entity({
        'name': 'netgroup'
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
                ipa_stanza({name:'identity', label:'Netgroup Details'}).
                    input({name:'cn'}).
                    input({name: 'description'}).
                    input({name:'nisdomainname'}));
            return that;
        }());


        var dialog = ipa_add_dialog({
            name: 'add',
            title: 'Add Netgroup',
            entity_name:'netgroup'
        });

        that.add_dialog(dialog);
        dialog.init();
        dialog.add_field(ipa_text_widget({ name: 'cn',
                                           entity_name:'netgroup'}));
        dialog.add_field(ipa_text_widget({ name: 'description',
                                           entity_name:'netgroup' }));
        that.create_association_facets();
        that.entity_init();
    }
    return that;
}());



