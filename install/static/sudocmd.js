/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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

function ipa_sudocmd() {

    var that = ipa_entity({
        'name': 'sudocmd'
    });

    that.init = function() {

        var dialog = ipa_sudocmd_add_dialog({
            'name': 'add',
            'title': 'Add New SUDO Command'
        });
        that.add_dialog(dialog);
        dialog.init();

        var facet = ipa_sudocmd_search_facet({
            'name': 'search',
            'label': 'Search'
        });
        that.add_facet(facet);

        facet = ipa_sudocmd_details_facet({
            'name': 'details',
            'label': 'Details'
        });
        that.add_facet(facet);

        that.entity_init();
    };

    return that;
}

IPA.add_entity(ipa_sudocmd());

function ipa_sudocmd_add_dialog(spec) {

    spec = spec || {};

    var that = ipa_add_dialog(spec);

    that.init = function() {

        that.add_field(ipa_text_widget({name:'sudocmd', undo: false}));
        that.add_field(ipa_text_widget({name:'description', undo: false}));

        that.add_dialog_init();
    };

    return that;
}

function ipa_sudocmd_search_facet(spec) {

    spec = spec || {};

    var that = ipa_search_facet(spec);

    that.init = function() {

        that.create_column({name:'sudocmd', primary_key: true});
        that.create_column({name:'description'});

        that.search_facet_init();
    };

    return that;
}


function ipa_sudocmd_details_facet(spec) {

    spec = spec || {};

    var that = ipa_details_facet(spec);

    that.init = function() {

        var section = ipa_details_list_section({
            'name': 'general',
            'label': 'General'
        });
        that.add_section(section);

        section.create_field({'name': 'sudocmd'});
        section.create_field({'name': 'description'});

        that.details_facet_init();
    };

    return that;
}