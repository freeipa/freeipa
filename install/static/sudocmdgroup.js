/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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

function ipa_sudocmdgroup() {

    var that = ipa_entity({
        'name': 'sudocmdgroup'
    });

    that.init = function() {

        that.create_association({
            'name': 'sudocmd',
            'add_method': 'add_member',
            'delete_method': 'remove_member'
        });

        var dialog = ipa_sudocmdgroup_add_dialog({
            'name': 'add',
            'title': 'Add New SUDO Command Group'
        });
        that.add_dialog(dialog);
        dialog.init();

        var facet = ipa_sudocmdgroup_search_facet({
            'name': 'search',
            'label': 'Search'
        });
        that.add_facet(facet);

        facet = ipa_sudocmdgroup_details_facet({
            'name': 'details',
            'label': 'Details'
        });
        that.add_facet(facet);

        facet = ipa_sudocmdgroup_association_facet({
            'name': 'associate'
        });
        that.add_facet(facet);

        that.entity_init();
    };

    return that;
}

IPA.add_entity(ipa_sudocmdgroup());

function ipa_sudocmdgroup_add_dialog(spec) {

    spec = spec || {};

    var that = ipa_add_dialog(spec);

    that.superior_init = that.superior('init');

    that.init = function() {

        this.superior_init();

        this.add_field(ipa_text_widget({name:'cn', label:'Name', undo: false}));
        this.add_field(ipa_text_widget({name:'description', label:'Description', undo: false}));
    };

    return that;
}

function ipa_sudocmdgroup_search_facet(spec) {

    spec = spec || {};

    var that = ipa_search_facet(spec);

    that.get_action_panel = function() {
        return $('#sudorule .action-panel');
    };

    that.init = function() {

        that.create_column({name:'cn', label:'Group', primary_key: true});
        that.create_column({name:'description', label:'Description'});

        that.search_facet_init();
    };

    that.create = function(container) {

        var action_panel = that.get_action_panel();

        var ul = $('ul', action_panel);

        $('<li/>', {
            title: 'sudorule',
            text: 'SUDO Rules'
        }).appendTo(ul);

        $('<li/>', {
            title: 'sudocmd',
            text: 'SUDO Command'
        }).appendTo(ul);

        that.search_facet_create(container);

        // TODO: replace with IPA.metadata[that.entity_name].label
        container.children().last().prepend(
            $('<h2/>', { 'html': 'SUDO Command Groups' }));
        container.children().last().prepend('<br/><br/>');

    };

    that.setup = function(container) {

        that.search_facet_setup(container);

        var action_panel = that.get_action_panel();

        var li = $('li[title=sudorule]', action_panel);
        li.click(function() {
            var state = {};
            state['sudo-entity'] = 'sudorule';
            nav_push_state(state);
            return false;
        });

        li = $('li[title=sudocmd]', action_panel);
        li.click(function() {
            var state = {};
            state['sudo-entity'] = 'sudocmd';
            nav_push_state(state);
            return false;
        });
    };

    return that;
}


function ipa_sudocmdgroup_details_facet(spec) {

    spec = spec || {};

    var that = ipa_details_facet(spec);

    that.get_action_panel = function() {
        return $('#sudorule .action-panel');
    };

    that.init = function() {

        var section = ipa_details_list_section({
            'name': 'general',
            'label': 'General'
        });
        that.add_section(section);

        section.create_field({ 'name': 'cn', 'label': 'Name' });
        section.create_field({ 'name': 'description', 'label': 'Description' });

        that.details_facet_init();
    };

    return that;
}

function ipa_sudocmdgroup_association_facet(spec) {

    spec = spec || {};

    var that = ipa_association_facet(spec);

    that.get_action_panel = function() {
        return $('#sudorule .action-panel');
    };

    return that;
}