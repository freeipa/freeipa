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

function ipa_hbacsvcgroup() {

    var that = ipa_entity({
        'name': 'hbacsvcgroup'
    });

    that.init = function() {

        that.create_association({
            'name': 'hbacsvc',
            'add_method': 'add_member',
            'delete_method': 'remove_member'
        });

        var dialog = ipa_hbacsvcgroup_add_dialog({
            'name': 'add',
            'title': 'Add New HBAC Service Group'
        });
        that.add_dialog(dialog);
        dialog.init();

        var facet = ipa_hbacsvcgroup_search_facet({
            'name': 'search',
            'label': 'Search'
        });
        that.add_facet(facet);

        facet = ipa_hbacsvcgroup_details_facet({
            'name': 'details',
            'label': 'Details'
        });
        that.add_facet(facet);

        facet = ipa_hbacsvcgroup_member_hbacsvc_facet({
            'name': 'member_hbacsvc',
            'label': 'Services',
            'other_entity': 'hbacsvc'
        });
        that.add_facet(facet);

        that.entity_init();
    };

    return that;
}

IPA.add_entity(ipa_hbacsvcgroup());

function ipa_hbacsvcgroup_add_dialog(spec) {

    spec = spec || {};

    var that = ipa_add_dialog(spec);

    that.superior_init = that.superior('init');

    that.init = function() {

        that.superior_init();

        that.add_field(ipa_text_widget({name:'cn', label:'Name', undo: false}));
        that.add_field(ipa_text_widget({name:'description', label:'Description', undo: false}));
    };

    return that;
}

function ipa_hbacsvcgroup_search_facet(spec) {

    spec = spec || {};

    var that = ipa_search_facet(spec);

    that.init = function() {

        that.create_column({name:'cn', label:'Group', primary_key: true});
        that.create_column({name:'description', label:'Description'});

        that.search_facet_init();
    };

    that.create = function(container) {
        that.search_facet_create(container);
        container.children().last().prepend(
            $('<h2/>', { 'html':IPA.metadata.hbacsvcgroup.label }));
        container.children().last().prepend('<br/><br/>');
    };

    that.setup = function(container) {

        that.search_facet_setup(container);

        var action_panel = that.get_action_panel();

        var li = $('li[title=hbac]', action_panel);
        li.click(function() {
            var state = {};
            state['hbac-entity'] = 'hbac';
            nav_push_state(state);
            return false;
        });

        li = $('li[title=hbacsvc]', action_panel);
        li.click(function() {
            var state = {};
            state['hbac-entity'] = 'hbacsvc';
            nav_push_state(state);
            return false;
        });
    };

    return that;
}


function ipa_hbacsvcgroup_details_facet(spec) {

    spec = spec || {};

    var that = ipa_details_facet(spec);

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

function ipa_hbacsvcgroup_member_hbacsvc_facet(spec) {

    spec = spec || {};

    var that = ipa_association_facet(spec);

    that.init = function() {

        var column = that.create_column({
            name: 'cn',
            label: 'Service',
            primary_key: true
        });

        column.setup = function(container, record) {
            container.empty();

            var value = record[column.name];
            value = value ? value.toString() : '';

            $('<a/>', {
                'href': '#'+value,
                'html': value,
                'click': function (value) {
                    return function() {
                        var state = IPA.tab_state(that.other_entity);
                        state[that.other_entity + '-facet'] = 'details';
                        state[that.other_entity + '-pkey'] = value;
                        $.bbq.pushState(state);
                        return false;
                    }
                }(value)
            }).appendTo(container);
        };

        that.create_column({name: 'description', label: 'Description'});

        that.association_facet_init();
    };

    return that;
}