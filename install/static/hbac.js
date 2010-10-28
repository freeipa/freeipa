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

function ipa_hbac() {

    var that = ipa_entity({
        'name': 'hbac'
    });

    that.init = function() {
        that.create_add_dialog({
            'name': 'add',
            'title': 'Add New Rule',
            'init': ipa_hbac_add_init
        });

        that.create_search_facet({
            'name': 'search',
            'label': 'Search',
            'init': ipa_hbac_search_init,
            'setup': ipa_hbac_search_setup
        });

        that.create_details_facet({
            'name': 'details',
            'label': 'Details',
            'init': ipa_hbac_details_init,
            'setup': ipa_hbac_details_setup
        });

        that.create_association_facet({
            'name': 'associate'
        });
    };

    that.init();

    return that;
}

IPA.add_entity(ipa_hbac());

function ipa_hbac_add_init() {
    this.create_field({name:'cn', label:'Rule Name'});
}

function ipa_hbac_search_init() {

    this.create_column({name:'cn', label:'Rule Name'});
    this.create_column({name:'usercategory', label:'Who'});
    this.create_column({name:'hostcategory', label:'Accessing'});
    this.create_column({name:'servicecategory', label:'Via Service'});
    this.create_column({name:'sourcehostcategory', label:'From'});
    this.create_column({name:'ipaenabledflag', label:'Active'});

    this.create_column({
        name: 'quick_links',
        label: 'Quick Links',
        setup: ipa_hbac_quick_links
    });
}

function ipa_hbac_search_setup(container) {

    var facet = this;

    facet.filter = $.bbq.getState(facet.entity_name + '-filter', true) || '';

    var toolbar = $('<span/>').appendTo(container);

    $('<input/>', {
        'type': 'button',
        'value': 'Troubleshoot Rules',
        'click': function() {
        }
    }).appendTo(toolbar);

    $('<input/>', {
        'type': 'button',
        'value': 'Cull Disabled Rules',
        'click': function() {
        }
    }).appendTo(toolbar);

    $('<input/>', {
        'type': 'button',
        'value': 'Login Services',
        'click': function() {
        }
    }).appendTo(toolbar);

    $('<input/>', {
        'type': 'button',
        'value': 'Login Svc Groups',
        'click': function() {
        }
    }).appendTo(toolbar);

    search_create(facet.entity_name, facet.columns, container);

    ipa_make_button('ui-icon-plus', IPA.messages.button.add).
        click(function() {
            var entity = IPA.get_entity(facet.entity_name);
            entity.add_dialog.open();
            return false;
        }).
        appendTo($('.search-controls', container));

    search_load(container, facet.filter);
}

function ipa_hbac_quick_links(tr, attr, value, entry_attrs) {

    var column = this;
    var facet = column.facet;

    var pkey = IPA.metadata[facet.entity_name].primary_key;
    var pkey_value = entry_attrs[pkey][0];

    var td = $('<td/>').appendTo(tr);

    $('<a/>', {
        'href': '#details',
        'title': 'Details',
        'text': 'Details',
        'click': function() {
            var state = {};
            state[facet.entity_name+'-facet'] = 'details';
            state[facet.entity_name+'-pkey'] = pkey_value;
            nav_push_state(state);
            return false;
        }
    }).appendTo(td);

    td.append(' | ');

    $('<a/>', {
        'href': '#test-rule',
        'title': 'Test Rule',
        'text': 'Test Rule',
        'click': function() {
            var state = {};
            state[facet.entity_name+'-facet'] = 'test-rule';
            state[facet.entity_name+'-pkey'] = pkey_value;
            nav_push_state(state);
            return false;
        }
    }).appendTo(td);
}

function ipa_hbac_details_init() {

    var section = this.create_section({name:'general', label:'General'});
    section.create_field({name:'cn', label:'Name'});
    section.create_field({name:'accessruletype', label:'Rule Type'});
    section.create_field({name:'description', label:'Description'});
    section.create_field({name:'ipaenabledflag', label:'Enabled'});

    section = this.create_section({name:'user', label:'Who'});
    section.create_field({name:'usercategory', label:'User Category'});

    section = this.create_section({name:'host', label:'Accessing'});
    section.create_field({name:'hostcategory', label:'Host Category'});

    section = this.create_section({name:'service', label:'Via Service'});
    section.create_field({name:'servicecategory', label:'Service Category'});

    section = this.create_section({name:'sourcehost', label:'From'});
    section.create_field({name:'sourcehostcategory', label:'Source Host Category'});
}

function ipa_hbac_details_setup(container, unspecified) {

    var facet = this;

    var pkey = $.bbq.getState(facet.entity_name + '-pkey', true);
    var pkey_name = IPA.metadata[facet.entity_name].primary_key;

    facet.setup_views(container);

    var sections = facet.get_sections();
    ipa_details_create(container, sections);

    container.find('.details-reset').click(function() {
        ipa_details_reset(container);
        return false;
    });

    container.find('.details-update').click(function() {
        ipa_details_update(container, ipa_details_cache[facet.entity_name][pkey_name][0]);
        return false;
    });

    ipa_details_load(container, pkey, null, null);
}
