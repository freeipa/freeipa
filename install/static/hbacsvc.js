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

function ipa_hbacsvc() {

    var that = ipa_entity({
        'name': 'hbacsvc'
    });

    that.superior_init = that.superior('init');

    that.init = function() {

        var dialog = ipa_hbacsvc_add_dialog({
            'name': 'add',
            'title': 'Add New HBAC Service'
        });
        that.add_dialog(dialog);
        dialog.init();

        var facet = ipa_hbacsvc_search_facet({
            'name': 'search',
            'label': 'Search'
        });
        that.add_facet(facet);

        facet = ipa_hbacsvc_details_facet({
            'name': 'details',
            'label': 'Details'
        });
        that.add_facet(facet);

        that.superior_init();
    };

    return that;
}

IPA.add_entity(ipa_hbacsvc());

function ipa_hbacsvc_add_dialog(spec) {

    spec = spec || {};

    var that = ipa_add_dialog(spec);

    that.superior_init = that.superior('init');

    that.init = function() {

        this.superior_init();

        this.add_field(ipa_text_widget({name:'cn', label:'Name'}));
        this.add_field(ipa_text_widget({name:'description', label:'Description'}));
    };

    return that;
}

function ipa_hbacsvc_search_facet(spec) {

    spec = spec || {};

    var that = ipa_search_facet(spec);

    that.superior_init = that.superior('init');
    that.superior_create = that.superior('create');
    that.superior_setup = that.superior('setup');

    that.init = function() {

        that.create_column({name:'cn', label:'Service', primary_key: true});
        that.create_column({name:'description', label:'Description'});

        that.create_column({
            name: 'quick_links',
            label: 'Quick Links',
            setup: ipa_hbacsvc_quick_links
        });

        that.superior_init();
    };

    that.create = function(container) {

        var that = this;

        // TODO: replace with IPA.metadata[that.entity_name].label
        $('<h2/>', { 'html': 'HBAC Services' }).appendTo(container);

        var right_buttons = $('<li/>', {
            'style': 'float: right;'
        }).appendTo($('.action-panel ul'));

        right_buttons.append(ipa_button({
            'label': 'HBAC Rules',
            'click': function() {
                var state = {};
                state['entity'] = 'hbac';
                nav_push_state(state);
                return false;
            }
        }));

        right_buttons.append(ipa_button({
            'label': 'HBAC Service Groups',
            'click': function() {
                var state = {};
                state['entity'] = 'hbacsvcgroup';
                nav_push_state(state);
                return false;
            }
        }));

        container.append('<br/><br/>');

        that.superior_create(container);
    };

    return that;
}


function ipa_hbacsvc_quick_links(container, name, value, record) {

    var that = this;

    var pkey = IPA.metadata[that.entity_name].primary_key;
    var pkey_value = record[pkey];

    var link = $('<a/>', {
        'href': '#details',
        'title': 'Details',
        'text': 'Details',
        'click': function() {
            var state = {};
            state[that.entity_name+'-facet'] = 'details';
            state[that.entity_name+'-pkey'] = pkey_value;
            nav_push_state(state);
            return false;
        }
    });

    var span = $('span[name="'+name+'"]', container);
    span.html(link);
}

function ipa_hbacsvc_details_facet(spec) {

    spec = spec || {};

    var that = ipa_details_facet(spec);

    that.superior_init = that.superior('init');
    that.superior_create = that.superior('create');
    that.superior_setup = that.superior('setup');

    that.init = function() {

        var section = that.create_section({
            'name': 'general',
            'label': 'General'
        });

        section.create_field({ 'name': 'cn', 'label': 'Name' });
        section.create_field({ 'name': 'description', 'label': 'Description' });

        that.superior_init();
    };

    return that;
}