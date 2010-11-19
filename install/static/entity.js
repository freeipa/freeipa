/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
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

/* REQUIRES: ipa.js, details.js, search.js, add.js */

function ipa_facet(spec) {

    spec = spec || {};

    var that = {};
    that.display_class = spec.display_class || 'entity-facet';
    that.name = spec.name;
    that.label = spec.label;
    that._entity_name = spec.entity_name;

    that.init = spec.init || init;
    that.create = spec.create || create;
    that.setup = spec.setup || setup;
    that.load = spec.load || load;

    that.__defineGetter__("entity_name", function(){
        return that._entity_name;
    });

    that.__defineSetter__("entity_name", function(entity_name){
        that._entity_name = entity_name;
    });

    that.create_action_panel = ipa_facet_create_action_panel;

    that.superior = function(name) {
        var method = that[name];
        return function () {
            return method.apply(that, arguments);
        };
    };

    function init() {
    }

    function create(container) {
    }

    function setup(container) {
        that.container = container;
    }

    function load() {
    }

    that.get_client_area = function() {
        return $('#' + that.entity_name+' .client');
    };

    that.get_action_panel = function() {
        return $('#' + that.entity_name+' .action-panel');
    };

    that.facet_init = that.init;
    that.facet_create = that.create;
    that.facet_setup = that.setup;

    return that;
}

function ipa_entity(spec) {

    spec = spec || {};

    var that = {};
    that.name = spec.name;
    that.label = spec.label;

    that.setup = spec.setup || ipa_entity_setup;

    that.dialogs = [];
    that.dialogs_by_name = {};

    that.facets = [];
    that.facets_by_name = {};

    that.facet_name = null;

    that.associations = [];
    that.associations_by_name = {};

    that.superior = function(name) {
        var method = that[name];
        return function () {
            return method.apply(that, arguments);
        };
    };

    that.get_dialog = function(name) {
        return that.dialogs_by_name[name];
    };

    that.add_dialog = function(dialog) {
        dialog.entity_name = that.name;
        that.dialogs.push(dialog);
        that.dialogs_by_name[dialog.name] = dialog;
    };

    that.get_facet = function(name) {
        return that.facets_by_name[name];
    };

    that.add_facet = function(facet) {
        facet.entity_name = that.name;
        that.facets.push(facet);
        that.facets_by_name[facet.name] = facet;
    };

    that.get_associations = function() {
        return that.associations;
    };

    that.get_association = function(name) {
        return that.associations_by_name[name];
    };

    that.add_association = function(config) {
        that.associations.push(config);
        that.associations_by_name[config.name] = config;
    };

    that.create_association = function(spec) {
        var config = ipa_association_config(spec);
        that.add_association(config);
        return config;
    };

    that.init = function() {
        for (var i=0; i<that.facets.length; i++) {
            var facet = that.facets[i];
            facet.init();
        }
    };

    that.entity_init = that.init;

    return that;
}

/* use this to track individual changes between two hashchange events */
var window_hash_cache = {};

function ipa_get_entity(entity_name) {

    var entity = IPA.get_entity(entity_name);
    if (entity) return entity;

    entity = ipa_entity({
        'name': entity_name
    });

    IPA.add_entity(entity);
    return entity;
}

function ipa_entity_get_search_facet(entity_name) {

    var entity = ipa_get_entity(entity_name);

    var facet = entity.get_facet('search');
    if (facet) return facet;

    facet = ipa_search_facet({
        'name': 'search',
        'label': 'Search'
    });
    entity.add_facet(facet);

    return facet;
}

function ipa_entity_set_search_definition(entity_name, data) {

    var facet = ipa_entity_get_search_facet(entity_name);

    for (var i=0; i<data.length; i++) {
        var defn = data[i];
        facet.create_column({
            'name': defn[0],
            'label': defn[1],
            'setup': defn[2]
        });
    }
}

function ipa_entity_set_add_definition(entity_name, data) {

    var entity = ipa_get_entity(entity_name);

    var dialog = ipa_add_dialog({
        'name': 'add',
        'title': data[1]
    });
    entity.add_dialog(dialog);
    dialog.init();

    for (var i=0; i<data[2].length; i++) {
        var field = data[2][i];
        dialog.add_field(ipa_text_widget({
            name: field[0],
            label: field[1],
            setup: field[2],
            undo: false
        }));
    }
}

function ipa_entity_get_add_dialog(entity_name) {

    var entity = ipa_get_entity(entity_name);
    return entity.get_add_dialog();
}

function ipa_entity_get_details_facet(entity_name) {

    var entity = ipa_get_entity(entity_name);

    var facet = entity.get_facet('details');
    if (facet) return facet;

    facet = ipa_details_facet({
        'name': 'details',
        'label': 'Details'
    });
    entity.add_facet(facet);

    return facet;
}

function ipa_entity_set_details_definition(entity_name, sections) {

    var facet = ipa_entity_get_details_facet(entity_name);

    for (var i=0; i<sections.length; i++) {
        var section = sections[i];
        facet.add_section(section);
    }
}

function ipa_entity_get_association_facet(entity_name) {

    var entity = ipa_get_entity(entity_name);

    var facet = entity.get_facet('associate');
    if (facet) return facet;

    facet = ipa_association_facet({
        'name': 'associate'
    });
    entity.add_facet(facet);

    return facet;
}

function ipa_entity_set_association_definition(entity_name, data) {

    var entity = ipa_get_entity(entity_name);

    ipa_entity_get_association_facet(entity_name);

    for (var other_entity in data) {
        var config = data[other_entity];
        entity.create_association({
            'name': other_entity,
            'associator': config.associator,
            'add_method': config.add_method,
            'delete_method': config.delete_method
        });
    }
}

function ipa_entity_set_facet_definition(entity_name, list) {

    var entity = ipa_get_entity(entity_name);

    for (var i=0; i<list.length; i++) {
        var facet = list[i];
        entity.add_facet(facet);
    }
}

function ipa_details_only_setup(container){
    ipa_entity_setup.call(this, container, 'details');
}

function ipa_current_facet(entity){
    return $.bbq.getState(entity.name + '-facet', true) || entity.default_facet || 'search';
}

function ipa_entity_setup(container) {

    var entity = this;

    var facet_name = ipa_current_facet(entity);


    var facet = entity.get_facet(facet_name);
    if (!facet) return;

    if (IPA.entity_name == entity.name) {
        if (entity.facet_name == facet_name) {
            if (!facet.is_dirty()) return;

        } else {
            entity.facet_name = facet_name;
        }
    } else {
        IPA.entity_name = entity.name;
    }

    container.empty();

    facet.create_action_panel(container);
    facet.create(container);
    container.children().last().addClass('client');
    facet.setup(container);
    facet.refresh();
}



function ipa_facet_create_action_panel(container) {

    var that = this;
    var entity_name = that.entity_name;

    var action_panel = $('<div/>', {
        "class": "action-panel",
        html: $('<h3>Actions</h3>')
    }).appendTo(container);

    function build_link(other_facet,label,other_entity){
        var li = $('<li/>', {
            "class" : other_facet.display_class,
            title: other_entity,
            text: label,
            click: function(entity_name, other_facet_name) {
                    return function() {
                        if($(this).hasClass('entity-facet-disabled')){
                            return false;
                        }
                        var this_pkey = $('input[id=pkey]', action_panel).val();
                        IPA.switch_and_show_page(
                            entity_name, other_facet_name,
                            this_pkey, other_entity);

                        return false;
                    };
                }(entity_name, other_facet_name)
            });
        return li;
    }

    /*Note, for debugging purposes, it is useful to set var pkey_type = 'text';*/
    var pkey_type = 'hidden';
    $('<input/>', {
        'type': pkey_type,
        id:'pkey',
        name:'pkey'
    }).appendTo(action_panel);

    var ul = $('<ul/>', {'class': 'action'}).appendTo(action_panel);

    var entity = IPA.get_entity(entity_name);
    var facet_name =  ipa_current_facet(entity);

    for (var i=0; i<entity.facets.length; i++) {
        var other_facet = entity.facets[i];
        var other_facet_name = other_facet.name;

        if (other_facet.label) {
            ul.append(build_link(other_facet,other_facet.label));

        } else { // For now empty label indicates an association facet
            var attribute_members = IPA.metadata[entity_name].attribute_members;
            for (var attribute_member in attribute_members) {
                var other_entities = attribute_members[attribute_member];
                for (var j = 0; j < other_entities.length; j++) {
                    var other_entity = other_entities[j];
                    var label = IPA.metadata[other_entity].label;
                    ul.append(build_link(other_facet,label,other_entity));
                }
            }
        }
    }

    /*When we land on the search page, disable all facets
      that require a pkey until one is selected*/
    if (facet_name === 'search'){
        $('.entity-facet', action_panel).addClass('entity-facet-disabled');
    }

    return action_panel;
}
