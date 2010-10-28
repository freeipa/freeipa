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
    that.name = spec.name;
    that.label = spec.label;
    that.entity_name = spec.entity_name;

    that.init = spec.init;
    that.setup = spec.setup;

    that.setup_views = ipa_facet_setup_views;

    return that;
}

function ipa_entity(spec) {

    spec = spec || {};

    var that = {};
    that.name = spec.name;
    that.label = spec.label;

    that.setup = spec.setup;

    that.add_dialog = null;

    that.facets = [];
    that.facets_by_name = {};

    this.facet_name = null;

    that.get_add_dialog = function() {
        return that.add_dialog;
    };

    that.create_add_dialog = function(spec) {
        spec.entity_name = that.name;
        that.add_dialog = ipa_add_dialog(spec);
        return that.add_dialog;
    };

    that.get_facets = function() {
        return that.facets;
    };

    that.get_facet = function(name) {
        return that.facets_by_name[name];
    };

    that.add_facet = function(facet) {
        that.facets.push(facet);
        that.facets_by_name[facet.name] = facet;
    };

    that.create_search_facet = function(spec) {
        spec.entity_name = that.name;
        var facet = ipa_search_facet(spec);
        that.add_facet(facet);
        return facet;
    };

    that.create_details_facet = function(spec) {
        spec.entity_name = that.name;
        var facet = ipa_details_facet(spec);
        that.add_facet(facet);
        return facet;
    };

    that.create_association_facet = function(spec) {
        spec.entity_name = that.name;
        var facet = ipa_association_facet(spec);
        that.add_facet(facet);
        return facet;
    };

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

    facet = entity.create_search_facet({
        'name': 'search',
        'label': 'Search'
    });

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

    var dialog = entity.create_add_dialog({
        'name': data[0],
        'title': data[1]
    });

    for (var i=0; i<data[2].length; i++) {
        var field = data[2][i];
        dialog.create_field({
            name: field[0],
            label: field[1],
            setup: field[2]
        });
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

    facet = entity.create_details_facet({
        'name': 'details',
        'label': 'Details'
    });

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

    facet = entity.create_association_facet({
        'name': 'associate'
    });

    return facet;
}

function ipa_entity_set_association_definition(entity_name, data) {

    var facet = ipa_entity_get_association_facet(entity_name);

    for (var other_entity in data) {
        var config = data[other_entity];
        facet.create_config({
            'name': other_entity,
            'associator': config.associator,
            'method': config.method
        });
    }
}

function ipa_entity_set_facet_definition(entity_name, list) {

    var entity = ipa_get_entity(entity_name);

    for (var i=0; i<list.length; i++) {
        var facet = list[i];
        facet.entity_name = entity_name;
        entity.add_facet(facet);
    }
}

function ipa_details_only_setup(container){
    ipa_entity_setup.call(this, container, 'details');
}

function ipa_entity_setup(container, unspecified) {

    var entity = this;

    container.empty();

    var facet_name = $.bbq.getState(entity.name + '-facet', true) || unspecified || 'search';

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

    if (facet.setup) {
        facet.setup(container, unspecified);
    }
}

function ipa_facet_setup_views(container) {

    var facet = this;

    var ul = $('<ul/>', {'class': 'entity-views'});

    var entity = IPA.get_entity(facet.entity_name);
    var facets = entity.get_facets();

    for (var i=0; i<facets.length; i++) {
        var other_facet = facets[i];
        var facet_name = other_facet.name;

        if (other_facet.label) {

            var label = other_facet.label;
            if (i > 0) label = '| '+label;

            ul.append($('<li/>', {
                title: other_facet.name,
                text: label,
                click: function(entity_name, facet_name) {
                    return function() { IPA.show_page(entity_name, facet_name); }
                }(facet.entity_name, facet_name)
            }));

        } else { // For now empty label indicates an association facet

            var attribute_members = IPA.metadata[facet.entity_name].attribute_members;
            for (var attribute_member in attribute_members) {
                var other_entities = attribute_members[attribute_member];
                for (var j = 0; j < other_entities.length; j++) {
                    var other_entity = other_entities[j];
                    var label = IPA.metadata[other_entity].label;

                    if (i > 0 || j > 0) label = '| ' + label;

                    ul.append($('<li/>', {
                        title: other_entity,
                        text: label,
                        click: function(entity_name, facet_name, other_entity) {
                            return function() { IPA.show_page(entity_name, facet_name, other_entity); }
                        }(facet.entity_name, facet_name, other_entity)
                    }));
                }
            }
        }
    }

    container.append(ul);
}

function ipa_entity_quick_links(tr, attr, value, entry_attrs) {

    var obj_name = tr.closest('.search-container').attr('title');
    var pkey = IPA.metadata[obj_name].primary_key;
    var pkey_value = entry_attrs[pkey][0];

    var td = $("<td/>").appendTo(tr);

    $("<a/>", {
        href: "#details",
        title: "Details",
        click: function() {
            var state = {};
            state[obj_name+'-facet'] = 'details';
            state[obj_name+'-pkey'] = pkey_value;
            nav_push_state(state);
            return false;
        }
    }).appendTo(td);

    var attribute_members = IPA.metadata[obj_name].attribute_members;
    for (attr_name in attribute_members) {
        var objs = attribute_members[attr_name];
        for (var i = 0; i < objs.length; ++i) {
            var m = objs[i];
            var label = IPA.metadata[m].label;

            $("<a/>", {
                href: '#'+m,
                title: label,
                text: label,
                click: function(m) {
                    return function() {
                        var state = {};
                        state[obj_name+'-facet'] = 'associate';
                        state[obj_name+'-enroll'] = m;
                        state[obj_name+'-pkey'] = pkey_value;
                        nav_push_state(state);
                        return false;
                    }
                }(m)
            }).append(' | ' ).appendTo(td);
        }
    }
}
