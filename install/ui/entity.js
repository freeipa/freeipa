/*jsl:import ipa.js */
/*jsl:import navigation.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
 *    Adam Young <ayoung@redhat.com>
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

/* REQUIRES: ipa.js, details.js, search.js, add.js */

IPA.facet = function (spec) {

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

    that.dialogs = [];
    that.dialogs_by_name = {};

    that.__defineGetter__('entity_name', function() {
        return that._entity_name;
    });

    that.__defineSetter__('entity_name', function(entity_name) {
        that._entity_name = entity_name;
    });

    that.create_action_panel = IPA.facet_create_action_panel;

    that.get_dialog = function(name) {
        return that.dialogs_by_name[name];
    };

    that.dialog = function(dialog) {
        that.dialogs.push(dialog);
        that.dialogs_by_name[dialog.name] = dialog;
        return that;
    };

    function init() {
        for (var i=0; i<that.dialogs.length; i++){
            var dialog = that.dialogs[i];
            dialog.entity_name = that._entity_name;
            dialog.init();
        }
    }

    function create(container) {
    }

    function setup(container) {
        that.container = container;
    }

    function load() {
    }

    that.is_dirty = function (){
        return false;
    };

    that.get_client_area = function() {
        return $('.client', that.container);
    };

    that.get_action_panel = function() {
        return $('.action-panel', that.container);
    };

    // methods that should be invoked by subclasses
    that.facet_init = that.init;
    that.facet_create = that.create;
    that.facet_setup = that.setup;

    return that;
};


IPA.entity = function (spec) {

    spec = spec || {};

    var that = {};
    that.name = spec.name;
    that.label = spec.label;

    that.setup = spec.setup || IPA.entity_setup;

    that.dialogs = [];
    that.dialogs_by_name = {};

    that.facets = [];
    that.facets_by_name = {};

    that.facet_name = null;

    that.autogenerate_associations = false;

    that.associations = [];
    that.associations_by_name = {};

    that.get_dialog = function(name) {
        return that.dialogs_by_name[name];
    };

    that.add_dialog = function(dialog) {
        return that.dialog(dialog);
    };

    that.dialog = function(dialog) {
        dialog.entity_name = that.name;
        that.dialogs.push(dialog);
        that.dialogs_by_name[dialog.name] = dialog;
        return that;
    };

    function init_dialogs (){
        var i;
        for (i = 0; i < that.dialogs.length; i += 1){
            that.dialogs[i].init();
        }
        return that;
    }

    that.get_facet = function(name) {
        return that.facets_by_name[name];
    };

    that.add_facet = function(facet) {
        facet.entity_name = that.name;
        that.facets.push(facet);
        that.facets_by_name[facet.name] = facet;
        return that;
    };

    that.facet = function(facet) {
        facet.entity_name = that.name;
        that.facets.push(facet);
        that.facets_by_name[facet.name] = facet;
        return that;
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
        var config = IPA.association_config(spec);
        that.add_association(config);
        return config;
    };

    that.association = function(spec) {
        var config = IPA.association_config(spec);
        that.add_association(config);
        return that;
    };


    that.create_association_facet = function(attribute_member, other_entity, label, facet_group) {

        if (!attribute_member) {
            attribute_member = IPA.get_member_attribute(
                that.entity_name, other_entity);
        }

        var association_name= attribute_member+'_'+other_entity;

        //TODO remove from the facets and facets_by_name collections
        var facet = that.get_facet(association_name);
        if (facet){
            facet.facet_group = facet_group;
            facet.attribute_member =  attribute_member;
            return;
        }

        var config = that.get_association(other_entity);
        if (!config){
            config = that.get_association(association_name);
        }

        var spec ={
            'name': association_name,
            'label': label,
            'other_entity': other_entity,
            'facet_group': facet_group,
            'attribute_member': attribute_member
        };

        if (config){
            for (var key in config){
                /*name is special, as iut has already been munged 
                  into the association name */
                if (key === "name"){
                    continue;
                }
                spec[key] = config[key] ;
            }
        }

        facet =  IPA.association_facet(spec);

        that.add_facet(facet);
    };

    that.create_association_facets = function() {

        var attribute_members = IPA.metadata[that.name].attribute_members;

        for (var attribute_member in attribute_members) {

            // skip non-assignable associations
            if (attribute_member === 'memberindirect') continue;
            if (attribute_member === 'enrolledby') continue;

            var other_entities = attribute_members[attribute_member];

            for (var j = 0; j < other_entities.length; j++) {
                var other_entity = other_entities[j];
                var other_entity_name = IPA.metadata[other_entity].label;

                var label = other_entity_name;

                var relationships = IPA.metadata[that.name].relationships;

                var relationship = relationships[attribute_member];
                if (!relationship)
                    relationship = ['Member', '', 'no_'];
                var facet_group = relationship[0];

                that.create_association_facet(
                    attribute_member, other_entity, label, facet_group);
            }
        }
        return that;
    };

    that.standard_associations = that.create_association_facets;


    that.init = function() {

        if (!that.label) {
            that.label = IPA.metadata[that.name].label;
        }

        if (that.autogenerate_associations) {
            that.create_association_facets();
        }

        for (var i=0; i<that.facets.length; i++) {
            var facet = that.facets[i];
            facet.init();
        }
        init_dialogs();
    };

    that.entity_init = that.init;

    return that;
};


/* use this to track individual changes between two hashchange events */
var window_hash_cache = {};

/*renamed to avoid clash with IPA.get_entity*/
IPA.fetch_entity = function (entity_name) {

    var entity = IPA.get_entity(entity_name);
/*
    if (entity) return entity;

    entity = IPA.entity({
        'name': entity_name
    });

    IPA.add_entity(entity);
*/
    return entity;
};


IPA.entity_get_search_facet  = function (entity_name) {

    var entity = IPA.fetch_entity(entity_name);

    var facet = entity.get_facet('search');
    if (facet) return facet;

    facet = IPA.search_facet({
        'name': 'search',
        'label': 'Search'
    });
    entity.add_facet(facet);

    return facet;
};


IPA.entity_set_search_definition =  function (entity_name, data) {

    var facet = IPA.entity_get_search_facet(entity_name);

    for (var i=0; i<data.length; i++) {
        var defn = data[i];
        facet.create_column({
            'name': defn[0],
            'label': defn[1],
            'setup': defn[2]
        });
    }
};


IPA.entity_get_add_dialog = function (entity_name) {

    var entity = IPA.fetch_entity(entity_name);
    return entity.get_add_dialog();
};


IPA.entity_get_details_facet = function (entity_name) {

    var entity = IPA.fetch_entity(entity_name);

    var facet = entity.get_facet('details');
    if (facet) return facet;

    facet = IPA.details_facet({
        'name': 'details'
    });
    entity.add_facet(facet);

    return facet;
};


IPA.entity_set_details_definition = function (entity_name, sections) {

    var facet = IPA.entity_get_details_facet(entity_name);

    for (var i=0; i<sections.length; i++) {
        var section = sections[i];
        facet.add_section(section);
    }
};


IPA.entity_set_association_definition = function (entity_name, data) {

    var entity = IPA.fetch_entity(entity_name);

    entity.autogenerate_associations = true;

    for (var other_entity in data) {
        var config = data[other_entity];
        entity.create_association({
            'name': other_entity,
            'associator': config.associator,
            'add_method': config.add_method,
            'remove_method': config.remove_method
        });
    }
};


IPA.entity_set_facet_definition = function (entity_name, list) {

    var entity = IPA.fetch_entity(entity_name);

    for (var i=0; i<list.length; i++) {
        var facet = list[i];
        entity.add_facet(facet);
    }
};


IPA.current_facet =  function (entity){
    var facet_name = $.bbq.getState(entity.name + '-facet', true);
    if (!facet_name && entity.facets.length) {
        facet_name = entity.facets[0].name;
    }
    return facet_name;
};


IPA.entity_setup = function (container) {

    var entity = this;

    IPA.current_entity = this;
    var facet_name = IPA.current_facet(entity);


    var facet = entity.get_facet(facet_name);
    if (!facet) return;

    if (IPA.entity_name == entity.name) {
        if (entity.facet_name == facet_name) {
            if (facet.new_key   && (!facet.new_key())) return;
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
};


IPA.nested_tab_labels = {};

IPA.get_nested_tab_label = function(entity_name){

    if (!IPA.nested_tab_labels[entity_name]){
        IPA.nested_tab_labels[entity_name] = "LABEL";

    }
    return IPA.nested_tab_labels[entity_name];

};




/*Returns the entity requested, as well as:
  any nested tabs underneath it or
  its parent tab and the others nested at the same level*/

IPA.nested_tabs = function(entity_name){

    var siblings = [];
    var nested_index;
    var nested_entities;
    var label;
    if (!IPA.tab_set) {
        siblings.push(entity_name);
        return siblings;
    }

    for (var top_tab_index = 0;
         top_tab_index < IPA.tab_set.length;
         top_tab_index += 1){
        var top_tab =  IPA.tab_set[top_tab_index];
        for (var subtab_index = 0;
             subtab_index < top_tab.children.length;
             subtab_index += 1){
            if(top_tab.children[subtab_index].name){
                if (top_tab.children[subtab_index].name === entity_name){
                    siblings.push(entity_name);
                    IPA.nested_tab_labels[entity_name] =
                        top_tab.children[subtab_index].label;
                    if (top_tab.children[subtab_index].children){
                        label = top_tab.children[subtab_index].label;
                        nested_entities = top_tab.children[subtab_index].children;
                        for ( nested_index = 0;
                              nested_index < nested_entities.length;
                              nested_index += 1){
                            siblings.push (nested_entities[nested_index].name);
                            IPA.nested_tab_labels[entity_name] =
                                top_tab.children[subtab_index].label;
                        }

                    }
                }else{
                    if (top_tab.children[subtab_index].children){
                        nested_entities = top_tab.children[subtab_index].children;
                        for (nested_index = 0;
                             nested_index < nested_entities.length;
                             nested_index += 1){
                            if (nested_entities[nested_index].name === entity_name){
                                siblings.push(top_tab.children[subtab_index].name);
                                IPA.nested_tab_labels[entity_name] =
                                    top_tab.children[subtab_index].label;

                                for (var nested_index2 = 0;
                                     nested_index2 < nested_entities.length;
                                     nested_index2 += 1){
                                    siblings.push(nested_entities[nested_index2].name);
                                IPA.nested_tab_labels[nested_entities[nested_index2].name] =
                                    top_tab.children[subtab_index].label;

                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return siblings;
};

IPA.selected_icon = '<span class="ipa-icon">&#x25B6;</span>';
IPA.back_icon = '<span class="ipa-icon">&#x25C0;</span>';

IPA. facet_create_action_panel = function(container) {


    function build_link(other_facet,label){
        var li = $('<li/>', {
            "class" : other_facet.display_class,
            title: other_facet.name,
            text: label,
            click: function(entity_name, other_facet_name) {
                return function() {
                    if($(this).hasClass('entity-facet-disabled')){
                        return false;
                    }
                    var this_pkey = $('input[id=pkey]', action_panel).val();
                    IPA.switch_and_show_page(
                        entity_name, other_facet_name,
                        this_pkey);
                    return false;
                };
            }(entity_name, other_facet_name)
        });
        return li;
    }


    var that = this;
    var entity_name = that.entity_name;
    var panel_title = IPA.metadata[entity_name].label;
    var nested_tabs = IPA.nested_tabs(entity_name);


    if (nested_tabs.length > 1){
        panel_title = IPA.get_nested_tab_label(entity_name);
    }

    var action_panel = $('<div/>', {
        "class": "action-panel",
        html: $('<h3>',{
            text: panel_title
        })
    }).appendTo(container);


    /*Note, for debugging purposes, it is useful to set var pkey_type = 'text';*/
    var pkey_type = 'hidden';
    $('<input/>', {
        'type': pkey_type,
        id:'pkey',
        name:'pkey'
    }).appendTo(action_panel);
    var ul = $('<ul/>', {'class': 'action'}).appendTo(action_panel);
    var entity = IPA.get_entity(entity_name);
    var facet_name =  IPA.current_facet(entity);
    var other_facet = entity.facets[0];
    var other_facet_name = other_facet.name;
    var main_facet = build_link(other_facet,other_facet.label);
    for (var nested_index = 0 ;
         nested_index < nested_tabs.length;
         nested_index += 1){
        if (nested_tabs[nested_index] === entity_name){
            /*assume for now that entities with only a single facet
              do not have search*/
            if (entity.facets.length > 0 ){
                if ( entity.facets[0].name === IPA.current_facet( entity)){
                    if (nested_tabs.length > 1 ){
                        main_facet.html(IPA.selected_icon +
                                IPA.metadata[nested_tabs[nested_index]].label);

                        main_facet.addClass('entity-facet-selected');
                        main_facet.appendTo(ul);
                    }
                    ul.append($('<li><span class="action-controls"/></li>'));
                } else {
                        main_facet.html(
                            $('<span />',{
                                "class":"input_link"
                            }).
                                append(IPA.back_icon + '  Back to List '));
                    main_facet.addClass('back-to-search');
                    main_facet.appendTo(ul);
                }
                ul.append($('<li><hr/></li>'));
            }
            var facet_groups = {};
            var li;
            for (var i=1; i<entity.facets.length; i++) {
                other_facet = entity.facets[i];
                other_facet_name = other_facet.name;

                if (other_facet.facet_group) {
                    var facet_group = other_facet.facet_group;
                    if (!facet_groups[facet_group]) {
                        li = $('<li/>', {
                            'class': 'entity-facet entity-facet-relation-label',
                            'text': other_facet.facet_group,
                            'title': other_facet.facet_group
                        });
                        ul.append(li);
                        facet_groups[facet_group] = li;
                    }
                    li = facet_groups[facet_group];
                    var link =  build_link(other_facet, other_facet.label);
                    link.addClass('facet-group-member');
                    li.after(link );
                    /*
                      If we are on the current facet, we make the text black, non-clickable,
                      add an icon and make sure the action controls are positioned underneath it.
                     */
                    if ( other_facet.name === IPA.current_facet( entity)){
                        var text = link.text();
                        link.text('');
                        link.append($('<ul>').
                                    append($('<li />',{
                                        'class': 'association-facet-selected',
                                        html:  IPA.selected_icon +  text
                                        })).
                                    append($('<li/>',{
                                        html:$('<span />',{
                                            'class':"action-controls"
                                        })
                                    })));
                    }
                    facet_groups[facet_group] = li.next();
                } else {
                    var innerlist = $('<ul/>').appendTo(ul);
                    var facet_link = build_link(other_facet, other_facet.label);
                    innerlist.append(facet_link);
                    if ( other_facet.name === IPA.current_facet( entity)){

                        text = facet_link.text();
                        facet_link.html(IPA.selected_icon +  text);
                        facet_link.addClass('entity-facet-selected');
                        innerlist.append($('<li class="entity-facet"><span class="action-controls"  /></li>'));
                    }
                }
            }
        }else{
            $('<li/>', {
                title: nested_tabs[nested_index],
                text: IPA.metadata[nested_tabs[nested_index]].label,
                "class": "search-facet",
                click: function() {
                    var state = {};
                    state[nested_tabs[0]+'-entity'] =
                        this.title;
                    nav_push_state(state);
                    return false;
                }
            }).appendTo(ul);
        }
    }
    /*When we land on the search page, disable all facets
          that require a pkey until one is selected*/
    if (facet_name === 'search'){
        $('.entity-facet', action_panel).addClass('entity-facet-disabled');
    }
    return action_panel;
};
