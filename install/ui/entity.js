/*jsl:import ipa.js */
/*jsl:import navigation.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *
 * Copyright (C) 2010-2011 Red Hat
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
    that.create_content = spec.create_content || create_content;
    that.setup = spec.setup || setup;
    that.load = spec.load || load;

    that.dialogs = [];
    that.dialogs_by_name = {};

    that.facet_group = spec.facet_group;

    that.__defineGetter__('entity_name', function() {
        return that._entity_name;
    });

    that.__defineSetter__('entity_name', function(entity_name) {
        that._entity_name = entity_name;
    });

    that.get_dialog = function(name) {
        return that.dialogs_by_name[name];
    };

    that.dialog = function(dialog) {
        that.dialogs.push(dialog);
        that.dialogs_by_name[dialog.name] = dialog;
        return that;
    };

    function init() {

        that.entity = IPA.get_entity(that.entity_name);

        for (var i=0; i<that.dialogs.length; i++){
            var dialog = that.dialogs[i];
            dialog.entity_name = that._entity_name;
            dialog.init();
        }
    }

    function create_content(container) {
    }

    function setup(container) {
        that.container = container;
        that.entity_header.facet_tabs.css('visibility','visible');
        $('#back_to_search', that.entity_header.search_bar).
            css('display','inline');
    }

    function load() {
    }

    that.is_dirty = function (){
        return false;
    };

    that.get_content = function() {
        return $('.content', that.container);
    };

    // methods that should be invoked by subclasses
    that.facet_init = that.init;
    that.facet_create_content = that.create_content;
    that.facet_setup = that.setup;

    return that;
};


IPA.fetch_facet_group = function (name,attribute_member){
    var relationships = IPA.metadata.objects[name].relationships;
    var relationship = relationships[attribute_member];
    if (!relationship){
        relationship = ['Member', '', 'no_'];
    }
    var facet_group = relationship[0];
    return facet_group;
};


IPA.entity = function (spec) {

    spec = spec || {};

    var that = {};
    that.metadata = spec.metadata;
    that.name = spec.name;
    that.label = spec.label || spec.metadata.label || spec.name;

    that.setup = spec.setup || IPA.entity_setup;

    that.dialogs = [];
    that.dialogs_by_name = {};

    that.facets = [];
    that.facets_by_name = {};

    that.facet_name = null;
    /*TODO:  Facet_groups are currently unordered.  If we need to
     * maintain order, we will introduce a class that keeps the order
     in an array, while maintaining the dictionary for direct access.*/
    that.facet_groups = {};

    that.autogenerate_associations = false;

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
        if (name === 'default'){
            var facet_group;
            var facet;
            if (that.facet_groups["Member"]){
                facet_group = that.facet_groups["Member"];
                facet =  facet_group[0];
            } else if (that.facets_by_name.details){
                facet= that.facets_by_name.details;
            }else  if (that.facet_groups["Member Of"]){
                facet_group = that.facet_groups["Member Of"];
                facet =  facet_group[0];
            }
            if (facet){
                name = facet.name;
                return facet;
            }
        }

        return that.facets_by_name[name];
    };

    that.add_facet = function(facet) {
        facet.entity_name = that.name;
        that.facets.push(facet);
        that.facets_by_name[facet.name] = facet;
        
        if (facet.facet_group){
            if (!that.facet_groups[facet.facet_group]){
                that.facet_groups[facet.facet_group] = [];
            }
            that.facet_groups[facet.facet_group].push(facet);
        }
        return that;
    };

    that.facet = function(facet) {
        return that.add_facet(facet);
    };

    that.create_association_facet = function(attribute_member, other_entity, label, facet_group) {

        var association_name = attribute_member+'_'+other_entity;

        //TODO remove from the facets and facets_by_name collections
        var facet = that.get_facet(association_name);
        if (facet) {
            facet.facet_group = facet_group;
            facet.attribute_member =  attribute_member;
            return;
        }

        facet = IPA.association_facet({
            name: association_name,
            label: label,
            attribute_member: attribute_member,
            other_entity: other_entity,
            facet_group: facet_group
        });

        that.add_facet(facet);
    };

    that.create_association_facets = function() {

        var attribute_members = that.metadata.attribute_members;

        for (var attribute_member in attribute_members) {

            // skip non-assignable associations
            if (attribute_member === 'memberindirect') continue;
            if (attribute_member === 'memberofindirect') continue;
            if (attribute_member === 'enrolledby') continue;

            var other_entities = attribute_members[attribute_member];

            for (var j = 0; j < other_entities.length; j++) {

                var other_entity = other_entities[j];
                var label = IPA.metadata.objects[other_entity].label;

                var facet_group =
                    IPA.fetch_facet_group(that.name,attribute_member);
                that.create_association_facet(
                    attribute_member, other_entity, label, facet_group);
            }
        }
        return that;
    };

    that.standard_associations = that.create_association_facets;

    that.init = function() {

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
        if (entity.facet_name == facet.name) {
            if (facet.new_key   && (!facet.new_key())) return;
        } else {
            entity.facet_name = facet.name;
        }
    } else {
        IPA.entity_name = entity.name;
    }

    container.attr('title', entity.name);
    if (!entity.header){
        entity.header = IPA.entity_header({entity:entity,container:container});
    }
    facet.entity_header = entity.header;

    entity.header.reset();
    facet.create_content(facet.entity_header.content);
    facet.setup(facet.entity_header.content);
    entity.header.select_tab();
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

IPA.nested_tabs = function(entity_name) {

    var siblings = [];
    var i;
    var i2;
    var nested_entities;
    var sub_i;
    var sub_tab;

    var key = entity_name;
    function push_sibling(sibling){
        siblings.push (sibling);
        IPA.nested_tab_labels[key] = sub_tab;
    }


    if (!IPA.nav.tabs) {
        siblings.push(entity_name);
        return siblings;
    }

    for (var top_i = 0; top_i < IPA.nav.tabs.length; top_i++) {
        var top_tab = IPA.nav.tabs[top_i];
        for (sub_i = 0; sub_i < top_tab.children.length; sub_i++) {
            sub_tab = top_tab.children[sub_i];
            nested_entities = sub_tab.children;
            if (sub_tab.name === entity_name){
                push_sibling(entity_name);
            }
            if (sub_tab.children){
                for (i = 0; i < nested_entities.length; i += 1){
                    if (sub_tab.name === entity_name){
                        push_sibling(nested_entities[i].name);
                    }else{
                        if (nested_entities[i].name === entity_name){
                            push_sibling(sub_tab.name);
                            for (i2 = 0; i2 < nested_entities.length; i2 += 1){
                                key = nested_entities[i].name;
                                push_sibling(nested_entities[i2].name);
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


IPA.entity_header = function(spec){
    var entity = spec.entity;
    var container = spec.container;

    var that = {};
    that.entity = entity;

    function pkey(){
        that.pkey_field = $("<input type='hidden' id='pkey' />");
        return that.pkey_field;
    }

    function select_tab(){
        $(that.facet_tabs).find('a').removeClass('selected');
        var facet_name = $.bbq.getState(entity.name + '-facet', true);

        if (!facet_name) return;

        if (facet_name === 'default'){
            that.facet_tabs.find('a:first').addClass('selected');
        }else{
            that.facet_tabs.find('a#' + facet_name ).addClass('selected');
        }

    }
    that.select_tab = select_tab;

    function set_pkey(val){
        that.pkey_field.val(val);
        that.title.empty();
        var title = $('<h3/>',{ text: entity.metadata.label+": "});
        title.append ($('<span/>',{text:val}));
        that.title.append(title);
    }
    that.set_pkey = set_pkey;

    function title(){
        that.title =
            $("<div/>",
              {
                  'class':'entity-title'
              });

        var title = $('<h3/>',{ text: entity.metadata.label});
        that.title.append(title);

        return that.title;
    }

    function buttons(){
        that.buttons = $("<span class='action-controls' />");
        return that.buttons;

    }
    function search_bar(){
        that.search_bar =
            $("<span class='entity-search'/>");

        if (entity.facets_by_name.search){
            that.search_bar.prepend(
                $('<span />',{
                    id:'back_to_search',
                    "class":"input_link",
                    click: function(){
                        if($(this).hasClass('entity-facet-disabled')){
                            return false;
                        }

                        IPA.show_page(entity.name, 'search');
                        $(that.facet_tabs).find('a').removeClass('selected');
                        return false;

                    }
                }).
                    append(IPA.back_icon + '  ' +
                           IPA.messages.buttons.back_to_list+' '));
        }

        return that.search_bar;
    }

    function facet_link(other_facet){
        var entity_name = that.entity.name;
        var other_facet_name = other_facet.name;
        var li = $('<li/>', {
            title: other_facet.name,
            html: $('<a />',{
                text: other_facet.label,
                id: other_facet_name
            }),
            click: function(entity_name, other_facet_name) {
                return function() {
                    if($(this).hasClass('entity-facet-disabled')){
                        return false;
                    }
                    var this_pkey = that.pkey_field.val();
                    IPA.show_page(
                        entity_name, other_facet_name,
                        this_pkey);
                    $(that.facet_tabs).find('a').removeClass('selected');
                    $(this).find('a').addClass('selected');

                    return false;
                };
            }(entity_name, other_facet_name)
        });
        return li;
    }


    function facet_group(label){
        var facets= entity.facet_groups[label];
        if (facets){
            that.facet_tabs.append(tab_section(label,  facets));
        }
    }

    function tab_section(label, facets){
        var tab_section = $("<span class='entity-tabs-section'/>").
            append("<label>"+label+"</label>");

        var ul = $("<ul class='entity-tabs'/>").appendTo(tab_section);

        var i;
        for (i = 0; i < facets.length; i += 1){
            var other_facet = facets[i];
            ul.append(facet_link(other_facet));
        }
        return tab_section;
    }

    function facet_tabs(){
        that.facet_tabs =   $("<div class='entity-tabs'/>");

        facet_group("Member");

        if (entity.facets_by_name.details){
            that.facet_tabs.append(
                tab_section('Settings',[entity.facets_by_name.details]));
        }
        facet_group("Member Of");
        facet_group("Managed by");

        return that.facet_tabs;
    }
    function content(){
        that.content = $("<div class='content'/>");        return that.content;
    }

    function entity_container() {
        that.entity_container =
            $("<div/>",{
                "class":'entity-container',
                id: 'entity-container-' + entity.name
            }).
            append(facet_tabs()).
            append(content());
        return that.entity_container;
    }

    function reset(){
        that.buttons.empty();
        that.content.empty();
    }
    that.reset = reset;

    that.header = $("<div class='entity-header'/>").
        append(title(entity)).
        append(buttons()).
        append(pkey()).
        append(search_bar()).
        append(entity_container());
    container.append(that.header);

    return that;
};

IPA.entity_builder = function(){

    var that = {};
    var entity = null;
    var facet = null;

    function section(spec){
        var current_section = null;
        spec.entity_name = entity.name;

        if (!spec.label){
            var obj_messages = IPA.messages.objects[entity.name];
            spec.label =  obj_messages[spec.name];
        }

        if (spec.factory){
            current_section =  spec.factory(spec);
        }else{
            current_section = IPA.details_list_section(spec);
        }
        facet.add_section(current_section);
        var fields = spec.fields;
        if (fields) {
            for (var i=0; i<fields.length; i++) {
                var field_spec = fields[i];
                var field;

                if (field_spec instanceof Object) {
                    field_spec.entity_name = entity.name;
                    var factory = field_spec.factory || IPA.text_widget;
                    field = factory(field_spec);
                } else {
                    field = IPA.text_widget({
                        name: field_spec,
                        entity_name: entity.name
                    });
                }
                current_section.add_field(field);
            }
        }
    }

    that.entity = function(param) {
        var spec;
        var factory = IPA.entity;
        if (param instanceof Object) {
            factory = param.factory || IPA.entity;
            spec = param;
        } else {
            spec = { name: param  };
        }
        spec.metadata = spec.metadata || IPA.metadata.objects[spec.name];
        if (!spec.metadata){
            throw "Entity not supported by server.";
        }

        entity = factory(spec);
        return that;
    };

    that.dialog = function(spec) {
        var dialog;
        if (spec instanceof Object){
            var factory = spec.factory || IPA.dialog;
            dialog = factory(spec);
        } else {
            dialog = IPA.dialog({ name: spec });
        }
        entity.dialog(dialog);
        return that;
    };

    that.adder_dialog = function(spec) {
        spec.factory = spec.factory || IPA.add_dialog;
        spec.name = spec.name || 'add';
        spec.title = spec.title || IPA.messages.objects.user.add;
        return that.dialog(spec);
    };

    that.details_facet = function (spec){
        var sections = spec.sections;
        spec.sections = null;
        spec.entity_name = entity.name;
        facet =IPA.details_facet(spec);
        entity.facet(facet);

        var i;
        for ( i =0; i < sections.length; i += 1){
            section(sections[i]);
        }

        return that;
    };

    that.facet = function(spec) {
        spec.entity_name  = entity.name;
        facet = spec.factory(spec);
        entity.facet(facet);
        return that;
    };

    that.search_facet = function (spec){
        facet = IPA.search_facet({
            entity_name: entity.name,
            search_all: spec.search_all || false,
            columns: spec.columns
        });
        entity.facet(facet);
        return that;
    };


    that.association_facet = function(spec){
        spec.entity_name = entity.name;
        entity.facet(IPA.association_facet(spec));
        return that;
    };

    that.standard_association_facets = function(){
        entity.standard_associations();
        return that;
    };

    that.build = function(){
        var item = entity;
        entity = null;
        return item;
    };

    return that;
};
