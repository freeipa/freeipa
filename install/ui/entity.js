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

    that.init = function() {

        for (var i=0; i<that.dialogs.length; i++){
            var dialog = that.dialogs[i];
            dialog.entity_name = that._entity_name;
            dialog.init();
        }
    };

    that.create = function(container) {

        that.container = container;

        that.header = $('<div/>', {
            'class': 'facet-header'
        }).appendTo(container);
        that.create_header(that.header);

        that.content = $('<div/>', {
            'class': 'facet-content'
        }).appendTo(container);
        that.create_content(that.content);
    };

    that.create_header = function(container) {

        that.title = $('<div/>', {
            'class': 'facet-title'
        }).appendTo(container);

        $('<h1/>').append(IPA.create_network_spinner()).appendTo(that.title);

        that.set_title(container, that.label);

        that.controls = $('<div/>', {
            'class': 'facet-controls'
        }).appendTo(container);
    };

    that.create_content = function(container) {
    };

    that.set_title = function(container, title) {
        var element = $('h1', that.title);
        element.html(title);
    };

    that.setup = function(container) {
        that.container = container;
    };

    that.show = function() {
        that.container.css('display', 'inline');
    };

    that.hide = function() {
        that.container.css('display', 'none');
    };

    that.load = function() {
    };

    that.is_dirty = function (){
        return false;
    };

    that.get_content = function() {
        return $('.content', that.container);
    };

    // methods that should be invoked by subclasses
    that.facet_init = that.init;
    that.facet_create_header = that.create_header;
    that.facet_create_content = that.create_content;
    that.facet_setup = that.setup;
    that.facet_show = that.show;
    that.facet_hide = that.hide;

    return that;
};

IPA.table_facet = function(spec) {

    spec = spec || {};

    var that = IPA.facet(spec);

    that.columns = [];
    that.columns_by_name = {};

    that.__defineGetter__('entity_name', function() {
        return that._entity_name;
    });

    that.__defineSetter__('entity_name', function(entity_name) {
        that._entity_name = entity_name;

        for (var i=0; i<that.columns.length; i++) {
            that.columns[i].entity_name = entity_name;
        }
    });

    that.get_columns = function() {
        return that.columns;
    };

    that.get_column = function(name) {
        return that.columns_by_name[name];
    };

    that.add_column = function(column) {
        column.entity_name = that.entity_name;
        that.columns.push(column);
        that.columns_by_name[column.name] = column;
    };

    that.create_column = function(spec) {
        var column = IPA.column(spec);
        that.add_column(column);
        return column;
    };

    that.column = function(spec){
        that.create_column(spec);
        return that;
    };

    var columns = spec.columns || [];
    for (var i=0; i<columns.length; i++) {
        var column_spec = columns[i];
        var column;

        if (column_spec instanceof Object) {
            var factory = column_spec.factory || IPA.column;
            column = factory(column_spec);
        } else {
            column = IPA.column({ name: column_spec });
        }
        that.add_column(column);
    }

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

    that.header = spec.header || IPA.entity_header({entity: that});

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
            facet.entity = that;
            facet.init();
        }
        init_dialogs();
    };

    that.create = function(container) {
        var entity_header = $('<div/>', {
            'class': 'entity-header'
        }).appendTo(container);
        that.header.create(entity_header);

        that.content = $('<div/>', {
            'class': 'entity-content'
        }).appendTo(container);
    };

    that.setup = function(container) {

        var prev_facet = that.facet;

        IPA.current_entity = that;
        var facet_name = IPA.current_facet(that);

        that.facet = that.get_facet(facet_name);
        if (!that.facet) return;

        if (IPA.entity_name == that.name) {
            if (that.facet_name == that.facet.name) {
                if (that.facet.new_key && (!that.facet.new_key())) return;
            } else {
                that.facet_name = that.facet.name;
            }
        } else {
            IPA.entity_name = that.name;
        }

        if (prev_facet) {
            prev_facet.hide();
        }

        var facet_container = $('.facet[name="'+that.facet.name+'"]', that.content);
        if (!facet_container.length) {
            facet_container = $('<div/>', {
                name: that.facet.name,
                'class': 'facet'
            }).appendTo(that.content);

            that.facet.create(facet_container);
            that.facet.setup(facet_container);
        }

        that.facet.show();
        that.header.select_tab();
        that.facet.refresh();
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

IPA.entity_header = function(spec) {

    spec = spec || {};

    var that = {};
    that.entity = spec.entity;

    that.select_tab = function() {
        $(that.facet_tabs).find('a').removeClass('selected');
        var facet_name = $.bbq.getState(that.entity.name + '-facet', true);

        if (!facet_name || facet_name === 'default') {
            that.facet_tabs.find('a:first').addClass('selected');
        } else {
            that.facet_tabs.find('a#' + facet_name ).addClass('selected');
        }
    };

    that.set_pkey = function(value) {

        if (value) {
            var span = $('.entity-pkey', that.pkey);
            span.text(value);
            that.pkey.css('display', 'inline');

        } else {
            that.pkey.css('display', 'none');
        }
    };

    that.facet_link = function(container, other_facet) {

        var li = $('<li/>', {
            title: other_facet.name,
            click: function() {
                if (li.hasClass('entity-facet-disabled')) {
                    return false;
                }

                var pkey = $.bbq.getState(that.entity.name+'-pkey', true);

                IPA.nav.show_page(that.entity.name, other_facet.name, pkey);
                $('a', that.facet_tabs).removeClass('selected');
                $('a', li).addClass('selected');

                return false;
            }
        }).appendTo(container);

        $('<a/>', {
            text: other_facet.label,
            id: other_facet.name
        }).appendTo(li);
    };

    that.facet_group = function(container, label) {
        var facets = that.entity.facet_groups[label];
        if (facets) {
            that.tab_section(container, label, facets);
        }
    };

    that.tab_section = function(container, label, facets) {

        var section = $('<span/>', {
            'class': 'facet-tab-group'
        }).appendTo(container);

        $('<label/>', {
            text: label
        }).appendTo(section);

        var ul = $('<ul/>', {
            'class': 'facet-tab'
        }).appendTo(section);

        for (var i=0; i<facets.length; i++) {
            var other_facet = facets[i];
            that.facet_link(ul, other_facet);
        }
    };

    that.create = function(container) {

        that.title = $('<div/>', {
            'class': 'entity-title'
        }).appendTo(container);

        var title_text = $('<h3/>', {
            text: that.entity.metadata.label
        }).appendTo(that.title);

        that.pkey = $('<span/>').appendTo(title_text);

        that.pkey.append(': ');
        that.pkey.append($('<span/>', {
            'class': 'entity-pkey'
        }));

        var search_bar = $('<span/>', {
            'class': 'entity-search'
        }).appendTo(container);

        that.back_link = $('<span/>', {
            'class': 'back-link',
            click: function() {
                if ($(this).hasClass('entity-facet-disabled')) {
                    return false;
                }

                IPA.nav.show_page(that.entity.name, 'search');
                $('a', that.facet_tabs).removeClass('selected');
                return false;
            }
        }).appendTo(search_bar);

        that.back_link.append(IPA.back_icon);
        that.back_link.append('  ');
        that.back_link.append(IPA.messages.buttons.back_to_list);

        that.facet_tabs = $('<div/>', {
            'class': 'entity-tabs'
        }).appendTo(container);

        that.facet_group(that.facet_tabs, "Member");

        if (that.entity.facets_by_name.details) {
            that.facet_tabs.append(
                that.tab_section(that.facet_tabs, 'Settings', [that.entity.facets_by_name.details]));
        }

        that.facet_group(that.facet_tabs, "Member Of");
        that.facet_group(that.facet_tabs, "Managed By");
    };

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
        entity.add_facet(facet);

        var i;
        for ( i =0; i < sections.length; i += 1){
            section(sections[i]);
        }

        return that;
    };

    that.facet = function(spec) {
        spec.entity_name  = entity.name;
        facet = spec.factory(spec);
        entity.add_facet(facet);
        return that;
    };

    that.search_facet = function (spec){
        facet = IPA.search_facet({
            entity_name: entity.name,
            search_all: spec.search_all || false,
            columns: spec.columns
        });
        entity.add_facet(facet);
        return that;
    };


    that.association_facet = function(spec){
        spec.entity_name = entity.name;
        entity.add_facet(IPA.association_facet(spec));
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
