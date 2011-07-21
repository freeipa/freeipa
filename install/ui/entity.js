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

    that.name = spec.name;
    that.label = spec.label;
    that.title = spec.title || that.label;
    that.display_class = spec.display_class;

    that.disable_breadcrumb = spec.disable_breadcrumb;
    that.disable_facet_tabs = spec.disable_facet_tabs;

    that.header = spec.header || IPA.facet_header({ facet: that });

    that._entity_name = spec.entity_name;

    that.dialogs = $.ordered_map();

    // facet group name
    that.facet_group = spec.facet_group;

    that.state = {};

    that.__defineGetter__('entity_name', function() {
        return that._entity_name;
    });

    that.__defineSetter__('entity_name', function(entity_name) {
        that._entity_name = entity_name;
    });

    that.get_dialog = function(name) {
        return that.dialogs.get(name);
    };

    that.dialog = function(dialog) {
        that.dialogs.put(dialog.name, dialog);
        return that;
    };

    that.init = function() {

        var dialogs = that.dialogs.values;
        for (var i=0; i<dialogs.length; i++){
            var dialog = dialogs[i];
            dialog.entity_name = that._entity_name;
            dialog.init();
        }
    };

    that.create = function(container) {

        that.container = container;

        if (that.disable_facet_tabs) that.container.addClass('no-facet-tabs');
        that.container.addClass(that.display_class);

        that.header_container = $('<div/>', {
            'class': 'facet-header'
        }).appendTo(container);
        that.create_header(that.header_container);

        that.content = $('<div/>', {
            'class': 'facet-content'
        }).appendTo(container);
        that.create_content(that.content);
    };

    that.create_header = function(container) {

        that.header.create(container);

        that.controls = $('<div/>', {
            'class': 'facet-controls'
        }).appendTo(container);
    };

    that.create_content = function(container) {
    };

    that.set_title = function(container, title) {
        var element = $('h1', that.title_container);
        element.html(title);
    };

    that.setup = function(container) {
        that.container = container;
    };

    that.show = function() {
        that.container.css('display', 'block');
    };

    that.hide = function() {
        that.container.css('display', 'none');
    };

    that.load = function(data) {
        that.data = data;
        that.header.load(data);
    };

    that.needs_update = function() {
        return true;
    };

    that.is_dirty = function() {
        return false;
    };

    that.get_content = function() {
        return $('.content', that.container);
    };

    that.report_error = function(error_thrown){
        var details = $('.details', that.container).empty();
        details.append('<p>Error: '+error_thrown.name+'</p>');
        details.append('<p>'+error_thrown.message+'</p>');
    };

    that.redirect = function() {
        var entity = that.entity;
        while (entity.containing_entity) {
            entity = entity.containing_entity;
        }

        IPA.nav.show_page(
            entity.name,
            that.entity.redirect_facet);
    };

    var redirect_errors =
        ["IPA Error 4001"];

    that.on_error = function(xhr, text_status, error_thrown) {

        /*If the error is in talking to the server, don't attempt to redirect,
          as there is nothing any other facet can do either. */
        if (that.entity.redirect_facet) {
            for (var i=0; i<redirect_errors.length; i++) {
                if (error_thrown.name ===  redirect_errors[i]) {
                    that.redirect();
                    return;
                }
            }
        }
        that.report_error(error_thrown);
    };


    // methods that should be invoked by subclasses
    that.facet_init = that.init;
    that.facet_create = that.create;
    that.facet_create_header = that.create_header;
    that.facet_create_content = that.create_content;
    that.facet_setup = that.setup;
    that.facet_show = that.show;
    that.facet_hide = that.hide;
    that.facet_load = that.load;

    return that;
};

IPA.facet_header = function(spec) {

    spec = spec || {};

    var that = {};

    that.facet = spec.facet;

    that.select_tab = function() {
        if (that.facet.disable_facet_tabs) return;

        $(that.facet_tabs).find('a').removeClass('selected');
        var facet_name = IPA.nav.get_state(that.facet.entity.name+'-facet');

        if (!facet_name || facet_name === 'default') {
            that.facet_tabs.find('a:first').addClass('selected');
        } else {
            that.facet_tabs.find('a#' + facet_name ).addClass('selected');
        }
    };

    that.set_pkey = function(value) {

        if (!value) return;

        if (!that.facet.disable_breadcrumb) {
            var breadcrumb = [];
            var entity = that.facet.entity.containing_entity;

            while (entity) {
                breadcrumb.unshift($('<a/>', {
                    text: IPA.nav.get_state(entity.name+'-pkey'),
                    title: entity.name,
                    click: function(entity) {
                        return function() {
                            IPA.nav.show_page(entity.name, 'default');
                            return false;
                        };
                    }(entity)
                }));

                entity = entity.containing_entity;
            }

            that.path.empty();

            for (var i=0; i<breadcrumb.length; i++){
                that.path.append(' &raquo; ');
                that.path.append(breadcrumb[i]);
            }

            that.path.append(' &raquo; ');
            that.path.append(value);
        }

        that.title_container.empty();
        var h3 = $('<h3/>').appendTo(that.title_container);
        h3.append(that.facet.title);
        h3.append(': ');

        $('<span/>', {
            'class': 'facet-pkey',
            text: value
        }).appendTo(h3);
    };

    that.create_facet_link = function(container, other_facet) {

        var li = $('<li/>', {
            name: other_facet.name,
            title: other_facet.name,
            click: function() {
                if (li.hasClass('entity-facet-disabled')) {
                    return false;
                }

                var pkey = IPA.nav.get_state(that.facet.entity.name+'-pkey');
                IPA.nav.show_page(that.facet.entity.name, other_facet.name, pkey);

                return false;
            }
        }).appendTo(container);

        $('<a/>', {
            text: other_facet.label,
            id: other_facet.name
        }).appendTo(li);
    };

    that.create_facet_group = function(container, facet_group) {

        var section = $('<span/>', {
            name: facet_group.name,
            'class': 'facet-group'
        }).appendTo(container);

        $('<div/>', {
            'class': 'facet-group-label',
            text: facet_group.label
        }).appendTo(section);

        var ul = $('<ul/>', {
            'class': 'facet-tab'
        }).appendTo(section);

        var facets = facet_group.facets.values;
        for (var i=0; i<facets.length; i++) {
            var facet = facets[i];
            that.create_facet_link(ul, facet);
        }
    };

    that.create = function(container) {

        if (!that.facet.disable_breadcrumb) {
            that.breadcrumb = $('<div/>', {
                'class': 'breadcrumb'
            }).appendTo(container);

            that.back_link = $('<span/>', {
                'class': 'back-link'
            }).appendTo(that.breadcrumb);

            var entity = that.facet.entity;
            while (entity.containing_entity) entity = entity.containing_entity;

            $('<a/>', {
                text: entity.metadata.label,
                click: function() {
                    that.facet.redirect();
                    return false;
                }
            }).appendTo(that.back_link);


            that.path = $('<span/>', {
                'class': 'path'
            }).appendTo(that.breadcrumb);
        }

        that.title_container = $('<div/>', {
            'class': 'facet-title'
        }).appendTo(container);

        var span = $('<h3/>', {
            text: that.facet.entity.metadata.label
        }).appendTo(that.title_container);

        if (!that.facet.disable_facet_tabs) {
            that.facet_tabs = $('<div/>', {
                'class': 'facet-tabs'
            }).appendTo(container);

            var facet_groups = that.facet.entity.facet_groups.values;
            for (var i=0; i<facet_groups.length; i++) {
                var facet_group = facet_groups[i];
                if (facet_group.facets.length) {
                    that.create_facet_group(that.facet_tabs, facet_group);
                }
            }
        }
    };

    that.load = function(data) {
        if (!that.facet.disable_facet_tabs) {
            var facet_groups = that.facet.entity.facet_groups.values;
            for (var i=0; i<facet_groups.length; i++) {
                var facet_group = facet_groups[i];
                var span = $('.facet-group[name='+facet_group.name+']', that.facet_tabs);

                var facets = facet_group.facets.values;
                for (var j=0; j<facets.length; j++) {
                    var facet = facets[j];
                    var link = $('li[name='+facet.name+'] a', span);

                    var values = data[facet.name];
                    if (values) {
                        link.text(facet.label+' ('+values.length+')');
                    } else {
                        link.text(facet.label);
                    }
                }
            }
        }
    };

    return that;
};

IPA.table_facet = function(spec) {

    spec = spec || {};

    var that = IPA.facet(spec);

    that.managed_entity_name = spec.managed_entity_name || that.entity_name;

    that.columns = $.ordered_map();

    that.get_columns = function() {
        return that.columns.values;
    };

    that.get_column = function(name) {
        return that.columns.get(name);
    };

    that.add_column = function(column) {
        column.entity_name = that.managed_entity_name;
        that.columns.put(column.name, column);
    };

    that.create_column = function(spec) {
        var column;
        if (spec instanceof Object) {
            var factory = spec.factory || IPA.column;
            column = factory(spec);
        } else {
            column = IPA.column({ name: spec });
        }
        that.add_column(column);
        return column;
    };

    that.column = function(spec){
        that.create_column(spec);
        return that;
    };

    var columns = spec.columns || [];
    for (var i=0; i<columns.length; i++) {
        that.create_column(columns[i]);
    }

    return that;
};

IPA.facet_group = function(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.label = spec.label;

    that.facets = $.ordered_map();

    that.add_facet = function(facet) {
        that.facets.put(facet.name, facet);
    };

    that.get_facet = function(name) {
        return that.facets.get(name);
    };

    return that;
};

IPA.entity = function (spec) {

    spec = spec || {};

    var that = {};
    that.metadata = spec.metadata;
    that.name = spec.name;
    that.label = spec.label || spec.metadata.label || spec.name;
    that.title = spec.title || that.label;

    that.dialogs = $.ordered_map();

    that.facets = $.ordered_map();
    that.facet_groups = $.ordered_map();

    // current facet
    that.facet = null;

    that.redirect_facet = spec.redirect_facet;
    that.containing_entity = null;

    that.get_dialog = function(name) {
        return that.dialogs.get(name);
    };

    that.add_dialog = function(dialog) {
        return that.dialog(dialog);
    };

    that.dialog = function(dialog) {
        dialog.entity_name = that.name;
        that.dialogs.put(dialog.name, dialog);
        return that;
    };

    that.add_facet_group = function(facet_group) {
        that.facet_groups.put(facet_group.name, facet_group);
    };

    that.get_facet_group = function(name) {
        return that.facet_groups.get(name);
    };

    that.remove_facet_groups = function() {
        that.facet_groups.empty();
    };

    that.get_facet = function(name) {
        if (name === undefined) {
            // return the current facet
            if (that.facet) return that.facet;

            // return the main facet
            return that.facets.values[0];

        } else if (name === 'default') {
            // return the first facet in the first facet group
            var facet_groups = that.facet_groups.values;
            for (var i=0; i<facet_groups.length; i++) {
                var facet_group = facet_groups[i];
                var facets = facet_group.facets.values;
                if (!facets.length) continue;
                return facets[0];
            }

            return that.facets.values[0];
        }

        return that.facets.get(name);
    };

    that.add_facet = function(facet) {
        facet.entity_name = that.name;
        that.facets.put(facet.name, facet);

        if (facet.facet_group) {
            var facet_group = that.get_facet_group(facet.facet_group);
            if (facet_group) {
                facet_group.add_facet(facet);
            }
        }

        return that;
    };

    that.init = function() {

        var facets = that.facets.values;
        for (var i=0; i<facets.length; i++) {
            var facet = facets[i];
            facet.entity = that;
            facet.init();
        }

        var dialogs = that.dialogs.values;
        for (var j=0; j<dialogs.length; j++) {
            dialogs[j].init();
        }
    };

    that.create = function(container) {
        that.container = container;
    };

    that.setup = function(container) {

        var prev_entity = IPA.current_entity;
        var prev_facet = prev_entity ? prev_entity.facet : null;

        IPA.current_entity = that;

        var facet_name = IPA.nav.get_state(that.name+'-facet');
        that.facet = that.get_facet(facet_name);

        // same entity, same facet, and doesn't need updating => return
        if (that == prev_entity && that.facet == prev_facet && !that.facet.needs_update()) {
            return;
        }

        if (prev_facet) {
            prev_facet.hide();
        }

        var facet_container = $('.facet[name="'+that.facet.name+'"]', that.container);
        if (!facet_container.length) {
            facet_container = $('<div/>', {
                name: that.facet.name,
                'class': 'facet'
            }).appendTo(that.container);

            that.facet.create(facet_container);
            that.facet.setup(facet_container);
        }

        that.facet.show();
        that.facet.header.select_tab();
        that.facet.refresh();
    };

    that.get_primary_key_prefix = function() {
        var pkey = [];
        var current_entity = that;
        current_entity = current_entity.containing_entity;
        while(current_entity !== null){

            var key = IPA.nav.get_state(current_entity.name+'-pkey');
            if (key){
                pkey.unshift(key);
            }
            current_entity = current_entity.containing_entity;
        }
        return pkey;
    };

    /*gets the primary key for the current entity out of the URL parameters */
    that.get_primary_key = function() {
        var pkey = that.get_primary_key_prefix();
        var current_entity = that;
        pkey.unshift(IPA.nav.get_state(current_entity.name+'-pkey'));
        return pkey;
    };
    /* most entites only require -pkey for their primary keys, but some
       are more specific.  This call allows those entites a place
       to override the other parameters. */
    that.get_key_names = function() {
        return [that.name + '-pkey'];
    };

    that.entity_init = that.init;

    return that;
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

IPA.entity_builder = function(){

    var that = {};

    var entity = null;
    var facet_group = null;
    var facet = null;
    var section = null;

    that.entity = function(spec) {
        var factory = IPA.entity;
        if (spec instanceof Object) {
            factory = spec.factory || IPA.entity;
        } else {
            spec = { name: spec };
        }

        spec.metadata = spec.metadata || IPA.metadata.objects[spec.name];
        if (!spec.metadata) {
            throw "Entity not supported by server.";
        }

        entity = factory(spec);

        that.facet_groups([
            'member',
            'memberindirect',
            'settings',
            'memberof',
            'memberofindirect',
            'managedby'
        ]);

        return that;
    };

    that.facet_group = function(spec) {
        if (spec instanceof Object) {
            var factory = spec.factory || IPA.facet_group;
            facet_group = factory(spec);
        } else {
            facet_group = IPA.facet_group({ name: spec });
        }

        if (!facet_group.label) {
            var relationships = entity.metadata.relationships;
            if (relationships) {
                var relationship = relationships[facet_group.name];
                if (relationship) {
                    facet_group.label = relationship[0];
                }
            }
        }

        if (!facet_group.label) {
            facet_group.label = IPA.messages.facet_groups[facet_group.name];
        }

        entity.add_facet_group(facet_group);

        return that;
    };

    that.facet_groups = function(specs) {

        entity.remove_facet_groups();

        for (var i=0; i<specs.length; i++) {
            that.facet_group(specs[i]);
        }

        return that;
    };

    that.facet = function(spec) {
        spec.entity_name  = entity.name;
        facet = spec.factory(spec);
        entity.add_facet(facet);
        return that;
    };

    that.search_facet = function(spec) {

        spec.entity_name = entity.name;
        spec.title = spec.title || entity.metadata.label;
        spec.label = spec.label || IPA.messages.facets.search;

        var factory = spec.factory || IPA.search_facet;
        facet = factory(spec);
        entity.add_facet(facet);
        add_redirect_info();

        return that;
    };

    that.nested_search_facet = function(spec) {

        spec.entity_name = entity.name;
        spec.title = spec.title || entity.metadata.label_singular;
        spec.label = spec.label || IPA.messages.facets.search;

        var factory = spec.factory || IPA.nested_search_facet;
        facet = factory(spec);
        entity.add_facet(facet);

        return that;
    };

    that.details_facet = function(spec) {

        var sections = spec.sections;
        spec.sections = null;
        spec.entity_name = entity.name;
        spec.title = spec.title || entity.metadata.label_singular;
        spec.label = spec.label || IPA.messages.facets.details;

        var factory = spec.factory || IPA.details_facet;
        facet = factory(spec);
        entity.add_facet(facet);

        if (sections) {
            for (var i=0; i<sections.length; i++) {
                that.section(sections[i]);
            }
        }

        return that;
    };

    that.association_facet = function(spec) {

        spec.entity_name = entity.name;

        var index = spec.name.indexOf('_');
        spec.attribute_member = spec.attribute_member ||
            spec.name.substring(0, index);
        spec.other_entity = spec.other_entity ||
            spec.name.substring(index+1);

        spec.facet_group = spec.facet_group ||
            spec.attribute_member;

        if (spec.facet_group == 'memberindirect' ||
            spec.facet_group == 'memberofindirect') {

            var length = spec.attribute_member.length;
            var direct_attribute_member = spec.attribute_member.substring(0, length-8);
            var direct_facet_name = direct_attribute_member+'_'+spec.other_entity;

            facet = entity.get_facet(direct_facet_name);

            if (facet) { // merge into previously created direct facet
                facet.indirect_attribute_member = spec.attribute_member;
                return that;

            } else {
                spec.read_only = true;
            }
        }

        spec.title = spec.label || entity.metadata.label_singular;

        spec.label = spec.label ||
            (IPA.metadata.objects[spec.other_entity] ?
             IPA.metadata.objects[spec.other_entity].label : spec.other_entity);

        var factory = spec.factory || IPA.association_facet;
        facet = factory(spec);
        entity.add_facet(facet);

        return that;
    };

    that.standard_association_facets = function(spec) {

        spec = spec || {};

        var direct_associations = [];
        var indirect_associations = [];

        for (var association in entity.metadata.attribute_members) {
            if (association == 'memberindirect' ||
                association == 'memberofindirect') {
                indirect_associations.push(association);
            } else {
                direct_associations.push(association);
            }
        }

        // make sure direct facets are created first
        var attribute_members = direct_associations.concat(indirect_associations);

        for (var i=0; i<attribute_members.length; i++) {
            var attribute_member = attribute_members[i];
            var other_entities = entity.metadata.attribute_members[attribute_member];

            for (var j=0; j<other_entities.length; j++) {

                var other_entity = other_entities[j];
                var association_name = attribute_member+'_'+other_entity;

                var facet = entity.get_facet(association_name);
                if (facet) continue;

                var tmp_spec = $.extend({}, spec);
                tmp_spec.name = association_name;

                that.association_facet(tmp_spec);
            }
        }

        return that;
    };

    that.section = function(spec) {
        spec.entity_name = entity.name;

        if (!spec.label) {
            var obj_messages = IPA.messages.objects[entity.name];
            spec.label = obj_messages[spec.name];
        }

        if (spec.factory) {
            section = spec.factory(spec);
        } else {
            section = IPA.details_list_section(spec);
        }
        facet.add_section(section);
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
                section.add_field(field);
            }
        }
    };

    function add_redirect_info(facet_name){
        if (!entity.redirect_facet){
            entity.redirect_facet = 'search';
        }
    }

    that.containing_entity = function(entity_name) {
        add_redirect_info();
        entity.containing_entity = IPA.get_entity(entity_name);
        return that;
    };

    that.dialog = function(spec) {
        var dialog;
        if (spec instanceof Object) {
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

        if (!spec.title) {
            var title = IPA.messages.dialogs.add_title;
            var label = entity.metadata.label_singular;
            spec.title = title.replace('${entity}', label);
        }

        return that.dialog(spec);
    };

    that.deleter_dialog = function(spec) {
        spec.factory = spec.factory || IPA.search_deleter_dialog;
        spec.name = spec.name || 'remove';

        return that.dialog(spec);
    };

    that.build = function(){
        var item = entity;
        entity = null;
        return item;
    };

    return that;
};
