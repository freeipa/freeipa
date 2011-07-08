/*jsl:import ipa.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
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

IPA.navigation = function(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;

    that.container = spec.container;
    that.content = spec.content;
    that.tab_class = spec.tab_class || 'tabs';
    that.max_depth = spec.max_depth || 3;

    that.tabs = [];
    that.tabs_by_name = {};

    that.set_tabs = function(tabs) {
        that.tabs = tabs;
        that.tabs_by_name = {};

        for (var i=0; i<tabs.length; i++) {
            that.add_tab(tabs[i]);
        }
    };

    that.add_tab = function(tab, parent) {
        if (!tab.name) {
            tab.name = tab.entity;
        }
        tab.parent = parent;

        that.tabs_by_name[tab.name] = tab;

        for (var i=0; tab.children && i<tab.children.length; i++) {
            that.add_tab(tab.children[i], tab);
        }
    };

    that.get_tab = function(name) {
        return that.tabs_by_name[name];
    };

    that.get_path_state = function(name) {

        var path_state = {};

        var tab = that.get_tab(name);
        var parent = tab.parent;

        while (parent) {
            path_state[parent.name] = tab.name;

            tab = parent;
            parent = tab.parent;
        }

        path_state[that.container.attr('id')] = tab.name;

        return path_state;
    };

    var state = $.bbq.getState();

    that.push_state = function(params) {

        if (IPA.current_entity) {
            var facet_name = IPA.current_facet(IPA.current_entity);
            var facet = IPA.current_entity.get_facet(facet_name);

            if (facet.is_dirty()) {
                var dialog = IPA.dirty_dialog({
                    facet: facet
                });

                dialog.callback = function() {
                    $.bbq.pushState(params);
                };

                dialog.init();
                dialog.open($('#navigation'));

                return false;
            }
        }

        for ( var param in params){
            state[param] = params[param];
        }

        var url_state ={};
        var key = 'navigation';
        while(state[key]){
            var value = state[key];
            url_state[key] = value;
            key = value;
        }

        /*We are at the leaf node, which is the sleected entity.*/
        var entity = value;
        for (var key2 in state){
            if ((key2 === entity) || (key2.search('^'+entity +'-') > -1)){
                url_state[key2] = state[key2];
            }
        }

        /*
           Trace back up the nested entities for their pkeys as well
        */
        var current_entity = IPA.get_entity(entity);
        while(current_entity !== null){
            var key_names = current_entity.get_key_names();
            for (var j = 0; j < key_names.length; j+= 1){
                var key_name = key_names[j];
                if (state[key_name]){
                    url_state[key_name] = state[key_name];
                }
            }
            current_entity = current_entity.containing_entity;
        }

        $.bbq.pushState(url_state,2);
        return true;
    };

    that.get_state = function(key) {
        var url_state = $.bbq.getState(key);
        if (!url_state){
            url_state = state[key];
        }
        return url_state;
    };

    that.remove_state = function(key) {
        delete state[key];
        $.bbq.removeState(key);
    };

    that.show_page = function(entity_name, facet_name, pkey) {
        var state = that.get_path_state(entity_name);

        if (facet_name) {
            state[entity_name + '-facet'] = facet_name;
        }

        if (pkey) {
            state[entity_name + '-pkey'] = pkey;
        }

        that.push_state(state);
    };

    /*like show page, but works for nested entities */
    that.show_entity_page = function(entity, facet_name, pkeys) {
        var state = that.get_path_state(entity.name);

        if (facet_name) {
            state[entity.name + '-facet'] = facet_name;
        }

        if (pkeys) {
            var current_entity = entity;
            while (current_entity){
                state[current_entity.name + '-pkey'] = pkeys.pop();
                current_entity = current_entity.containing_entity;
            }
        }

        that.push_state(state);
    };


    that.create = function() {

        var container = $('<div/>', {
            name: 'navigation'
        }).appendTo(that.container);

        that._create(that.tabs, container, 1);

        var tabs = $('.' + that.tab_class, that.container);
        tabs.tabs({
            select: function(event, ui) {
                var panel = $(ui.panel);
                var name = panel.attr('name');

                return that.show_page(name);
            }
        });
    };

    that._create = function(tabs, container, depth) {

        container.addClass(that.tab_class);
        container.addClass('tabs'+depth);

        var ul = $('<ul/>').appendTo(container);

        for (var i=0; i<tabs.length; i++) {
            var tab = tabs[i];
            var tab_id = 'navigation-'+tab.name;

            if (tab.entity) {
                var entity = IPA.get_entity(tab.entity);
                if (!entity){
                    tabs.splice(i, 1);
                    i--;
                    continue;
                }
                tab.entity = entity;

                if (!tab.label) {
                    tab.label = entity.label;
                }
            }

            var tab_li =$('<li/>').append($('<a/>', {
                href: '#'+tab_id,
                title: tab.label,
                html: tab.label
            })).appendTo(ul);

            if (tab.hidden){
                tab_li.css('display','none');
            }

            tab.container = $('<div/>', {
                id: tab_id,
                name: tab.name
            }).appendTo(container);

            if (tab.children && tab.children.length) {
                that._create(tab.children, tab.container, depth+1);
            }
        }
    };

    that.update = function() {
        for (var i=1; i<=that.max_depth; i++) {
            that.container.removeClass(that.tab_class+'-'+i);
            that.content.removeClass(that.tab_class+'-'+i);
        }
        $('.entity', that.content).css('display', 'none');

        var container = $('div[name=navigation]', that.container);
        that._update(that.tabs, container, 1);
    };

    that._update = function(tabs, container, depth) {

        var parent_name = container.attr('name');
        var tab_name = that.get_state(parent_name);

        var index = 0;
        while (index < tabs.length && tabs[index].name != tab_name) index++;
        if (index >= tabs.length) index = 0;

        container.tabs('select', index);

        var tab = tabs[index];
        if (tab.hidden){
            depth = depth -1;
        }

        if (tab.children && tab.children.length) {
            var next_depth = depth + 1;
            that._update(tab.children, tab.container, next_depth);

        } else if (tab.entity) {

            that.container.addClass(that.tab_class+'-'+depth);
            that.content.addClass(that.tab_class+'-'+depth);

            var entity_container = $('.entity[name="'+tab.entity.name+'"]',
                                     that.content);
            if (!entity_container.length) {
                tab.content = $('<div/>', {
                    name: tab.name,
                    title: tab.label,
                    'class': 'entity'
                }).appendTo(that.content);
                tab.entity.create(tab.content);
            }

            entity_container.css('display', 'block');
            tab.entity.setup(tab.content);
        }
    };

    // methods that should be invoked by subclasses
    that.navigation_update = that.update;

    that.set_tabs(spec.tabs);

    return that;
};
