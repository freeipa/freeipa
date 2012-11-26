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
    that.root = that.container.attr('id');

    that.content = spec.content;
    that.tab_class = spec.tab_class || 'tabs';
    that.max_depth = spec.max_depth || 3;

    that.tabs = [];
    that.tabs_by_name = {};

    that.path = {};

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

    that.get_active_tab = function(state) {
        var name = null;
        var next = state[that.root];

        while (next) {
            name = next;
            next = state[name];
        }

        return that.get_tab(name);
    };

    that.is_ancestor = function(tab, ancestor) {
        var parent = tab.parent;
        while (parent) {
            if (parent == ancestor) return true;
            parent = parent.parent;
        }
        return false;
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

        path_state[that.root] = tab.name;

        return path_state;
    };

    that.push_state = function(params) {

        var param_path = {};
        var param_state = {};

        for (var key in params) {
            var value = params[key];
            if (key.indexOf('-') < 0) {
                param_path[key] = value;
            } else {
                param_state[key] = value;
            }
        }

        var state = {};

        var prev_entity = IPA.current_entity;
        var prev_facet = prev_entity ? prev_entity.facet : null;

        if (prev_facet) {

            if (prev_facet.is_dirty()) {
                var dialog = IPA.dirty_dialog({
                    facet: prev_facet
                });

                dialog.callback = function() {

                    // Some facet's might not call reset before this call but after
                    // so they are still dirty. Calling reset prevent's opening of
                    // dirty dialog again.
                    if (prev_facet.is_dirty()) prev_facet.reset();
                    $.bbq.pushState(params);
                };

                dialog.open(that.container);

                return false;
            }

            // get prev facet state
            $.extend(state, prev_facet.state);
        }

        // merge existing path with new path
        $.extend(that.path, param_path);

        // find the tab pointed by the path
        var tab = that.get_active_tab(that.path);

        // find the active tab at the lowest level
        while (!tab.entity) {
            var index = tab.container.tabs('option', 'selected');
            tab = tab.children[index];
        }

        var facet_name;
        if (tab.entity == prev_entity) {
            // merge prev facet state with new state to find new facet name
            $.extend(state, param_state);
            facet_name = state[tab.entity.name+'-facet'];

        } else {
            // find new facet name in the new state
            facet_name = param_state[tab.entity.name+'-facet'];
        }

        var facet = tab.entity.get_facet(facet_name);

        // update new facet state with new state
        $.extend(facet.state, param_state);

        var entity = tab.entity.get_containing_entity();
        while (entity) {
            var facet2 = entity.get_facet();

            var key_names = entity.get_key_names();
            for (var i=0; i<key_names.length; i++) {
                var key_name = key_names[i];
                var key_value = param_state[key_name];
                if (!key_value) key_value = facet2.state[key_name];
                if (key_value) facet.state[key_name] = key_value;
            }

            entity = entity.get_containing_entity();
        }

        // push entity path and facet state
        state = {};
        $.extend(state, that.get_path_state(tab.name));
        $.extend(state, facet.state);
        $.bbq.pushState(state, 2);

        return true;
    };

    that.get_state = function(key) {
        return $.bbq.getState(key);
    };

    that.remove_state = function(key) {
        $.bbq.removeState(key);
    };

    that.show_tab = function(tab_name, pkey) {

        var tab = that.get_tab(tab_name);

        var state = that.get_path_state(tab.name);

        if (tab.entity) {

            if (tab.facet) {
                state[tab.entity.name + '-facet'] = tab.facet;
            }

            if (pkey) {
                state[tab.entity.name + '-pkey'] = pkey;
            }
        }

        return that.push_state(state);
    };

    that.show_page = function(entity_name, facet_name, pkey) {
        var state = that.get_path_state(entity_name);

        if (facet_name) {
            state[entity_name + '-facet'] = facet_name;
        }

        if (pkey) {
            state[entity_name + '-pkey'] = pkey;
        }

        return that.push_state(state);
    };

    /*like show page, but works for nested entities */
    that.show_entity_page = function(entity, facet_name, pkeys) {
        var state = that.get_path_state(entity.name);

        if (facet_name) {
            state[entity.name + '-facet'] = facet_name;
        }

        if (pkeys) {
            if (pkeys instanceof Array){
                var current_entity = entity;
                while (current_entity){
                    state[current_entity.name + '-pkey'] = pkeys.pop();
                    current_entity = current_entity.get_containing_entity();
                }
            }else{
                state[entity.name + '-pkey'] = pkeys;
            }
        }

        return that.push_state(state);
    };

    that.show_top_level_page = function() {
        jQuery.bbq.pushState({}, 2);
    };

    that.get_tab_facet = function(tab_name) {

        var facet = null;
        var tab = that.get_tab(tab_name);

        if (tab.entity) {
            if (tab.facet) {
                facet = tab.entity.get_facet(tab.facet);
            } else {
                facet = tab.entity.get_facet(tab.entity.redirect_facet);
            }
        }

        return facet;
    };


    that.create = function() {

        var container = $('<div/>', {
            name: that.root
        }).appendTo(that.container);

        that._create(that.tabs, container, 1);

        var tabs = $('.' + that.tab_class, that.container);
        tabs.tabs({
            select: function(event, ui) {

                // get the selected tab
                var panel = $(ui.panel);
                var name = panel.attr('name');
                var selected_tab = that.get_tab(name);

                // get the tab specified in the URL state
                var state = that.get_state();
                var url_tab = that.get_active_tab(state);

                if (url_tab) {
                    // if they are the same, the selection is triggered by hash change
                    if (url_tab == selected_tab) {
                        // use the URL state to update internal state
                        return that.push_state(state);

                    // if the selection is for the ancestor
                    } else if (that.is_ancestor(url_tab, selected_tab)) {
                        // let the tab be updated and don't change the state
                        return true;
                    }
                }

                // selection is triggered by mouse click, update the URL state
                return that.show_tab(name);
            }
        });
    };

    that._create = function(tabs, container, depth) {

        var parent_name = container.attr('name');
        that.path[parent_name] = tabs[0].name;

        container.addClass(that.tab_class);
        container.addClass('tabs'+depth);

        var ul = $('<ul/>').appendTo(container);
        var created_count = 0;

        for (var i=0; i<tabs.length; i++) {
            var tab = tabs[i];
            tab.container = container;

            var tab_id = that.root+'-'+tab.name;

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

            var tab_li = $('<li/>').append($('<a/>', {
                href: '#'+tab_id,
                title: tab.label,
                html: tab.label
            }));

            if (tab.hidden) {
                tab_li.css('display', 'none');
            }

            tab.children_container = $('<div/>', {
                id: tab_id,
                name: tab.name
            });

            if (tab.children && tab.children.length) {
                var kids =
                    that._create(tab.children, tab.children_container, depth+1);
                /*If there are no child tabs, remove the container */
                if (kids === 0) {
                    tabs.splice(i, 1);
                    i -= 1;
                    continue;
                }
            }
            created_count += 1;
            tab_li.appendTo(ul);
            tab.children_container.appendTo(container);
        }
        return created_count;
    };

    that.update = function() {
        for (var i=1; i<=that.max_depth; i++) {
            that.container.removeClass(that.tab_class+'-'+i);
            that.content.removeClass(that.tab_class+'-'+i);
        }
        $('.entity', that.content).css('display', 'none');

        var container = $('div[name='+that.root+']', that.container);
        that._update(that.tabs, container, 1);
    };

    that._update = function(tabs, container, depth) {

        var parent_name = container.attr('name');
        var tab_name = that.get_state(parent_name);
        if (!tab_name) tab_name = that.path[parent_name];
        that.path[parent_name] = tab_name;

        var index = 0;
        while (index < tabs.length && tabs[index].name != tab_name) index++;
        if (index >= tabs.length) index = 0;

        container.tabs('select', index);

        var tab = tabs[index];
        if (tab.depth !== undefined) {
            depth += tab.depth;
        }

        if (tab.children && tab.children.length) {
            var next_depth = depth + 1;
            that._update(tab.children, tab.children_container, next_depth);

        } else if (tab.entity) {

            that.container.addClass(that.tab_class+'-'+depth);
            that.content.addClass(that.tab_class+'-'+depth);

            var entity_container = $('.entity[name="'+tab.entity.name+'"]',
                                     that.content);
            if (!entity_container.length) {
                tab.content = $('<div/>', {
                    name: tab.entity.name,
                    title: tab.entity.label,
                    'class': 'entity'
                }).appendTo(that.content);
                tab.entity.create(tab.content);
            }

            entity_container.css('display', 'block');
            tab.entity.display(tab.content);
        }
    };

    // methods that should be invoked by subclasses
    that.navigation_update = that.update;

    that.set_tabs(spec.tabs);

    return that;
};
