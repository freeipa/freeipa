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

    that.container = spec.container;
    that.content = spec.content;
    that.tab_class = spec.tab_class || 'tabs';

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

        var state = {};

        var tab = that.get_tab(name);
        var parent = tab.parent;

        while (parent) {
            state[parent.name] = tab.name;

            tab = parent;
            parent = tab.parent;
        }

        state[that.container.attr('id')] = tab.name;

        return state;
    };

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

        $.bbq.pushState(params);
        return true;
    };

    that.get_state = function(key) {
        return $.bbq.getState(key);
    };

    that.remove_state = function(key) {
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

    that.create = function() {

        that._create(that.tabs, that.container, 1);

        var tabs = $('.' + that.tab_class);
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

        var parent_id = container.attr('id');

        var ul = $('<ul/>').appendTo(container);

        for (var i=0; i<tabs.length; i++) {
            var tab = tabs[i];
            var tab_id = parent_id+'-'+i;

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

            $('<li/>').append($('<a/>', {
                href: '#'+tab_id,
                title: tab.label,
                html: tab.label
            })).appendTo(ul);

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
        $('.entity', that.content).css('display', 'none');
        that._update(that.tabs, that.container, 1);
    };

    that._update = function(tabs, container, depth) {

        var parent_name = container.attr('name') || container.attr('id');
        var tab_name = that.get_state(parent_name);

        var index = 0;
        while (index < tabs.length && tabs[index].name != tab_name) index++;
        if (index >= tabs.length) index = 0;

        container.tabs('select', index);

        var tab = tabs[index];

        if (tab.children && tab.children.length) {
            that._update(tab.children, tab.container, depth+1);

        } else if (tab.entity) {
            var entity_container = $('.entity[name="'+tab.entity.name+'"]', that.content);
            if (!entity_container.length) {
                tab.content = $('<div/>', {
                    name: tab.name,
                    title: tab.label,
                    'class': 'entity'
                }).appendTo(that.content);
                tab.entity.create(tab.content);
            }

            entity_container.css('display', 'inline');
            tab.entity.setup(tab.content);
        }
    };

    // methods that should be invoked by subclasses
    that.navigation_update = that.update;

    that.set_tabs(spec.tabs);

    return that;
};
