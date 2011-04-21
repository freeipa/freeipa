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
    that.tab_class = spec.tab_class || 'tabs';

    that.tabs = spec.tabs || [];

    that.push_state = function(params) {
        if (!IPA.test_dirty()) {
            return false;
        }
        $.bbq.pushState(params);
        return true;
    };

    that.get_state = function(key) {
        return $.bbq.getState(key, true);
    };

    that.remove_state = function(key) {
        $.bbq.removeState(key);
    };

    that.create = function() {

        that._create(that.tabs, that.container, 1);

        var tabs = $('.' + that.tab_class);
        tabs.tabs({
            select: function(event, ui) {
                var panel = $(ui.panel);
                var parent = panel.parent();
                var id = parent.attr('id');
                var state = {};
                state[id] = ui.index;
                return that.push_state(state);
            }
        });
    };

    that._create = function(tabs, container, depth) {

        container.addClass(that.tab_class);
        container.addClass('tabs'+depth);

        var ul = $('<ul/>').appendTo(container);

        for (var i=0; i<tabs.length; i++) {
            var tab = tabs[i];

            if (!tab.name) {
                tab.name = tab.entity;
            }

            var label = tab.name;
            if (tab.entity) {
                var entity = IPA.get_entity(tab.entity);
                if (!entity){
                    tabs.splice(i, 1);
                    i--;
                    continue;
                }
                label = entity.label;
                tab.entity = entity;
            }
            if (tab.label){
                label = tab.label;
            }

            var li = that.create_tab_li(tab.name, label);
            ul.append(li);

            var div = that.create_tab_div(tab.name);
            container.append(div);

            if (tab.entity) {
                div.addClass('entity-container');
            }

            if (tab.children && tab.children.length) {
                that._create(tab.children, div, depth+1);
            }
        }
    };

    that.create_tab_li = function(id, name) {
        return $('<li/>').append($('<a/>', {
            href: '#'+id,
            title: id,
            html: name
        }));
    };

    that.create_tab_div = function(id) {
        return $('<div/>', {
            id: id
        });
    };

    that.update = function() {
        that._update(that.tabs, that.container, 1);
    };

    that._update = function(tabs, container, depth) {

        var id = container.attr('id');
        var index = that.get_state(id);
        if (!index || index >= tabs.length) index = 0;

        container.tabs('select', index);

        var tab = tabs[index];
        var container2 = $('#' + tab.name);

        if (tab.children && tab.children.length) {
            that._update(tab.children, container2, depth+1);

        } else if (tab.entity) {
            tab.entity.setup(container2);
        }
    };

    // methods that should be invoked by subclasses
    that.navigation_update = that.update;

    return that;
};

IPA.tab_state = function(entity_name,tab){
    var state;
    var i;
    var children;
    var tab_name;

    if (!tab){
        children = IPA.nav.tabs;
        tab_name = 'navigation';
    }else if (tab.children){
        children = tab.children;
        tab_name = tab.name;
    }else if (tab.entity){
        if (tab.entity.name === entity_name){
            state = {};
            state[entity_name] =  0;
        }
        return state;
    }

    for (i = 0; i < children.length; i +=1){
        state = IPA.tab_state(entity_name,children[i]);
        if (state){
            state[tab_name] = i;
            return state;
        }
    }
    return null;
};
