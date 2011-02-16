/*jsl:import ipa.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
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

IPA.nav = {
    tabs_lists : {},
    nav_container : {},

    push_state : function (params) {
        if (!IPA.test_dirty()){
            return false;
        }
        $.bbq.pushState(params);
        return true;
    },

    get_state : function (key) {
        return $.bbq.getState(key, true);
    },

    remove_state : function (key) {
        $.bbq.removeState(key);
    },

    create : function (nls, container, tabclass) {
        if (!container)
            container = $('#navigation');
        if (!tabclass)
            tabclass = 'tabs';

        IPA.nav.tabs_lists = nls;
        IPA.nav.nav_container = container;

        IPA.nav.generate_tabs(nls, container, tabclass, 1);

        var tabs = $('.' + tabclass);
        tabs.tabs({
            select: function(event, ui) {
                var panel = $(ui.panel);
                var parent = panel.parent();
                var id = parent.attr('id');
                var state = {};
                state[id] = ui.index;
                return IPA.nav.push_state(state);
            }
        });

        IPA.nav.update_tabs();
    },

    generate_tabs : function (nls, container, tabclass, depth) {
        container.addClass(tabclass);
        container.addClass('tabs'+depth);

        var ul = $('<ul/>');
        container.append(ul);

        for (var i = 0; i < nls.length; ++i) {
            var tab = nls[i];

            var label = tab.name;
            if (tab.entity) {
                var entity = IPA.get_entity(tab.entity);
                label = entity.label;
            }
            if (tab.label){
                label = tab.label;
            }

            var li = IPA.nav.create_tab_li(tab.name, label);
            ul.append(li);

            var div = IPA.nav.create_tab_div(tab.name);
            container.append(div);

            if (tab.entity) {
                div.addClass('entity-container');
            }

            if (tab.children && depth === 1) {
                IPA.nav.generate_tabs(tab.children, div, tabclass, depth +1 );
            }
        }
    },

    create_tab_li : function (id, name) {
        return $('<li/>').append($('<a/>', {
            href: '#'+id,
            title: id,
            html: name
        }));
    },

    create_tab_div : function (id) {
        return $('<div/>', {
            id: id
        });
    },

    update_tabs : function () {
        IPA.nav._update_tabs(IPA.nav.tabs_lists, IPA.nav.nav_container,1);
    },

    _update_tabs : function (nls, container,depth) {
        var id = container.attr('id');
        var index = IPA.nav.get_state(id);
        if (!index || index >= nls.length) index = 0;

        container.tabs('select', index);

        var tab = nls[index];
        var container2 = $('#' + tab.name);

        if (tab.children   && depth === 1 ) {
            IPA.nav._update_tabs(tab.children, container2,depth+1);

        } else if (tab.entity) {
            var entity_name = tab.entity;

            var nested_entity = IPA.nav.get_state(entity_name+'-entity');

            if (nested_entity){
                entity_name = nested_entity;
            }

            var entity = IPA.get_entity(entity_name);
            entity.setup(container2);
        }
    }
};
