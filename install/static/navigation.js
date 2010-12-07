/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
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

var nav_tabs_lists;
var nav_container;

function nav_push_state(params)
{
    $.bbq.pushState(params);
}

function nav_get_state(key)
{
    return $.bbq.getState(key, true);
}

function nav_remove_state(key)
{
    $.bbq.removeState(key);
}

function nav_create(nls, container, tabclass)
{
    if (!container)
        container = $('#navigation');
    if (!tabclass)
        tabclass = 'tabs';

    nav_tabs_lists = nls;
    nav_container = container;

    nav_generate_tabs(nls, container, tabclass, 1);

    var tabs = $('.' + tabclass);
    tabs.tabs({
        select: function(event, ui) {
            var panel = $(ui.panel);
            var parent = panel.parent();
            var id = parent.attr('id');
            var state = {};
            state[id] = ui.index;
            nav_push_state(state);
            return true;
        }
    });

    nav_update_tabs();
}

function nav_generate_tabs(nls, container, tabclass, depth)
{
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

        var li = nav_create_tab_li(tab.name, label);
        ul.append(li);

        var div = nav_create_tab_div(tab.name);
        container.append(div);

        if (tab.entity) {
            div.addClass('entity-container');
        }

        if (tab.children && depth === 1) {
            nav_generate_tabs(tab.children, div, tabclass, depth +1 );
        }
    }
}

function nav_create_tab_li(id, name)
{
    return $('<li/>').append($('<a/>', {
        href: '#'+id,
        title: id,
        html: name
    }));
}

function nav_create_tab_div(id)
{
    return $('<div/>', {
        id: id
    });
}

function nav_update_tabs()
{
    _nav_update_tabs(nav_tabs_lists, nav_container,1);
}

function _nav_update_tabs(nls, container,depth)
{
    var id = container.attr('id');
    var index = nav_get_state(id);
    if (!index || index >= nls.length) index = 0;

    container.tabs('select', index);

    var tab = nls[index];
    var container2 = $('#' + tab.name);

    if (tab.children   && depth === 1 ) {
        _nav_update_tabs(tab.children, container2,depth+1);

    } else if (tab.entity) {
        var entity_name = tab.entity;

        var nested_entity = nav_get_state(entity_name+'-entity');

        if (nested_entity){
            entity_name = nested_entity;
        }

        var entity = IPA.get_entity(entity_name);
        entity.setup(container2);
    }
}
