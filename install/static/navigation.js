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
            var state = {};
            var id = $(ui.panel).parent().attr('id');
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
        var n = nls[i];

        var name = n.name;
        if ((ipa_objs[n.name]) && (ipa_objs[n.name].label)){
            name = ipa_objs[n.name].label;
        }

        var li = nav_create_tab_li(n.name, name);
        ul.append(li);

        var div = nav_create_tab_div(n.name);
        container.append(div);

        if (n.children) {
            nav_generate_tabs(n.children, div, tabclass, depth +1 );
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
    _nav_update_tabs(nav_tabs_lists, nav_container);
}

function _nav_update_tabs(nls, container)
{
    var id = container.attr('id');
    var index = nav_get_state(id);
    if (!index || index >= nls.length) index = 0;

    container.tabs('select', index);

    var tab = nls[index];
    var container2 = $('#' + tab.name);

    if (tab.children) {
        _nav_update_tabs(tab.children, container2);

    } else if (tab.setup) {
        tab.setup(container2);
    }
}
