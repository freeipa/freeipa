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

/* use this to track individual changes between two hashchange events */
var window_hash_cache = {};

function nav_create(nls, container, tabclass)
{
    if (!container)
        container = $('#navigation');
    if (!tabclass)
        tabclass = 'tabs';

    nav_generate_tabs(nls, container, tabclass, 1);

    var tabs = $('.' + tabclass);
    tabs.tabs({
        select: function(event, ui) {
            var state = {};
            var id = $(ui.panel).parent().attr('id');
            state[id] = ui.index;
            $.bbq.pushState(state);
            return true;
        }
    });

    nav_update_tabs(nls, container);
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

function nav_select_tabs(nls, container)
{
    var id = container.attr('id');
    var selectedTab = $.bbq.getState(id, true) || 0;
    if (selectedTab >= nls.length) selectedTab = 0;
    container.tabs('select', selectedTab);

    for (var i = 0; i < nls.length; ++i) {
        var n = nls[i];

        var div = $('#'+n.name);

        if ( (!n.setup) && n.children) {
            nav_select_tabs(n.children, div);
        }
    }
}

function nav_update_tabs(nls, container)
{
    nav_select_tabs(nls, container);

    var index1 = container.tabs('option', 'selected');
    if (index1 >= nls.length) return;

    var tab1 = nls[index1];
    if (!tab1.children) return;

    var div1 = $('#' + tab1.name);
    var index2 = div1.tabs('option', 'selected');
    if (index2 >= tab1.children.length) return;

    var tab2 = tab1.children[index2];
    var obj_name = tab2.name;
    var entity_setup = tab2.setup;
    var div2 = $('#' + tab2.name);

    var state = obj_name + '-facet';
    var facet = $.bbq.getState(state, true) || 'search';
    var last_facet = window_hash_cache[state];

    if (facet != last_facet) {
        entity_setup(div2);
        window_hash_cache[state] = facet;

    } else if (facet == 'search') {
        state = obj_name + '-filter';
        var filter = $.bbq.getState(state, true);
        var last_filter = window_hash_cache[state];
        if (filter == last_filter) return;

        entity_setup(div2);
        window_hash_cache[state] = filter;

    } else if (facet == 'details') {
        state = obj_name + '-pkey';
        var pkey = $.bbq.getState(state, true);
        var last_pkey = window_hash_cache[state];
        if (pkey == last_pkey) return;

        entity_setup(div2);
        window_hash_cache[state] = pkey;

    } else if (facet == 'associate') {
        state = obj_name + '-enroll';
        var enroll = $.bbq.getState(state, true);
        var last_enroll = window_hash_cache[state];
        if (enroll == last_enroll) return;

        entity_setup(div2);
        window_hash_cache[state] = enroll;
    }
}
