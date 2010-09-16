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

function nav_create(nls, container, tabclass)
{
    if (!container)
        container = $('#navigation');
    if (!tabclass)
        tabclass = 'tabs';

    nav_generate_tabs(nls, container, tabclass, 1);

    var tabs = $('.' + tabclass);
    tabs.tabs({event: 'change'});
    tabs.find('ul.ui-tabs-nav a').click(_nav_tab_on_click);
}

function nav_generate_tabs(nls, container, tabclass, depth)
{
    container.addClass(tabclass);
    container.addClass('tabs'+depth);
    container.prepend('<ul></ul>');

    var ul = container.children().first();
    for (var i = 0; i < nls.length; ++i) {
        var n = nls[i];

        nav_insert_tab_li(ul, n[0], n[1]);
        nav_insert_tab_div(container, n[0]);

        var div = ul.parent().children().last();
        if (typeof n[2] == 'function') {
            n[2](div);
        } else if (n[2].length) {
            nav_generate_tabs(n[2], div, tabclass, depth +1 );
        }
    }
}

var _nav_li_tab_template = '<li><a href="#I">N</a></li>';

function nav_insert_tab_li(jobj, id, name)
{
    jobj.append(_nav_li_tab_template.replace('I', id).replace('N', name));
}

var _nav_div_tab_template = '<div id="T"></div>';

function nav_insert_tab_div(jobj, id)
{
    jobj.append(_nav_div_tab_template.replace('T', id));
}

function _nav_tab_on_click(obj)
{
    var jobj = $(this);
    var state = {};
    var id = jobj.closest('.tabs').attr('id');
    var index = jobj.parent().prevAll().length;

    state[id] = index;
    $.bbq.pushState(state);
}

