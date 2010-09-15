/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
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

/* REQUIRES: ipa.js */

function search_create(obj_name, scl, container)
{
    function find_on_click() {
        var filter = $(this).prev('input[type=text]').val();
        var state = {};
        state[obj_name + '-filter'] = filter;
        $.bbq.pushState(state);
    };

    if (!container) {
        alert('ERROR: search_create: Second argument "container" missing!');
        return;
    }

    container.attr('title', obj_name);
    container.addClass('search-container');

    container.append('<div class="search-controls"></div>');
    var div = container.children().last();
    div.append('<span class="search-filter"></span>');
    var jobj = div.children().last();
    jobj.append('<input type="text" />');
    jobj.children().last().attr('name', 'search-' + obj_name + '-filter')
    jobj.append('<input type="submit" value="find" />');;
    jobj.children().last().click(find_on_click);
    div.append('<span class="search-buttons"></span>');

    container.append('<table class="search-table"></table>');
    jobj = container.children().last();
    jobj.append('<thead><tr></tr></thead>');
    jobj.append('<tbody></tbody>');
    jobj.append('<tfoot></tfoot>');

    var tr = jobj.find('tr');
    for (var i = 0; i < scl.length; ++i) {
        var c = scl[i];
        search_insert_th(tr, obj_name, c[0], c[1], c[2]);
    }
}

var _search_th_template = '<th abbr="A" title="C">N</th>';

function search_insert_th(jobj, obj_name, attr, name, render_call)
{
    var th = _search_th_template.replace('A', attr);

    var param_info = ipa_get_param_info(obj_name, attr);
    if (param_info && param_info['label'])
        th = th.replace('N', param_info['label']);
    else
        th = th.replace('N', name);

    if (typeof render_call == 'function')
        th = th.replace('C', render_call.name);
    else
        th = th.replace('C', '-');

    jobj.append(th);
}

function search_load(obj_name, criteria, on_win, on_fail)
{
    function load_on_win(data, text_status, xhr) {
        if (data.error)
            return;
        search_display(obj_name, data);
        if (on_win)
            on_win(data, text_status, xhr);
    };

    function load_on_fail(xhr, text_status, error_thrown) {
        if (on_fail)
            on_fail(xhr, text_status, error_thrown);
    };

    ipa_cmd(
      'find', [criteria], {all: true}, load_on_win, load_on_fail, obj_name
    );
}

function search_generate_tr(thead, tbody, entry_attrs)
{
    tbody.append('<tr></tr>');
    var tr = tbody.children().last();

    var ths = thead.find('th');
    for (var i = 0; i < ths.length; ++i) {
        var jobj = $(ths[i]);
        var attr = jobj.attr('abbr');
        var value = entry_attrs[attr];

        var render_call = window[jobj.attr('title')];
        if (typeof render_call == 'function') {
            render_call(tr, attr, value, entry_attrs);
        } else
            search_generate_td(tr, attr, value);
    }

    tbody.find('.search-a-pkey').click(function () {
        var jobj = $(this);
        var obj_name = tbody.closest('.search-container').attr('title');

        var state = {};
        state[obj_name + '-facet'] = 'details';
        state[obj_name + '-pkey'] = $(this).text();
        $.bbq.pushState(state);

        return (false);
    });
}

var _search_td_template = '<td title="A">V</td>';
var _search_a_pkey_template = '<a href="jslink" class="search-a-pkey">V</a>';

function search_generate_td(tr, attr, value)
{
    var obj_name = tr.closest('.search-container').attr('title');

    var param_info = ipa_get_param_info(obj_name, attr);
    if (param_info && param_info['primary_key'])
        value = _search_a_pkey_template.replace('V', value);

    tr.append(_search_td_template.replace('A', attr).replace('V', value));
}

function search_display(obj_name, data)
{
    var selector = '.search-container[title=' + obj_name + ']';
    var thead = $(selector + ' thead');
    var tbody = $(selector + ' tbody');
    var tfoot = $(selector + ' tfoot');

    tbody.find('tr').remove();

    var result = data.result.result;
    for (var i = 0; i < result.length; ++i)
        search_generate_tr(thead, tbody, result[i]);

    if (data.result.truncated) {
        tfoot.text(
            'More than ' + sizelimit + ' results returned. ' +
            'First ' + sizelimit + ' results shown.'
        );
    } else {
        tfoot.text(data.result.summary);
    }
}

