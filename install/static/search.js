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
    if (!scl){
        scl = [];
    }

    function find_on_click() {
        var filter = $(this).prev('input[type=text]').val();
        var state = {};
        state[obj_name + '-filter'] = filter;
        $.bbq.pushState(state);
    };

    function delete_on_click_outer() {
        var delete_list = [];
        var delete_dialog = $('<div></div>', {
            title: ipa_messages.button.delete,
            'class': 'search-dialog-delete',
        });

        function delete_on_click() {
            ipa_cmd('del', delete_list, {}, delete_on_win, null, obj_name);
            delete_dialog.dialog('close');
        };

        function delete_on_win() {
            for (var i = 0; i < delete_list.length; ++i) {
                var chk = container.find(
                    '.search-selector[title=' + delete_list[i] + ']'
                );
                if (chk)
                    chk.closest('tr').remove();
            }
        };

        function cancel_on_click() {
            delete_dialog.dialog('close');
        };

        container.find('.search-selector').each(function () {
            var jobj = $(this);
            if (jobj.attr('checked'))
                delete_list.push(jobj.attr('title'));
        });

        if (delete_list.length == 0)
            return;

        delete_dialog.text(ipa_messages.search.delete_confirm);

        delete_dialog.dialog({
            modal: true,
            buttons: {
                'Delete': delete_on_click,
                'Cancel': cancel_on_click,
            },
        });
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
    ipa_make_button('ui-icon-search',ipa_messages.button.find).
        click(find_on_click).appendTo(jobj);

    ipa_make_button('ui-icon-trash',ipa_messages.button.delete).
        click(delete_on_click_outer).appendTo(jobj);

    div.append('<span class="search-buttons"></span>');

    var search_results = $('<div/>', {
        class: 'search-results'
    }).appendTo(container);

    var search_table = $('<table/>', {
        class: 'search-table'
    }).appendTo(search_results);

    search_table.append('<thead><tr></tr></thead>');
    search_table.append('<tbody></tbody>');
    search_table.append('<tfoot></tfoot>');

    var tr = search_table.find('tr');
    search_insert_checkbox_th(tr);
    for (var i = 0; i < scl.length; ++i) {
        var c = scl[i];
        search_insert_th(tr, obj_name, c[0], c[1], c[2]);
    }
}

function search_insert_checkbox_th(jobj)
{
    function select_all_on_click() {
        var jobj = $(this);

        var checked = null;
        if (jobj.attr('checked')) {
            checked = true;
            jobj.attr('title', 'Unselect All');
        } else {
            checked = false;
            jobj.attr('title', 'Select All');
        }
        jobj.attr('checked', checked);

        var chks = jobj.closest('.search-container').find('.search-selector');
        for (var i = 0; i < chks.length; ++i)
            chks[i].checked = checked;
    };

    var checkbox = $('<input />', {
        type: 'checkbox',
        title: 'Select All',
    });
    checkbox.click(select_all_on_click);

    var th = $('<th></th>');
    th.append(checkbox);

    jobj.append(th);
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

function search_load(jobj, criteria, on_win, on_fail)
{
    var obj_name = jobj.attr('id');

    function search_on_success(data, text_status, xhr) {
        if (on_win)
            on_win(data, text_status, xhr);
        if (data.error)
            return;
        search_display(obj_name, data);
    };

    function search_on_error(xhr, text_status, error_thrown) {
        if (on_fail)
            on_fail(xhr, text_status, error_thrown);

        var search_results = $('.search-results', jobj);
        search_results.append('<p>Error: '+error_thrown.name+'</p>');
        search_results.append('<p>URL: '+this.url+'</p>');
        search_results.append('<p>'+error_thrown.message+'</p>');
    }

    ipa_cmd(
      'find', [criteria], {all: true}, search_on_success, search_on_error, obj_name
    );
}

function search_generate_tr(thead, tbody, entry_attrs)
{
    var obj_name = tbody.closest('.search-container').attr('title');
    var pkey = ipa_objs[obj_name].primary_key;
    var pkey_value = entry_attrs[pkey];

    tbody.append('<tr></tr>');
    var tr = tbody.children().last();
    search_generate_checkbox_td(tr, pkey_value);

    var ths = thead.find('th');
    for (var i = 1; i < ths.length; ++i) {
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

        var state = {};
        state[obj_name + '-facet'] = 'details';
        state[obj_name + '-pkey'] = $(this).text();
        $.bbq.pushState(state);

        return (false);
    });
}

function search_generate_checkbox_td(tr, pkey)
{
    var checkbox = $('<input />', {
        name: pkey,
        title: pkey,
        type: 'checkbox',
        'class': 'search-selector',
    });
    var td = $('<td></td>');

    td.append(checkbox);
    tr.append(td);
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
            'More than ' + ipa_record_limit + ' results returned. ' +
            'First ' + ipa_record_limit + ' results shown.'
        );
    } else {
        tfoot.text(data.result.summary);
    }
}

