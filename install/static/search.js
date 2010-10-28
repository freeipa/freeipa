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

function ipa_search_column(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.label = spec.label || that.name;
    that.facet = spec.facet;

    that.init = spec.init || init;
    that.setup = spec.setup || setup;

    function init() {
    }

    function setup(tr, attr, value, entry_attrs) {
        search_generate_td(tr, attr, value, entry_attrs);
    }

    return that;
}

function ipa_search_facet(spec) {

    spec = spec || {};

    var that = ipa_facet(spec);

    that.init = spec.init || init;
    that.setup = spec.setup || setup;

    that.columns = [];
    that.columns_by_name = {};

    that.get_columns = function() {
        return that.columns;
    };

    that.get_column = function(name) {
        return that.columns_by_name[name];
    };

    that.add_column = function(column) {
        that.columns.push(column);
        that.columns_by_name[column.name] = column;
    };

    that.create_column = function(spec) {
        spec.facet = that;
        var column = ipa_search_column(spec);
        that.add_column(column);
        return column;
    };

    function init() {
    }

    that.is_dirty = function() {
        var filter = $.bbq.getState(that.entity_name + '-filter', true) || '';
        return filter != that.filter;
    };

    function setup(container, unspecified) {

        that.filter = $.bbq.getState(that.entity_name + '-filter', true) || '';

        search_create(that.entity_name, that.columns, container);

        ipa_make_button('ui-icon-plus', IPA.messages.button.add).
            click(function() {
                var entity = IPA.get_entity(that.entity_name);
                if (entity) {
                    entity.add_dialog.open();
                    return false;
                }

                var dialog = ipa_entity_get_add_dialog(that.entity_name);
                dialog.open();

                return false;
            }).
            appendTo($('.search-controls', container));

        search_load(container, that.filter);
    }

    if (spec.columns) {
        for (var i=0; i<spec.columns.length; i++) {
            var column = spec.columns[i];
            column.facet = that;
            that.add_column(column);
        }
    }

    that.init();

    return that;
}


function search_create(entity_name, columns, container) {

    function find_on_click() {
        var filter = $(this).prev('input[type=text]').val();
        var state = {};
        state[entity_name + '-filter'] = filter;
        $.bbq.pushState(state);
    }

    function delete_on_click_outer() {
        var delete_list = [];
        var delete_dialog = $('<div></div>', {
            title: IPA.messages.button.delete,
            'class': 'search-dialog-delete'
        });

        function delete_on_click() {
            ipa_cmd('del', delete_list, {}, delete_on_win, null, entity_name);
            delete_dialog.dialog('close');
        }

        function delete_on_win() {
            for (var i = 0; i < delete_list.length; ++i) {
                var chk = container.find(
                    '.search-selector[title=' + delete_list[i] + ']'
                );
                if (chk)
                    chk.closest('tr').remove();
            }
        }

        function cancel_on_click() {
            delete_dialog.dialog('close');
        }

        container.find('.search-selector').each(function () {
            var jobj = $(this);
            if (jobj.attr('checked'))
                delete_list.push(jobj.attr('title'));
        });

        if (delete_list.length == 0)
            return;

        delete_dialog.text(IPA.messages.search.delete_confirm);

        delete_dialog.dialog({
            modal: true,
            buttons: {
                'Delete': delete_on_click,
                'Cancel': cancel_on_click
            }
        });
    }

    if (!container) {
        alert('ERROR: search_create: Second argument "container" missing!');
        return null;
    }

    container.attr('title', entity_name);
    container.addClass('search-container');

    var search_controls = $('<div/>', {
        'class': 'search-controls'
    }).appendTo(container);

    var search_filter = $('<span/>', {
        'class': 'search-filter'
    }).appendTo(search_controls);

    var filter = $('<input/>', {
        'type': 'text',
        'name': 'search-' + entity_name + '-filter'
    }).appendTo(search_filter);

    ipa_make_button('ui-icon-search', IPA.messages.button.find).
        click(find_on_click).appendTo(search_filter);

    ipa_make_button('ui-icon-trash',IPA.messages.button.delete).
        click(delete_on_click_outer).appendTo(search_filter);

    search_controls.append('<span class="search-buttons"></span>');

    var search_results = $('<div/>', {
        'class': 'search-results'
    }).appendTo(container);

    var search_table = $('<table/>', {
        'class': 'search-table'
    }).appendTo(search_results);

    search_table.append('<thead><tr></tr></thead>');
    search_table.append('<tbody></tbody>');
    search_table.append('<tfoot></tfoot>');

    var tr = search_table.find('tr');
    search_insert_checkbox_th(tr);
    for (var i = 0; i < columns.length; ++i) {
        var c = columns[i];
        search_insert_th(tr, entity_name, c.name, c.label, c.setup);
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
        title: 'Select All'
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

function search_load(container, criteria, on_win, on_fail)
{
    var entity_name = container.attr('id');

    function search_on_success(data, text_status, xhr) {
        if (on_win)
            on_win(data, text_status, xhr);
        if (data.error)
            return;
        search_display(entity_name, data);
    }

    function search_on_error(xhr, text_status, error_thrown) {
        if (on_fail)
            on_fail(xhr, text_status, error_thrown);

        var search_results = $('.search-results', container);
        search_results.append('<p>Error: '+error_thrown.name+'</p>');
        search_results.append('<p>URL: '+this.url+'</p>');
        search_results.append('<p>'+error_thrown.message+'</p>');
    }

    ipa_cmd(
      'find', [criteria], {all: true}, search_on_success, search_on_error, entity_name
    );
}

function search_generate_tr(thead, tbody, entry_attrs)
{
    var obj_name = tbody.closest('.search-container').attr('title');
    var pkey = IPA.metadata[obj_name].primary_key;
    var pkey_value = entry_attrs[pkey];

    var entity = IPA.get_entity(obj_name);
    var facet = entity ? entity.get_facet('search') : null;

    tbody.append('<tr></tr>');
    var tr = tbody.children().last();
    search_generate_checkbox_td(tr, pkey_value);

    var ths = thead.find('th');
    for (var i = 1; i < ths.length; ++i) {
        var jobj = $(ths[i]);
        var attr = jobj.attr('abbr');
        var value = entry_attrs[attr];

        var column = facet ? facet.get_column(attr) : null;
        var render_call = window[jobj.attr('title')];

        if (column && column.setup) {
            column.setup(tr, attr, value, entry_attrs);

        } else if (typeof render_call == 'function') {
            render_call(tr, attr, value, entry_attrs);

        } else
            search_generate_td(tr, attr, value, entry_attrs);
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
        'class': 'search-selector'
    });
    var td = $('<td></td>');

    td.append(checkbox);
    tr.append(td);
}

var _search_td_template = '<td title="A">V</td>';
var _search_a_pkey_template = '<a href="jslink" class="search-a-pkey">V</a>';

function search_generate_td(tr, attr, value, entry_attrs)
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
            'Query returned results than configured size limit will show.' +
            'First ' + data.result.count + ' results shown.'
        );
    } else {
        tfoot.text(data.result.summary);
    }
}

