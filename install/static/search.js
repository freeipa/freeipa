/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
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

function ipa_search_widget(spec) {

    spec = spec || {};

    var that = ipa_table_widget(spec);

    that.super_create = that.super('create');
    that.super_setup = that.super('setup');

    that.create = function(container) {

        var div = $('#'+that.id);
        var search_controls = $('<div/>', {
            'class': 'search-controls'
        }).appendTo(div);

        var search_filter = $('<span/>', {
            'class': 'search-filter'
        }).appendTo(search_controls);

        this.filter = $('<input/>', {
            'type': 'text',
            'name': 'search-' + that.entity_name + '-filter'
        }).appendTo(search_filter);

        ipa_button({
            'label': IPA.messages.button.find,
            'icon': 'ui-icon-search',
            'click': function() { that.find(container); }
        }).appendTo(search_filter);

        ipa_button({
            'label': IPA.messages.button.remove,
            'icon': 'ui-icon-trash',
            'click': function() { that.remove(container); }
        }).appendTo(search_filter);

        ipa_button({
            'label': IPA.messages.button.add,
            'icon': 'ui-icon-plus',
            'click': function() { that.add(container); }
        }).appendTo(search_filter);

        search_controls.append('<span class="search-buttons"></span>');

        var search_results = $('<div/>', {
            'class': 'search-results'
        }).appendTo(div);

        that.super_create(container);
    };

    that.setup = function(container) {

        that.super_setup(container);

        var filter = $.bbq.getState(that.entity_name + '-filter', true) || '';
        this.filter.val(filter);
    };

    that.find = function(container) {
        var filter = this.filter.val();
        var state = {};
        state[that.entity_name + '-filter'] = filter;
        $.bbq.pushState(state);
    };

    that.add = function(container) {

        var entity = IPA.get_entity(that.entity_name);

        var dialog = entity.get_dialog('add');
        dialog.open(container);

        return false;
    };

    that.remove = function(container) {

        var values = that.get_selected_values();

        if (!values.length) {
            alert('Select '+that.label+' to be removed.');
            return;
        }

        var title = 'Remove '+that.label;

        var dialog = ipa_deleter_dialog({
            'title': title,
            'parent': container,
            'values': values
        });

        dialog.remove = function() {
            var batch = ipa_batch_command();

            for (var i=0; i<values.length; i++) {
                var command = ipa_command({
                    'method': that.entity_name+'_del'
                });
                command.add_arg(values[i]);
                batch.add_command(command);
            }

            batch.execute(
                function() {
                    that.refresh(container);
                    dialog.close();
                },
                function() {
                    that.refresh(container);
                    dialog.close();
                }
            );
        };

        dialog.init();

        dialog.open(container);
    };

    that.refresh = function(container) {

        function on_success(data, text_status, xhr) {

            that.tbody.empty();

            var result = data.result.result;
            for (var i = 0; i<result.length; i++) {
                var record = that.get_record(result[i], 0);
                that.add_row(container, record);
            }

            var summary = $('span[name=summary]', that.tfoot);

            if (data.result.truncated) {
                summary.text(
                    'Query returned results than configured size limit will show.' +
                    'First ' + data.result.count + ' results shown.'
                );
            } else {
                summary.text(data.result.summary);
            }
        }

        function on_error(xhr, text_status, error_thrown) {
            var search_results = $('.search-results', container);
            search_results.append('<p>Error: '+error_thrown.name+'</p>');
            search_results.append('<p>'+error_thrown.title+'</p>');
            search_results.append('<p>'+error_thrown.message+'</p>');
        }

        var filter = $.bbq.getState(that.entity_name + '-filter', true) || '';
        ipa_cmd(
          'find', [filter], {all: true}, on_success, on_error, that.entity_name
        );
    };

    return that;
}

function ipa_search_column(spec) {

    spec = spec || {};

    var that = ipa_column_widget(spec);

    return that;
}

function ipa_search_facet(spec) {

    spec = spec || {};

    var that = ipa_facet(spec);

    that.init = spec.init || init;
    that.create = spec.create || ipa_search_facet_create;
    that.setup = spec.setup || setup;
    that.load = spec.load || load;

    that.columns = [];
    that.columns_by_name = {};

    that.__defineGetter__("entity_name", function(){
        return that._entity_name;
    });

    that.__defineSetter__("entity_name", function(entity_name){
        that._entity_name = entity_name;

        for (var i=0; i<that.columns.length; i++) {
            that.columns[i].entity_name = entity_name;
        }
    });

    that.get_columns = function() {
        return that.columns;
    };

    that.get_column = function(name) {
        return that.columns_by_name[name];
    };

    that.add_column = function(column) {
        column.entity_name = that.entity_name;
        that.columns.push(column);
        that.columns_by_name[column.name] = column;
    };

    that.create_column = function(spec) {
        var column = ipa_search_column(spec);
        that.add_column(column);
        return column;
    };

    function init() {

        that.table = ipa_search_widget({
            'id': that.entity_name+'-search',
            'name': that.entity_name, 'label': IPA.metadata[that.entity_name].label,
            'entity_name': that.entity_name
        });

        for (var i=0; i<that.columns.length; i++) {
            var column = that.columns[i];

            var param_info = ipa_get_param_info(that.entity_name, column.name);
            var primary_key = param_info && param_info['primary_key'];

            column.primary_key = primary_key;
            column.link = primary_key;

            that.table.add_column(column);
        }
    }

    that.is_dirty = function() {
        var filter = $.bbq.getState(that.entity_name + '-filter', true) || '';
        return filter != that.filter;
    };

    function ipa_search_facet_create(container) {

        container.attr('title', that.entity_name);

        $('<div/>', {
            'id': that.entity_name+'-search'
        }).appendTo(container);

        that.table.create(container);
    }

    function setup(container, unspecified) {
        that.table.setup(container);
    }

    function load(container, unspecified) {
        that.filter = $.bbq.getState(that.entity_name + '-filter', true) || '';
        that.table.refresh(container);
    }

    if (spec.columns) {
        for (var i=0; i<spec.columns.length; i++) {
            var column = spec.columns[i];
            column.facet = that;
            that.add_column(column);
        }
    }

    return that;
}

function search_generate_tr(thead, tbody, entry_attrs)
{
    var obj_name = tbody.closest('.entity-container').attr('title');
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
    var obj_name = tr.closest('.entity-container').attr('title');

    var param_info = ipa_get_param_info(obj_name, attr);
    if (param_info && param_info['primary_key'])
        value = _search_a_pkey_template.replace('V', value);

    tr.append(_search_td_template.replace('A', attr).replace('V', value));
}
