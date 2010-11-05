/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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

function ipa_widget(spec) {

    spec = spec || {};

    var that = {};

    that.id = spec.id;
    that.name = spec.name;
    that.label = spec.label;
    that.read_only = spec.read_only;
    that._entity_name = spec.entity_name;

    that.create = spec.create || create;
    that.setup = spec.setup || setup;
    that.load = spec.load || load;
    that.save = spec.save || save;

    that.super = function(name) {
        var method = that[name];
        return function () {
            return method.apply(that, arguments);
        };
    };

    that.__defineGetter__("entity_name", function(){
        return that._entity_name;
    });

    that.__defineSetter__("entity_name", function(entity_name){
        that._entity_name = entity_name;
    });

    function create(container) {
    }

    function setup(container) {
    }

    function load(container, result) {
    }

    function save(container) {
        return [];
    }

    return that;
}

function ipa_text_widget(spec) {

    spec = spec || {};

    spec.setup = spec.setup || setup;
    spec.load = spec.load || load;
    spec.save = spec.save || save;

    var that = ipa_widget(spec);

    function setup(container) {
    }

    function load(container, result) {
        that.value = result[that.name] || '';
        var input = $('input[name="'+that.name+'"]', container);

        var param_info = ipa_get_param_info(that.entity_name, that.name);
        if (param_info.primary_key) {
            input.replaceWith($('<label/>', { 'html': that.value.toString() }));

        } else {
            input.val(that.value);
        }
    }

    function save(container) {
        var values = [];

        if (that.value) {
            values.push(that.value);

        } else {
            var input = $('input[name="'+that.name+'"]', container);
            values.push(input.val());
        }

        return values;
    }

    return that;
}

function ipa_radio_widget(spec) {

    spec = spec || {};

    spec.setup = spec.setup || setup;
    spec.load = spec.load || load;
    spec.save = spec.save || save;

    var that = ipa_widget(spec);

    function setup(container) {
    }

    function load(container, result) {
        var value = result[that.name] || '';
        $('input[name="'+that.name+'"][value="'+value+'"]', container).attr('checked', 'checked');
    }

    function save(container) {
        var values = [];

        var value = $('input[name="'+that.name+'"]:checked', container).val();
        values.push(value);

        return values;
    }

    return that;
}

function ipa_textarea_widget(spec) {

    spec = spec || {};

    spec.setup = spec.setup || setup;
    spec.load = spec.load || load;
    spec.save = spec.save || save;

    var that = ipa_widget(spec);

    function setup(container) {
    }

    function load(container, result) {
        var value = result[that.name] || '';
        $('textarea[name="'+that.name+'"]', container).val(value);
    }

    function save(container) {
        var values = [];

        var value = $('textarea[name="'+that.name+'"]', container).val();
        values.push(value);

        return values;
    }

    return that;
}

function ipa_button_widget(spec) {

    spec = spec || {};

    spec.setup = spec.setup || setup;
    spec.load = spec.load || load;
    spec.save = spec.save || save;

    var that = ipa_widget(spec);

    that.click = spec.click;

    function setup(container) {
        var input = $('[name="'+that.name+'"]', container);
        input.replaceWith(ipa_button({ 'label': that.label, 'click': that.click }));
    }

    function load(container, result) {
    }

    function save(container) {
        var values = [];
        return values;
    }

    return that;
}

function ipa_column_widget(spec) {

    spec = spec || {};

    var that = ipa_widget(spec);

    that.primary_key = spec.primary_key;
    that.link = spec.link;

    return that;
}

function ipa_table_widget(spec) {

    spec = spec || {};

    spec.create = spec.create || create;
    spec.setup = spec.setup || setup;
    spec.load = spec.load || load;
    spec.save = spec.save || save;

    var that = ipa_widget(spec);

    that.add = spec.add;
    that.remove = spec.remove;

    that.columns = [];
    that.columns_by_name = {};

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
        var column = ipa_column_widget(spec);
        that.add_column(column);
        return column;
    };

    function create(container) {

        var div = $('#'+that.id, container);
        if (div.children().length) {
            // widget loaded from template
            return;
        }

        div.empty();

        var table = $('<table/>', {
            'class': 'search-table'
        }).appendTo(div);

        var thead = $('<thead/>').appendTo(table);

        var tr = $('<tr/>').appendTo(thead);

        var th = $('<th/>', {
            'style': 'width: 25px;'
        }).appendTo(tr);

        $('<input/>', {
            'type': 'checkbox',
            'name': 'select'
        }).appendTo(th);

        for (var i=0; i<that.columns.length; i++) {
            th = $('<th/>').appendTo(tr);

            $('<span/>', {
                'style': 'float: left;',
                'html': that.columns[i].label
            }).appendTo(th);

            if (i == that.columns.length-1) {
                $('<span/>', {
                    'name': 'buttons',
                    'style': 'float: right;'
                }).appendTo(th);
            }
        }

        var tbody = $('<tbody/>').appendTo(table);

        tr = $('<tr/>').appendTo(tbody);

        var td = $('<td/>').appendTo(tr);

        $('<input/>', {
            'type': 'checkbox',
            'name': 'select',
            'value': 'user'
        }).appendTo(td);

        for (var i=0; i<that.columns.length; i++) {
            td = $('<td/>').appendTo(tr);

            $('<span/>', {
                'name': that.columns[i].name
            }).appendTo(td);
        }
    }

    function setup(container) {
        var div = $('#'+that.id, container);
        that.table = $('table', div);
        that.thead = $('thead', that.table);
        that.tbody = $('tbody', that.table);

        var select_all_checkbox = $('input[name=select]', that.thead);
        select_all_checkbox.attr('title', 'Select All');

        select_all_checkbox.click(function() {
            var checked = select_all_checkbox.is(':checked');
            select_all_checkbox.attr('title', checked ? 'Unselect All' : 'Select All');
            var checkboxes = $('input[name=select]', that.tbody).get();
            for (var i=0; i<checkboxes.length; i++) {
                checkboxes[i].checked = checked;
            }
        });

        var button = $('input[name=remove]', that.table);
        button.replaceWith(ipa_button({
            'label': button.val(),
            'icon': 'ui-icon-trash',
            'click': function() { that.remove(container); }
        }));

        button = $('input[name=add]', that.table);
        button.replaceWith(ipa_button({
            'label': button.val(),
            'icon': 'ui-icon-plus',
            'click': function() { that.add(container) }
        }));

        that.row = that.tbody.children().first();
        that.row.detach();
    }

    function load(container, result) {

        that.tbody.empty();

        var values = result[that.name];
        if (!values) return;

        for (var i=0; i<values.length; i++) {
            var record = that.get_record(result, i);
            that.add_row(container, record);
        }
    }

    function save(container) {
        var values = [];

        $('input[name="select"]', that.tbody).each(function() {
            values.push($(this).val());
        });

        return values;
    }

    that.get_selected_values = function(container) {
        var values = [];

        $('input[name="select"]:checked', that.tbody).each(function() {
            values.push($(this).val());
        });

        return values;
    };

    that.get_record = function(result, index) {
        var record = {};
        for (var i=0; i<that.columns.length; i++){
            var name = that.columns[i].name;
            record[name] = result[name][index];
        }
        return record;
    };

    that.add_row = function(container, record) {

        var tr = that.row.clone();
        tr.appendTo(that.tbody);

        for (var i=0; i<that.columns.length; i++){
            var column = that.columns[i];

            var name = column.name;
            var value = record[name];

            var span = $('span[name="'+name+'"]', tr);
            span.html(value);

            if (column.primary_key) {
                // set checkbox value
                $('input[name="select"]', tr).val(value);
            }

            if (column.primary_key && column.link) {
                // wrap value with a link
                var link = $('<a/>', {
                    'click': function (value) {
                        return function() {
                            var state = {};
                            state[that.other_entity + '-facet'] = 'details';
                            state[that.other_entity + '-pkey'] = value;
                            //Before this will work, we need to set the tab one level up
                            //for example:
                            //state['identity'] = 0;
                            //but we have no way of getting the index.

                            $.bbq.pushState(state);
                            return false;
                        }
                    }(value)
                });
                span.before(link);
                link.append(span);
            }
        }
    };

    that.refresh = function(container) {

        function on_success(data, text_status, xhr) {

            that.tbody.empty();

            var column_name = that.columns[0].name;
            var values = data.result.result[column_name];
            //TODO, this is masking an error where the wrong
            //direction association is presented upon page reload.
            //if the values is unset, it is because
            //form.associationColumns[0] doesn't exist in the results
            if (!values) return;

            for (var i = 0; i<values.length; i++){
                var record = that.get_record(data.result.result, i);
                that.add_row(container, record);
            }
        }

        function on_error(xhr, text_status, error_thrown) {
            var div = $('#'+that.id, container).empty();
            div.append('<p>Error: '+error_thrown.name+'</p>');
            div.append('<p>'+error_thrown.title+'</p>');
            div.append('<p>'+error_thrown.message+'</p>');
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        ipa_cmd('show', [pkey], {'rights': true}, on_success, on_error, that.entity_name);
    };

    if (spec.columns) {
        for (var i=0; i<spec.columns; i++) {
            that.create_column(spec.columns[i]);
        }
    }
    return that;
}