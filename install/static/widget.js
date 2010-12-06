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

    that.width = spec.width;
    that.height = spec.height;

    that.undo = typeof spec.undo == 'undefined' ? true : spec.undo;

    that.init = spec.init || init;
    that.create = spec.create || create;
    that.setup = spec.setup || setup;
    that.load = spec.load || load;
    that.save = spec.save || save;
    that.clear = spec.clear || clear;

    that.superior = function(name) {
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

    function init() {
        if (that.entity_name && !that.label){
            var param_info = ipa_get_param_info(that.entity_name, spec.name);
            if (param_info) that.label = param_info.label;
        }
    }

    function create(container) {
    }

    function setup(container) {
        that.container = container;
    }

    function load(result) {
    }

    function save() {
        return [];
    }

    function clear() {
    }

    that.is_dirty = function() {
        if (!that.values) return true;
        var values = that.save();
        if (values.length != that.values.length) return true;
        for (var i=0; i<values.length; i++) {
            if (values[i] != that.values[i]) return true;
        }
        return false;
    };

    that.set_values = function(values) {
    };

    that.reset = function() {
        that.hide_undo();
        that.set_values(that.values);
    };

    that.get_undo = function() {
        return $('span[name="undo"]', that.container);
    };

    that.show_undo = function() {
        var undo = that.get_undo();
        undo.css('display', 'inline');
    };

    that.hide_undo = function() {
        var undo = that.get_undo();
        undo.css('display', 'none');
    };

    that.refresh = function() {
    };

    // methods that should be invoked by subclasses
    that.widget_init = that.init;
    that.widget_create = that.create;
    that.widget_setup = that.setup;

    return that;
}

function ipa_text_widget(spec) {

    spec = spec || {};

    var that = ipa_widget(spec);

    that.size = spec.size || 30;

    that.create = function(container) {

        $('<input/>', {
            'type': 'text',
            'name': that.name,
            'size': that.size
        }).appendTo(container);

        if (that.undo) {
            $('<span/>', {
                'name': 'undo',
                'style': 'display: none;',
                'html': 'undo'
            }).appendTo(container);
        }
    };

    that.setup = function(container) {

        this.widget_setup(container);

        var input = $('input[name="'+that.name+'"]', that.container);
        input.keyup(function() {
            that.show_undo();
        });

        var undo = that.get_undo();
        undo.click(function() {
            that.reset();
        });
    };

    that.load = function(result) {

        that.values = result[that.name] || [''];

        if (that.read_only) {
            var input = $('input[name="'+that.name+'"]', that.container);
            var label = $('<label/>', {
                'name': that.name,
                'html': that.values[0]
            });
            input.replaceWith(label);

        } else {
            that.reset();
        }
    };

    that.save = function() {
        if (that.read_only) {
            return that.values;
        } else {
            var value = $('input[name="'+that.name+'"]', that.container).val();
            return [value];
        }
    };

    that.set_values = function(values) {
        if (that.read_only) {
            $('label[name="'+that.name+'"]', that.container).val(values[0]);
        } else {
            $('input[name="'+that.name+'"]', that.container).val(values[0]);
        }
    };

    that.clear = function() {
        that.set_values(['']);
    };

    return that;
}

function ipa_checkbox_widget(spec) {

    spec = spec || {};

    var that = ipa_widget(spec);

    that.create = function(container) {

        $('<input/>', {
            'type': 'checkbox',
            'name': that.name
        }).appendTo(container);

        if (that.undo) {
            $('<span/>', {
                'name': 'undo',
                'style': 'display: none;',
                'html': 'undo'
            }).appendTo(container);
        }
    };

    that.setup = function(container) {

        that.widget_setup(container);

        var input = $('input[name="'+that.name+'"]', that.container);
        input.change(function() {
            that.show_undo();
        });

        var undo = that.get_undo();
        undo.click(function() {
            that.reset();
        });
    };

    that.load = function(result) {
        that.values = result[that.name] || [false];
        that.reset();
    };

    that.save = function() {
        var value = $('input[name="'+that.name+'"]', that.container).is(':checked');
        return [value];
    };

    that.set_values = function(values) {
        var value = values && values.length ? values[0] : false;
        $('input[name="'+that.name+'"]', that.container).get(0).checked = value;
    };

    that.clear = function() {
        $('input[name="'+that.name+'"]', that.container).get(0).checked = false;
    };

    return that;
}

function ipa_radio_widget(spec) {

    spec = spec || {};

    var that = ipa_widget(spec);

    that.options = spec.options;

    that.create = function(container) {

        for (var i=0; i<that.options.length; i++) {
            var option = that.options[i];

            $('<input/>', {
                'type': 'radio',
                'name': that.name,
                'value': option.value
            }).appendTo(container);

            container.append(option.label);
        }

        if (that.undo) {
            $('<span/>', {
                'name': 'undo',
                'style': 'display: none;',
                'html': 'undo'
            }).appendTo(container);
        }
    };

    that.setup = function(container) {

        that.widget_setup(container);

        var input = $('input[name="'+that.name+'"]', that.container);
        input.change(function() {
            that.show_undo();
        });

        var undo = that.get_undo();
        undo.click(function() {
            that.reset();
        });
    };

    that.load = function(result) {
        that.values = result[that.name] || [''];
        that.reset();
    };

    that.save = function() {
        var value = $('input[name="'+that.name+'"]:checked', that.container).val();
        return [value];
    };

    that.set_values = function(values) {
        var input = $('input[name="'+that.name+'"][value="'+values[0]+'"]', that.container);
        if (!input.length) return;
        input.get(0).checked = true;
    };

    that.clear = function() {
        $('input[name="'+that.name+'"]', that.container).each(function() {
            var input = this;
            input.checked = false;
        });
    };

    return that;
}

function ipa_textarea_widget(spec) {

    spec = spec || {};

    var that = ipa_widget(spec);

    that.rows = spec.rows || 5;
    that.cols = spec.cols || 40;

    that.create = function(container) {

        $('<textarea/>', {
            'rows': that.rows,
            'cols': that.cols,
            'name': that.name
        }).appendTo(container);

        if (that.undo) {
            $('<span/>', {
                'name': 'undo',
                'style': 'display: none;',
                'html': 'undo'
            }).appendTo(container);
        }
    };

    that.setup = function(container) {

        that.widget_setup(container);

        var input = $('textarea[name="'+that.name+'"]', that.container);
        input.keyup(function() {
            undo.css('display', 'inline');
        });

        var undo = that.get_undo();
        undo.click(function() {
            that.reset();
        });
    };

    that.load = function(result) {
        that.values = result[that.name] || [''];
        that.reset();
    };

    that.save = function() {
        var value = $('textarea[name="'+that.name+'"]', that.container).val();
        return [value];
    };

    that.set_values = function(values) {
        $('textarea[name="'+that.name+'"]', that.container).val(values[0]);
    };

    that.clear = function() {
        that.set_values(['']);
    };

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

        that.widget_setup(container);

        var input = $('[name="'+that.name+'"]', that.container);
        input.replaceWith(ipa_button({ 'label': that.label, 'click': that.click }));
    }

    function load(result) {
    }

    function save() {
        return [];
    }

    return that;
}


function ipa_column(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.label = spec.label;
    that.primary_key = spec.primary_key;
    that.width = spec.width;
    that.entity_name = spec.entity_name;

    that.setup = spec.setup || setup;

    that.init = function() {
        if (that.entity_name && !that.label) {
            var param_info = ipa_get_param_info(that.entity_name, that.name);
            if (param_info) that.label = param_info.label;
        }
    };

    function setup(container, record) {

        container.empty();

        var value = record[that.name];
        value = value ? value.toString() : '';

        container.append(value);
    }

    return that;
}

function ipa_table_widget(spec) {

    spec = spec || {};

    var that = ipa_widget(spec);

    that.scrollable = spec.scrollable;

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

    that.set_columns = function(columns) {
        that.clear_columns();
        for (var i=0; i<columns.length; i++) {
            that.add_column(columns[i]);
        }
    };

    that.clear_columns = function() {
        that.columns = [];
        that.columns_by_name = {};
    };

    that.create_column = function(spec) {
        var column = ipa_column(spec);
        that.add_column(column);
        return column;
    };

    that.init = function() {
        that.widget_init();

        for (var i=0; i<that.columns.length; i++) {
            var column = that.columns[i];
            column.init();
        }
    };

    that.create = function(container) {

        var table = $('<table/>', {
            'class': 'search-table'
        }).appendTo(container);

        var thead = $('<thead/>').appendTo(table);

        if (that.scrollable) {
            thead.css('display', 'block');
        }

        var tr = $('<tr/>').appendTo(thead);

        var th = $('<th/>', {
            'style': 'width: 22px;'
        }).appendTo(tr);

        $('<input/>', {
            'type': 'checkbox',
            'name': 'select'
        }).appendTo(th);

        for (var i=0; i<that.columns.length; i++) {
            var column = that.columns[i];

            th = $('<th/>').appendTo(tr);

            if (that.scrollable && (i == that.columns.length-1)) {
                if (column.width) {
                    var width = parseInt(column.width.substring(0, column.width.length-2));
                    width += 16;
                    th.css('width', width+'px');
                }
            } else {
                if (column.width) {
                    th.css('width', column.width);
                }
            }

            var label = column.label;

            $('<span/>', {
                'style': 'float: left;',
                'html': label
            }).appendTo(th);

            if (i == that.columns.length-1) {
                $('<span/>', {
                    'name': 'buttons',
                    'style': 'float: right;'
                }).appendTo(th);
            }
        }

        var tbody = $('<tbody/>').appendTo(table);

        if (that.scrollable) {
            tbody.css('display', 'block');
            tbody.css('overflow', 'auto');
        }

        if (that.height) {
            tbody.css('height', that.height);
        }

        tr = $('<tr/>').appendTo(tbody);

        var td = $('<td/>', {
            'style': 'width: 22px;'
        }).appendTo(tr);

        $('<input/>', {
            'type': 'checkbox',
            'name': 'select',
            'value': 'user'
        }).appendTo(td);

        for (var i=0; i<that.columns.length; i++) {
            var column = that.columns[i];

            td = $('<td/>').appendTo(tr);
            if (column.width) {
                td.css('width', column.width);
            }

            $('<span/>', {
                'name': column.name
            }).appendTo(td);
        }

        var tfoot = $('<tfoot/>').appendTo(table);

        tr = $('<tr/>').appendTo(tfoot);

        td = $('<td/>', { colspan: that.columns.length+1 }).appendTo(tr);

        $('<span/>', {
            'name': 'summary'
        }).appendTo(td);
    };


    that.select_changed = function(){
    };


    that.setup = function(container) {

        that.widget_setup(container);

        that.table = $('table', that.container);
        that.thead = $('thead', that.table);
        that.tbody = $('tbody', that.table);
        that.tfoot = $('tfoot', that.table);

        var select_all_checkbox = $('input[name=select]', that.thead);
        select_all_checkbox.attr('title', 'Select All');

        select_all_checkbox.change(function() {
            var checked = select_all_checkbox.is(':checked');
            select_all_checkbox.attr('title', checked ? 'Unselect All' : 'Select All');
            var checkboxes = $('input[name=select]', that.tbody).get();
            for (var i=0; i<checkboxes.length; i++) {
                checkboxes[i].checked = checked;
            }
            that.select_changed();
            return false;
        });

        that.row = that.tbody.children().first();
        that.row.detach();
    };

    that.empty = function() {
        that.tbody.empty();
    };

    that.load = function(result) {

        that.empty();

        var values = result[that.name];
        if (!values) return;

        for (var i=0; i<values.length; i++) {
            var record = that.get_record(result, i);
            that.add_record(record);
        }
    };

    that.save = function() {
        var values = [];

        $('input[name="select"]', that.tbody).each(function() {
            values.push($(this).val());
        });

        return values;
    };

    that.get_selected_values = function() {
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
            var values = result[name];
            if (!values) continue;
            record[name] = values[index];
        }
        return record;
    };

    that.add_record = function(record) {

        var tr = that.row.clone();
        tr.appendTo(that.tbody);

        for (var i=0; i<that.columns.length; i++){
            var column = that.columns[i];

            var value = record[column.name];
            value = value ? value.toString() : '';

            if (column.primary_key) {
                // set checkbox value
                $('input[name="select"]', tr).val(value);

                $('input[name="select"]', tr).click(function(){
                    that.select_changed();
                });

            }

            var span = $('span[name="'+column.name+'"]', tr);

            column.setup(span, record);
        }
    };

    that.add_rows = function(rows) {
        for (var i=0; i<rows.length; i++) {
            that.tbody.append(rows[i]);
        }
    };

    that.remove_selected_rows = function() {
        var rows = [];
        that.tbody.children().each(function() {
            var tr = $(this);
            if (!$('input[name="select"]', tr).get(0).checked) return;
            tr.detach();
            rows.push(tr);
        });
        return rows;
    };

    that.refresh = function() {

        function on_success(data, text_status, xhr) {
            that.load(data.result.result);
        }

        function on_error(xhr, text_status, error_thrown) {
            var summary = $('span[name=summary]', that.tfoot).empty();
            summary.append('<p>Error: '+error_thrown.name+'</p>');
            summary.append('<p>'+error_thrown.title+'</p>');
            summary.append('<p>'+error_thrown.message+'</p>');
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        ipa_cmd('show', [pkey], {'all': true, 'rights': true}, on_success, on_error, that.entity_name);
    };

    if (spec.columns) {
        for (var i=0; i<spec.columns; i++) {
            that.create_column(spec.columns[i]);
        }
    }

    // methods that should be invoked by subclasses
    that.table_init = that.init;
    that.table_create = that.create;
    that.table_setup = that.setup;

    return that;
}

/**
 * This is a base class for dialog boxes.
 */
function ipa_dialog(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.title = spec.title;
    that._entity_name = spec.entity_name;

    that.width = spec.width || 400;

    that.buttons = {};

    that.fields = [];
    that.fields_by_name = {};

    that.superior = function(name) {
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

        for (var i=0; i<that.fields.length; i++) {
            that.fields[i].entity_name = entity_name;
        }
    });

    that.add_button = function(name, handler) {
        that.buttons[name] = handler;
    };

    that.get_field = function(name) {
        return that.fields_by_name[name];
    };

    that.add_field = function(field) {
        field.entity_name = that.entity_name;
        that.fields.push(field);
        that.fields_by_name[field.name] = field;
    };

    that.init = function() {
    };

    /**
     * Create content layout
     */
    that.create = function() {

        var table = $('<table/>').appendTo(that.container);

        for (var i=0; i<that.fields.length; i++) {
            var field = that.fields[i];

            var tr = $('<tr/>').appendTo(table);

            var td = $('<td/>', {
                'style': 'vertical-align: top;'
            }).appendTo(tr);
            td.append(field.label+': ');

            td = $('<td/>', {
                'style': 'vertical-align: top;'
            }).appendTo(tr);

            var span = $('<span/>', { 'name': field.name }).appendTo(td);
            field.create(span);
        }
    };

    /**
     * Setup behavior
     */
    that.setup = function() {
        for (var i=0; i<that.fields.length; i++) {
            var field = that.fields[i];

            var span = $('span[name="'+field.name+'"]', that.container);
            field.setup(span);
        }
    };

    /**
     * Open dialog
     */
    that.open = function(container) {

        that.container = $('<div/>').appendTo(container);

        that.create();
        that.setup();

        that.container.dialog({
            'title': that.title,
            'modal': true,
            'width': that.width,
            'buttons': that.buttons
        });
    };

    that.option = function(name, value) {
        that.container.dialog('option', name, value);
    };

    that.get_record = function() {
        var record = {};
        for (var i=0; i<that.fields.length; i++) {
            var field = that.fields[i];
            var values = field.save();
            record[field.name] = values[0];
        }
        return record;
    };

    that.close = function() {
        that.container.dialog('destroy');
        that.container.remove();
    };

    that.clear = function() {
        for (var i=0; i<that.fields.length; i++) {
            var field = that.fields[i];
            field.clear();
        }
    };

    that.dialog_init = that.init;
    that.dialog_create = that.create;
    that.dialog_setup = that.setup;
    that.dialog_open = that.open;

    return that;
}

/**
 * This dialog provides an interface for searching and selecting
 * values from the available results.
 */
function ipa_adder_dialog(spec) {

    spec = spec || {};

    var that = ipa_dialog(spec);

    that.width = spec.width || '600px';

    that.columns = [];
    that.columns_by_name = {};

    that.get_column = function(name) {
        return that.columns_by_name[name];
    };

    that.add_column = function(column) {
        that.columns.push(column);
        that.columns_by_name[column.name] = column;
    };

    that.set_columns = function(columns) {
        that.clear_columns();
        for (var i=0; i<columns.length; i++) {
            that.add_column(columns[i]);
        }
    };

    that.clear_columns = function() {
        that.columns = [];
        that.columns_by_name = {};
    };

    that.create_column = function(spec) {
        var column = ipa_column(spec);
        that.add_column(column);
        return column;
    };

    that.init = function() {
        that.available_table = ipa_table_widget({
            name: 'available',
            scrollable: true,
            height: 150
        });

        that.available_table.set_columns(that.columns);

        that.available_table.init();

        that.selected_table = ipa_table_widget({
            name: 'selected',
            scrollable: true,
            height: 150
        });

        that.selected_table.set_columns(that.columns);

        that.selected_table.init();
    };

    that.create = function() {

        // do not call that.dialog_create();

        var search_panel = $('<div/>').appendTo(that.container);

        $('<input/>', {
            type: 'text',
            name: 'filter'
        }).appendTo(search_panel);

        $('<input/>', {
            type: 'button',
            name: 'find',
            value: 'Find'
        }).appendTo(search_panel);

        var results_panel = $('<div/>').appendTo(that.container);
        results_panel.css('border', '2px solid rgb(0, 0, 0)');
        results_panel.css('position', 'relative');
        results_panel.css('width', '100%');
        results_panel.css('height', '200px');

        var available_title = $('<div/>', {
            html: 'Available',
            style: 'float: left; width: 250px;'
        }).appendTo(results_panel);

        var buttons_title = $('<div/>', {
            html: '&nbsp;',
            style: 'float: left; width: 50px;'
        }).appendTo(results_panel);

        var selected_title = $('<div/>', {
            html: 'Prospective',
            style: 'float: left; width: 250px;'
        }).appendTo(results_panel);

        var available_panel = $('<div/>', {
            name: 'available',
            style: 'clear:both; float: left; width: 250px; height: 150px;'
        }).appendTo(results_panel);

        that.available_table.create(available_panel);

        var buttons_panel = $('<div/>', {
            name: 'buttons',
            style: 'float: left; width: 50px; height: 150px; text-align: center;'
        }).appendTo(results_panel);

        var p = $('<p/>').appendTo(buttons_panel);
        $('<input />', {
            type: 'button',
            name: 'remove',
            value: '<<'
        }).appendTo(p);

        p = $('<p/>').appendTo(buttons_panel);
        $('<input />', {
            type: 'button',
            name: 'add',
            value: '>>'
        }).appendTo(p);

        var selected_panel = $('<div/>', {
            name: 'selected',
            style: 'float: left; width: 250px; height: 150px;'
        }).appendTo(results_panel);

        that.selected_table.create(selected_panel);
    };

    that.setup = function() {

        // do not call that.dialog_setup();

        var available_panel = $('div[name=available]', that.container);
        that.available_table.setup(available_panel);

        var selected_panel = $('div[name=selected]', that.container);
        that.selected_table.setup(selected_panel);

        that.filter_field = $('input[name=filter]', that.container);

        var button = $('input[name=find]', that.container);
        that.find_button = ipa_button({
            'label': button.val(),
            'icon': 'ui-icon-search',
            'click': function() { that.search(); }
        });
        button.replaceWith(that.find_button);

        button = $('input[name=remove]', that.container);
        that.remove_button = ipa_button({
            'label': button.val(),
            'icon': 'ui-icon-trash',
            'click': function() {
                var rows = that.selected_table.remove_selected_rows();
                that.available_table.add_rows(rows);
            }
        });
        button.replaceWith(that.remove_button);

        button = $('input[name=add]', that.container);
        that.add_button = ipa_button({
            'label': button.val(),
            'icon': 'ui-icon-plus',
            'click': function() {
                var rows = that.available_table.remove_selected_rows();
                that.selected_table.add_rows(rows);
            }
        });
        button.replaceWith(that.add_button);

        that.search();
    };

    that.open = function(container) {
        that.buttons = {
            'Enroll': that.add,
            'Cancel': that.close
        };

        that.dialog_open(container);
    };

    that.get_filter = function() {
        return that.filter_field.val();
    };

    that.clear_available_values = function() {
        that.available_table.empty();
    };

    that.clear_selected_values = function() {
        that.selected_table.empty();
    };

    that.add_available_value = function(record) {
        that.available_table.add_record(record);
    };

    that.get_selected_values = function() {
        return that.selected_table.save();
    };

    that.close = function() {
        that.container.dialog('close');
    };

    that.adder_dialog_init = that.init;
    that.adder_dialog_create = that.create;
    that.adder_dialog_setup = that.setup;

    return that;
}

/**
 * This dialog displays the values to be deleted.
 */
function ipa_deleter_dialog(spec) {

    spec = spec || {};

    var that = ipa_dialog(spec);

    that.title = spec.title || IPA.messages.button.remove;
    that.remove = spec.remove;

    that.values = spec.values || [];

    that.add_value = function(value) {
        that.values.push(value);
    };

    that.set_values = function(values) {
        that.values = that.values.concat(values);
    };

    that.create = function() {
        var ul = $('<ul/>');
        ul.appendTo(that.container);

        for (var i=0; i<that.values.length; i++) {
            $('<li/>',{
                'text': that.values[i]
            }).appendTo(ul);
        }

        $('<p/>', {
            'text': IPA.messages.search.delete_confirm
        }).appendTo(that.container);
    };

    that.open = function(container) {
        that.buttons = {
            'Delete': that.remove,
            'Cancel': that.close
        };

        that.dialog_open(container);
    };

    return that;
}
