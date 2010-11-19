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

    that.is_dirty = function(container) {
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

    that.reset = function(container) {
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
        $('input[name="'+that.name+'"][value="'+values[0]+'"]', that.container).get(0).checked = true;
    };

    that.clear = function() {
        $('input[name="'+that.name+'"]', that.container).get().checked = false;
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

function ipa_column_widget(spec) {

    spec = spec || {};

    // TODO: should not inherit from widget
    var that = ipa_widget(spec);

    that.primary_key = spec.primary_key;
    that.setup = spec.setup || setup;
    that.link = spec.link;

    function setup(container, name, value, record) {

        var span = $('span[name="'+name+'"]', container);

        var param_info = ipa_get_param_info(that.entity_name, name);
        var primary_key = that.primary_key || param_info && param_info['primary_key'];

        if (primary_key && that.link) {
            var link = $('<a/>', {
                'href': '#'+value,
                'html': value,
                'click': function (value) {
                    return function() {
                        var state = {};
                        state[that.entity_name + '-facet'] = 'details';
                        state[that.entity_name + '-pkey'] = value;
                        //Before this will work, we need to set the tab one level up
                        //for example:
                        //state['identity'] = 0;
                        //but we have no way of getting the index.

                        $.bbq.pushState(state);
                        return false;
                    }
                }(value)
            });
            span.html(link);

        } else {
            span.html(value);
        }
    }

    return that;
}

function ipa_table_widget(spec) {

    spec = spec || {};

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

    that.create = function(container) {

        var table = $('<table/>', {
            'class': 'search-table'
        }).appendTo(container);

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
            var column = that.columns[i];
            th = $('<th/>').appendTo(tr);

            var label = column.label;

            var param_info = ipa_get_param_info(that.entity_name, column.name);
            if (param_info && param_info['label']) label = param_info['label'];

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

    that.load = function(result) {

        that.tbody.empty();

        var values = result[that.name];
        if (!values) return;

        for (var i=0; i<values.length; i++) {
            var record = that.get_record(result, i);
            that.add_row(record);
        }
    };

    that.save = function() {
        var values = [];

        $('input[name="select"]', that.tbody).each(function() {
            values.push($(this).val());
        });

        return values;
    };

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
            var values = result[name];
            if (!values) continue;
            record[name] = values[index];
        }
        return record;
    };

    that.add_row = function(record) {

        var tr = that.row.clone();
        tr.appendTo(that.tbody);

        for (var i=0; i<that.columns.length; i++){
            var column = that.columns[i];

            var name = column.name;
            var value = record[name];

            if (column.primary_key) {
                // set checkbox value
                $('input[name="select"]', tr).val(value);

                $('input[name="select"]', tr).click(function(){
                    that.select_changed();
                });

            }

            column.setup(tr, name, value, record);
        }
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

    return that;
}

/**
 * This dialog provides an interface for searching and selecting
 * values from the available results.
 */
function ipa_adder_dialog(spec) {

    spec = spec || {};

    var that = ipa_dialog(spec);

    that.width = spec.width || 600;

    that.superior_open = that.superior('open');

    that.create = function() {

        var search_panel = $('<div/>').appendTo(that.container);

        that.filter_field = $('<input/>', {
            type: 'text'
        }).appendTo(search_panel);

        that.find_button = $('<input/>', {
            type: 'button',
            value: 'Find'
        }).appendTo(search_panel);

        var results_panel = $('<div/>').appendTo(that.container);
        results_panel.css('border', '2px solid rgb(0, 0, 0)');
        results_panel.css('position', 'relative');
        results_panel.css('height', '200px');

        var available_panel = $('<div/>').appendTo(results_panel);
        available_panel.css('float', 'left');

        $('<div/>', {
            text: 'Available'
        }).appendTo(available_panel);

        that.available_list = $('<select/>', {
            width: '150px',
            size: '10',
            multiple: 'true'
        }).appendTo(available_panel);

        var buttons_panel = $('<div/>').appendTo(results_panel);
        buttons_panel.css('float', 'left');

        var p = $('<p/>').appendTo(buttons_panel);
        that.remove_button = $('<input />', {
            type: 'button',
            value: '<<'
        }).appendTo(p);

        p = $('<p/>').appendTo(buttons_panel);
        that.add_button = $('<input />', {
            type: 'button',
            value: '>>'
        }).appendTo(p);

        var selected_panel = $('<div/>').appendTo(results_panel);
        selected_panel.css('float', 'left');

        $('<div/>', {
            text: 'Prospective'
        }).appendTo(selected_panel);

        that.selected_list = $('<select/>', {
            width: '150px',
            size: '10',
            multiple: 'true'
        }).appendTo(selected_panel);
    };

    that.setup = function() {

        that.add_button.click(function(){
            var values = $(':selected', that.available_list).detach();
            values.each(function(i, selected){
                that.selected_list.append(selected);
            });
        });

        that.remove_button.click(function(){
            var values = $(':selected', that.selected_list).detach();
            values.each(function(i, selected){
                that.available_list.append(selected);
            });
        });

        that.find_button.click(function(){
            that.search();
        });
    };

    that.open = function(container) {
        that.buttons = {
            'Enroll': that.add,
            'Cancel': that.close
        };

        that.superior_open(container);
    };

    that.get_filter = function() {
        return that.filter_field.val();
    };

    that.clear_available_values = function() {
        that.available_list.html('');
    };

    that.clear_selected_values = function() {
        that.selected_list.html('');
    };

    that.add_available_value = function(value) {
        $('<option></option>',{
            'value': value,
            'html': value
        }).appendTo(that.available_list);
    };

    that.add_selected_value = function(value) {
        $('<option></option>',{
            'value': value,
            'html': value
        }).appendTo(that.available_list);
    };

    that.get_selected_values = function() {
        var values = [];
        that.selected_list.children().each(function (i, selected) {
            values.push(selected.value);
        });
        return values;
    };

    that.close = function() {
        that.container.dialog('close');
    };

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

    that.superior_open = that.superior('open');

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

        that.superior_open(container);
    };

    return that;
}
