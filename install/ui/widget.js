/*jsl:import ipa.js */
/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* REQUIRES: ipa.js */

IPA.widget = function(spec) {

    spec = spec || {};

    var that = {};

    that.id = spec.id;
    that.name = spec.name;
    that.label = spec.label;
    that.tooltip = spec.tooltip;
    that.read_only = spec.read_only;
    that._entity_name = spec.entity_name;

    that.width = spec.width;
    that.height = spec.height;

    that.undo = typeof spec.undo == 'undefined' ? true : spec.undo;
    that.join = spec.join;

    that.init = spec.init || init;
    that.create = spec.create || create;
    that.setup = spec.setup || setup;
    that.load = spec.load || load;
    that.save = spec.save || save;
    that.update = spec.update || update;
    that.validate_input = spec.validate_input || validate_input;
    that.valid = true;
    that.param_info = spec.param_info;

    that.__defineGetter__("entity_name", function(){
        return that._entity_name;
    });

    that.__defineSetter__("entity_name", function(entity_name){
        that._entity_name = entity_name;
    });

    /*returns true and clears the error message if the field value  passes
      the validation pattern.  If the field value does not pass validation,
      displays the error message and returns false. */
    function validate_input(text) {
        if (!(that.param_info && that.param_info.pattern)) {
            that.valid = true;
            return;
        }
        var error_link = that.get_error_link();
        if (!error_link) {
            that.valid = true;
            return;
        }
        var regex = new RegExp( that.param_info.pattern );
        //If the field is empty, don't validate
        if ( !text || text.match(regex) ) {
            error_link.css('display', 'none');
            that.valid = true;
        }else{
            error_link.css('display', 'block');
            if (that.param_info.pattern_errmsg) {
                error_link.html(that.param_info.pattern_errmsg);
            }
            that.valid = false;
        }
    }

    function init() {
        if (that.entity_name) {
            that.param_info = IPA.get_param_info(that.entity_name, that.name);

            if (that.param_info) {

                if (that.label === undefined) {
                    that.label = that.param_info.label;
                }

                if (that.tooltip === undefined) {
                    that.tooltip = that.param_info.doc;
                }
            }
        }
    }

    function create(container) {
    }

    function setup(container) {
        that.container = container;
    }

    function load(record) {
        that.record = record;
        that.values = record[that.name];
        that.reset();
    }

    that.reset = function() {
        that.hide_undo();
        that.update();
    };

    function update() {
    }

    function save() {
        return [];
    }

    that.is_dirty = function() {

        if (that.read_only) {
            return false;
        }

        var values = that.save();

        if (!that.values) {

            if (!values) {
                return false;
            }

            if (values === '') {
                return false;
            }

            if (values instanceof Array) {

                if ((values.length === 0) ||
                    (values.length === 1) &&
                    (values[0] === '')) {
                    return false;
                }
            }

            return true;
        }

        if (values.length != that.values.length) {
            return true;
        }

        for (var i=0; i<values.length; i++) {
            if (values[i] != that.values[i]) {
                return true;
            }
        }

        return false;
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

    that.get_error_link = function() {
        return $('span[name="error_link"]', that.container);
    };

    that.show_error_link = function() {
        var error_link = that.get_error_link();
        error_link.css('display', 'inline');
    };

    that.hide_error_link = function() {
        var error_link = that.get_error_link();
        error_link.css('display', 'none');
    };

    that.set_enabled = function() {
    };

    that.refresh = function() {
    };

    // methods that should be invoked by subclasses
    that.widget_init = that.init;
    that.widget_create = that.create;
    that.widget_setup = that.setup;
    that.widget_reset = that.reset;

    return that;
};


IPA.text_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.size = spec.size || 30;

    that.create = function(container) {

        $('<input/>', {
            type: 'text',
            name: that.name,
            size: that.size,
            title: that.tooltip
        }).appendTo(container);

        $('<span/>', {
            'name': 'undo',
            'style': 'display: none;',
            'html': 'undo'
        }).appendTo(container);

        $("<span/>",{
            name:'error_link',
            html:"Text does not match field pattern",
            "class":"ui-state-error ui-corner-all",
            style:"display:none"
        }).appendTo(container);
    };

    that.setup = function(container) {

        this.widget_setup(container);

        var input = $('input[name="'+that.name+'"]', that.container);
        input.keyup(function() {
            if(that.undo){
                that.show_undo();
            }
            var value = $('input[name="'+that.name+'"]', that.container).val();
            that.validate_input(value);
        });

        var undo = that.get_undo();
        undo.click(function() {
            that.reset();
        });
        that.input = input;
    };

    that.load = function(record) {

        that.values = record[that.name] || [''];

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

    that.update = function() {
        var value = that.values && that.values.length ? that.values[0] : '';
        if (that.read_only) {
            $('label[name="'+that.name+'"]', that.container).val(value);
        } else {
            $('input[name="'+that.name+'"]', that.container).val(value);
        }
    };

    return that;
};

IPA.checkbox_widget = function (spec) {

    spec = spec || {};
    var is_checked = spec.checked || '';
    var that = IPA.widget(spec);

    that.create = function(container) {

        $('<input/>', {
            type: 'checkbox',
            name: that.name,
            checked : is_checked,
            title: that.tooltip
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

    that.load = function(record) {
        that.values = record[that.name] || [false];
        that.reset();
    };

    that.save = function() {
        var value = $('input[name="'+that.name+'"]', that.container).is(':checked');
        return [value];
    };

    that.update = function() {
        var value = that.values && that.values.length ? that.values[0] : false;
        $('input[name="'+that.name+'"]', that.container).get(0).checked = value;
    };

    return that;
};

IPA.radio_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

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

    that.load = function(record) {
        that.values = record[that.name] || [''];
        that.reset();
    };

    that.save = function() {
        var input = $('input[name="'+that.name+'"]:checked', that.container);
        if (!input.length) return [];
        return [input.val()];
    };

    that.update = function() {
        if (that.values && that.values.length) {
            var input = $('input[name="'+that.name+'"][value="'+that.values[0]+'"]', that.container);
            if (input.length) {
                input.get(0).checked = true;
                return;
            }
        }

        $('input[name="'+that.name+'"]', that.container).each(function() {
            var input = this;
            input.checked = false;
        });
    };

    // methods that should be invoked by subclasses
    that.radio_save = that.save;

    return that;
};

IPA.textarea_widget = function (spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.rows = spec.rows || 5;
    that.cols = spec.cols || 40;

    that.create = function(container) {

        $('<textarea/>', {
            rows: that.rows,
            cols: that.cols,
            name: that.name,
            title: that.tooltip
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

    that.load = function(record) {
        that.values = record[that.name] || [''];
        that.reset();
    };

    that.save = function() {
        var value = $('textarea[name="'+that.name+'"]', that.container).val();
        return [value];
    };

    that.update = function() {
        var value = that.values && that.values.length ? that.values[0] : '';
        $('textarea[name="'+that.name+'"]', that.container).val(value);
    };

    return that;
};

IPA.button_widget = function (spec) {

    spec = spec || {};

    spec.setup = spec.setup || setup;
    spec.load = spec.load || load;
    spec.save = spec.save || save;

    var that = IPA.widget(spec);

    that.click = spec.click;

    function setup(container) {

        that.widget_setup(container);

        var input = $('[name="'+that.name+'"]', that.container);
        input.replaceWith(IPA.button({ 'label': that.label, 'click': that.click }));
    }

    function load(record) {
    }

    function save() {
        return [];
    }

    return that;
};

IPA.column = function (spec) {

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
            var param_info = IPA.get_param_info(that.entity_name, that.name);
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
};

IPA.table_widget = function (spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.scrollable = spec.scrollable;
    that.save_values = typeof spec.save_values == 'undefined' ? true : spec.save_values;

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
        var column = IPA.column(spec);
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

        if (that.scrollable) {
            table.addClass('scrollable');
        }

        var thead = $('<thead/>').appendTo(table);

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
                    var width = parseInt(column.width.substring(0, column.width.length-2),10);
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

        for (/* var */ i=0; i<that.columns.length; i++) {
            /* var */ column = that.columns[i];

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

        that.values = result[that.name];
        if (!that.values) return;

        for (var i=0; i<that.values.length; i++) {
            var record = that.get_record(result, i);
            that.add_record(record);
        }
    };

    that.save = function() {
        if (that.save_values) {
            var values = [];

            $('input[name="select"]', that.tbody).each(function() {
                values.push($(this).val());
            });

            return values;

        } else {
            return null;
        }
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
            if (values instanceof Array){
                record[name] = values[index];
            }else{
                record[name] = values;
            }
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

    that.set_enabled = function(enabled) {
        if (enabled) {
            $('input[name="select"]', that.table).attr('disabled', false);
        } else {
            $('input[name="select"]', that.table).attr('disabled', true);
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
        IPA.cmd('show', [pkey], {'all': true, 'rights': true}, on_success, on_error, that.entity_name);
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
    that.table_set_enabled = that.set_enabled;

    return that;
};
