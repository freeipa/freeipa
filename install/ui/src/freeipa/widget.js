/*jsl:import ipa.js */
/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Pavel Zuna <pzuna@redhat.com>
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


define(['dojo/_base/array',
       'dojo/_base/lang',
       'dojo/dom-construct',
       'dojo/Evented',
       'dojo/has',
       'dojo/keys',
       'dojo/on',
       'dojo/string',
       'dojo/topic',
       './builder',
       './config',
       './datetime',
       './entity',
       './ipa',
       './jquery',
       './metadata',
       './navigation',
       './phases',
       './reg',
       './rpc',
       './text',
       './util',
       'exports'
       ],
       function(array, lang, construct, Evented, has, keys, on, string,
                topic, builder, config, datetime, entity_mod, IPA, $,
                metadata, navigation, phases, reg, rpc, text, util, exp) {

/**
 * Widget module
 * =============
 *
 * External usage:
 *
 *      var widget = require('freeipa/widget')
 * @class widget
 * @singleton
 */

/**
 * Width of column which contains only checkbox
 * @member IPA
 * @property {number}
 */
IPA.checkbox_column_width = 13;

/**
 * String to show next to required fields to indicate that the field is required.
 * @member IPA
 * @property {string}
 */
IPA.required_indicator = '*';

/**
 * Base widget
 * @class
 * @param {Object} spec
 * @abstract
 */
IPA.widget = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    /**
     * Normalize tooltip
     * @protected
     */
    that._normalize_tooltip = function(tt_spec) {
        var tt = typeof tt_spec === 'string' ? { title: tt_spec } : tt_spec;
        if (tt) {
            tt.title = text.get(tt.title);
        }
        return tt;
    };

    /**
     * Widget name. Should be container unique.
     */
    that.name = spec.name;

    /**
     * Widget element ID.
     * @deprecated
     */
    that.id = spec.id;

    /**
     * Label
     * @property {string}
     */
    that.label = text.get(spec.label);

    /**
     * Title text
     * @property {string}
     */
    that.title = text.get(spec.title);

    /**
     * Measurement unit
     * @property {string}
     */
    that.measurement_unit = spec.measurement_unit;

    /**
     * Tooltip text
     *
     *     '''
     *     var tooltip = {
     *         title: 'Helper text',
     *         placement: 'right'
     *         // possible placements: left, top, bottom, right
     *     };
     *
     *     // or  just string, it will be normalized later:
     *     tooltip = "Helper text";
     *
     *     '''
     *
     * Check Bootstrap documentation for more tooltip options.
     *
     * @property {Object|string}
     */
    that.tooltip = that._normalize_tooltip(spec.tooltip);

    /**
     * Parent entity
     * @deprecated
     * @property {IPA.entity}
     */
    that.entity = IPA.get_entity(spec.entity); //some old widgets still need it

    /**
     * Parent facet
     * @property {IPA.facet}
     */
    that.facet = spec.facet;

    /**
     * Widget is enabled - can be focus and edited (depends also on writable
     * and read_only)
     * @property {boolean}
     */
    that.enabled = spec.enabled === undefined ? true : spec.enabled;

    /**
     * Enables showing of validation errors
     * @property {boolean}
     */
    that.show_errors = spec.show_errors === undefined ? true : spec.show_errors;

    /**
     * Facet should be visible
     * @property {boolean}
     */
    that.visible = spec.visible === undefined ? true : spec.visible;

    /**
     * If true, widget visible is set to false when value is empty
     * @property {boolean}
     */
    that.hidden_if_empty = spec.hidden_if_empty === undefined ? config.hide_empty_widgets :
                                spec.hidden_if_empty;

    /**
     * Disable `hidden_if_empty`
     * @property {boolean}
     */
    that.ignore_empty_hiding = spec.ignore_empty_hiding === undefined ? config.hide_empty_sections :
                                spec.ignore_empty_hiding;

    /**
     * Default main element's css classes
     * @property {string}
     */
    that.base_css_class = spec.base_css_class || 'widget';

    /**
     * Additional main element's css classes
     *
     * Intended to be overridden in spec objects
     *
     * @property {string}
     */
    that.css_class = spec.css_class || '';

    /**
     * Create HTML representation of a widget.
     * @method
     * @param {HTMLElement} container - Container node
     */
    that.create = function(container) {
        container = $(container);
        container.addClass(that.base_css_class);
        container.addClass(that.css_class);
        that.container = container;
    };

    /**
     * Reset widget content. All user-modifiable information have to be
     * changed back to widgets defaults.
     */
    that.clear = function() {
    };

    /**
     * Widget post constructor/factory initialization
     *
     * Called by builder by default.
     */
    that.ctor_init = function() {
    };

    /**
     * Set enabled state.
     * @param {boolean} value - True - enabled; False - disabled
     */
    that.set_enabled = function(value) {
        var changed = that.enabled !== value;
        that.enabled = value;
        if (changed) {
            that.emit('enabled-change', { source: that, enabled: value });
        }
    };

    /**
     * Whether widget should be displayed.
     * @param {boolean} [value] - True - visible; False - hidden,
     *                            undefined - use previous (enforce state)
     */
    that.set_visible = function(visible) {
        var old = that._effective_visible;
        visible = visible === undefined ? that.visible : visible;
        that.visible = visible;
        var current = that.get_visible();
        that._effective_visible = current;

        if (current) {
            that.show();
        } else {
            that.hide();
        }
        if (old !== current) {
            that.emit('visible-change', { source: that, visible: current });
        }
    };

    that.get_visible = function() {
        return that.visible;
    };

    that.hide = function() {
        that.container.hide();
    };

    that.show = function() {
        that.container.show();
    };

    /**
     * Utility method. Build widget based on spec with this widget's context.
     * @param {boolean} spec - Widget specification object
     * @param {Object} context - Context object. Gets mixed with this widget context.
     * @param {Object} overrides - Build overrides
     */
    that.build_child = function(spec, context, overrides) {

        var def_c = {
            entity: that.entity,
            facet: that.facet
        };
        context = lang.mixin(def_c, context);
        var child = builder.build('widget', spec, context, overrides);
        return child;
    };

    that.add_class = function(cls) {
        if (that.container) {
            that.container.addClass(cls);
        }
    };

    that.remove_class = function(cls) {
        if (that.container) {
            that.container.removeClass(cls);
        }
    };

    that.toggle_class = function(cls, flag) {
        if (that.container) {
            that.container.toggleClass(cls, flag);
        }
    };

    that.widget_create = that.create;
    that.widget_set_enabled = that.set_enabled;

    return that;
};

/**
 * Working widget which contains spinner and can be used while some other
 * widget is working.
 *
 * @class
 * @param {Object} spec
 */
IPA.working_widget = function(spec) {

    spec = spec || {};
    spec.base_css_class = spec.base_css_class || 'working-widget';

    var that = IPA.widget(spec);

    /**
     * Patternfly class name which defines size of spinner. Possible values:
     * ''|'spinner-lg'|'spinner-sm'|'spinner-xs'
     *
     * @property {string} class_name
     */
    that.spinner_size_cls = spec.spinner_size_cls || 'spinner-sm';

    /**
     * The variable defines the background color of working widget.
     *
     * @property {string} color definition
     */
    that.bg_color = spec.bg_color || 'rgba(255,255,255,0.7)';

    /**
     * Z-index of this widget.
     *
     * @property {number}
     */
    that.z_index = spec.z_index || 99;

    that.create = function(container) {

        that.spin_div = $('<div />', {
            'class': that.base_css_class,
            style: 'background-color: ' + that.bg_color + ';'
                    + 'z-index: ' + that.z_index + ';'
        });
        that.spinner = $('<div />', {
            'class': 'spinner ' + that.spinner_size_cls
        }).appendTo(that.spin_div);

        that.spin_div.appendTo(container);

        that.on('hide-spinner', function() {
            that.spin_div.fadeOut();
        });

        that.on('display-spinner', function() {
            that.spin_div.fadeIn();
            that.spin_div.css('display', 'flex');
            that.spin_div.css('display', '-webkit-flex');
        });
    };

    return that;
};

/**
 * Base class for input gathering widgets.
 * @class
 * @extends IPA.widget
 * @abstract
 */
IPA.input_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    /**
     * Placeholder
     * @property {string}
     */
    that.placeholder = text.get(spec.placeholder);

    /**
     * Widget's width.
     * @deprecated
     * @property {number}
     */
    that.width = spec.width;

    /**
     * Widget's height.
     * @deprecated
     * @property {number}
     */
    that.height = spec.height;

    /**
     * Widget is required
     * @property {boolean}
     */
    that.required = spec.required;

    /**
     * Enable undo button showing. Undo button is displayed when user
     * modifies data.
     * @property {boolean} undo=true
     */
    that.undo = spec.undo === undefined ? true : spec.undo;

    /**
     * User has rights to modify widgets content. Ie. based on LDAP ACL.
     * @property {boolean} writable=true
     */
    that.writable = spec.writable === undefined ? true : spec.writable;

    /**
     * This widget content is read-only.
     * @property {boolean}
     */
    that.read_only = spec.read_only;



    //events
    //each widget can contain several events
    /**
     * Value changed event.
     *
     * Raised when user modifies data by hand.
     * @deprecated
     *
     * @event
     */
    that.value_changed = IPA.observer();

    /**
     * Undo clicked event.
     * @deprecated
     *
     * @event
     */
    that.undo_clicked = IPA.observer();

    /**
     * @inheritDoc
     */
    that.ctor_init = function() {
        on(that, 'value-change', that.hide_if_empty);
        on(that, 'readable-change', function() {
            that.set_visible();
        });
    };

    /**
     * Creates HTML representation of error link
     * @param {HTMLElement} container - node to place the error link
     */
    that.create_error_link = function(container) {
        container.append(' ');

        $('<span/>', {
            name: 'error_link',
            'class': 'help-block',
            style: 'display:none'
        }).appendTo(container);
    };

    /**
     * Creates HTML representation of required indicator.
     * @param {HTMLElement} container - node to place the indicator
     */
    that.create_required = function(container) {
        that.required_indicator = $('<span/>', {
            'class': 'required-indicator',
            text: IPA.required_indicator,
            style: 'display: none;'
        }).appendTo(container);
    };

    /**
     * Update displayed information by supplied values.
     * @param {Object|Array|null} values - values to be edited/displayed by
     *                                     widget.
     */
    that.update = function() {
    };

    /**
     * Alias of update
     */
    that.set_value = function(value) {
        that.update(value);
    };

    /**
     * This function saves the values entered in the UI.
     * It returns the values in an array, or null if
     * the field should not be saved.
     * @returns {Array|null} entered values
     */
    that.save = function() {
        return [];
    };

    /**
     * Alias of save
     */
    that.get_value = function() {
        return that.save();
    };

    /**
     * This function creates an undo link in the container.
     * On_undo is a link click callback. It can be specified to custom
     * callback. If a callback isn't set, default callback is used. If
     * spefified to value other than a function, no callback is registered.
     * @param {HTMLElement} container
     * @param {Function} link clicked callback
     */
    that.create_undo = function(container, on_undo) {
        container.append(' ');

        that.undo_span = IPA.button({
            name: 'undo',
            style: 'display: none;',
            'class': 'undo',
            title: text.get('@i18n:widget.undo_title'),
            label: text.get('@i18n:widget.undo')
        }).appendTo(container);

        if(on_undo === undefined) {
            on_undo = function() {
                that.undo_clicked.notify([], that);
                that.emit('undo-click', { source: that });
            };
        }

        if(typeof on_undo === 'function') {
            that.undo_span.click(on_undo);
        }
    };

    /**
     * Get reference to undo element
     * @return {jQuery} undo button jQuery reference
     */
    that.get_undo = function() {
        return $(that.undo_span);
    };

    /**
     * Display undo button
     */
    that.show_undo = function() {
        that.get_undo().css('display', '');
    };

    /**
     * Hide undo button
     */
    that.hide_undo = function() {
        $(that.undo_span).css('display', 'none');
    };

    /**
     * Get error link reference
     * @return {jQuery} error link jQuery reference
     */
    that.get_error_link = function() {
        return $('span[name="error_link"]', that.container).eq(0);
    };

    /**
     * Set's validity of widget's value. Usually checked by outside logic.
     * @param {Object} result Validation result as defined in IPA.validator
     */
    that.set_valid = function(result) {

        var old = that.valid;
        that.valid = result.valid;

        that.toggle_class('valid', that.valid);
        if (!that.valid) {
            that.show_error(result.message);
        } else  {
            that.hide_error();
        }
        if (old !== that.valid) {
            that.emit("valid-change", {
                source: that,
                valid: that.valid,
                result: result
            });
        }
    };

    /**
     * Show error message
     * @protected
     * @fires error-show
     * @param {Object} error
     */
    that.show_error = function(message) {
        if (that.show_errors) {
            var error_link = that.get_error_link();
            error_link.html(message);
            error_link.css('display', '');
        }
        that.emit('error-show', {
            source: that,
            error: message,
            displayed: that.show_errors
        });
    };

    /**
     * Hide error message
     * @protected
     * @fires error-hide
     */
    that.hide_error = function() {
        var error_link = that.get_error_link();
        error_link.html('');
        error_link.css('display', 'none');
        that.emit('error-hide', { source: that });
    };

    /**
     * Set required
     * @param {boolean} required
     */
    that.set_required = function(required) {

        var changed = required !== that.required;

        that.required = required;

        if (that.required_indicator) {
            that.required_indicator.css('display', that.required ? '' : 'none');
        }
        if (changed) {
            that.emit('require-change', { source: that, required: required });
        }
    };

    /**
     * Set enabled
     * @param {boolean} value - enabled
     */
    that.set_enabled = function(value) {

        that.widget_set_enabled(value);

        if (that.input) {
            that.input.prop('disabled', !value);
        }
    };

    /**
     * Raise value change event
     * @protected
     */
    that.on_value_changed = function(value) {
        var old = that.value;
        if (value === undefined) value = that.save();
        that.value = value;
        that.value_changed.notify([value], that);
        that.emit('value-change', { source: that, value: value, old: old });
    };

    /**
     * Hide widget if value is empty and widget is read_only.
     * @protected
     */
    that.hide_if_empty = function(event) {

        var value = event.value !== undefined ? event.value : true;
        that.has_value = !util.is_empty(value);
        that.set_visible();
    };

    that.get_visible = function() {

        var visible = that.visible;
        if (that.has_value === false && !that.is_writable() && that.hidden_if_empty) {
            visible = false;
        }
        if (that.readable !== undefined) {
            visible = visible && that.readable;
        }
        return visible;
    };

    that.set_readable = function(readable) {

        var old = that.readable;
        that.readable = readable;

        if (old !== that.readable) {
            that.emit('readable-change', { source: that, readable: readable });
        }
    };

    /**
     * Widget is writable
     * @return {boolean}
     */
    that.is_writable = function() {
        return !that.read_only && !!that.writable;
    };

    /**
     * Set writable
     * @fires writable-change
     * @param {boolean} writable
     */
    that.set_writable = function(writable) {

        var changed = writable !== that.writable;

        that.writable = writable;
        that.update_read_only();

        if (changed) {
            that.emit('writable-change', { source: that, writable: writable });
        }
    };

    /**
     * Set read only
     * @fires readonly-change
     * @param {boolean} writable
     */
    that.set_read_only = function(read_only) {

        var changed = read_only !== that.read_only;

        that.read_only = read_only;
        that.update_read_only();

        if (changed) {
            that.emit('readonly-change', { source: that, read_only: read_only });
        }
    };

    /**
     * Update widget's HTML based on `read_only` and `writable` properties
     * @protected
     */
    that.update_read_only = function() {
        var input = that.get_input();
        if (input) {
            var ro = that.is_writable();
            input.prop('readOnly', !ro);
        }
    };

    /**
     * Focus input element
     * @abstract
     */
    that.focus_input = function() {

        var input = that.get_input();

        if (!input) {
            return;
        } else if (input.jquery || input.length === undefined) {
            input.focus();
        } else if (input.length) {
            input[0].focus();
        }
    };

    /**
     * Get input element or array of input elements in case of multivalued
     * widgets.
     *
     * - useful for label.for
     *
     * @return {null|HTMLElement[]}
     */
    that.get_input = function() {

        if (that.input) return that.input;
        return null;
    };

    /**
     * Mark element as deleted.
     *
     * Ie. textbox with strike-through
     * @abstract
     */
    that.set_deleted = function() {};

    // methods that should be invoked by subclasses
    that.widget_hide_error = that.hide_error;
    that.widget_show_error = that.show_error;
    that.widget_set_valid = that.set_valid;
    that.widget_hide_undo = that.hide_undo;
    that.widget_show_undo = that.show_undo;
    that.widget_set_writable = that.set_writable;
    that.widget_set_read_only = that.set_read_only;

    return that;
};

/**
 * Select text in input.
 * Uses a browser specific technique to select a range.
 * @member IPA
 * @param {jQuery} input jQuery reference
 * @param {number} start
 * @param {number} end
 */
IPA.select_range = function(input,start, end) {
    input.focus();
    if (input[0].setSelectionRange) {
        input[0].setSelectionRange(start, end);
    } else if (input[0].createTextRange) {
        var range = input[0].createTextRange();
        range.collapse(true);
        range.moveEnd('character', end);
        range.moveStart('character', start);
        range.select();
    }
};

/**
 * A textbox widget. Displayed as label when not modifiable.
 * @class
 * @extends IPA.input_widget
 */
IPA.text_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    /**
     * Size of the input.
     * @property {number}
     */
    that.size = spec.size || 30;

    /**
     * Input type
     * @property {string} input_type='text'
     */
    that.input_type = spec.input_type || 'text';

    that.base_css_class = that.base_css_class + ' text-widget';

    /**
     * Select range of text
     */
    that.select_range = function(start, end){
        IPA.select_range(that.input, start, end);
    };

    /**
     * @inheritDoc
     */
    that.create = function(container) {

        that.widget_create(container);

        that.display_control = $('<p/>', {
            name: that.name,
            'class': 'form-control-static',
            style: 'display: none;'
        }).appendTo(container);

        var id = IPA.html_util.get_next_id(that.name);

        that.input_group = $('<div/>').appendTo(container);

        that.input = $('<input/>', {
            type: that.input_type,
            name: that.name,
            id: id,
            'class': 'form-control',
            size: that.size,
            title: that.title,
            placeholder: that.placeholder,
            keyup: function() {
                that.on_value_changed();
            }
        }).appendTo(that.input_group);

        that.input_group_btn = $('<div/>', {
            'class': 'input-group-btn'
        }).appendTo(that.input_group);

        that.input.bind('input', function() {
            that.on_value_changed();
        });

        if (that.undo) {
            that.create_undo(that.input_group_btn);
        }

        that.create_error_link(container);
        that.set_enabled(that.enabled);
        that.update_read_only();
        that.update_input_group_state();
    };

    /**
     * @inheritDoc
     */
    that.update = function(values) {
        var value = values && values.length ? values[0] : '';
        that.display_control.text(value);
        that.input.val(value);
        that.on_value_changed(values);
    };

    /**
     * @inheritDoc
     */
    that.update_read_only = function() {
        if (!that.input) return;
        if (!that.is_writable()) {
            that.display_control.css('display', '');
            that.input_group.css('display', 'none');
        } else {
            that.display_control.css('display', 'none');
            that.input_group.css('display', '');
        }
    };

    /**
     * @inheritDoc
     */
    that.save = function() {

        var value = that.input.val();
        return value === '' ? [] : [value];
    };

    /**
     * @inheritDoc
     */
    that.clear = function() {
        that.input.val('');
        that.display_control.text('');
        that.on_value_changed([]);
    };

    /**
     * @inheritDoc
     */
    that.set_deleted = function(deleted) {
        if(deleted) {
            that.input.addClass('strikethrough');
        } else {
            that.input.removeClass('strikethrough');
        }
    };

    /**
     * Display undo button
     */
    that.show_undo = function() {
        that.widget_show_undo();
        that.update_input_group_state();
    };

    /**
     * Hide undo button
     */
    that.hide_undo = function() {
        that.widget_hide_undo();
        that.update_input_group_state();
    };

    /**
     * Set 'input_group' class to input group if input_group_btn has any
     * visible content.
     */
    that.update_input_group_state = function() {
        var children = that.input_group_btn.children();
        var visible = $.grep(children, function(el, i) {
            return $(el).css('display') !== 'none';
        }).length > 0;
        that.input_group.toggleClass('input-group', visible);
    };

    // methods that should be invoked by subclasses
    that.text_load = that.load;

    return that;
};

/**
 * @class
 * @extends IPA.text_widget
 *  A textbox widget where input type is 'password'.
 */
IPA.password_widget = function(spec) {

    spec = spec || {};
    spec.input_type = 'password';

    var that = IPA.text_widget(spec);
    return that;
};

/**
 * Widget which allows to edit multiple values. It display one
 * editor (text widget by default) for each value.
 * @class
 * @extends IPA.input_widget
 */
IPA.multivalued_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.child_spec = spec.child_spec;
    that.size = spec.size || 30;
    that.undo_control = null;
    that.initialized = true;
    that.updating = false;

    /**
     *
     * CUSTOM ACTION MENU HELP:
     *
     * Custom actions variable sets whether each row will use custom menu
     * for showing remove button or not. Default is false - button will be
     * displayed classicaly as any other button. True means custom menu is
     * present..
     *
     * In case that the variable is set to true, the widget of each row
     * has to offer following method:
     *      action_object get_custom_actions();
     *
     * Then the action_object has to have following interface:
     *      Array[item] get_items();
     *      set_items(Array[item]);
     *      enable_item(name);
     *      disable_item(name);
     */
    that.custom_actions = !!spec.custom_actions;

    that.rows = [];

    that.base_css_class = that.base_css_class + ' multivalued-widget';

    that.on_child_value_changed = function(row) {
        if (that.test_dirty_row(row)) {
            that.toggle_remove_link(row, false);
            row.widget.show_undo();
        } else {
            row.widget.hide_undo();
            that.toggle_remove_link(row, true);
        }

        if (that.updating) return;
        that.on_value_changed();
        that.emit('value-change', { source: that });
        that.emit('child-value-change', { source: that, row: row });
    };

    that.on_child_undo_clicked = function(row) {
        if (row.is_new) {
            that.remove_row(row);
        } else {
            that.reset_row(row);
        }
        that.emit('child-undo-click', { source: that, row: row });
    };

    that.hide_undo = function() {

        $(that.undo_span).css('display', 'none');
        for(var i=0; i<that.rows.length; i++) {
            var row = that.rows[i];
            row.widget.hide_undo();
            if (that.is_writable()) {
                that.toggle_remove_link(row, true);
            }
        }
    };


    that.update_child = function(values, index) {
        that.rows[index].widget.update(values);
    };

    that.show_child_undo = function(index) {
        that.rows[index].widget.show_undo();
        that.show_undo();
    };

    that.hide_error = function() {

        that.widget_hide_error();

        for (var i=0; i<that.rows.length; i++) {
            that.rows[i].widget.hide_error();
        }
    };

    that.set_valid = function (result) {

        var old = that.valid;
        that.valid = result.valid;

        if (!result.valid && result.results) {
            var offset = 0;
            for (var i=0; i<that.rows.length; i++) {

                var val_result = null;
                if (that.rows[i].deleted) {
                    offset++;
                    val_result = { valid: true };
                } else {
                    val_result = result.results[i-offset];
                }
                var widget = that.rows[i].widget;
                if (val_result) widget.set_valid(val_result);
            }

            if (that.rows.length > 0) {
                var error_link = that.get_error_link();
                error_link.css('display', 'none');
                error_link.html('');
            }
        } else if (!result.valid) {
            that.show_error(result.message);
        } else {
            that.hide_error();
        }

        if (old !== that.valid) {
            that.emit("valid-change", {
                source: that,
                valid: that.valid,
                result: result
            });
        }
    };

    that.save = function() {

        var values = [];

        for (var i=0; i<that.rows.length;i++) {

            if(that.rows[i].deleted) continue;

            values.push(that.extract_child_value(that.rows[i].widget.save()));
        }

        return values;
    };

    that.extract_child_value = function(value) {

        if (value instanceof Array) {
            if (value.length > 0) {
                return value[0];
            }
            return '';
        }

        if (value) return value;

        return '';
    };

    that.focus_last = function() {
        if (!that.rows.length) return;
        var last_row = that.rows[that.rows.length-1];
        last_row.widget.focus_input();
    };

    that.focus_input = function() {

        if (that.rows.length) {
            that.focus_last();
        } else {
            that.add_link.focus();
        }
    };

    that.add_row = function(values) {
        var row = {};
        that.rows.push(row);
        var row_index = that.rows.length - 1;
        row.is_new = that.initialized;

        row.container = $('<div/>', { name: 'value'});

        var spec = that.child_spec || {};
        if (typeof spec !== 'function') {
                lang.mixin(spec, {
                name: that.name+'-'+row_index,
                undo: that.undo || row.is_new,
                read_only: that.read_only,
                writable: that.writable,
                enabled: that.enabled
            });
        }

        row.widget = builder.build('widget', spec);
        row.widget.create(row.container);

        row.original_values = values;
        row.widget.update(values);

        on(row.widget, 'value-change', function() {
            that.on_child_value_changed(row);
        });
        on(row.widget, 'undo-click', function() {
            that.on_child_undo_clicked(row);
        });
        on(row.widget, 'error-show', function() {
            that.emit('error-show', { source: that });
        });

        var remove_row = function() {
            that.remove_row(row);
        };

        var remove_link_visible = !(row.is_new || !that.is_writable());

        if (!that.custom_actions) {
            row.remove_link = $('<button/>', {
                name: 'remove',
                'class': 'btn btn-default',
                title: text.get('@i18n:buttons.remove'),
                html: text.get('@i18n:buttons.remove'),
                click: function () {
                    remove_row();
                    return false;
                }
            });

            if (row.widget.input_group_btn) {
                // A little hack to make delete button part of row widget
                row.remove_link.appendTo(row.widget.input_group_btn);
            } else {
                row.remove_link.appendTo(row.container);
            }
        } else {
            row.remove_link = {
                name: 'remove',
                label: text.get('@i18n:buttons.remove'),
                handler: remove_row
            };

            var custom_actions = row.widget.get_custom_actions();
            var items = custom_actions.get_items();
            items.push(row.remove_link);
            custom_actions.set_items(items);
        }

        if (row.is_new) {
            row.widget.show_undo();
            that.value_changed.notify([], that);
            that.emit('value-change', { source: that });
        }

        row.container.insertBefore(that.add_link);
        that.toggle_remove_link(row, remove_link_visible);
        return row;
    };

    that.new_row = function() {
        that.add_row('');
        that.focus_last();
    };

    that.toggle_remove_link = function(row, show) {
        if (show) {
            if (that.custom_actions) {
                row.widget.get_custom_actions().enable_item('remove');
            }
            else {
                row.remove_link.show();
            }
        } else {
            if (that.custom_actions) {
                row.widget.get_custom_actions().disable_item('remove');
            }
            else {
                row.remove_link.hide();
            }
        }

        if (row.widget.update_input_group_state) {
            row.widget.update_input_group_state();
        }
    };

    that.create = function(container) {

        that.widget_create(container);

        that.create_error_link(container);

        that.add_link = $('<button/>', {
            name: 'add',
            'class': 'btn btn-default',
            title: text.get('@i18n:buttons.add'),
            html: text.get('@i18n:buttons.add'),
            click: function() {
                that.new_row();
                return false;
            }
        }).appendTo(container);


        container.append(' ');

        that.undo_span = IPA.button({
            name: 'undo_all',
            style: 'display: none;',
            'class': 'undo',
            title: text.get('@i18n:widget.undo_all_title'),
            label: text.get('@i18n:widget.undo_all'),
            click: function() {
                that.undo_clicked.notify([], that);
                that.emit('undo-click', { source: that });
            }
        }).appendTo(container);
    };

    that.reset_row = function(row) {
        row.widget.update(row.original_values);
        row.widget.set_deleted(false);
        row.deleted = false;
        row.widget.hide_undo();
        that.toggle_remove_link(row, true);

        that.value_changed.notify([], that);
        that.emit('value-change', { source: that });
    };

    that.remove_row = function(row) {
        if (row.is_new) {
            row.container.remove();
            that.rows.splice(that.rows.indexOf(row), 1); //not supported by IE<9
        } else {
            row.deleted = true;
            row.widget.set_deleted(true);
            that.toggle_remove_link(row, false);
            row.widget.show_undo();
        }
        that.value_changed.notify([], that);
        that.emit('value-change', { source: that });
    };

    that.remove_rows = function() {
        for(var i=0; i < that.rows.length; i++) {
            that.rows[i].container.remove();
        }
        that.rows = [];
    };

    that.clear = function() {
        that.remove_rows();
    };

    that.test_dirty_row = function(row) {

        if (row.deleted || row.is_new) return true;

        var value = row.widget.save();

        if (util.dirty(value, row.original_values, { unordered: true })) {
            return true;
        }
        return false;
    };

    that.update = function(values, index) {

        var value;
        that.updating = true;

        if (index === undefined) {

            that.initialized = false;
            that.remove_rows();

            for (var i=0; i<values.length; i++) {
                value = [values[i]];
                if(value[0]) {
                    that.add_row(value);
                }
            }

            that.initialized = true;

            that.update_add_link_visibility();
        } else {
            value = values[index];
            var row = that.rows[index];
            row.widget.update(values);
        }

        that.updating = false;

        that.on_value_changed();
    };

    /** @inheritDoc */
    that.update_read_only = function() {
        that.update_add_link_visibility();
    };

    that.update_add_link_visibility = function() {
        if (!that.add_link) return;
        var visible = that.is_writable() && that.enabled;
        if (visible) {
            that.add_link.css('display', '');
        } else {
            that.add_link.css('display', 'none');
        }
    };

    that.update_row_buttons = function(row) {

        var w = that.is_writable();
        if (!that.enabled || !w) {
            row.widget.hide_undo();
            that.toggle_remove_link(row, false);
        } else {
            if (row.is_new || that.test_dirty_row(row)) {
                row.widget.show_undo();
                that.toggle_remove_link(row, false);
            } else {
                that.toggle_remove_link(row, w);
            }
        }
    };

    that.set_writable = function(writable) {
        that.widget_set_writable(writable);
        for (var i=0,l=that.rows.length; i<l; i++) {
            var row = that.rows[i];
            row.widget.set_writable(writable);
            that.update_row_buttons(row);
        }
    };

    that.set_read_only = function(read_only) {
        that.widget_set_read_only(read_only);
        for (var i=0,l=that.rows.length; i<l; i++) {
            var row = that.rows[i];
            row.widget.set_read_only(read_only);
            that.update_row_buttons(row);
        }
    };

    that.set_enabled = function(enabled) {

        that.widget_set_enabled(enabled);
        that.update_add_link_visibility();

        for (var i=0,l=that.rows.length; i<l; i++) {
            var row = that.rows[i];
            row.widget.set_enabled(enabled);
            that.update_row_buttons(row);
        }
    };

    return that;
};


/**
 * Multivalued widget which allows to perform add and remove using commands
 * like 'entity_{add|remove}_item', i.e. 'user_add_cert', etc.
 *
 * @class
 * @extends IPA.multivalued_widget
 */
IPA.custom_command_multivalued_widget = function(spec) {

    spec = spec || {};

    spec.spec_child = spec.spec_child || {};

    var that = IPA.multivalued_widget(spec);

    that.item_name = spec.item_name || '';

    that.adder_dialog_spec = spec.adder_dialog_spec;
    that.remove_dialog_spec = spec.remove_dialog_spec;

    /**
     * Called on success of add command. Override point.
     */
    that.on_success_add = function(data, text_status, xhr) {
        that.facet.refresh();
        IPA.notify_success(data.result.summary);
        that.adder_dialog.close();
    };

    /**
     * Called on error of add command. Override point.
     */
    that.on_error_add = function(xhr, text_status, error_thrown) {
        that.adder_dialog.show();
        exp.focus_invalid(that.adder_dialog);
    };

    /**
     * Called on success of remove command. Override point.
     */
    that.on_success_remove = function(data, text_status, xhr) {
        that.facet.refresh();
        IPA.notify_success(data.result.summary);
    };

    /**
     * Called on error of remove command. Override point.
     */
    that.on_error_remove = function(xhr, text_status, error_thrown) {
        if (error_thrown.message) {
            var msg = error_thrown.message;
            IPA.notify(msg, 'error');
        }
    };

    /**
     * Checks whether the facet doesn't need 'Save' or 'Revert' before
     * refreshing.
     */
    that.handle_dirty_facet_dialog = function(dialog) {
        if (that.facet.is_dirty()) {
            var dirty_dialog = IPA.dirty_dialog({
                facet: that.facet
            });

            dirty_dialog.callback = function() {
                dialog.open();
            };
            dirty_dialog.open();

        } else {
            dialog.open();
        }
    };

    /* On widget's Add button click */
    that.new_row = function() {
        that.open_adder_dialog();
    };

    that.open_adder_dialog = function() {
        that.create_adder_dialog();

        that.handle_dirty_facet_dialog(that.adder_dialog);
    };

    /**
     * New adder dialog is stored in that.adder_dialog.
     */
    that.create_adder_dialog = function() {
        var spec = that.adder_dialog_spec || {
            name: 'custom-add-dialog'
        };

        spec.on_ok = function() {
            if (!that.adder_dialog.validate()) {
                exp.focus_invalid(that.adder_dialog);
            }
            else {
                that.add(that.adder_dialog);
            }
        };

        that.adder_dialog = IPA.custom_command_multivalued_dialog(spec);
    };

    /* on button 'Add' on adder dialog click */
    that.add = function() {
        var command = that.create_add_command();
        command.execute();
    };

    /* Function is called after clicking on widget's 'Delete' button */
    that.remove_row = function(row) {
        that.open_remove_dialog(row);
    };

    that.open_remove_dialog = function(row) {
        that.create_remove_dialog(row);

        that.handle_dirty_facet_dialog(that.remove_dialog);
    };

    /**
     * Create remove dialog title. Override point.
     *
     * @param {Object} row
     * @return {String} title
     */
    that.create_remove_dialog_title = function(row) {
        var title = text.get('@i18n:dialogs.confirmation');

        return title;
    };

    /**
     * Create remove dialog message. Override point.
     *
     * @param {Object} row
     * @return {String} title
     */
    that.create_remove_dialog_message = function(row) {
        var message = text.get('@i18n:search.delete_confirm');

        return message;
    };

    /**
     * New remove dialog is stored in that.remove_dialog.
     */
    that.create_remove_dialog = function(row) {
        var perform_remove = function() {
            that.perform_remove(row);
        };

        var title = that.create_remove_dialog_title(row);
        var message = that.create_remove_dialog_message(row);

        var spec = that.remove_dialog_spec || {
            title: title,
            message: message,
            on_ok: perform_remove,
            ok_label: '@i18n:buttons.remove'
        };

        that.remove_dialog = IPA.confirm_dialog(spec);
    };

    that.perform_remove = function(row) {
        var command = that.create_remove_command(row);
        command.execute();
    };

    /**
     * Compose remove command. Override point
     *
     * @param {Object} row
     * @return {Object} command
     */
    that.create_remove_command = function(row) {
        var method = that.create_remove_method(row);
        var args = that.create_remove_args(row);
        var options = that.create_remove_options(row);

        var command = rpc.command({
            entity: that.facet.entity.name,
            method: method,
            args: args,
            options: options,
            on_success: that.on_success_remove,
            on_error: that.on_error_remove
        });

        return command;
    };

    /**
     * Compose remove method. Override point
     *
     * @param {Object} row
     * @return {String} method
     */
    that.create_remove_method = function(row) {
        return 'remove_' + that.item_name;
    };

    /**
     * Compose args for remove command. Override point
     *
     * @param {Object} row
     * @return {Array} args
     */
    that.create_remove_args = function(row) {
        var pkey = that.facet.get_pkey();
        return [pkey];
    };

    /**
     * Compose options for remove command. Override point
     *
     * @param {Object} row
     * @return {Object} options
     */
    that.create_remove_options = function(row) {
        var options = {};

        return options;
    };

    /**
     * Compose add command
     *
     * @return {Object} command
     */
    that.create_add_command = function() {
        var method = that.create_add_method();
        var args = that.create_add_args();
        var options = that.create_add_options();

        var command = rpc.command({
            entity: that.facet.entity.name,
            method: method,
            args: args,
            options: options,
            on_success: that.on_success_add,
            on_error: that.on_error_add
        });

        return command;
    };

    /**
     * Compose method for add command. Override point.
     * @return {String} method
     */
    that.create_add_method = function() {
        return 'add_' + that.item_name;
    };

    /**
     * Compose args for add command. Override point
     * @return {Array} args
     */
    that.create_add_args = function() {
        var pkey = that.facet.get_pkey();

        return [pkey];
    };

    /**
     * Compose options for add command. Override point
     * @return {Object} options
     */
    that.create_add_options = function() {
        var options = {};

        return options;
    };

    return that;
};

/**
 * Multivalued widget which is used for working with kerberos principal aliases.
 *
 * @class
 * @extends IPA.custom_command_multivalued_widget
 */
IPA.krb_principal_multivalued_widget = function (spec) {

    spec = spec || {};
    spec.child_spec = spec.child_spec || {};
    spec.child_spec.data_name = spec.child_spec.data_name || 'krb-principal';

    spec.adder_dialog_spec = spec.adder_dialog_spec || {
        title: '@i18n:krbaliases.adder_title',
        fields: [
            {
                $type: 'text',
                name: 'krbprincalname',
                label: '@i18n:krbaliases.add_krbal_label'
            }
        ]
    };

    var that = IPA.custom_command_multivalued_widget(spec);

    that.create_remove_dialog_title = function(row) {
        return text.get('@i18n:krbaliases.remove_title');
    };

    that.create_remove_dialog_message = function(row) {
        var message = text.get('@i18n:krbaliases.remove_message');
        message = message.replace('${alias}', row.widget.new_value);

        return message;
    };


    that.create_remove_args = function(row) {
        var pkey = that.facet.get_pkey();
        var krbprincipalname = row.widget.new_value;
        krbprincipalname = [ krbprincipalname ];

        var args = [
            pkey,
            krbprincipalname
        ];

        return args;
    };

    that.create_add_args = function(row) {
        var pkey = that.facet.get_pkey();
        var krbprincipalname = that.adder_dialog.get_field('krbprincalname').value;

        var args = [
            pkey,
            krbprincipalname
        ];

        return args;
    };

    return that;
};

/**
 * Widget which is used as row in multivalued widget. Each row is just
 * non-editable text field.
 *
 * @class
 * @extends IPA.input_widget
 */
IPA.non_editable_row_widget = function(spec) {
    spec = spec || {};

    var that = IPA.input_widget();

    /**
     * Prefix of CSS class of each row.
     */
    that.data_name = spec.data_name || 'non-editable';

    that.create = function(container) {
        that.widget_create(container);

        that.data_text = $('<span />', {
            'class': that.data_name + '-data',
            text: ''
        }).appendTo(container);

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
    };

    that.update = function(value) {

        var single_value = value[0] || '';

        that.new_value = single_value;
        that.update_text();
    };

    that.update_text = function() {
        that.data_text.text(that.new_value);
    };

    return that;
};


/**
 * Option widget base
 *
 * @class IPA.option_widget_base
 * @mixin
 *
 * Widget base for checkboxes and radios. Doesn't handle dirty states but
 * it's nestable.
 *
 * Nesting rules:
 *
 * 1. parent should be checked when one of its child is checked
 *
 *     Consequences:
 *     - childs get unchecked when parent gets unchecked
 *     - parent will be checked when child is checked even when input
 *          values don't contain parent's value.
 * 2. parent can be configured not to include it's value when children are
 *     checked
 * 3. each subtree containing a checked input has to return at least one value
 *     on save()
 * 4. each option has to have unique value
 *
 * Has subset of widget interface - overrides the values in widget
 *
 * - save(): get values
 * - update(values): set values
 * - value_changed: event when change happens
 * - create: creates HTML
 *
 */
IPA.option_widget_base = function(spec, that) {

    spec = spec || {};

    // when that is specified, this constructor behaves like a mixin
    that = that || IPA.object();

    // classic properties
    that.name = spec.name;
    that.label = text.get(spec.label);
    that.title = text.get(spec.title);
    that.sort = spec.sort === undefined ? false : spec.sort;
    that.value_changed = that.value_changed || IPA.observer();

    /**
     * Value which should be check when no value supplied
     * @type {string|null}
     */
    that.default_value = spec.default_value || null;

    /**
     * Consider empty string as non-value -> enable setting default value in such case
     * @type {string}
     */
    that.default_on_empty = spec.default_on_empty === undefined ? true : spec.default_on_empty;

    /**
     * Jquery reference to current node
     */
    that.$node = null;

    /**
     * Type of rendered inputs: ['checkbox', 'radio']
     */
    that.input_type = spec.input_type || 'checkbox';

    /**
     * CSS class for container
     */
    that.css_class = spec.css_class || '';

    /**
     * If it's nested widget
     */
    that.nested = !!spec.nested;

    /**
     * How items should be rendered.
     *
     * values: ['inline', 'vertical']
     */
    that.layout = spec.layout || 'vertical';

    // private properties
    that._child_widgets = [];
    that._input_name = null;
    that._selector = null;
    that._option_next_id = 0;


    /**
     * Normalizes options spec
     * @protected
     */
    that.prepare_options = function(options) {

        var ret = [];

        if (!options) return options;

        for (var i=0; i<options.length; i++) {
            ret.push(that.prepare_option(options[i]));
        }

        return ret;
    };

    /**
     * Prepare option
     *
     * Transform option spec to option.
     * @protected
     * @param {Object} spec
     * @param {string} spec.label
     * @param {string} spec.value
     * @param {boolean} spec.nested
     * @param {IPA.widget} spec.widget
     * @param {boolean} spec.combine_values - default true. Whether to
     *                  include this value if some of its children is specified
     */
    that.prepare_option = function(spec) {

        var option = spec;

        if (!option) throw {
            error: 'Invalid option specified',
            option: option
        };

        if (typeof option === 'string') {
            option = {
                label: option,
                value: option
            };
        } else {
            if (option.type || option.$factory) {
                var factory = option.$factory || reg.widget.get(option.type);
                if (typeof factory !== 'function') throw {
                    error: 'Invalid factory',
                    $factory: factory
                };
                option.nested = true;
                option.widget = factory(option);
                option.widget.value_changed.attach(that.on_input_change);

                that._child_widgets.push(option.widget);
            }
        }

        option.enabled = spec.enabled === undefined ? true : spec.enabled;
        option.label = text.get(option.label);
        option.combine_values = option.combine_values === undefined ? true :
                                    !!option.combine_values;

        return option;
    };

    that.add_option = function(option, suppress_update) {
        that.options.push(that.prepare_option(option));
        if (!suppress_update) that.update_dom();
    };

    that.update_dom = function() {

        if (that.$node) {
            var values = that.save();
            var container = that.$node.parent();
            that.create(container);
            that.update(values);
        }
    };

    that.sort_options = function() {
        var options = that.options.concat();
        options.sort(function(a,b) {
            if (a.value > b.value)
              return 1;
            if (a.value < b.value)
              return -1;
            return 0;
        });
        return options;
    };

    that.create_options = function(container) {
        container = $(container)[0];
        var options = that.options;
        if (that.sort) options = that.sort_options();
        for (var i=0, l=options.length; i<l; i++) {
            var option_container = that.create_option_container();
            var option = options[i];
            that.create_option(option, option_container);
            construct.place(option_container, container);
        }
    };

    that.create_option_container = function() {
        return construct.create('li');
    };

    that._create_option = function(option, container) {
        var input_name = that.get_input_name();
        var id = that._option_next_id + input_name;
        var enabled = that.enabled && option.enabled;

        var opt_cont = construct.create('span', {
            "class": that.intput_type + '-cnt'
        });

        option.input_node = construct.create('input', {
            id: id,
            type: that.input_type,
            name: input_name,
            disabled: !enabled,
            value: option.value,
            title: option.title || that.title || '',
            change: that.on_input_change
        }, opt_cont);

        option.label_node = construct.create('label', {
            title: option.title || that.title || '',
            'for': id
        }, opt_cont);
        option.label_node.textContent = option.label || '';

        that.new_option_id();
        construct.place(opt_cont, container);
    };

    that.create_option = function(option, container) {

        that._create_option(option, container);

        if (option.widget) {
            option.widget.create(container);
        }
    };

    that.new_option_id = function() {
        that._option_next_id++;
    };

    that.get_input_name = function() {

        if (!that._input_name) {
            var name = IPA.html_util.get_next_id(that.name);
            that._input_name = name;
            that._selector = 'input[name="'+name+'"]';
        }
        return that._input_name;
    };

    that.create = function(container) {
        that.destroy();
        var css_class = [that.css_class, 'option_widget', that.layout,
                that.nested ? 'nested': ''].join(' ');

        that.$node = $('<ul/>', { 'class': css_class });
        that.create_options(that.$node);

        if (container) that.$node.appendTo(container);
    };

    that.destroy = function() {
        if (that.$node) {
            that.$node.empty();
            that.$node.remove();
        }

        for (var i=0; i< that._child_widgets.length; i++) {
            that._child_widgets[i].destroy();
        }
    };

    that.get_option = function(value) {
        for (var i=0; i<that.options.length; i++) {
            var option = that.options[i];
            if (option.value === value) return option;
        }
        return null;
    };

    /**
     * Get values for specific option and its children.
     *
     * If option is not specified, gets values of all options and children.
     */
    that.get_values = function(option) {

        var values = [];
        if (option) {
            values.push(option.value);
            if (option.widget) {
                values.push.apply(values, option.widget.get_values());
            }
        } else {
            for (var i=0; i<that.options.length; i++) {
                var vals = that.get_values(that.options[i]);
                values.push.apply(values, vals);
            }
        }

        return values;
    };

    that.on_input_change = function(e) {

        // uncheck child widgets on uncheck of parent option
        if (that._child_widgets.length > 0) {

            var parents_selected = [];

            $(that._selector+':checked', that.$node).each(function() {
                var value = $(this).val();
                var option = that.get_option(value);
                if (option && option.nested) {
                    parents_selected.push(value);
                }
            });

            for (var i=0; i<that.options.length; i++) {

                var option = that.options[i];

                if (option.nested) {
                    var selected = parents_selected.indexOf(option.value) > -1;
                    option.widget.update_enabled(selected, true);
                }
            }
        }
        that.value_changed.notify([], that);
        that.emit('value-change', { source: that });
    };

    that.save = function() {

        var values = [];

        if (that.$node) {

            $(that._selector+':checked', that.$node).each(function() {
                var value = $(this).val();
                var child_values = [];
                var option = that.get_option(value);

                if (option && option.widget) {
                    child_values = option.widget.save();
                    values.push.apply(values, child_values);
                }

                // don't use value if cannot be combined with children's value
                if (!(child_values.length > 0 && !option.combine_values)) {
                    values.push(value);
                }
            });
        }

        return values;
    };

    that.update = function(values) {

        var i;

        var check = function(selector, uncheck) {
            $(selector, that.$node).prop('checked', !uncheck);
        };

        if (that.$node) {

            // uncheck all inputs
            check(that._selector, true /*uncheck*/);

            // enable/disable the inputs and their children
            // they might be disabled later if not checked
            var writable = !that.read_only && !!that.writable && that.enabled;
            if (!that.nested) {
                that.update_enabled(writable);
            }

            // use default value if none supplied
            var def_used = false;
            if (values && values.length > 0 && that.default_on_empty &&
                    that.default_value !== null) {
                for (i=0; i<values.length; i++) {
                    if (values[i] === '') {
                        values[i] = that.default_value;
                        def_used = true;
                    }
                }
            } else if (!values || !values.length) {
                var default_value = that.default_value || '';
                values = [default_value];
                def_used = true;
            }

            // check the option if it or some of its children should be checked
            for (i=0; i<that.options.length; i++) {
                var option = that.options[i];
                var opt_vals = that.get_values(option);
                var has_opt = array.some(values, function(val) {
                    return array.indexOf(opt_vals, val) > -1;
                });

                if (has_opt) {
                    check(that._selector+'[value="'+ option.value +'"]');
                }

                // disable options without value
                if (option.widget && !has_opt) {
                    option.widget.update_enabled(false);
                }
            }

            // update nested
            for (var j=0; j<that._child_widgets.length; j++) {
                var widget = that._child_widgets[j];
                widget.writable = that.writable;
                widget.read_only = that.read_only;
                widget.enabled = that.enabled;
                widget.update(values);
            }

            // notify if a value other than supplied was used
            if (def_used) {
                util.emit_delayed(that, 'value-change', { source: that });
            }
        }

        if (that.on_value_changed) {
            that.on_value_changed(values);
        }
    };

    that.set_enabled = function(enabled) {

        that.widget_set_enabled(enabled);
        that.update_enabled(enabled);
    };

    that.update_enabled = function(enabled, clear) {

        if (!that.$node) return;

        $(that._selector, that.$node).prop('disabled', !enabled);

        if (!enabled && clear) that.clear();

        for (var i=0; i<that._child_widgets.length;i++) {
            that._child_widgets[i].update_enabled(enabled, clear);
        }
    };

    that.update_read_only = function() {
        // a little hack
        var enabled = that.is_writable() && that.enabled;
        that.update_enabled(enabled);
    };


    that.clear = function() {

        $(that._selector, that.$node).prop('checked', false);

        if (that.default_value) {
            $(that._selector+'[value="'+that.default_value+'"]', that.$node).
                prop('checked', true);
        }

        for (var i=0; i<that._child_widgets.length; i++) {
            that._child_widgets[i].clear();
        }
    };

    that.options = that.prepare_options(spec.options || []);

    that.owb_create = that.create;
    that.owb_save = that.save;
    that.owb_update = that.update;

    return that;
};


/**
 * Radio widget
 *
 * - default layout: inline
 *
 * @class IPA.radio_widget
 * @extends IPA.input_widget
 * @mixins IPA.option_widget_base
 */
IPA.radio_widget = function(spec) {

    spec = spec || {};

    spec.input_type = spec.input_type || 'radio';
    spec.layout = spec.layout || 'inline';

    var that = IPA.input_widget(spec);
    IPA.option_widget_base(spec, that);

    that.base_css_class = that.base_css_class + ' radio-widget';

    /** @inheritDoc */
    that.create = function(container) {
        that.widget_create(container);
        that.owb_create(container);

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
    };

    /**
     * @inheritDoc
     */
    that.focus_input = function() {
        that.options[0].input_node.focus();
    };

    return that;
};

/**
 * Single checkbox widget
 *
 * @class
 * @extends IPA.input_widget
 * @mixins IPA.option_widget_base
 */
IPA.checkbox_widget = function (spec) {

    var checked = 'checked';

    spec = spec || {};
    spec.input_type = spec.input_type || 'checkbox';

    if (!spec.options) {
        spec.options = [ { value: checked, label: '', enabled: spec.enabled } ];
    }

    if (spec.checked) spec.default_value = spec.checked;

    var that = IPA.radio_widget(spec);

    that.save = function() {
        var values = that.owb_save();
        return [values.length > 0];
    };

    that.update = function(values) {
        var value = values ? values[0] : '';

        if (typeof value !== 'boolean') {
            value = that.default_value || '';
        } else {
            value = value ? checked : '';
        }
        that.owb_update([value]);
    };

    /**
     * @inheritDoc
     */
    that.get_input = function() {
        return that.options[0].input_node;
    };

    return that;
};

/**
 * Multiple checkbox widget
 *
 * - default layout: vertical
 *
 * @class
 * @extends IPA.input_widget
 * @mixins IPA.option_widget_base
 */
IPA.checkboxes_widget = function (spec) {
    spec = spec || {};
    spec.input_type = spec.input_type || 'checkbox';
    spec.layout = spec.layout || 'vertical';
    var that = IPA.radio_widget(spec);
    return that;
};


/**
 * @class IPA.custom_checkboxes_widget
 * @extends IPA.checkboxes_widget
 */
IPA.custom_checkboxes_widget = function(spec) {

    spec = spec || {};
    spec.layout = spec.layout || 'columns attribute_widget';
    spec.sort = spec.sort === undefined ? true : spec.sort;

    var that = IPA.checkboxes_widget(spec);

    that.set_value_to_lowercase = spec.set_value_to_lowercase || false;

    that.add_dialog_title = spec.add_dialog_title ||
                            "@i18n:dialogs.add_custom_value";
    that.add_field_label = spec.add_field_label ||
                            '@i18n:dialogs.custom_value';

    /**
     * Additional options
     * @property {string[]}
     */
    that.custom_options = spec.custom_options || [];

    that.skip_unmatched = spec.skip_unmatched === undefined ? false : spec.skip_unmatched;

    var id = spec.name;

    that.create = function(container) {
        that.container = container;
        that.widget_create(container);

        that.controls = $('<div/>', {
            'class': 'form-inline controls'
        });
        that.controls.appendTo(container);
        that.create_search_filter(that.controls);
        that.create_add_control(that.controls);
        if (that.undo) {
            that.create_undo(that.controls);
        }

        that.owb_create(container);

        that.create_error_link(container);
    };

    that.create_search_filter = function(container) {
        var filter_container = $('<div/>', {
            'class': 'search-filter'
        });

        that.filter = $('<input/>', {
            type: 'text',
            name: 'filter',
            'class': 'form-control',
            placeholder: text.get('@i18n:search.placeholder_filter')
        }).appendTo(filter_container);

        that.filter.keyup(function(e) {
            that.filter_options();
        });

        var find_button = IPA.action_button({
            name: 'find',
            icon: 'fa-search',
            click: function() {
                that.filter_options();
                return false;
            }
        }).appendTo(filter_container);

        filter_container.appendTo(container);
    };

    that.create_add_control = function(container) {

        that.add_button = IPA.button({
            label: '@i18n:buttons.add',
            click: that.show_add_dialog
        });
        container.append(' ');
        that.add_button.appendTo(container);
    };

    that.show_add_dialog = function() {

        var dialog = IPA.form_dialog({
            name: "add_option",
            title: that.add_dialog_title,
            fields: [
                {
                    name: 'custom_value',
                    label: that.add_field_label,
                    required: true
                }
            ]
        });
        dialog.on_confirm = function() {
            if (!dialog.validate()) return;
            var attr = dialog.get_field('custom_value');
            var value = attr.get_value()[0];
            that.add_custom_option(value, false, true, true);
            dialog.close();
        };
        dialog.open();
    };

    that.filter_options = function() {
        $("li", that.$node).each(function() {
            var item = $(this);
            if(item.find('input').val().indexOf(that.filter.val()) === -1) {
                item.css('display','none');
            } else {
                item.css('display','inline');
            }
        });
    };

    that.update = function(values) {

        that.values = [];

        values = values || [];
        for (var i=0; i<values.length; i++) {

            var value = values[i];

            if (!value || value === '') continue;

            if (that.set_value_to_lowercase) value = value.toLowerCase();
            that.values.push(value);
        }

        that.populate();
        that.append();
        that.owb_create(that.container);
        that.owb_update(that.values);
    };

    /**
     * Method which can be overridden by child class for adding own
     * autogenerated values. These values should be prepared using
     * that.prepare_option() method and stored in that.options.
     */
    that.populate = function() {};

    that.append = function() {

        var unmatched = [];

        function add_unmatched(source) {
            for (var i=0, l=source.length; i<l; i++) {
                if (!that.has_option(source[i])) {
                    that.add_option(source[i], true /* suppress update */);
                }
            }
        }

        add_unmatched(that.custom_options);

        if (that.values && !that.skip_unmatched) {
            add_unmatched(that.values);
        }
    };

    that.add_custom_option = function(name, to_custom, check, update) {

        var value = (name || '').toLowerCase();
        if (to_custom) that.custom_options.push(value);
        if (check) that.values.push(value);
        if (update) that.update(that.values);
    };

    that.has_option = function(value) {
        var o = that.options;
        for (var i=0, l=o.length; i<l; i++) {
            if (o[i].value === value) return true;
        }
        return false;
    };

    return that;
};


/**
 * Creates input with properties defined by `spec` and an empty label which
 * targets the input.
 *
 * Main purpose is to always create label tight with input[radio] or
 * input[checkbox].
 *
 * - Creates checkbox if not type specified.
 * - Adds them to container node if specified.
 *
 * @param {Object} spec
 * @param {HTMLElement} [container]
 * @param {string} [label] Label text
 * @return {jQuery[]} [input, label]
 */
IPA.standalone_option = function(spec, container, label) {

    spec = $.extend({}, spec);

    var id = spec.id || IPA.html_util.get_next_id(spec.name);
    spec.id = id;

    spec.type = spec.type || 'checkbox';

    var opt_cont = $('<span/>', {
        'class': spec.type + '-cnt'
    });

    var input = $('<input/>', spec);

    if (!label) {
        input.addClass('standalone');
        label = '';
    }

    var label_el = $('<label/>', {
        type: 'checkbox',
        'for': id,
        html: label
    });

    if (container) {
        input.appendTo(opt_cont);
        label_el.appendTo(opt_cont);
        opt_cont.appendTo(container);
    }

    return [input, label_el, opt_cont];
};

/**
 * Select widget
 *
 * @class
 * @extends IPA.input_widget
 */
IPA.select_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.options = spec.options || [];

    that.base_css_class = that.base_css_class + ' select-widget';

    that.create = function(container) {

        that.widget_create(container);

        that.display_control = $('<p/>', {
            name: that.name,
            'class': 'form-control-static',
            style: 'display: none;'
        }).appendTo(container);

        that.select = $('<select/>', {
            name: that.name,
            'class':'form-control',
            change: function() {
                that.value_changed.notify([], that);
                that.emit('value-change', { source: that });
                return false;
            }
        }).appendTo(container);

        that.create_options();

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
        that.set_enabled(that.enabled);
    };

    that.set_enabled = function(value) {
        that.widget_set_enabled(value);

        if (that.select) {
            that.select.prop('disabled', !value);
        }
    };

    that.create_options = function() {

        that.select.empty();

        for (var i=0; i<that.options.length; i++) {
            var option = that.options[i];

            $('<option/>', {
                text: option.label,
                value: option.value
            }).appendTo(that.select);
        }
    };

    that.save = function() {
        var value;

        if (that.select) {
            value = that.select.val() || '';
        } else if (that.options.length > 0) {
            value = that.options[0].value; //will be default value
        }

        return [value];
    };

    that.update = function(values) {
        var old = that.save()[0];
        var value = values[0] || "";
        var option = $('option[value="'+value+'"]', that.select);
        if (option.length) {
            option.prop('selected', true);
            that.display_control.text(option.text());
        } else {
            // default was selected instead of supplied value, hence notify
            util.emit_delayed(that,'value-change', { source: that });
        }
        that.on_value_changed(values);
    };

    that.update_read_only = function() {
        if (!that.select) return;
        if (!that.is_writable()) {
            that.display_control.css('display', '');
            that.select.css('display', 'none');
        } else {
            that.display_control.css('display', 'none');
            that.select.css('display', '');
        }
    };

    that.empty = function() {
        $('option', that.select).remove();
    };

    that.clear = function() {
        $('option', that.select).prop('selected', false);
    };

    that.set_options_enabled = function(enabled, options) {

        if (!options) {
            $('option', that.select).prop('disabled', !enabled);
        } else {
            for (var i=0; i<options.length;i++) {
                var value = options[i];
                var option = $('option[value="'+value+'"]', that.select);
                option.prop('disabled', !enabled);
            }
        }
    };

    that.enable_options = function(options) {

        that.set_options_enabled(true, options);
    };

    that.disable_options = function(options) {

        that.set_options_enabled(false, options);
    };

    /**
     * @inheritDoc
     */
    that.get_input = function() {
        return that.select;
    };

    // methods that should be invoked by subclasses
    that.select_save = that.save;
    that.select_update = that.update;
    that.select_create_options = that.create_options;

    return that;
};

/**
 * Textarea widget
 *
 * @class
 * @extends IPA.input_widget
 */
IPA.textarea_widget = function (spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.rows = spec.rows || 5;
    that.cols = spec.cols || 40;
    that.style = spec.style;

    that.base_css_class = that.base_css_class + ' textarea-widget';

    that.create = function(container) {

        that.widget_create(container);

        that.input = $('<textarea/>', {
            name: that.name,
            rows: that.rows,
            cols: that.cols,
            'class': 'form-control',
            readOnly: !!that.read_only,
            title: that.title || '',
            placeholder: that.placeholder,
            keyup: function() {
                that.on_value_changed();
            }
        }).appendTo(container);

        if (that.style) that.input.css(that.style);

        that.input.bind('input', function() {
            that.on_value_changed();
        });

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
        that.set_enabled(that.enabled);
    };

    that.save = function() {
        var value = that.input.val();
        return [value];
    };

    that.update = function(values) {

        var value = values && values.length ? values[0] : '';
        that.input.val(value);
        that.on_value_changed(values);
    };

    that.update_read_only = function() {
        if (!that.input) return;
        var read_only = !that.is_writable();
        that.input.prop('readOnly', read_only);
    };

    that.clear = function() {
        that.input.val('');
    };

    return that;
};

/**
 * Base class for formatters
 *
 * Formatter can be used in various widgets such as column to perform value
 * parsing, normalization and output formatting.
 *
 * @class
 */
IPA.formatter = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    /**
     * Type of output format
     *
     * - default: plain text
     * @property {string}
     */
    that.type = spec.type;

    /**
     * Parse attribute value into a normalized value
     * @return parsed value
     */
    that.parse = function(value) {
        return value;
    };

    /**
     * Format normalized value
     * @return formatted value
     */
    that.format = function(value) {
        return value;
    };

    return that;
};

/**
 * Formatter for boolean values
 * @class
 * @extends IPA.formatter
 */
IPA.boolean_formatter = function(spec) {

    spec = spec || {};

    var that = IPA.formatter(spec);
    /** Parse error */
    that.parse_error = text.get(spec.parse_error || 'Boolean value expected');
    /** Formatted value for true */
    that.true_value = text.get(spec.true_value || '@i18n:true');
    /** Formatted value for false */
    that.false_value = text.get(spec.false_value || '@i18n:false');
    /** Show formatted value if parsed value is false */
    that.show_false = spec.show_false;
    /** Parse return inverted value  */
    that.invert_value = spec.invert_value;
    /**
     * Result of parse of `undefined` or `null` value will be `empty_value`
     * if set.
     * @property {boolean}
     */
    that.empty_value = spec.empty_value !== undefined ? spec.empty_value : false;

    /**
     * Convert string boolean value into real boolean value, or keep
     * the original value
     *
     * @param {Mixed} value Value to parse
     * @return {boolean|""}
     */
    that.parse = function(value) {

        if (util.is_empty(value)) {
            value = that.empty_value;
        }

        if (value instanceof Array) {
            value = value[0];
        }

        if (typeof value === 'string') {
            value = value.toLowerCase();

            if (value === 'true') {
                value = true;
            } else if (value === 'false') {
                value = false;
            }
        }

        if (typeof value === 'boolean') {
            if (that.invert_value) value = !value;
        } else {
            throw {
                reason: 'parse',
                value: that.empty_value,
                message: that.parse_error
            };
        }

        return value;
    };

    /**
     * Convert boolean value into formatted string, or keep the original value
     */
    that.format = function(value) {

        if (typeof value === 'boolean') {
            if (value) {
                value = that.true_value;

            } else {
                if (that.show_false) {
                    value = that.false_value;
                } else {
                    value = '';
                }
            }
        }

        return value;
    };

    that.boolean_formatter_parse = that.parse;
    that.boolean_formatter_format = that.format;

    return that;
};

/**
 * Format as HTML disabled/enabled status icon
 * @class
 * @extends IPA.boolean_formatter
 */
IPA.boolean_status_formatter = function(spec) {

    spec = spec || {};

    spec.true_value = spec.true_value || '@i18n:status.enabled';
    spec.false_value = spec.false_value || '@i18n:status.disabled';

    var that = IPA.boolean_formatter(spec);

    that.show_false = true;
    that.type = 'html';
    that.enabled_icon = spec.disabled_icon || 'fa fa-check';
    that.disabled_icon = spec.disabled_icon || 'fa fa-minus';

    that.format = function(value) {
        var icon_cls = value ? that.enabled_icon : that.disabled_icon;
        var formatted_value = that.boolean_formatter_format(value);
        formatted_value = '<i class=\"'+icon_cls+'\"/> '+formatted_value;
        return formatted_value;
    };

    return that;
};

/**
 * Take supported ISO 8601 or LDAP format date and format it
 * @class
 * @extends IPA.formatter
 */
IPA.datetime_formatter = function(spec) {

    spec = spec || {};

    var that = IPA.formatter(spec);
    that.template = spec.template;
    that.parse_error = text.get(spec.parse_error || '@i18n:widget.validation.datetime');

    that.parse = function(value) {
        if (value === '') return null;
        var date = datetime.parse(value);
        if (!date) {
            throw {
                reason: 'parse',
                value: null,
                message: that.parse_error
            };
        }
        return date;
    };

    that.format = function(value) {

        if (!value) return '';
        if (!(value instanceof Date)) {
            throw {
                reason: 'format',
                value: '',
                message: 'Input value is not of Date type'
            };
        }
        var str = datetime.format(value, that.template);
        return str;
    };
    return that;
};

/**
 * Format DN into single pkey
 * @class
 * @extends IPA.formatter
 */
IPA.dn_formatter = function(spec) {

    var that = IPA.formatter(spec);
    that.format = function(value) {
        return util.get_val_from_dn(value);
    };
    return that;
};

/**
 * Datetime widget
 * @class
 * @extends IPA.input_widget
 */
IPA.datetime_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.base_css_class = that.base_css_class + ' datetime-widget';
    that.date_format = spec.data_format || 'yyyy-mm-dd';
    that.date_format_tmpl = spec.date_format_tmpl || '${YYYY}-${MM}-${DD}';
    that._seconds = null;
    that._tab_pressed = false;

    /**
     * bootstrap-datepicker options
     *
     * spec property: 'options'
     *
     * @property {Object}
     */
    that.datepicker_options = lang.extend({
        format: that.date_format,
        clearBtn: true,
        autoclose: true,
        todayHighlight: true
    }, spec.options || {});

    /**
     * @inheritDoc
     */
    that.create = function(container) {

        that.widget_create(container);

        var id_date = IPA.html_util.get_next_id(that.name);
        var id_hour = IPA.html_util.get_next_id(that.name);
        var id_min = IPA.html_util.get_next_id(that.name);

        // UI used if user doesn't have write rights:
        that.display_control = $('<p/>', {
            name: that.name,
            'class': 'form-control-static',
            style: 'display: none;'
        }).appendTo(container);

        // editable UI:
        that.input_group = $('<div/>', {
            'class': 'input-group',
            keyup: function(e) {
                if (e.keyCode === 9) that._tab_pressed = false;
            }
        }).appendTo(container);

        that.date_input = $('<input/>', {
            type: 'text',
            name: that.name,
            id: id_date,
            placeholder: that.date_format.toUpperCase(),
            'class': 'form-control datetime-date',
            keydown: function(e) {
                if (e.keyCode === 9) that._tab_pressed = true;
            }
        }).appendTo(that.input_group);

        var time_cnt = $('<div/>', {
            'class': 'time-cnt'
        }).appendTo(that.input_group);

        that.time_group = $('<div/>', {
            'class': 'time-group'
        }).appendTo(time_cnt);

        that.hour_input = $('<input/>', {
            type: 'text',
            size: '2',
            maxlength: '2',
            name: that.name,
            id: id_hour,
            'class': 'form-control datetime-hour',
            placeholder: 'hh',
            keyup: function() {
                that.on_value_changed();
            }
        }).appendTo(that.time_group);

        $('<div/>', {
            'class': 'input-group-addon time-separator',
            text: ':'
        }).appendTo(that.time_group);

        that.minutes_input = $('<input/>', {
            type: 'text',
            size: '2',
            maxlength: '2',
            name: that.name,
            id: id_min,
            'class': 'form-control datetime-minutes',
            placeholder: 'mm',
            keyup: function() {
                that.on_value_changed();
            }
        }).appendTo(that.time_group);

        $('<div/>', {
            'class': 'input-group-addon',
            text: 'UTC'
        }).appendTo(that.time_group);

        that.input_group_btn = $('<div/>', {
            'class': 'input-group-btn'
        }).appendTo(that.input_group);

        that.date_input.bind('input', function() {
            that.on_value_changed();
        });
        that.hour_input.bind('input', function() {
            that.on_value_changed();
        });
        that.minutes_input.bind('input', function() {
            that.on_value_changed();
        });
        that.date_input.datepicker(that.datepicker_options);
        that.date_input.on('changeDate', function(e) {
            that.on_value_changed();
        });

        that.date_input.on('hide', function(e) {
            if (!that._tab_pressed) {
                that.hour_input.select();
                that._tab_pressed = false;
            }
        });


        if (that.undo) {
            that.create_undo(that.input_group_btn);
        }

        that.create_error_link(container);
        that.set_enabled(that.enabled);
        that.update_read_only();
    };

    /**
     * @inheritDoc
     */
    that.get_input = function() {

        if (that.date_input) return that.date_input;
        return null;
    };

    /**
     * Expects Date object
     * @inheritDoc
     */
    that.update = function(values) {
        var date = values && values.length ? values[0] : '';

        var fullstr = '';
        var datestr = '';
        var hourstr = '';
        var minstr = '';

        if (date) {
            fullstr =datetime.format(date);
            datestr = datetime.format(date, that.date_format_tmpl);
            hourstr = datetime.format(date, '${HH}');
            minstr = datetime.format(date, '${mm}');
            that._seconds = datetime.format(date, '${ss}');
        }

        that.display_control.text(fullstr);
        that.date_input.datepicker('update', datestr);
        that.hour_input.val(hourstr);
        that.minutes_input.val(minstr);
        that.on_value_changed(values);
    };

    /**
     * @inheritDoc
     */
    that.update_read_only = function() {
        if (!that.input_group) return;
        if (!that.is_writable()) {
            that.display_control.css('display', '');
            that.input_group.css('display', 'none');
        } else {
            that.display_control.css('display', 'none');
            that.input_group.css('display', '');
        }
    };

    /**
     * Return generalized time string or []
     * @inheritDoc
     */
    that.save = function() {

        var date = that.date_input.val();
        var hh = that.hour_input.val() || '00';
        var mm = that.minutes_input.val() || '00';
        var ss = that._seconds || '00';
        hh = string.pad(hh, 2, '0');
        mm = string.pad(mm, 2, '0');
        // turn into generalized time
        var val = [date + ' ' + hh + ':' + mm + ':' + ss + 'Z'];

        // date must be set otherwise it's treated as nothing is set
        if (!date) {
            val = [];
        }
        return val;
    };

    /**
     * @inheritDoc
     */
    that.clear = function() {
        that.display_control.text('');
        that.date_input.val('');
        that.hour_input.val('');
        that.minutes_input.val('');
        that.on_value_changed([]);
    };

    /**
     * @inheritDoc
     */
    that.set_deleted = function(deleted) {
        var c = 'strikethrough';
        if(deleted) {
            that.date_input.addClass(c);
            that.hour_input.addClass(c);
            that.minutes_input.addClass(c);
        } else {
            that.date_input.removeClass(c);
            that.hour_input.removeClass(c);
            that.minutes_input.removeClass(c);
        }
    };

    return that;
};

/**
 * Column for {@link IPA.table_widget}
 *
 * Handles value rendering.
 *
 * @class
 * @param {Object} spec
 * @param {string|IPA.entity} spec.entity Entity or its name
 * @param {string} spec.name
 * @param {string} [spec.label]
 * @param {number} [spec.width]
 * @param {string} [spec.primary_key]
 * @param {boolean} spec.link
 *                  render as link
 * @param {IPA.formatter|Object} spec.formatter
 *                               formatter or its spec
 */
IPA.column = function (spec) {

    spec = spec || {};

    var that = IPA.object();

    that.entity = IPA.get_entity(spec.entity);
    that.name = spec.name;
    that.param = spec.param || that.name;

    that.label = text.get(spec.label);
    that.width = spec.width;
    that.primary_key = spec.primary_key;
    that.link = spec.link;
    that.adapter = builder.build('adapter', spec.adapter || 'adapter', { context: that });
    that.formatter = builder.build('formatter', spec.formatter);
    that.target_entity = spec.target_entity;
    that.target_facet = spec.target_facet;

    if (!that.entity) {
        throw {
            expected: false,
            message: 'Column created without an entity.'
        };
    }

    /**
     * Extract value from record and set formatted value to a container
     *
     * - parses and formats value if formatter is set
     * - also works with promises. Value can be a promise or promise can be
     *   encapsulated in a object along with temporal value.
     *
     *        {
     *            promise: deffered.promise,
     *            temp: 'temporal value to be shown until promise is resolve'
     *        }
     *
     *
     *
     * @param {jQuery} container
     * @param {Object} record - value is located using 'name' property
     * @param {boolean} suppress_link
     */
    that.setup = function(container, record, suppress_link) {
        var value = that.adapter.load(record);
        var type;
        if (that.formatter) {
            value = that.formatter.parse(value);
            value = that.formatter.format(value);
            type = that.formatter.type;
        }

        var promise, temp = '';
        if (value && typeof value.then === 'function') promise = value;
        if (value && value.promise && typeof value.promise.then === 'function') {
            promise = value.promise;
            temp = value.temp || '';
        }

        if (promise) {
            var fulfilled = false;
            promise.then(function(val) {
                fulfilled = true;
                that.set_value(container, val, type, suppress_link);
            });

            if (fulfilled) return;
            // val obj can contain temporal value which is displayed
            // until promise is fulfilled
            value = temp;
        }

        that.set_value(container, value, type, suppress_link);
    };

    /**
     * Set value to the container
     * @protected
     */
    that.set_value = function(container, value, type, suppress_link) {

        if (value instanceof Array) {
            value = value.join(', ');
        }
        value = value ? value.toString() : '';
        container.empty();

        var c;
        if (that.link && !suppress_link) {
            c = $('<a/>', {
                href: '#'+value,
                click: function() {
                    return that.link_handler(value);
                }
            }).appendTo(container);

        } else {
            c = container;
        }

        if (type === 'html') {
            c.html(value);
        } else {
            c.text(value);
        }
    };

    /**
     * Handle clicks on link.
     *
     * Intended to be overridden.
     */
    that.link_handler = function(value) {

        // very simple implementation which doesn't handle navigation to
        // nested entities
        navigation.show_entity(that.target_entity, that.target_facet, [value]);
        return false;
    };


    /*column initialization*/
    if (that.entity && !that.label) {
        var metadata = IPA.get_entity_param(that.entity.name, that.name);
        if (metadata) {
            that.label = metadata.label;
        }
    }


    return that;
};

/**
 * Table
 *
 * TODO: document properties and methods
 *
 * @class
 * @extends IPA.input_widget
 *
 * @param {Object} spec
 * @param {boolean} [spec.scrollable]
 * @param {boolean} [spec.selectable=true]
 * @param {boolean} [spec.save_values=true]
 * @param {string} [spec.class] css class
 * @param {boolean} [spec.pagination] render pagination
 * @param {number} [spec.page_length=config.table_page_size]
 * @param {boolean} [spec.multivalued=true]
 * @param {Array} columns columns or columns specs
 * @param {string} [value_attr_name=name]
 */
IPA.table_widget = function (spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.scrollable = spec.scrollable;
    that.selectable = spec.selectable === undefined ? true : spec.selectable;
    that.save_values = spec.save_values === undefined ? true : spec.save_values;
    that['class'] = spec['class'];

    /**
     * Flag to render footer
     * @property {boolean}
     */
    that.footer = spec.footer === undefined ? true : spec.footer;

    that.pagination = spec.pagination;
    that.current_page = 1;
    that.total_pages = 1;
    that.page_length = spec.page_length || config.get('table_page_size');

    that.multivalued = spec.multivalued === undefined ? true : spec.multivalued;

    that.columns = $.ordered_map();
    that.value_attr_name = spec.value_attribute || that.name;
    that.base_css_class = that.base_css_class + ' table-widget table-responsive';

    that.get_columns = function() {
        return that.columns.values;
    };

    that.get_column = function(name) {
        return that.columns.get(name);
    };

    that.add_column = function(column) {
        column.entity = that.entity;
        // check for facet to avoid overriding with undefined, because of
        // initialization bug - column may be already created by facet (and
        // therefore facet set) but this table widget may not have facet set.
        if (that.facet) column.facet = that.facet;
        that.columns.put(column.name, column);
    };

    that.set_columns = function(columns) {
        that.clear_columns();
        for (var i=0; i<columns.length; i++) {
            that.add_column(columns[i]);
        }
    };

    that.clear_columns = function() {
        that.columns.empty();
    };

    that.create_column = function(spec) {
        var column = IPA.column(spec);
        that.add_column(column);
        return column;
    };


    that.create = function(container) {

        that.widget_create(container);

        that.table = $('<table/>', {
            'class': 'content-table table table-condensed table-striped table-hover table-bordered',
            name: that.name
        }).appendTo(container);

        if (that['class']) that.table.addClass(that['class']);

        if (that.scrollable) {
            that.table.addClass('scrollable');
        }

        that.thead = $('<thead/>').appendTo(that.table);

        var tr = $('<tr/>').appendTo(that.thead);

        var th;

        if (that.selectable) {
            th = $('<th/>', {
                'style': 'width: '+IPA.checkbox_column_width+'px;'
            }).appendTo(tr);

            if (that.multivalued) {
                var select_all_checkbox = IPA.standalone_option({
                    type: 'checkbox',
                    name: that.name,
                    title: text.get('@i18n:search.select_all')
                }, th)[0];

                select_all_checkbox.change(function() {
                    if(select_all_checkbox.is(':checked')) {
                        that.select_all();
                    } else {
                        that.unselect_all();
                    }
                    return false;
                });
            }
        }
        var columns = that.columns.values;

        for (i=0; i<columns.length; i++) {
            var column = columns[i];

            th = $('<th/>').appendTo(tr);

            $('<div/>', {
                'html': column.label,
                'style': 'float: left;'
            }).appendTo(th);

            if (i == columns.length-1) {
                that.buttons = $('<div/>', {
                    'name': 'buttons',
                    'style': 'float: right;'
                }).appendTo(th);
            }

        }

        that.tbody = $('<tbody/>').appendTo(that.table);

        // workaround for #2835
        if (has('ie')) {
            that.tbody.mousedown(function(event) {
                that.scroll_top = that.tbody.scrollTop();
                window.setTimeout(function() {
                    if (that.tbody.scrollTop() === 0) {
                        that.tbody.scrollTop(that.scroll_top);
                    }
                }, 0);
            });
        }

        if (that.height) {
            that.tbody.css('height', that.height);
        }

        if (that.footer) {
            that.create_footer();
        }

        that.set_enabled(that.enabled);
    };

    that.create_footer = function() {

        that.tfoot = $('<tfoot/>').appendTo(that.table);

        var tr = $('<tr/>').appendTo(that.tfoot);

        var td = $('<td/>', {
            'class': 'table-summary',
            colspan: that.columns.values.length + (that.selectable ? 1 : 0)
        }).appendTo(tr);

        that.create_error_link(td);

        that.summary = $('<div/>', {
            'class': 'summary'
        }).appendTo(td);

        if (that.pagination) {
            that.create_pagination(td);
        }
    };

    /**
     * Create or recreate pagination
     * @param  {jQuery} container parent element
     * @protected
     */
    that.create_pagination = function(container) {

        if (container && !that.pagination_control) {
            that.pagination_control = $('<span/>', {
                'class': 'dataTables_paginate pagination-control'
            }).appendTo(container);
        } else if (that.pagination_control) {
            that.pagination_control.empty();
        } else {
            return;
        }

        if (that.total_pages <= 1) return;

        function render_btn(cls, icon, title, disabled, handler) {
            var li = $('<li/>', {
                'class': cls,
                title: title
            });
            var span = $('<span/>', {
                'class': 'i fa ' + icon
            }).appendTo(li);
            if (disabled) {
                li.addClass('disabled');
            } else {
                span.click(handler);
            }
            return li;
        }

        var prev_ul = $('<ul/>', { 'class': 'pagination' });
        var middle = $('<div/>', { 'class': 'pagination-input' });
        var next_ul = $('<ul/>', { 'class': 'pagination' });

        var cp = that.current_page;
        var tp = that.total_pages;

        prev_ul.append(render_btn('first',
            'fa-angle-double-left',
            text.get('@i18n:widget.first'),
            cp <= 1,
            function() {
                that.set_page(1);
                return false;
            }));

        prev_ul.append(render_btn('prev',
            'fa-angle-left',
            text.get('@i18n:widget.prev'),
            cp <= 1,
            function() {
                that.prev_page();
                return false;
            }));

        next_ul.append(render_btn('next',
            'fa-angle-right',
            text.get('@i18n:widget.next'),
            cp >= tp,
            function() {
                that.next_page();
                return false;
            }));

        next_ul.append(render_btn('last',
            'fa-angle-double-right',
            text.get('@i18n:widget.last'),
            cp >= tp,
            function() {
                that.set_page(tp);
                return false;
            }));

        var current = $('<input/>', {
            type: 'text',
            'class': 'paginate_input',
            keypress: function(e) {
                if (e.which == 13) {
                    var page = parseInt(current.val(), 10) || 1;
                    that.set_page(page);
                }
            }
        }).appendTo(middle);
        current.val(cp);

        var of = $('<span/>', {
            'class': 'paginate_of'
        }).appendTo(middle);
        of.append(' '+ text.get('@i18n:widget.of', 'of')+ ' ');
        of.append($('<b/>', { text: tp }));

        that.pagination_control.append(prev_ul);
        that.pagination_control.append(middle);
        that.pagination_control.append(next_ul);
    };

    /**
     * Refresh pagination
     */
    that.refresh_pagination = function() {
        that.create_pagination();
    };

    /**
     * Create empty row
     */
    that.create_row = function() {

        var columns = that.columns.values;
        var row = $('<tr/>');
        var td;

        if (that.selectable) {

            td = $('<td/>', {
                'style': 'width: '+ (IPA.checkbox_column_width + 7) +'px;'
            }).appendTo(row);

            var selectable_type = that.multivalued ? 'checkbox' : 'radio';
            IPA.standalone_option({
                type: selectable_type,
                name: that.name,
                value: ''
            }, td);
        }

        var width;

        for ( var  i=0; i<columns.length; i++) {

            var column = columns[i];

            td = $('<td/>').appendTo(row);

            $('<div/>', {
                'name': column.name
            }).appendTo(td);
        }

        return row;
    };

    that.prev_page = function() {
        if (that.current_page > 1) {
            that.current_page--;
            that.refresh();
        }
    };

    that.next_page = function() {
        if (that.current_page < that.total_pages) {
            that.current_page++;
            that.refresh();
        }
    };

    that.set_page = function(page) {
        if (page < 1) {
            page = 1;
        } else if (page > that.total_pages) {
            page = that.total_pages;
        }
        that.current_page = page;
        that.refresh_pagination();
        that.refresh();
    };

    that.select_changed = function() {
    };

    that.select_all = function() {
        $('input[name="'+that.name+'"]', that.thead).prop('checked', true).
            attr('title', text.get('@i18n:search.unselect_all'));
        $('input[name="'+that.name+'"]', that.tbody).prop('checked', true);
        that.select_changed();
    };

    that.unselect_all = function() {
        $('input[name="'+that.name+'"]', that.thead).prop('checked', false).
            attr('title', text.get('@i18n:search.select_all'));
        $('input[name="'+that.name+'"]', that.tbody).prop('checked', false);
        that.select_changed();
    };

    that.set_values = function(values) {
        $('input[name="'+that.name+'"]', that.tbody).prop('checked', false);
        for (var i=0; values && i<values.length; i++) {
            var value = values[i];
            $('input[name="'+that.name+'"][value="'+value+'"]', that.tbody).prop('checked', true);
        }
        that.select_changed();
    };

    that.empty = function() {
        that.tbody.empty();
    };

    that.load = function(result) {

        that.empty();

        that.values = result[that.value_attr_name] || [];
        for (var i=0; i<that.values.length; i++) {
            var record = that.get_record(result, i);
            that.add_record(record);
        }
    };

    that.update = function(records) {

        that.empty();

        that.values = [];
        that.records = records;

        for (var i=0; i<records.length; i++) {
            var record = records[i];
            that.values.push(record[that.value_attr_name]);
            that.add_record(record);
        }
        that.on_value_changed(records);
    };

    that.save = function() {
        if (that.save_values) {
            var values = [];

            $('input[name="'+that.name+'"]', that.tbody).each(function() {
                values.push($(this).val());
            });

            return values;

        } else {
            return null;
        }
    };

    that.get_selected_values = function() {
        var values = [];

        $('input[name="'+that.name+'"]:checked', that.tbody).each(function() {
            values.push($(this).val());
        });

        return values;
    };

    that.get_selected_rows = function() {
        return $('input[name="'+that.name+'"]:checked', that.tbody).closest('tr');
    };

    /**
     * Create record from supplied result.
     *
     * @param {Object} result
     * @param {number} index Used when record information for each individual
     * column is located in an array at given index
     */
    that.get_record = function(result, index) {

        var record = {};

        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++){

            var name = columns[i].name;
            var values = columns[i].adapter.load(result);
            if (!values) continue;

            if (values instanceof Array){
                record[name] = values[index];
            } else {
                record[name] = values;
            }
        }

        return record;
    };

    that.add_record = function(record) {

        var tr = that.create_row();
        tr.appendTo(that.tbody);

        $('input[name="'+that.name+'"]', tr).click(function(){
            that.select_changed();
        });

        var select_set = false;
        var value;
        var columns = that.columns.values;

        for (var i=0; i<columns.length; i++){
            var column = columns[i];

            value = column.adapter.load(record);
            value = value ? value.toString() : '';

            if (column.primary_key) {
                $('input[name="'+that.name+'"]', tr).val(value);
                select_set = true;
            }

            var div = $('div[name="'+column.name+'"]', tr);

            that.setup_column(column, div, record);
        }

        if (!select_set) {
            value = record[that.value_attr_name];
            value = value ? value.toString() : '';
            $('input[name="'+that.name+'"]', tr).val(value);
        }

        return tr;
    };

    that.set_row_enabled = function(tr, enabled) {
        if (enabled) {
            tr.removeClass('disabled');
        } else {
            tr.addClass('disabled');
        }
    };

    that.setup_column = function(column, div, record) {
        column.setup(div, record);
    };

    that.add_rows = function(rows) {
        for (var i=0; i<rows.length; i++) {
            var tr = rows[i];
            $('input', tr).attr('name', that.name);
            that.tbody.append(tr);
        }
    };

    that.remove_selected_rows = function() {
        var rows = [];
        that.tbody.children().each(function() {
            var tr = $(this);
            if (!$('input[name="'+that.name+'"]', tr).get(0).checked) return;
            tr.detach();
            rows.push(tr);
        });
        return rows;
    };

    that.set_enabled = function(enabled) {
        that.widget_set_enabled(enabled);

        if (that.table) {
            $('input[name="'+that.name+'"]', that.table).prop('disabled', !enabled);
        }
    };

    that.clear = function() {
        that.empty();
        if (that.footer) {
            that.summary.text('');
        }
    };

    //column initialization
    if (spec.columns) {
        for (var i=0; i<spec.columns; i++) {
            that.create_column(spec.columns[i]);
        }
    }

    // methods that should be invoked by subclasses
    that.table_create = that.create;
    that.table_load = that.load;
    that.table_next_page = that.next_page;
    that.table_prev_page = that.prev_page;
    that.table_set_enabled = that.set_enabled;
    that.table_set_page = that.set_page;
    that.table_show_error = that.show_error;
    that.table_set_values = that.set_values;
    that.table_update = that.update;

    return that;
};

/**
 * Attribute table
 *
 * A table which acks as `IPA.association_table` but serves only for one
 * multivalued attribute.
 *
 * TODO: document properties and methods
 *
 * @class
 * @extends IPA.table_widget
 *
 * @param {Object} spec
 * @param {string} [spec.attribute_nam] name of attribute if different
 *                                            than widget name
 * @param {boolean} [spec.adder_dialog] adder dialog spec
 * @param {boolean} [spec.css_class]
 * @param {string} [spec.add_command] add command/method name
 * @param {string} [spec.remove_command] remove command/method name
 * @param {Function} [spec.on_add]
 * @param {Function} [spec.on_add_error]
 * @param {Function} [spec.on_remove]
 * @param {Function} [spec.on_remove_error]
 */
IPA.attribute_table_widget = function(spec) {


    spec = spec || {};
    spec.columns = spec.columns || [];

    var that = IPA.table_widget(spec);

    that.attribute_name = spec.attribute_name || that.name;
    that.adder_dialog_spec = spec.adder_dialog;
    that.css_class = spec.css_class;

    that.add_command = spec.add_command;
    that.remove_command = spec.remove_command;

    that.on_add = spec.on_add;
    that.on_add_error = spec.on_add_error;
    that.on_remove = spec.on_remove;
    that.on_remove_error = spec.on_remove_error;

    that.create_column = function(spec) {

        if (typeof spec === 'string') {
            spec = {
                name: spec
            };
        }

        spec.entity = that.entity;

        var factory = spec.$factory || IPA.column;

        var column = factory(spec);
        that.add_column(column);
        return column;
    };

    that.create_columns = function() {
        that.clear_columns();
        if (spec.columns) {
            for (var i=0; i<spec.columns.length; i++) {
                that.create_column(spec.columns[i]);
            }
        }

        that.post_create_columns();
    };

    that.post_create_columns = function() {
    };

    that.create_buttons = function(container) {

        that.remove_button = IPA.button_widget({
            name: 'remove',
            label: '@i18n:buttons.remove',
            icon: 'fa-trash-o',
            enabled: false,
            button_class: 'btn btn-link',
            click: that.remove_handler
        });
        that.remove_button.create(container);

        that.add_button = IPA.button_widget({
            name: 'add',
            label: '@i18n:buttons.add',
            icon: 'fa-plus',
            button_class: 'btn btn-link',
            click: that.add_handler
        });
        that.add_button.create(container);
    };

    that.create = function(container) {

        that.create_columns();
        that.table_create(container);
        if (that.css_class)
            container.addClass(that.css_class);
        that.create_buttons(that.buttons);
    };

    that.set_enabled = function(enabled) {
        that.table_set_enabled(enabled);
        if (!enabled) {
            that.unselect_all();
        }
        if (that.add_button) {
            that.add_button.set_enabled(enabled);
            that.remove_button.set_enabled(false);
        }
    };

    that.select_changed = function() {

        var values = that.get_selected_values();

        if (that.remove_button) {
            that.remove_button.set_enabled(values.length > 0);
        }
    };

    that.add_handler = function() {
        var facet = that.entity.get_facet();

        if (facet.is_dirty()) {
            var dialog = IPA.dirty_dialog({
                entity:that.entity,
                facet: facet
            });

            dialog.callback = function() {
                that.show_add_dialog();
            };

            dialog.open();

        } else {
            that.show_add_dialog();
        }
    };

    that.remove_handler = function() {
        var facet = that.entity.get_facet();

        if (facet.is_dirty()) {
            var dialog = IPA.dirty_dialog({
                entity:that.entity,
                facet: facet
            });

            dialog.callback = function() {
                that.show_remove_dialog();
            };

            dialog.open();

        } else {
            that.show_remove_dialog();
        }
    };

    that.show_remove_dialog = function() {

        var dialog = that.create_remove_dialog();
        if (dialog) dialog.open();
    };

    that.create_remove_dialog = function() {
        var selected_values = that.get_selected_values();

        if (!selected_values.length) {
            var message = text.get('@i18n:dialogs.remove_empty');
            window.alert(message);
            return null;
        }

        var dialog = IPA.deleter_dialog({
            entity: that.entity,
            values: selected_values
        });

        dialog.execute = function() {
            var command = that.create_remove_command(
                selected_values,
                function(data, text_status, xhr) {
                    var handler = that.on_remove || that.on_command_success;
                    handler.call(this, data, text_status, xhr);
                },
                function(xhr, text_status, error_thrown) {
                    var handler = that.on_remove_error || that.on_command_error;
                    handler.call(this, xhr, text_status, error_thrown);
                }
            );
            command.execute();
        };

        return dialog;
    };

    that.on_command_success = function(data) {
        that.reload_facet(data);
    };

    that.on_command_error = function() {
        that.refresh_facet();
    };

    that.get_pkeys = function() {
        var pkey = that.facet.get_pkey();
        return [pkey];
    };

    that.get_additional_options = function() {
        return [];
    };

    that.create_remove_command = function(values, on_success, on_error) {

        var pkeys = that.get_pkeys();

        var command = rpc.command({
            entity: that.entity.name,
            method: that.remove_command || 'del',
            args: pkeys,
            on_success: on_success,
            on_error: on_error
        });

        command.set_option(that.attribute_name, values);

        var additional_options = that.get_additional_options();
        for (var i=0; i<additional_options.length; i++) {
            var option = additional_options[i];
            command.set_option(option.name, option.value);
        }

        return command;
    };

    that.create_add_dialog = function() {

        var dialog_spec = {
            entity: that.entity,
            method: that.add_command
        };

        if (that.adder_dialog_spec) {
            $.extend(dialog_spec, that.adder_dialog_spec);
        }

        var label = that.entity.metadata.label_singular;
        var pkey = that.facet.get_pkey();
        dialog_spec.title = text.get(dialog_spec.title || '@i18n:dialogs.add_title');
        dialog_spec.title = dialog_spec.title.replace('${entity}', label);
        dialog_spec.title = dialog_spec.title.replace('${pkey}', pkey);


        var factory = dialog_spec.$factory || IPA.entity_adder_dialog;
        var dialog = factory(dialog_spec);

        var cancel_button = dialog.buttons.get('cancel');
        dialog.buttons.empty();

        dialog.create_button({
            name: 'add',
            label: '@i18n:buttons.add',
            click: function() {
                dialog.hide_message();
                dialog.add(
                    function(data, text_status, xhr) {
                        var handler = that.on_add || that.on_command_success;
                        handler.call(this, data, text_status, xhr);
                        dialog.close();
                    },
                    dialog.on_error);
            }
        });

        dialog.create_button({
            name: 'add_and_add_another',
            label: '@i18n:buttons.add_and_add_another',
            click: function() {
                dialog.hide_message();
                dialog.add(
                    function(data, text_status, xhr) {
                        var label = that.entity.metadata.label_singular;
                        var message = text.get('@i18n:dialogs.add_confirmation');
                        message = message.replace('${entity}', label);
                        dialog.show_message(message);

                        var handler = that.on_add || that.on_command_success;
                        handler.call(this, data, text_status, xhr);

                        dialog.reset();
                    },
                    dialog.on_error);
            }
        });

        dialog.buttons.put('cancel', cancel_button);

        dialog.create_add_command = function(record) {
            return that.adder_dialog_create_command(dialog, record);
        };

        return dialog;
    };

    that.adder_dialog_create_command = function(dialog, record) {
        var command  = dialog.entity_adder_dialog_create_add_command(record);
        command.args = that.get_pkeys();

        var additional_options = that.get_additional_options();
        for (var i=0; i<additional_options.length; i++) {
            var option = additional_options[i];
            command.set_option(option.name, option.value);
        }

        return command;
    };

    that.show_add_dialog = function() {

        var dialog = that.create_add_dialog();
        dialog.open();
    };

    that.update = function(values) {
        that.table_update(values);
        that.unselect_all();
    };

    that.reload_facet = function(data) {

        that.facet.load(data);
    };

    that.refresh_facet = function() {

        that.facet.refresh();
    };

    that.attribute_table_adder_dialog_create_command = that.adder_dialog_create_command;
    that.attribute_table_create_remove_command = that.create_remove_command;
    that.attribute_table_update = that.update;

    return that;
};

/**
 * Combobox widget
 *
 * Widget which allows to select a value from a predefined set or write custom
 * value.
 *
 * TODO: document properties and methods
 *
 * @class
 * @extends IPA.input_widget
 *
 * @param {Object} spec
 * @param {string} [spec.attribute_nam] name of attribute if different
 *                                            than widget name
 * @param {boolean} [spec.editable] user can write his own values
 * @param {boolean} [spec.searchable]
 * @param {number} [spec.size] number of rows in dropdown select
 * @param {boolean} [spec.empty_option] has empty option
 * @param {Array} [spec.options] - options to pick from
 * @param {number} [spec.z_index]
 */
IPA.combobox_widget = function(spec) {

    spec = spec || {};

    var that = IPA.text_widget(spec);

    that.editable = spec.editable;
    that.searchable = spec.searchable;
    that.size = spec.size || 5;
    that.empty_option = spec.empty_option === undefined ? true : spec.empty_option;
    that.options = spec.options || [];
    that.z_index = spec.z_index ? spec.z_index + 9000000 : 9000000;
    that.base_css_class = that.base_css_class + ' combobox-widget';

    that.create = function(container) {
        that.widget_create(container);

        that.input_group = $('<div/>', {}).appendTo(container);

        that.input_container = $('<div/>', {
            'class': 'combobox-widget-input'
        }).appendTo(that.input_group);

        that.text = $('<label/>', {
            name: that.name,
            style: 'display: none;'
        }).appendTo(that.input_container);

        var id = IPA.html_util.get_next_id(that.name);

        that.input = $('<input/>', {
            type: 'text',
            name: that.name,
            'class': 'form-control',
            id: id,
            title: that.title,
            keydown: that.on_input_keydown,
            mousedown: that.on_no_close,
            click: function() {
                that.no_close_flag = false;
                if (that.editable) return false;
                if (that.is_open()) {
                    that.close();
                    IPA.select_range(that.input, 0, 0);
                } else {
                    that.open();
                    that.list.focus();
                }
                return false;
            }
        }).appendTo(that.input_container);


        that.input.bind('input', that.on_input_input);

        that.open_button = IPA.action_button({
            name: 'open',
            icon: 'fa-angle-down',
            focusable: false,
            click: function() {
                that.no_close_flag = false;
                if (that.is_open()) {
                    that.close();
                    IPA.select_range(that.input, 0, 0);
                } else {
                    that.open();
                    that.list.focus();
                }
                return false;
            }
        }).appendTo(that.input_container);

        that.open_button.bind('mousedown', that.on_no_close);

        that.list_container = $('<div/>', {
            'class': 'combobox-widget-list',
            css: { 'z-index': that.z_index, 'display':'none' },
            keyup: that.on_list_container_keyup
        }).appendTo(that.input_container);

        var div = $('<div/>', {
            style: 'position: relative; width: 100%;'
        }).appendTo(that.list_container);

        if (that.searchable) {
            that.filter = $('<input/>', {
                type: 'text',
                name: 'filter',
                'class': 'form-control',
                keyup: that.on_filter_keyup,
                keydown: that.on_filter_keydown,
                blur: that.list_child_on_blur
            }).appendTo(div);

            that.search_button = IPA.action_button({
                name: 'search',
                icon: 'fa-search',
                focusable: false,
                click: function() {
                    that.no_close_flag = false;
                    var filter = that.filter.val();
                    that.search(filter);
                    // focus the list to allow keyboard usage and to allow
                    // closing on focus lost
                    that.list.focus();
                    return false;
                }
            }).appendTo(div);

            that.search_button.bind('mousedown', that.on_no_close);
        }

        that.list = $('<select/>', {
            name: 'list',
            style: 'width: 100%',
            keydown: that.list_on_keydown,
            keyup: that.list_on_keyup,
            change: that.list_on_change,
            blur: that.list_child_on_blur
        }).appendTo(div);
        that.list.prop('size', that.size);

        that.input_group_btn = $('<div/>', {
            'class': 'input-group-btn'
        }).appendTo(that.input_group);

        if (that.undo) {
            that.create_undo(that.input_group_btn);
        }

        that.create_error_link(container);
        that.set_enabled(that.enabled);
        that.update_input_group_state();
    };

    that.on_no_close = function() {
        // tell list_child_on_blur that focus lost is caused intentionally
        that.no_close_flag = true;
    };

    that.on_input_keydown = function(e) {

        var key = e.which;

        if (key === keys.TAB ||
            key === keys.ESCAPE ||
            key === keys.ENTER ||
            key === keys.SHIFT ||
            e.ctrlKey ||
            e.metaKey ||
            e.altKey) return true;

        if (that.read_only) {
            e.preventDefault();
            return true;
        }

        if (key === keys.UP_ARROW || key === keys.DOWN_ARROW) {
            e.preventDefault();
            that.open();

            if (key === keys.UP_ARROW) {
                that.select_prev();
            } else {
                that.select_next();
            }
            that.list.focus();
            return false;
        }

        if (!that.editable) {
            e.preventDefault();
            that.open();
            that.filter.focus();
            return false;
        }

        return true;
    };

    that.on_input_input = function(e) {
        if (!that.editable || that.read_only) {
            e.preventDefault();
        } else {
            that.value_changed.notify([], that);
            that.emit('value-change', { source: that });
        }
    };

    that.on_list_container_keyup = function(e) {
        // close on ESCAPE and consume event to prevent unwanted
        // behaviour like closing dialog
        if (e.which == keys.ESCAPE) {
            e.preventDefault();
            e.stopPropagation();
            that.close();
            IPA.select_range(that.input, 0, 0);
            return false;
        }
    };

    that.on_filter_keyup = function(e) {
        if (e.which == keys.ENTER) {
            e.preventDefault();
            e.stopPropagation();

            var filter = that.filter.val();
            that.search(filter);
            return false;
        }
    };

    that.on_filter_keydown = function(e) {
        var key = e.which;
        if (key === keys.UP_ARROW) {
            e.preventDefault();
            that.select_prev();
            that.list.focus();
        } else if (key === keys.DOWN_ARROW) {
            e.preventDefault();
            that.select_next();
            that.list.focus();
        } else if (key === keys.ESCAPE) {
            e.stopPropagation();
        }
    };

    that.list_on_keydown = function(e) {
        if (e.which === keys.ESCAPE) {
            e.stopPropagation();
            return false;
        } else if (e.which === keys.TAB) {
            e.preventDefault();
            if (that.searchable) {
                that.filter.focus();
            } else {
                that.input.focus();
            }
            return false;
        }
    };

    that.list_on_keyup = function(e) {
        if (e.which === keys.ENTER || e.which === keys.SPACE) {
            e.stopPropagation();
            that.list_on_change();
            that.close();
            IPA.select_range(that.input, 0, 0);
            return false;
        }
    };

    that.list_on_change = function(e) {

        var org_val = that.input.val();
        var value = that.list.val();
        if (org_val != value) {
            that.input.val(value);
            that.value_changed.notify([[value]], that);
            that.emit('value-change', { source: that, value: value });
        }
    };

    that.list_child_on_blur = function(e) {

        // wait for the browser to focus new element
        window.setTimeout(function() {

            // close only when focus went outside of list_container
            if (that.list_container.find(':focus').length === 0 &&
                    // don't close when clicked on input, open_button or
                    // search_button their handlers will call close, otherwise
                    // they would reopen the list_container
                    !that.no_close_flag) {
                that.close();
            }
        }, 50);
    };

    that.option_on_click = function(e) {
        // Close list when user selects and option by click
        // doesn't work in IE, can be fixed by moving the handler to list.click,
        // but it breaks UI automation tests. #3014
        that.list_on_change();
        that.close();
        IPA.select_range(that.input, 0, 0);
    };

    that.open = function() {
        if (!that.read_only && that.enabled) {
            that.list_container.css('display', '');
        }
    };

    that.close = function() {
        that.list_container.css('display', 'none');
    };

    that.is_open = function() {
        return that.list_container.css('display') != 'none';
    };

    that.search = function(filter, on_success, on_error) {

        that.recreate_options();
        if (on_success) on_success.call(this);
    };

    that.set_options = function(options) {
        that.options = options;
        that.recreate_options();
    };

    that.recreate_options = function() {

        that.remove_options();

        if (that.empty_option) {
            that.create_option();
        }

        for (var i=0; i<that.options.length; i++) {
            var option = that.options[i];

            var label, value;
            if (option instanceof Object) {
                label = option.label;
                value = option.value;
            } else {
                label = option;
                value = option;
            }

            that.create_option(label, value);
        }
    };

    that.update = function(values) {
        that.close();

        if (that.searchable) {
            that.filter.empty();
        }

        // In a details page the following code will get the stored value.
        // In a dialog box the value will be null.
        var value = values.length ? values[0] : null;

        // In a details page the following code will show the stored
        // value immediately without waiting to populate the list.
        // In a dialog box it will show blank.
        that.set_value(value || '');

        // In a details page the following code will populate the list
        // and select the stored value.
        // In a dialog box it will populate the list and select the first
        // available option.
        that.search(
            null,
            function(data, text_status, xhr) {
                that.select(value);
            }
        );
        that.on_value_changed(values);
    };

    that.update_read_only = function() {
        if (!that.input) return;
        if (that.is_writable()) {
            that.text.css('display', 'none');
            that.input.css('display', 'inline');
            that.open_button.css('display', 'inline');
        } else {
            that.text.css('display', 'inline');
            that.input.css('display', 'none');
            that.open_button.css('display', 'none');
        }
    };

    that.set_value = function(value) {
        that.text.text(value);
        that.input.val(value);
    };

    that.select = function(value) {

        var option;

        if (value) {
            // select specified value
            option = $('option[value="'+value+'"]', that.list);
        } else {
            // select first available option
            option = $('option', that.list).first();
        }

        // if no option found, skip
        if (!option.length) return;

        option.prop('selected', true);

        that.set_value(option.val());
        that.value_changed.notify([], that);
        that.emit('value-change', { source: that, value: value });
    };

    that.select_next = function() {
        var value = that.list.val();
        var option = $('option[value="'+value+'"]', that.list);
        var next = option.next();
        if (!next || !next.length) return;
        that.select(next.val());
    };

    that.select_prev = function() {
        var value = that.list.val();
        var option = $('option[value="'+value+'"]', that.list);
        var prev = option.prev();
        if (!prev || !prev.length) return;
        that.select(prev.val());
    };

    that.save = function() {
        var value = that.input.val();
        return value === '' ? [] : [value];
    };

    that.create_option = function(label, value) {
        var option = $('<option/>', {
            text: label,
            value: value,
            click: that.option_on_click
        }).appendTo(that.list);
    };

    that.remove_options = function() {
        that.list.empty();
    };

    that.clear = function() {
        that.input.val('');
        that.remove_options();
    };

    return that;
};

/**
 * Entity select widget
 *
 * Specialized combobox which allows to select an entity. Widget performs
 * search - an RPC call - to get a list of entities.
 *
 * TODO: document properties and methods
 *
 * @class
 * @extends IPA.combobox_widget
 *
 * @param {Object} spec
 * @param {string} [spec.other_entity]
 * @param {string} [spec.other_field]
 * @param {Array} [spec.options]
 * @param {Object} [spec.filter_options] RPC command options
 */
IPA.entity_select_widget = function(spec) {

    spec = spec || {};
    spec.searchable = spec.searchable === undefined ? true : spec.searchable;

    var that = IPA.combobox_widget(spec);

    that.other_entity = IPA.get_entity(spec.other_entity);
    that.other_field = spec.other_field;
    that.label_field = spec.label_field || spec.other_field;

    that.options = spec.options || [];
    that.filter_options = spec.filter_options || {};

    that.create_search_command = function(filter) {
        var cmd  = rpc.command({
            entity: that.other_entity.name,
            method: 'find',
            args: [filter],
            options: that.filter_options,
            suppress_warnings: [rpc.errors.search_result_truncated]
        });
        var no_members = metadata.get('@mc-opt:' + cmd.get_command() + ':no_members');
        if (no_members) {
            cmd.set_option('no_members', true);
        }
        return cmd;
    };

    that.search = function(filter, on_success, on_error) {

        that.on_search_success = on_success;

        var command = that.create_search_command(filter);
        command.on_success = that.search_success;
        command.on_error = on_error;

        command.execute();
    };

    that.search_success = function(data, text_status, xhr) {

        var adapter = builder.build('adapter', 'adapter', { context: that });

        //get options
        var options = [];

        var entries = data.result.result;
        for (var i=0; i<data.result.count; i++) {
            var entry = entries[i];
            var values = adapter.load(entry, that.other_field);
            var label = adapter.load(entry, that.label_field);
            var option = { label: label[0], value: values[0] };

            options.push(option);
        }

        that.set_options(options);

        if (that.on_search_success) that.on_search_success.call(this, data, text_status, xhr);
    };

    that.entity_select_set_options = that.set_options;

    return that;
};

/**
 * Display value as a link or text
 *
 * @class
 * @extends IPA.input_widget
 *
 * @param {Object} spec
 * @param {boolean} [spec.is_link=false]
 */
IPA.link_widget = function(spec) {
    var that = IPA.input_widget(spec);

    /**
     * Entity a link points to
     * @property {entity.entity}
     */
    that.other_entity = IPA.get_entity(spec.other_entity);

    /**
     * Function which should return primary keys of link target in case of
     * link points to an entity.
     * @property {Function}
     */
    that.other_pkeys = spec.other_pkeys || other_pkeys;

    /**
     * Indicates if it's a valid link
     * @property {boolean}
     */
    that.is_link = spec.is_link || false;

    /**
     * Whether to skip entity validation step
     *
     * Value of `is_link` won't be changed.
     *
     * @property {boolean}
     */
    that.no_check = spec.no_check;

    /**
     * Whether value can be displayed even if link is not valid.
     * @property {boolean}
     */
    that.require_link = spec.require_link !== undefined ? spec.require_link : false;

    that.value = '';
    that.values = [];

    function other_pkeys () {
        return that.values;
    }

    /** @inheritDoc */
    that.create = function(container) {
        that.widget_create(container);
        that.link =
        $('<a/>', {
            href: '#',
            title: '',
            html: '',
            'class': 'link-btn',
            click: function() {
                that.on_link_clicked();
                return false;
            }
        }).appendTo(container);

        that.nonlink = $('<label/>').
            appendTo(container);
    };

    /** @inheritDoc */
    that.update = function(values) {

        that.values = util.normalize_value(values);
        that.value = that.values.slice(-1)[0] || '';
        that.link.text(that.value);
        that.nonlink.text(that.value);
        that.update_link();
        that.check_entity_link();
        that.on_value_changed(values);
    };

    that.update_link = function() {

        var link = false;
        var nonlink = false;

        if (that.value) {
            link = !!that.is_link;
            nonlink = !that.is_link && !that.require_link;
        }

        that.link.css('display', link ? '' : 'none');
        that.nonlink.css('display', nonlink ? '' : 'none');
    };

    /**
     * Handler for widget `link_click` event
     */
    that.on_link_clicked = function() {

        navigation.show_entity(
            that.other_entity.name,
            'default',
            that.other_pkeys());
    };

    /**
     * Check if entity exists
     *
     * - only if link points to an entity
     * - updates link visibility accordingly
     */
    that.check_entity_link = function() {

        //In some cases other entity may not be present.
        //For example when DNS is not configured.
        if (!that.other_entity) {
            that.is_link = false;
            return;
        }

        if (that.no_check) return;

        rpc.command({
            entity: that.other_entity.name,
            method: 'show',
            args: that.other_pkeys(),
            options: {},
            retry: false,
            on_success: function(data) {
                that.is_link = data.result && data.result.result;
                that.update_link();
            },
            on_error: function() {
                that.is_link = false;
                that.update_link();
            }
        }).execute();
    };

    /** @inheritDoc */
    that.clear = function() {
        that.nonlink.text('');
        that.link.text('');
    };


    return that;
};

/**
 * Create button
 *
 * @method
 * @member IPA
 *
 * @param {Object} spec
 * @param {string} [spec.name]
 * @param {string} [spec.label] button text
 * @param {string} [spec.title=label] button title
 * @param {string} [spec.icon] icon name (class)
 * @param {string} [spec.id]
 * @param {string} [spec.href]
 * @param {string} [spec.style] css style
 * @param {string} [spec.class]
 * @param {Function} [spec.click] click handler
 * @param {boolean} [spec.focusable] button is focusable
 *
 */
IPA.action_button = function(spec) {

    spec = $.extend({}, spec);

    spec.element = spec.element || '<a/>';
    spec.button_class = spec.button_class || 'button action-button';

    var button = IPA.button(spec);
    button.prop('href', spec.href || '#');
    return button;
};

/**
 * Create button
 *
 * Has different styling than action button.
 *
 * @method
 * @member IPA
 *
 * @param {Object} spec
 * @param {string} [spec.name]
 * @param {string} [spec.label] button text
 * @param {string} [spec.title=label] button title
 * @param {string} [spec.icon] icon name (class)
 * @param {string} [spec.id]
 * @param {string} [spec.style] css style
 * @param {string} [spec.class]
 * @param {string} [spec.button_class]
 * @param {string} [spec.element]
 * @param {string} [spec.type]
 * @param {Function} [spec.click] click handler
 * @param {boolean} [spec.focusable] button is focusable
 * @param {Function} [spec.blur] blur handler
 */
IPA.button = function(spec) {

    spec = spec || {};

    var el = spec.element || '<button/>';
    var button_class = spec.button_class || 'btn btn-default';

    var button = $(el, {
        id: spec.id,
        name: spec.name,
        title: text.get(spec.title || spec.label),
        'class': button_class,
        style: spec.style,
        click: spec.click,
        type: spec.type || 'button',
        blur: spec.blur
    });

    if (spec.focusable === false) {
        button.attr('tabindex', '-1');
    }

    if (spec['class']) button.addClass(spec['class']);

    if (spec.type) button.addClass(spec.type);

    var label = text.get(spec.label);

    if (spec.icon) {
        $('<i/>', {
            'class': 'fa '+spec.icon
        }).appendTo(button);
        if (label) label = " " + label ;
    }

    if (label) {
        button.append(label);
    }

    return button;
};

/**
 * Widget encapsulating an `IPA.button`
 *
 * @class
 * @extends IPA.widget
 */
IPA.button_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    /**
     * Additional CSS style
     * @property
     */
    that.style = spec.style;
    /**
     * Click handler
     * @property {Function}
     */
    that.click = spec.click;

    /**
     * Additional CSS class(es)
     * @property {String}
     */
    that['class'] = spec['class'];

    /**
     * Override for button classes
     * @property {string}
     */
    that.button_class = spec.button_class;

    /**
     * Icon name
     * @property {string}
     */
    that.icon = spec.icon;

    /**
     * Widget click handler.
     *
     * Calls provided click handler.
     */
    that.on_click = function() {

        if (that.click && that.enabled) {
            that.click();
        }
        return false;
    };

    /** @inheritDoc */
    that.create = function(container) {
        that.button = IPA.button({
            id: that.id,
            name: that.name,
            title: that.title,
            label: that.label,
            'class': that['class'],
            button_class: that.button_class,
            style: that.style,
            icon: that.icon,
            click: that.on_click
        }).appendTo(container);
        that.container = that.button;

        that.set_enabled(that.enabled);
        return that.button;
    };

    /** @inheritDoc */
    that.set_enabled = function(enabled) {
        that.widget_set_enabled(enabled);

        if (that.button) {
            that.button.prop('disabled', !enabled);
        }
    };

    that.button_widget_create = that.create;

    return that;
};

/**
 * Widget just for rendering provided HTML code
 *
 * @class
 * @extends IPA.widget
 */
IPA.html_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    /** Code to render */
    that.html = spec.html;

    that.create = function(container) {

        that.widget_create(container);

        if (that.html) {
            container.append(that.html);
        }
    };

    return that;
};

/**
 * Widget just for rendering provided HTML code
 *
 * @class
 * @extends IPA.widget
 */
IPA.composite_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.widgets = IPA.widget_container();

    that.create = function(container) {

        that.widget_create(container);
        that.widgets.create(container);
    };

    that.clear = function() {

        var widgets = that.widgets.get_widgets();

        for (var i=0; i< widgets.length; i++) {
            widgets[i].clear();
        }
    };

    that.composite_widget_create = that.create;
    that.composite_widget_clear = that.clear;

    return that;
};

/**
 * Section which can be collapsed
 * @class
 * @extends IPA.composite_widget
 */
IPA.section = function(spec) {

    spec = spec || {};

    var that = IPA.composite_widget(spec);

    that.hidden_if_empty = spec.hidden_if_empty === undefined ? true : spec.hidden_if_empty;
    that.show_header = spec.show_header === undefined ? true : spec.show_header;
    that.base_css_class = that.base_css_class + ' details-section';
    that.layout_css_class = spec.layout_css_class || 'col-sm-12';

    that.ctor_init = function() {
        on(that.widgets, 'widget-add', that.on_widget_add);
    };

    that.on_widget_add = function(event) {
        on(event.widget, 'visible-change', that.hide_if_empty);
    };

    that.hide_if_empty = function() {
        if (!that.hidden_if_empty) return;
        var widgets = that.widgets.get_widgets();
        var any = false;
        for (var i=0, l=widgets.length; i<l; i++) {
            any = widgets[i].get_visible();
            if (any) break;
        }
        that.set_visible(any);
    };

    that.create = function(container) {

        that.widget_create(container);
        that.container.addClass(that.layout_css_class);

        if (that.show_header) {
            that.create_header(container);
        }

        that.content_container = $('<div/>', {
            name: that.name,
            'class': 'details-section-content'
        }).appendTo(container);

        that.create_content();
    };

    that.create_header = function(container) {

        that.header = $('<h2/>', {
            name: that.name
        }).appendTo(container);

        that.header.append(' ');

        that.header.append(that.label);
    };

    that.create_content = function() {
        that.composite_widget_create(that.content_container);
    };

    return that;
};

/**
 * Base layout
 * @class
 */

IPA.layout = function(spec) {

    var that = {};

    that.get_measurement_unit_text = function(widget) {

        if (widget.measurement_unit) {
            var unit = text.get('@i18n:measurement_units.'+widget.measurement_unit);
            return ' (' + unit + ')';
        }
        return '';
    };

    that.create_tooltip_icon = function(widget) {

        if (!widget.tooltip) return null;

        var el = $('<span/>', {
            'data-toggle': 'tooltip'
        }).append($('<i/>', {
            'class': 'fa fa-info-circle'
        }));
        $(el).tooltip(widget.tooltip);
        return el;
    };

    return that;
};

/**
 * Table layout
 * Creates list of widgets into table with two columns: label and widget
 * @class
 * @extends IPA.layout
 */
IPA.table_layout = function(spec) {

    spec = spec || {};

    var that = IPA.layout(spec);
    that.table_class = spec.table_class || 'section-table';
    that.label_cell_class = spec.label_cell_class || 'section-cell-label';
    that.field_cell_class = spec.field_cell_class || 'section-cell-field';
    that.label_class = spec.label_class || 'field-label';
    that.field_class = spec.field_class || 'field';

    that.create = function(widgets) {

        that.rows = $.ordered_map();

        var table = $('<table/>', {
            'class': that.table_class
        });

        for (var i=0; i<widgets.length; i++) {
            var widget = widgets[i];
            var tr = $('<tr/>');
            that.rows.put(widget.name, tr);

            if (!widget.visible) {
                tr.css('display', 'none');
            }

            tr.appendTo(table);

            var td = $('<td/>', {
                'class': that.label_cell_class,
                title: widget.label
            }).appendTo(tr);

            var label_text = widget.label + that.get_measurement_unit_text(widget) + ':';

            $('<label/>', {
                name: widget.name,
                'class': that.label_class,
                text: label_text
            }).appendTo(td);

            if(widget.create_required) {
                widget.create_required(td);
            }

            td = $('<td/>', {
                'class': that.field_cell_class,
                title: widget.label
            }).appendTo(tr);

            var widget_container = $('<div/>', {
                name: widget.name,
                'class': that.field_class
            }).appendTo(td);

            widget.create(widget_container);
        }
        return table;
    };


    that.get_measurement_unit_text = function(widget) {

        if (widget.measurement_unit) {
            var unit = text.get('@i18n:measurement_units.'+widget.measurement_unit);
            return ' (' + unit + ')';
        }
        return '';
    };

    return that;
};

exp.fluid_layout = IPA.fluid_layout = function(spec) {

    var that = IPA.layout(spec);

    that.cont_cls = spec.cont_cls || 'form-horizontal';
    that.widget_cls = spec.widget_cls || 'col-sm-9 controls';
    that.label_cls = spec.label_cls || 'col-sm-3 control-label';
    that.group_cls = spec.group_cls || 'form-group';

    that.create = function(widgets) {

        that.rows = $.ordered_map();

        var container = $('<div/>', { 'class': that.cont_cls });

        for (var i=0; i<widgets.length; i++) {
            var widget = widgets[i];
            var group = that.create_control_group(container, widget);
            var control = that.create_control(widget);
            var label = that.create_label(widget);

            label.appendTo(group);
            control.appendTo(group);

            that.register_state_handlers(widget);
            that.update_state(group, widget);
        }

        return container;
    };

    that.create_control_group = function(container, widget) {
        var group = $('<div/>', { 'class': that.group_cls });
        that.rows.put(widget.name, group);

        if (!widget.get_visible()) {
            group.css('display', 'none');
        }

        group.appendTo(container);
        return group;
    };

    that.create_label = function(widget) {
        var label_text = widget.label + that.get_measurement_unit_text(widget);

        var label_cont = $('<div/>', { 'class': that.label_cls });

        var label_el = $('<label/>', {
            name: widget.name,
            'class': '',
            text: label_text
        }).appendTo(label_cont);
        var tooltip = that.create_tooltip_icon(widget);
        if (tooltip) label_el.append(' ').append(tooltip);

        var input = widget.get_input && widget.get_input();

        if (input && input.length) input = input[0];

        if (input && input.id) {
            label_el.prop('for', input.id);
        } else {
            label_el.bind('click', function() {
                widget.focus_input();
            });
        }
        return label_cont;
    };

    that.create_control = function(widget) {
        var controls = $('<div/>', {
            'class': that.widget_cls
        });

        var widget_container = $('<div/>', {
            name: widget.name,
            'class': that.field_class
        }).appendTo(controls);

        widget.create(widget_container);
        return controls;
    };

    that.register_state_handlers = function(widget) {
        on(widget, 'require-change', that.on_require_change);
        on(widget, 'enabled-change', that.on_enabled_change);
        on(widget, 'readonly-change', that.on_require_change);
        on(widget, 'writable-change', that.on_require_change);
        on(widget, 'error-show', that.on_error_show);
        on(widget, 'error-hide', that.on_error_hide);
        on(widget, 'visible-change', that.on_visible_change);
    };

    that.on_enabled_change = function(event) {

        var row = that._get_row(event);
        if (!row) return;
        row.toggleClass('disabled', !event.enabled);
    };

    that.on_require_change = function(event) {

        var row = that._get_row(event);
        if (!row) return;
        row.toggleClass('required', !!event.required && event.source.is_writable());
    };

    that.on_error_show = function(event) {

        var row = that._get_row(event);
        if (!row) return;
        row.toggleClass('has-error', true);
    };

    that.on_error_hide= function(event) {

        var row = that._get_row(event);
        if (!row) return;
        row.toggleClass('has-error', false);
    };

    that.on_visible_change = function(event) {

        var row = that._get_row(event);
        if (!row) return;

        if (event.visible) {
            row.css('display', '');
        } else {
            row.css('display', 'none');
        }
    };

    that.update_state = function(row, widget) {
        row.toggleClass('disabled', !widget.enabled);
        row.toggleClass('required', !!widget.required && widget.is_writable());
    };

    that._get_row = function(event) {
        var widget = event.source;
        if (!widget) return null;
        return that.rows.get(widget.name);
    };

    return that;
};

/**
 * Section with fluid form layout
 * @class
 * @extends IPA.section
 */
IPA.details_section = function(spec) {

    spec = spec || {};

    var that = IPA.section(spec);
    that.layout = IPA.build(spec.layout || IPA.fluid_layout);
    that.action_panel = that.build_child(spec.action_panel, {},
                                         { $factory: IPA.action_panel });

    that.rows = $.ordered_map();

    that.create_content = function() {

        if (that.action_panel) {
            that.action_panel.create(that.content_container);
        }
        var widgets = that.widgets.get_widgets();
        var layout = that.layout.create(widgets);
        layout.appendTo(that.content_container);
        that.rows = that.layout.rows;
    };


    that.add_row = function(name, row) {
        that.rows.put(name, row);
    };

    that.get_row = function(name) {
        return that.rows.get(name);
    };

    that.set_row_visible = function(name, visible) {
        var row = that.get_row(name);
        row.css('display', visible ? '' : 'none');
    };

    return that;
};

/**
 * Section with table layout
 * @class
 * @extends IPA.details_section
 */
IPA.details_table_section = function(spec) {

    spec.layout = spec.layout || IPA.table_layout;

    var that = IPA.details_section(spec);
    return that;
};

/**
 * Policy which hides specific widget if it doesn't have any value
 * @class
 * @extends IPA.facet_policy
 */
IPA.hide_empty_row_policy = function (spec) {

    spec = spec || {};

    var that = IPA.facet_policy();
    that.value_name = spec.value_name || spec.widget;
    that.widget_name = spec.widget;
    that.section_name = spec.section;

    that.post_load = function(data) {

        var value = data.result.result[that.value_name];
        var visible = !IPA.is_empty(value);

        var section = that.container.widgets.get_widget(that.section_name);
        section.set_row_visible(that.widget_name, visible);
    };

    return that;
};

/**
 * Not collabsible details section with table layout
 *
 * @class
 * @extends IPA.details_table_section
 */
IPA.details_table_section_nc = function(spec) {

    spec = spec || {};
    spec.show_header = spec.show_header === undefined ? false : spec.show_header;

    var that = IPA.details_section(spec);

    return that;
};

/**
 * Section which can contain multiple subsections
 *
 * Only one subsection can be active. Widgets in non-active subsections are
 * disabled.
 *
 * Selection of active section is based on radio button selection.
 *
 * Presence of `multiple_choice_section_policy` is required.
 *
 * @class
 * @extends IPA.composite_widget
 */
IPA.multiple_choice_section = function(spec) {

    spec = spec || {};

    var that = IPA.composite_widget(spec);
    that.choices = $.ordered_map().put_array(spec.choices, 'name');
    that.layout = spec.layout || IPA.fluid_layout;

    that.create = function(container) {

        var i, choice, choices;

        that.widget_create(container);
        that.container.addClass('multiple-choice-section col-sm-12');

        that.header_element = $('<div/>', {
            'class': 'multiple-choice-section-header',
            text: that.label
        }).appendTo(container);

        that.choice_container = $('<div/>', {
            'class': 'choices'
        }).appendTo(container);

        choices = that.choices.values;
        for (i=0; i<choices.length; i++) {
            choice = choices[i];
            that.create_choice(choice);
        }

        that.set_enabled(that.enabled);
    };

    that.create_choice = function(choice) {

        var widgets, i, widget, field, section, layout, choice_el, header, radio,
            enabled, radio_id;

        widgets = [];

        if (choice.widgets) {
            for (i=0; i<choice.widgets.length; i++) {
                widget = that.widgets.get_widget(choice.widgets[i]);
                widgets.push(widget);
            }
        } else if (choice.fields) {
            for (i=0; i<choice.fields.length; i++) {
                field = that.facet.fields.get_field(choice.fields[i]);
                widgets.push(field.widget);
            }
        }

        choice_el = $('<div/>',{
            'class': 'choice',
            name: choice.name
        });

        header = $('<div/>',{
            'class': 'choice-header'
        }).appendTo(choice_el);

        enabled = choice.enabled !== undefined ? choice.enabled : false;

        radio_id = that.name + '_' + choice.name;

        $('<input/>',{
            type: 'radio',
            name: that.name,
            id: radio_id,
            value: choice.name,
            checked: enabled,
            disabled: !that.enabled,
            change: function() {
                that.select_choice(this.value);
            }
        }).appendTo(header);

        $('<label/>',{
            text: text.get(choice.label),
            'for': radio_id
        }).appendTo(header);

        layout = IPA.build(that.layout);
        section = layout.create(widgets);
        section.appendTo(choice_el);
        choice_el.appendTo(that.choice_container);
    };

    that.select_choice = function(choice_name) {

        var i, choice, enabled;

        for (i=0; i<that.choices.values.length; i++) {
            choice = that.choices.values[i];
            enabled = choice.name === choice_name;
            that.set_choice_enabled(choice, enabled);
        }
    };

    that.set_choice_enabled = function (choice, enabled) {

        var i, field_name, field, fields, required;

        fields = that.facet.fields;

        for (i=0; i<choice.fields.length; i++) {
            field_name = choice.fields[i];
            field = fields.get_field(field_name);
            field.set_enabled(enabled);
            required = enabled && choice.required.indexOf(field_name) > -1;
            field.set_required(required);
            field.validate(); //hide validation errors
        }
    };

    that.set_enabled = function(value) {
        var i, choice;

        that.widget_set_enabled(value);

        for (i=0; i<that.choices.values.length; i++) {
            choice = that.choices.values[i];
            that.set_choice_enabled(choice, value);
        }
    };

    that.init_enabled = function() {
        if (!that.enabled) {
            return;
        }

        var i, choice;

        for (i=0; i<that.choices.values.length; i++) {
            choice = that.choices.values[i];
            if (choice.enabled) {
                that.select_choice(choice.name);
                break;
            }
        }
    };

    return that;
};

/**
 * Policy which makes `multiple_choice_section` work properly.
 */
IPA.multiple_choice_section_policy = function(spec) {

    spec = spec || {};

    var that = IPA.facet_policy(spec);
    that.widget_name = spec.widget;

    that.init = function() {
        that.widget = that.container.widgets.get_widget(that.widget_name);
    };

    that.post_create = function() {
        that.widget.init_enabled();
    };

    return that;
};

/**
 * Enable widget
 * Basically a radio button
 *
 * @class
 * @extends IPA.radio_widget
 */
IPA.enable_widget = function(spec) {

    spec = spec  || {};

    var that = IPA.radio_widget(spec);

    return that;
};

/**
 * Header widget
 *
 * Can be used as subsection header.
 * @class
 * @extends IPA.widget
 */
IPA.header_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.level = spec.level || 3;
    that.text = text.get(spec.text);
    that.description = text.get(spec.description);

    that.create = function(container) {
        container.append($('<h'+that.level+' />', {
            text: that.text,
            title: that.description
        }));
    };

    return that;
};

/**
 * Event
 *
 * @class IPA.observer
 */
IPA.observer = function(spec) {

    var that = IPA.object();

    /**
     * Listeners
     */
    that.listeners = [];

    /**
     * Register new listener
     * @param {Function} callback
     */
    that.attach = function(callback) {
        that.listeners.push(callback);
    };

    /**
     * Remove registered listener
     * @param {Function} callback
     */
    that.detach = function(callback) {
        for(var i=0; i < that.listeners.length; i++) {
            if(callback === that.listeners[i]) {
                that.listeners.splice(i,1);
                break;
            }
        }
    };

    /**
     * Call all listeners in order of registration with given context and
     * arguments.
     *
     * @param {Array} arguments
     * @param {Object} context
     */
    that.notify = function(args, context) {
        args = args || [];
        context = context || this;

        for(var i=0; i < that.listeners.length; i++) {
            that.listeners[i].apply(context, args);
        }
    };

    return that;
};

/**
 * Utility class for HMTL generation
 * @class
 */
IPA.html_util = function() {

    var that = IPA.object();

    /**
     * Last used ID
     * @property {number}
     */
    that.id_count = 0;

    /**
     * Creates unique ID
     * Usable for controls where same id/name would cause unintended
     * interactions. IE. radios with same name influence each other.
     * @param {string} prefix is concatenated with current `id_count`
     */
    that.get_next_id = function(prefix) {
        that.id_count++;
        return prefix ? prefix + that.id_count : that.id_count;
    };

    return that;
}();

/**
 * Widget container
 *
 * - provides means for nesting widgets
 * - used ie in facets, dialogs or composite widgets
 *
 * @class
 */
IPA.widget_container = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    that.new_container_for_child = spec.new_container_for_child !== undefined ?
    spec.new_container_for_child : true;

    that.widgets = $.ordered_map();

    that.add_widget = function(widget) {
        that.widgets.put(widget.name, widget);
        that.emit('widget-add', { source: that, widget: widget });
    };

    that.get_widget = function(path) {

        var path_len = path.length;
        var i = path.indexOf('.');
        var name, child_path, widget, child;

        if (i >= 0) {
            name = path.substring(0, i);
            child_path = path.substring(i + 1);

            child = that.widgets.get(name);
            widget = child.widgets.get_widget(child_path);
        } else {
            widget = that.widgets.get(path);
        }

        return widget;
    };

    that.get_widgets = function() {
        return that.widgets.values;
    };

    that.create = function(container) {

        var widgets = that.widgets.values;
        for (var i=0; i<widgets.length; i++) {
            var widget = widgets[i];

            var child_container = container;
            if(that.new_container_for_child) {
                child_container = $('<div/>', {
                    name: widget.name,
                    'class': widget['class']
                }).appendTo(container);
            }
            widget.create(child_container);

            if(i < widgets.length - 1) {
                that.create_widget_delimiter(container);
            }
        }
    };

    that.clear = function() {

        var widgets = that.widgets.values;
        for (var i=0; i<widgets.length; i++) {
            widgets[i].clear();
        }
    };

    that.create_widget_delimiter = function(container) {
    };

    that.widget_container_create = that.create;
    that.widget_container_clear = that.clear;

    return that;
};

/**
 * Widget builder
 * @class widget.widget_builder
 * @alternateClassName IPA.widget_builder
 */
exp.widget_builder = IPA.widget_builder = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    that.container = spec.container;
    that.widget_options = spec.widget_options;

    that.build_widget = function(spec, container) {

        var context = lang.mixin({}, that.widget_options);
        context.container = container || that.container;
        var widget = builder.build('widget', spec, context);
        return widget;
    };

    that.build_widgets = function(specs, container) {

        return that.build_widget(specs, container);
    };

    return that;
};

/**
 * SSH keys widget
 *
 * Multivalued widget with SSH key widget instead of text widget.
 *
 * @class
 * @extends IPA.multivalued_widget
 */
IPA.sshkeys_widget = function(spec) {

    spec = spec || {};
    spec.child_spec = { $factory: IPA.sshkey_widget };

    var that = IPA.multivalued_widget(spec);

    that.new_row = function() {
        var row = that.add_row('');
        row.widget.open_edit_dialog();
    };

    that.test_dirty_row = function(row) {

        if(row.deleted || row.is_new) return true;

        var values = row.widget.save();

        var key = values[0];
        var original_key = row.original_values[0];

        if (original_key && original_key.key && original_key.key !== key) {
            return true;
        }

        return false;
    };

    return that;
};

/**
 * SSH key widget
 *
 * @class
 * @extends IPA.input_widget
 */
IPA.sshkey_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.key = null;
    that.originally_set = false;

    that.create = function(container) {

        that.widget_create(container);

        that.status_label = $('<span />', {
            'class': 'sshkey-status',
            text: ''
        }).appendTo(container);

        that.link = $('<a/>', {
            type: that.type,
            'class': 'sshkey-set btn btn-default',
            name: that.name,
            href: '#show-certificate',
            title: that.tooltip,
            text: text.get('@i18n:objects.sshkeystore.show_set_key'),
            click: function() {
                that.open_edit_dialog();
                return false;
            }
        }).appendTo(container);

        if (that.undo) {
            that.create_undo(container);
        }

        that.create_error_link(container);
    };

    that.update = function(value) {

        var key = value[0];

        if (!key || key === '') {
            key = {};
        }

        that.key = $.extend({}, key);

        if (that.key.key && that.key.key !== '' &&
                that.key.fingerprint && that.key.fingerprint !== '') {
            that.originally_set = true;
            that.original_key = that.key.key;
        }
        that.update_link();
        that.on_value_changed(value);
    };

    that.set_deleted = function(deleted) {
        if (deleted) {
            that.status_label.addClass('strikethrough');
        } else {
            that.status_label.removeClass('strikethrough');
        }
    };

    that.save = function() {
        return that.key;
    };

    that.update_link = function() {
        var text = that.get_status();
        that.status_label.text(text);
    };

    that.get_status = function() {

        var status = '';
        var value = that.key.key;

        if (that.original_key) {

            if (value !== that.original_key) {
                if (value === '') {
                    status = text.get('@i18n:objects.sshkeystore.status_mod_ns');
                } else {
                    status = text.get('@i18n:objects.sshkeystore.status_mod_s');
                }
            } else {
                status = that.key.fingerprint;
            }

        } else {

            if (!value || value === '') {
                status = text.get('@i18n:objects.sshkeystore.status_new_ns');
            } else {
                status = text.get('@i18n:objects.sshkeystore.status_new_s');
            }
        }

        return status;
    };

    that.set_user_value = function(value) {

        var previous = that.key.key;
        that.key.key = value;
        that.update_link();

        if (value !== previous) {
            that.value_changed.notify([], that);
            that.emit('value-change', { source: that });
        }
    };

    that.open_edit_dialog = function() {

        var dialog = that.create_edit_dialog();
        dialog.open();
    };

    that.create_edit_dialog = function() {

        var writable = that.is_writable();

        var dialog = IPA.dialog({
            name: 'sshkey-edit-dialog',
            title: '@i18n:objects.sshkeystore.set_dialog_title',
            width: 500,
            height: 380
        });

        dialog.message = text.get('@i18n:objects.sshkeystore.set_dialog_help');

        if (writable) {
            dialog.create_button({
                name: 'update',
                label: '@i18n:buttons.set',
                click: function() {
                    var value = dialog.textarea.val();
                    that.set_user_value(value);
                    dialog.close();
                }
            });
        }

        var label = '@i18n:buttons.cancel';
        if (!writable) {
            label = '@i18n:buttons.close';
        }

        dialog.create_button({
            name: 'cancel',
            label: label,
            click: function() {
                dialog.close();
            }
        });

        dialog.create_content = function() {

            dialog.container.append(dialog.message);

            dialog.textarea = $('<textarea/>', {
                'class': 'certificate',
                readonly: !writable,
                disabled: !that.enabled
            }).appendTo(dialog.container);

            var key = that.key.key || '';
            dialog.textarea.val(key);
        };

        return dialog;
    };

    return that;
};

/**
 * Action panel
 *
 * - usable in sections
 *
 * @class
 * @extends IPA.widget
 */
IPA.action_panel = function(spec) {

    spec = spec || {};
    spec.label = spec.label || '@i18n:actions.title';

    var that = IPA.widget(spec);

    that.action_names = spec.actions;
    that.actions = $.ordered_map();
    that.facet = spec.facet;
    that.initialized = false;

    that.init = function() {

        for (var i=0; i<that.action_names.length; i++) {
            var name = that.action_names[i];
            var action = that.facet.actions.get(name);

            that.add_action(action, true);

            that.actions.put(name, action);
        }

        that.initialized = true;
    };

    that.add_action = function(action, batch) {
        that.actions.put(action.name, action);
        action.enabled_changed.attach(that.action_enabled_changed);
        action.visible_changed.attach(that.action_visible_changed);

        if (!batch) {
            that.create_items();
        }
    };

    that.create = function(container) {

        if (!that.initialized) that.init();

        that.element = $('<div/>', {
            'data-name': that.name,
            'class': 'action-panel'
        });

        that.header_element = $('<h3/>', {
            'class': 'action-title'
        }).appendTo(that.element);

        that.list_element = $('<ul/>', {
            'class': 'action-panel-list'
        }).appendTo(that.element);

        that.element.appendTo(container);

        that.create_items();
    };

    that.create_item = function(action) {

        var classes, state, li, a;

        if (!action.visible) return;

        classes = ['action'];
        state = action.enabled && that.enabled ? 'enabled' : 'disabled';
        classes.push(state);

        li = $('<li/>');
        a = $('<a/>', {
            'data-name': action.name,
            href: '#',
            text: action.label,
            'class': classes.join(' '),
            click: function() {
                that.action_clicked(action);
                return false;
            }
        }).appendTo(li);
        li.appendTo(that.list_element);
    };

    that.clear_items = function() {

        that.list_element.empty();
    };

    that.create_items = function() {

        if (!that.element) return;

        that.clear_items();

        var actions = that.actions.values;

        for (var i=0; i<actions.length; i++) {
            var action = actions[i];
            that.create_item(action);
        }

        that.header_element.text(that.label);
    };

    that.action_clicked = function(action) {

        if (!that.enabled || !action.enabled || !action.visible) return;

        action.execute(that.facet);
    };

    that.action_enabled_changed = function() {

        that.create_items();
    };

    that.action_visible_changed = function() {

        that.create_items();
    };


    return that;
};

/**
 * Value map widget
 *
 * Read-only widget which shows different string based on current value.
 *
 * Basically there is a map between values(keys) and strings (displayed values).
 *
 * @class
 * @extends IPA.input_widget
 */
IPA.value_map_widget = function(spec) {

    spec = spec  || {};
    spec.read_only = true;

    var that = IPA.input_widget(spec);
    that.value_map = spec.value_map || {};
    that.default_label = text.get(spec.default_label || '');
    that.value = '';
    that.base_css_class = that.base_css_class + ' status-section form-control-static';

    that.create = function(container) {
        that.widget_create(container);

        that.display_control = $('<span/>', {
            name: that.name
        }).appendTo(container);
    };

    that.update = function(values) {

        var value, found, label;

        found = false;
        that.value = '';

        if ($.isArray(values)) {
            for (value in that.value_map) {

                if (!that.value_map.hasOwnProperty(value)) continue;

                if (values.indexOf(value) > -1) {
                    label = text.get(that.value_map[value]);
                    that.value = value;
                    found = true;
                }
            }
        }

        if (!found) {
            label = that.default_label;
        }

        that.display_control.text(label);
        that.on_value_changed(values);
    };

    that.save = function() {
        return [that.value];
    };

    that.clear = function() {
        that.display_control.text('');
    };

    return that;
};

/**
 * Helper class for rendering bootstrap alerts
 * @class widget.alert_helper
 * @alternateClassName IPA.alert_helper
 * @singleton
 */
exp.alert_helper = IPA.alert_helper = {

    /**
     * Create alert object
     * @param  {string} name
     * @param  {string|HTMLElement} text
     * @param  {string} type error|warning|success|info
     * @return {Object} alert
     */
    create_alert: function(name, text, type) {

        var alert = null;
        switch (type) {
            case 'error':
                alert = this.create_error(name, text);
                break;
            case 'warning':
                alert = this.create_warning(name, text);
                break;
            case 'success':
                alert = this.create_success(name, text);
                break;
            default:
                alert = this.create_info(name, text);
                break;
        }
        return alert;
    },

    /**
     * Create error alert
     * @param  {string} name
     * @param  {string|HTMLElement} text
     * @return {Object} alert
     */
    create_error: function(name, text) {
        return {
            name: name,
            text: text,
            cls: 'alert alert-danger',
            icon: 'fa fa-exclamation-circle',
            type: 'error'
        };
    },

    /**
     * Create warning alert
     * @param  {string} name
     * @param  {string|HTMLElement} text
     * @return {Object} alert
     */
    create_warning: function(name, text) {
        return {
            name: name,
            text: text,
            cls: 'alert alert-warning',
            icon: 'fa fa-warning',
            type: 'warning'
        };
    },

    /**
     * Create info alert
     * @param  {string} name
     * @param  {string|HTMLElement} text
     * @return {Object} alert
     */
    create_info: function(name, text) {
        return {
            name: name,
            text: text,
            cls: 'alert alert-info',
            icon: 'fa fa-info-circle',
            type: 'info'
        };
    },

    /**
     * Create success alert
     * @param  {string} name
     * @param  {string|HTMLElement} text
     * @return {Object} alert
     */
    create_success: function(name, text) {
        return {
            name: name,
            text: text,
            cls: 'alert alert-success',
            icon: 'fa fa-check-circle-o',
            type: 'success'
        };
    },

    /**
     * Render alert
     * @param  {Object} alert
     * @return {jQuery} alert as html element
     */
    render_alert: function(alert, close_icon) {

        var el = $('<div/>', {
            'data-name': alert.name,
            'class': "fade in " + alert.cls
        });
        if (close_icon) {
            el.addClass('alert-dismissable');
            el.append("<button type=\"button\" class=\"close\" \
            data-dismiss=\"alert\"><span aria-hidden=\"true\">&times;\
            </span><span class=\"sr-only\">Close</span></button>");
        }
        $('<span/>', { 'class': alert.icon }).appendTo(el);
        el.append(' ');
        el.append(alert.text);
        return el;
    }
};

exp.validation_summary_widget = IPA.validation_summary_widget = function(spec) {

    var that = IPA.widget(spec);

    /**
     * Map of items to display
     *
     * - key: source ie. widget name
     * - value: error text
     * @protected
     * @property {ordered_map}
     */
    that.items = $.ordered_map();

    that.items_node = null;

    that.create = function(container) {
        that.widget_create(container);
        that.add_class('validation-summary');

        that.items_node = $('<div/>', {}).appendTo(container);
        that.render_items();
    };

    that.render_items = function() {

        if (that.enabled) {
            that.set_visible(that.items.length > 0);
        }

        if (!that.items_node) return;

        that.items_node.empty();

        var items = that.items.values;
        for (var i=0, l=items.length; i<l; i++) {

            var alert = items[i];
            exp.alert_helper.render_alert(alert).appendTo(that.items_node);
        }
    };

    that.add = function(alert) {
        that.items.put(alert.name, alert);
        that.render_items();
    };

    that.add_error = function(name, text) {
        that.add(exp.alert_helper.create_error(name, text));
    };

    that.add_warning = function(name, text) {
        that.add(exp.alert_helper.create_warning(name, text));
    };

    that.add_info = function(name, text) {
        that.add(exp.alert_helper.create_info(name, text));
    };

    that.add_success = function(name, text) {
        that.add(exp.alert_helper.create_success(name, text));
    };

    that.remove = function(name) {
        that.items.remove(name);
        that.render_items();
    };

    that.remove_all = function(type) {

        if (!type) that.items.empty();

        for (var i=0, l=that.items.length; i<l; i++) {
            var alert = that.items.get_value_by_index(i);
            if (alert.type !== type) continue;
            that.items.remove(alert.name);
            i--;
            l--;
        }

        that.render_items();
    };

    return that;
};

/**
 * Activity widget
 *
 * Displays spinner with optional text.
 *
 * @class  IPA.activity_widget
 * @extends IPA.widget
 */
exp.activity_widget = IPA.activity_widget = function(spec) {

    var that = IPA.widget(spec);

    /**
     * Optional text to display next to spinner
     * @property {string}
     */
    that.text = spec.text || '';

    that.dots_node = null;

    that.text_node = null;

    that.row_node = null;

    that.dots = spec.dots || 0;

    that.step = spec.step || 1;

    that.max_dots = spec.max_dots || 3;

    that.timer = null;

    that.speed = spec.speed || 800;

    that.icon = spec.icon || 'fa fa-spinner fa-spin';

    that.connection_counter = 0;

    /**
     * Operation mode
     *
     * ['dots', 'icon']
     *
     * @property {string}
     */
    that.mode = spec.mode || "dots";

    that.activate_event = spec.activate_event || 'rpc-start';
    that.deactivate_event = spec.deactivate_event || 'rpc-end';
    that.set_activity_event = 'set-activity';

    that.create = function(container) {
        that.widget_create(container);
        that.add_class('global-activity-indicator slider closed');
        that.row_node = $("<div/>", { 'class': 'activity-row' }).appendTo(that.container);
        that.text_node = $("<div/>", {
            text: that.text,
            'class': 'activity-text'
        }).appendTo(that.row_node);

        if (that.mode === 'icon') {
            that.text_node.prepend(' ');
            $('<i/>', {
                'class': that.icon
            }).prependTo(that.text_node);
        }

        if (that.visible) {
            that.show();
        } else {
            that.hide();
        }
        that.set_visible(that.visible);
        topic.subscribe(that.activate_event, function() {
            ++that.connection_counter;

            if (that.connection_counter === 1) that.show();
        });
        topic.subscribe(that.deactivate_event, function() {
            --that.connection_counter;

            if (that.connection_counter === 0) that.hide();
            if (that.connection_counter < 0) that.connection_counter = 0;
        });

        topic.subscribe(that.set_activity_event, function(new_text) {
             that.text = new_text;
        });
    };

    that.toggle_timer = function(start) {

        if (that.mode === 'icon') return;

        if (start) {
            that.timer = window.setInterval( function() {
                that.make_step();
            }, that.speed);
        } else {
            if (that.timer) window.clearInterval(that.timer);
        }
    };

    that.hide = function() {
        that.toggle_class('closed', true);
        that.row_node.detach(); // to save CPU time (spinner icon)
        that.toggle_timer(false);

    };

    that.show = function() {
        that.toggle_class('closed', false);
        that.row_node.appendTo(that.container);
        that.toggle_timer(true);
    };

    that.make_step = function() {

        that.dots += that.step;
        if (that.dots > that.max_dots) that.dots = 0;
        var dot_str = string.rep('.', that.dots);
        that.text_node.text(that.text + " " + dot_str);
    };

    return that;
};

/**
 * Find and focus first focusable invalid widget
 * @member widget
 * @param {IPA.widget|facet.facet} widget Widget container
 * @return {boolean} A widget was focused
 */
exp.focus_invalid = function(widget) {

    var widgets = widget.widgets.widgets;
    var focused = false;
    for (var i=0, l=widgets.length; i<l; i++) {
        var w = widgets.values[i];
        if (w.valid === false && w.focus_input) {
            w.focus_input();
            focused = true;
        }
        else if (w.widgets) focused = exp.focus_invalid(w);
        if (focused) break;
    }
    return focused;
};

/**
 * pre_op operations for widgets
 * - sets facet and entity if present in context
 * @member widget
 */
exp.pre_op = function(spec, context) {

    if (context.facet) spec.facet = context.facet;
    if (context.parent) spec.parent = context.parent;
    if (context.entity) spec.entity = context.entity;
    return spec;
};

/**
 * Enables widget nesting
 * @member widget
 */
exp.post_op = function(obj, spec, context) {

    if (context.container) context.container.add_widget(obj);

    if (spec.widgets) {
        var nc = lang.mixin({}, context);
        nc.container = obj.widgets;
        builder.build('widget', spec.widgets, nc);
    }
    if (obj.ctor_init) obj.ctor_init();
    return obj;
};

/**
 * Widget builder
 * - instantiated in global builder registry for type: 'widget'
 * @member widget
 */
exp.builder = builder.get('widget');
exp.builder.factory = IPA.text_widget;
exp.builder.string_mode = 'property';
exp.builder.string_property = 'name';
exp.builder.pre_ops.push(exp.pre_op);
exp.builder.post_ops.push(exp.post_op);

reg.set('widget', exp.builder.registry);

/**
 * Formatter builder
 * - added as builder for 'formatter' registry
 * @member widget
 */
exp.formatter_builder = builder.get('formatter');
exp.formatter_builder.factory = IPA.formatter;
reg.set('formatter', exp.formatter_builder.registry);

/**
 * Register widgets and formatters to registries
 * @member widget
 */
exp.register = function() {
    var w = reg.widget;
    var f = reg.formatter;

    w.register('action_panel', IPA.action_panel);
    w.register('activity', IPA.activity_widget);
    w.register('attribute_table', IPA.attribute_table_widget);
    w.register('custom_checkboxes', IPA.custom_checkboxes_widget);
    w.register('button', IPA.button_widget);
    w.register('checkbox', IPA.checkbox_widget);
    w.register('checkboxes', IPA.checkboxes_widget);
    w.register('combobox', IPA.combobox_widget);
    w.register('composite_widget', IPA.composite_widget);
    w.register('datetime', IPA.datetime_widget);
    w.register('details_section', IPA.details_section);
    w.register('details_table_section', IPA.details_table_section);
    w.register('details_table_section_nc', IPA.details_section);
    w.register('multiple_choice_section', IPA.multiple_choice_section);
    w.register('enable', IPA.enable_widget);
    w.register('entity_select', IPA.entity_select_widget);
    w.register('header', IPA.header_widget);
    w.register('html', IPA.html_widget);
    w.register('link', IPA.link_widget);
    w.register('multivalued', IPA.multivalued_widget);
    w.register('non_editable_row', IPA.non_editable_row_widget);
    w.register('custom_command_multivalued',
        IPA.custom_command_multivalued_widget);
    w.register('krb_principal_multivalued',
                            IPA.krb_principal_multivalued_widget);
    w.register('krb_principal',
                            IPA.krb_principal_widget);
    w.register('password', IPA.password_widget);
    w.register('radio', IPA.radio_widget);
    w.register('select', IPA.select_widget);
    w.register('sshkeys', IPA.sshkeys_widget);
    w.register('textarea', IPA.textarea_widget);
    w.register('text', IPA.text_widget);
    w.register('validation_summary', IPA.validation_summary_widget);
    w.register('value_map', IPA.value_map_widget);

    f.register('boolean', IPA.boolean_formatter);
    f.register('boolean_status', IPA.boolean_status_formatter);
    f.register('datetime', IPA.datetime_formatter);
    f.register('dn', IPA.dn_formatter);
};

phases.on('registration', exp.register);

return exp;
});
