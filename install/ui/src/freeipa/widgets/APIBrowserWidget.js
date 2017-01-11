//
// Copyright (C) 2015  FreeIPA Contributors see COPYING for license
//

define([
    'dojo/_base/declare',
    'dojo/_base/lang',
    'dojo/on',
    'dojo/Evented',
    'dojo/Stateful',
    '../jquery',
    '../ipa',
    '../metadata',
    '../reg',
    '../text',
    '../util',
    './ListViewWidget',
    './browser_widgets'
], function(declare, lang, on, Evented, Stateful, $, IPA, metadata, reg, text,
    util, ListViewWidget, browser_widgets) {

var widgets = {};

/**
 * API browser widget
 *
 * Consists of two parts: command browser and details.
 *
 * Command browser consist of:
 * - filter
 * - list view with commands
 *
 * Details could be:
 * - command
 * - object
 * - param
 *
 * @class
 */
widgets.APIBrowserWidget = declare([Stateful, Evented], {

    // widgets
    filter_w: null,
    list_w: null,
    object_detail_w: null,
    command_detail_w: null,
    param_detail_w: null,
    current_details_w: null, // Current details widget, one of the three above

    // nodes
    container_node: null,
    el: null,
    default_view_el: null,
    details_view_el: null,
    current_view: null, // either default_view_el or details_view_el
    filter_el: null,
    list_el: null,
    sidebar_el: null,
    details_el: null,

    /**
     * Currently displayed item or view
     *
     * Monitor this property to reflect the change of item
     *
     * @property {Object}
     */
    current: {},


    metadata_map: {
        'object': '@mo:',
        'command': '@mc:',
        'param': '@mo-param:'
    },

    _to_list: function(objects) {
        var names = [];
        for (name in objects) {
            if (objects.hasOwnProperty(name)) {
                names.push(name);
            }
        }
        names.sort();
        var new_objects = [];
        var o;
        for (var i=0,l=names.length; i<l; i++) {
            o = objects[names[i]];
            if (!o.name) o.name = names[i];
            if (o.only_webui) continue;
            new_objects.push(o);
        }
        return new_objects;
    },

    _get_commands: function() {
        var commands = metadata.get('@m:commands');
        commands = this._to_list(commands);
        return [{
            name: "commands",
            label: "Commands",
            items: commands
        }];
    },

    _get_objects: function() {
        var objects = metadata.get('@m:objects');
        objects = this._to_list(objects);
        return [{
            name: "commands",
            label: "Objects",
            items: objects
        }];
    },

    _get_params: function(name) {
        var object = metadata.get('@mo:'+name);
        var params = object.takes_params;
        return [{
            name: object.name,
            label:object.label_singular + ' params',
            items: params
        }];
    },

    _get_list: function(type, name, filter) {

        var groups = null;
        if (type === 'object') {
            groups = this._get_objects();
        } else if (type === 'command') {
            groups = this._get_commands();
        } else if (type === 'param') {
            var parts = name.split(':');
            groups = this._get_params(parts[0]);
        }

        if (filter && groups) {
            filter = filter.toLowerCase();
            var new_groups = [];
            for (var i=0,l=groups.length; i<l; i++) {
                var filtered_list = [];
                var items = groups[i].items;
                for (var j=0,m=items.length; j<m; j++) {
                    var item = items[j];
                    if (item.name.match(filter) ||
                        (item.label && item.label.toLowerCase().match(filter))) {
                        filtered_list.push(item);
                    }
                }
                groups[i].items = filtered_list;
                if (filtered_list.length > 0) {
                    new_groups.push(groups[i]);
                }
            }
            groups = new_groups;
        }

        return groups;
    },

    /**
     * Search metadata for object of given type and name. Display it if found.
     * Display default view otherwise.
     *
     * Supported types and values:
     * - 'object', value is object name, e.g., 'user'
     * - 'command', value is command name, e.g., 'user_show'
     * - 'param', value is tuple 'object_name:param_name', e.g., 'user:cn'
     *
     * @param  {string} type Type of the object
     * @param  {string} name Object identifier
     */
    show_item: function (type, name) {
        var item;
        if (!this.metadata_map[type]) {
            IPA.notify("Invalid object type requested: "+type, 'error');
            this.show_default();
        } else {
            item = metadata.get(this.metadata_map[type] + name);
            if (!item) {
                IPA.notify("Requested "+ type +" does not exist: " + name, 'error');
                this.show_default();
                return;
            }
        }
        this._set_item(type, item, name);
    },

    /**
     * Show default view.
     *
     * For now a fallback if item is not found. Later could be extended to
     * contain help info how to use the API.
     */
    show_default: function() {
        // switch view
        if (this.current_view !== this.default_view_el) {
            this.el.empty();
            this.el.append(this.default_view_el);
            this.current_view = this.default_view_el;
        }
        this.set('current', {
            view: 'default'
        });
    },

    /**
     * Shows default command
     */
    show_default_command: function() {
        this.show_item('command', 'user_show'); // TODO: change
    },

    /**
     * Shows default object
     */
    show_default_object: function() {
        this.show_item('object', 'user'); // TODO: change
    },

    /**
     * Show item
     *
     * @param {string} type Type of item
     * @param {Object} item The item
     * @param {string} name Name of the item
     */
    _set_item: function(type, item, name) {

        // get widget
        var widget = null;
        if (type === 'object') {
            widget = this.object_detail_w;
        } else if (type === 'command') {
            widget = this.command_detail_w;
        } else if (type === 'param') {
            widget = this.param_detail_w;
        } else {
            IPA.notify("Invalid type", 'error');
            this.show_default();
        }

        // switch view
        if (!this.details_view_el) {
            this._render_details_view();
        }
        if (this.current_view !== this.details_view_el) {
            this.el.empty();
            this.el.append(this.details_view_el);
            this.current_view = this.details_view_el;
        }

        // switch widget
        if (widget && !widget.el) widget.render();
        if (widget && this.current_details_w !== widget) {
            this.details_el.empty();
            this.details_el.append(widget.el);
        }

        // set list
        var list = this._get_list(type, name, this.current.filter);
        this.list_w.set('groups', list);
        this.list_w.select(item);

        // set item
        if (widget) widget.set('item', item);
        this.set('current', {
            item: item,
            type: type,
            name: name,
            filter: this.current.filter,
            view: 'details'
        });

        // update sidebar
        $(window).trigger('resize');

        $('html, body').animate({
            scrollTop: 0
        }, 500);
    },

    render: function() {
        this.el = $('<div/>', { 'class': this.css_class });
        this._render_default_view().appendTo(this.el);
        if (this.container_node) {
            this.el.appendTo(this.container_node);
        }
        return this.el;
    },

    _render_details_view: function() {
        this.details_view_el = $('<div/>', { 'class': 'details-view' });
        var row = $('<div/>', { 'class': 'row' });
        this.sidebar_el = $('<div/>', { 'class': 'sidebar-pf sidebar-pf-left col-sm-4 col-md-3 col-sm-pull-8 col-md-pull-9' });
        this.details_el = $('<div/>', { 'class': 'col-sm-8 col-md-9 col-sm-push-4 col-md-push-3' });
        this.details_el.appendTo(row);
        this.sidebar_el.appendTo(row);
        row.appendTo(this.details_view_el);
        this._render_select().appendTo(this.sidebar_el);
        return this.details_view_el;
    },

    _render_select: function() {
        var el  = $('<div/>', { 'class': 'item-select' });

        $('<div/>', { 'class': 'nav-category' }).
        append($('<h2/>', {
            'class': 'item-select',
            text: 'Browse'
        })).
        appendTo(el);

        this.filter_el = this.filter_w.render();
        this.list_el = this.list_w.render();
        this.filter_el.appendTo(el);
        this.list_el.appendTo(el);
        return el;
    },

    _render_default_view: function() {
        this.default_view_el = $('<div/>', { 'class': 'default-view' });
        $('<h1/>', { text: "API Browser" }).appendTo(this.default_view_el);
        var commands = $('<div/>').appendTo(this.default_view_el);
        $('<p/>').append($('<a/>', {
            href: "#/p/apibrowser/type=command",
            text: "Browse Commands"
        })).appendTo(commands);
        var objects = $('<div/>').appendTo(this.default_view_el);
        $('<p/>').append($('<a/>', {
            href: "#/p/apibrowser/type=object",
            text: "Browse Objects"
        })).appendTo(commands);
        return this.default_view_el;
    },

    _apply_filter: function(filter) {
        var current = this.current;
        current.filter = filter;
        var list = this._get_list(current.type, current.name, current.filter);
        this.list_w.set('groups', list);
        this.list_w.select(current.item);
        // reset min height so that PatternFly can set proper min height
        this.sidebar_el.css({'min-height': 0});
        this.details_el.css({'min-height': 0});
        $(window).trigger('resize');
    },

    _item_selected: function(item) {
        var t = this.current.type;
        var n = item.name;
        if (t == 'param') {
            var obj = this.current.name.split(':')[0];
            n = [obj, n].join(':');
        }
        this.show_item(t, n);
    },

    _init_widgets: function() {
        this.filter_w = new browser_widgets.FilterWidget();
        this.filter_w.watch('filter', function(name, old, value) {
            this._apply_filter(value);
        }.bind(this));

        this.list_w = new ListViewWidget();
        this.object_detail_w = new browser_widgets.ObjectDetailWidget();
        this.command_detail_w = new browser_widgets.CommandDetailWidget();
        this.param_detail_w = new browser_widgets.ParamDetailWidget();

        on(this.list_w, 'item-click', function(args) {
            this._item_selected(args.context);
        }.bind(this));
    },

    constructor: function(spec) {
        lang.mixin(this, spec);
        this._init_widgets();
    }
});

    return widgets.APIBrowserWidget;
});
