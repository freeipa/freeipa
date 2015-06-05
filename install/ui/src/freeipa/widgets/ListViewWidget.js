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
    '../reg',
    '../text',
    '../util'
], function(declare, lang, on, Evented, Stateful, $, IPA, reg, text, util) {

var widgets = {};

/**
 * Widget for rendering a list of groups of items
 * @class
 */
widgets.ListViewWidget = declare([Stateful, Evented], {

    /**
     * List of groups
     * @type {Object[]}
     */
    groups: null,

    /**
     * Should be visible
     * @type {Boolean}
     */
    visible: true,

    /**
     * Selected item
     * @property {Object}
     */
    selected_item: null,

    // behavior
    select_on_click: true,

    /**
     * Raised when menu item is clicked
     * @event item-click
     */

    // nodes
    el: null,
    group_els: null,
    item_els: null,

    // html and styling
    css_class: '',
    group_el_type: '<div/>',
    group_class: '',
    group_label_el_type: '<div/>',
    group_label_class: 'nav-category',
    group_label_title_el_type: '<h2/>',
    group_label_title_class: '',
    item_cont_el_type: '<div/>',
    item_cont_class: '',
    item_list_el_type: '<ul/>',
    item_list_class: 'nav nav-pills nav-stacked',
    item_el_type: '<li/>',
    item_class: 't',
    item_link_class: 'item-link',
    selected_class: 'active',

    _groupsSetter: function(value) {
        this.groups = value;
        this.render_groups();
    },

    _get_group_items: function(group) {
        return group.items;
    },

    render: function() {

        this.el = $('<div/>', { 'class': this.css_class });
        this.render_groups();
        return this.el;
    },

    render_groups: function() {
        if (!this.el) return;

        this.group_els = {};
        this.item_els = {};

        this.el.empty();
        if (!this.groups) return;

        for (var i=0; i<this.groups.length; i++) {
            var group = this.groups[i];
            var items = this._get_group_items(group);
            if (items.length) {
                var group_el = this.render_group(group);
                this.el.append(group_el);
            }
        }
    },

    render_group: function(group) {

        var gr = this.group_els[group.name] = { item_els: {}};

        gr.group_el = $(this.group_el_type, {
            'class': this.group_class,
            name: group.name
        });

        gr.label_el = $(this.group_label_el_type, {
            'class': this.group_label_class
        }).appendTo(gr.group_el);

        gr.label_title_el = $(this.group_label_title_el_type, {
            'class': this.group_label_title_class,
            text: ' '
        }).appendTo(gr.label_el);


        var item_cont = $(this.item_cont_el_type, { 'class': this.item_cont_class });
        var item_list = $(this.item_list_el_type, { 'class': this.item_list_class });
        item_list.appendTo(item_cont);
        var items = this._get_group_items(group);
        for (var i=0,l=items.length; i<l; i++) {
            var item = items[i];
            var item_el = this.item_els[item.name] = this.render_item(item);
            item_list.append(item_el);
        }
        gr.group_el.append(item_cont);

        return gr.group_el;
    },

    render_item: function(item) {
        var self = this;
        var el = $(this.item_el_type, {
            name: item.name,
            'class': this.item_class,
            click: function() {
                if (item.disabled || el.hasClass('entity-facet-disabled')) {
                    return false;
                }
                self.on_click(item);
                return false;
            }
        });

        $('<a/>', {
            text: item.label || item.name || '',
            'class': 'item-link',
            href: this.create_item_link(item),
            name: item.name,
            title: item.title
        }).appendTo(el);

        return el;
    },

    create_item_link: function(item) {
        return '#';
    },

    on_click: function(item) {
        this.emit('item-click', { source: this, context: item });
        if (this.select_on_click) {
            this.select(item);
        }
    },

    update_group: function(group) {
        if (!this.group_els[group.name]) return;
        var label_el = this.group_els[group.name].label_title_el;
        label_el.text(group.label);
        if (group.title) label_el.attr('title', group.title);
    },

    update_item: function(item) {
        var item_el = this.item_els[item.name];
        var label_el = $('a', item_el);
        label_el.text(item.label);
        if (item.title) label_el.attr('title', item.title);
    },

    select: function(item) {
        if (!this.el) return;
        var cls = this.selected_class;
        var item_el = this.item_els[item.name];

        this.el.find(this.item_class).removeClass(cls);
        this.el.find(this.item_link_class).removeClass(cls);

        if (!item_el) return; // return if can't select

        item_el.addClass(cls);
        item_el.find(this.item_link_class).addClass(cls);
        this.set('selected_item', item);
        this.emit('select', { source: this, context: item });
    },

    select_first: function() {
        if (!this.el) return;
        this.el.find(this.item_link_class).removeClass(this.selected_class);
        this.el.find(this.item_class).removeClass(this.selected_class);
        var first = this.el.find(this.item_link_class + ':first');
        first.addClass(this.selected_class);
        first.parent().addClass(this.selected_class);
    },

    set_visible: function(visible) {
        this.set('visible', visible);
        this._apply_visible();
    },

    _apply_visible: function() {
        if (!this.el) return;
        this.el.css('display', this.visible ? '' : 'none');
    },

    constructor: function(spec) {
        lang.mixin(this, spec);
    }
});

    return widgets.ListViewWidget;
});