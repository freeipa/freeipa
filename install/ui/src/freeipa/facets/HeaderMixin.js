//
// Copyright (C) 2015  FreeIPA Contributors see COPYING for license
//

define(['dojo/_base/declare',
        'dojo/_base/lang',
        'dojo/on',
        'dojo/dom-construct',
        'dojo/dom-class',
        '../builder',
        '../facet',
        '../text',
        '../widgets/ActionDropdownWidget'
       ],
       function(declare, lang, on, construct, dom_class,
            builder, mod_facet, text, ActionDropdownWidget) {


/**
 * Header Mixin
 *
 * Extension of facet - header with title and facet groups. Requires
 * facets.ActionMixin.
 *
 * @class facets.HeaderMixin
 */
var HeaderMixin = declare([], {

    /**
     * Facet header
     * @property {facet.facet_header}
     */
    header: null,

    /**
     * Facet tabs are not displayed when set.
     * @property {boolean}
     */
    disable_facet_tabs: false,

    /**
     * Facet tabs in sidebar
     *
     * There is and effort (#4625) to move all facet tabs into sidebar but it
     * was not user tested, therefore they remain on the old place for the
     * time  being.
     *
     * This option should be changed when ^^ is removed.
     * @property {boolean}
     */
    tabs_in_sidebar: true,

    /**
     * Array of actions which are displayed in facet header
     * @property {Array.<string>}
     */
    header_actions: null,

    /**
     * Facet groups
     *
     * @property {IPA.facet_group[]}
     */
    facet_groups: null,

    /**
     * Facet group name
     * @property {string}
     */
    facet_group: null,


    /**
     * Create facet's HTML representation
     * NOTE: may be renamed to render
     */
    create: function() {

        // this create method is Facet.create extended by header/sidebar logic

        if (this.dom_node) {
            construct.empty(this.dom_node);
        } else {
            this.dom_node = construct.create('div', {
                'class': 'facet',
                name: this.name,
                'data-name': this.name
            });
        }
        if (this['class']) {
            dom_class.add(this.dom_node, this['class']);
        }
        if (this.container_node) {
            construct.place(this.dom_node, this.container_node);
        }

        var row = $('<div/>', {
            'class': 'row'
        }).appendTo(this.dom_node);
        var content_cont = row;

        this.sidebar_content_el = $('<div/>', {
            'class': mod_facet.sidebar_content_width
        }).appendTo(row);
        content_cont = $('<div/>', {
            'class': 'row'
        }).appendTo(this.sidebar_content_el);

        this.sidebar_el = $('<div/>', {
            'class': mod_facet.sidebar_class  + mod_facet.sidebar_width
        }).appendTo(row);

        this.header_container = $('<div/>', {
            'class': 'facet-header col-sm-12'
        }).appendTo(content_cont);
        this.create_header(this.header_container);

        this.content = $('<div/>', {
            'class': 'facet-content col-sm-12'
        }).appendTo(content_cont);


        this.children_node = this.content[0];
        return this.dom_node;
    },

    /**
     * Create control buttons
     *
     * @param {jQuery} container
     * @protected
     */
    create_header: function(container) {

        this.header.create(container);

        this.controls = $('<div/>', {
            'class': 'facet-controls clearfix'
        }).appendTo(container);

        this.controls_left = $('<div/>', {
            'class': 'facet-controls-left'
        }).appendTo(this.controls);

        this.controls_right = $('<div/>', {
            'class': 'facet-controls-right'
        }).appendTo(this.controls);

        this.create_controls();
    },

    /**
     * Create header controls
     *
     * - ie control buttons orActionDropDown
     */
    create_controls: function() {

        this.create_control_buttons(this.controls_left);
        this.create_action_dropdown(this.controls_left);
    },

    /**
     * Create control buttons
     *
     * @param {jQuery} container
     * @protected
     */
    create_control_buttons: function(container) {

        if (this.control_buttons) {
            this.control_buttons.create(container);
        }
    },

    /**
     * Create action dropdown widget in supplied container
     *
     * @param {jQuery} container
     * @protected
     */
    create_action_dropdown: function(container) {
        if (this.action_dropdown && this.header_actions && this.header_actions.length > 0) {
            var dropdown = this.action_dropdown.render();
            container.append(dropdown);
        }
    },

    /**
     * Display or hide facet tabs - either in sidebar or facet header
     * @param {boolean} visible
     */
    set_tabs_visible: function(visible) {

        if (this.disable_facet_tabs) return;
        if (this.tabs_in_sidebar && this.sidebar_el) {
            var a = visible ? mod_facet.sidebar_content_width : mod_facet.sidebar_content_full_width;
            var r = visible ? mod_facet.sidebar_content_full_width : mod_facet.sidebar_content_width;
            this.sidebar_content_el.removeClass(r);
            this.sidebar_content_el.addClass(a);
            this.sidebar_el.css('display', visible ? '' : 'none');
        }
        this.header.set_tabs_visible(visible);
    },

    /**
     * Overrides parent's object(usually facet.Facet) show method. To select a
     * tab.
     */
    show: function() {
        this.inherited(arguments);
        this.header.select_tab();
    },

    /** Constructor */
    constructor: function(spec) {

        this.facet_groups = builder.build('', spec.facet_groups, {}, {
            $factory: mod_facet.facet_group
        });
        this.facet_group = spec.facet_group;

        this.header = builder.build(
            '',
            spec.header || { init_group_names: true},
            {},
            {
                $pre_ops: [{ facet: this }],
                $factory: mod_facet.simple_facet_header
            }
        );
        this.header.init();
        this.header_actions = spec.header_actions || [];

        var buttons_spec = {
            $factory: mod_facet.control_buttons_widget,
            name: 'control-buttons',
            css_class: 'control-buttons',
            buttons: spec.control_buttons
        };

        this.control_buttons = builder.build(null, buttons_spec);
        this.control_buttons.init(this);

        this.action_dropdown = builder.build(null, {
            $ctor: ActionDropdownWidget,
            action_names: this.header_actions,
            name: 'facet_actions',
            'class': 'dropdown facet-actions',
            right_aligned: true,
            toggle_text: text.get('@i18n:actions.title') + ' ',
            toggle_class: 'btn btn-default',
            toggle_icon: 'fa fa-angle-down'
        });
        this.action_dropdown.init(this);
    }
});

return HeaderMixin;
});