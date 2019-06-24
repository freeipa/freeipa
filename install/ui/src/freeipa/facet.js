/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Endi Sukma Dewata <edewata@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2010-2011 Red Hat
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

define([
        'dojo/_base/declare',
        'dojo/_base/lang',
        'dojo/dom-construct',
        'dojo/topic',
        'dojo/on',
        'dojo/Stateful',
        'dojo/Evented',
        './_base/Singleton_registry',
        './_base/construct',
        './builder',
        './config',
        './ipa',
        './jquery',
        './navigation',
        './phases',
        './reg',
        './rpc',
        './spec_util',
        './text',
        './widgets/ActionDropdownWidget',
        './dialog',
        './field',
        './widget'
    ], function(declare, lang, construct, topic, on, Stateful, Evented,
                   Singleton_registry, construct_utils, builder, config, IPA, $,
                   navigation, phases, reg, rpc, su, text, ActionDropdownWidget) {

/**
 * Facet module
 *
 * @class facet
 * @singleton
 */
var exp = {
    sidebar_class: 'sidebar-pf sidebar-pf-left',
    sidebar_width: ' col-sm-3 col-md-2 col-sm-pull-9 col-md-pull-10',
    sidebar_content_width: ' col-sm-9 col-md-10 col-sm-push-3 col-md-push-2',
    sidebar_content_full_width: 'col-md-12'
};
exp.facet_spec = {};

/**
 * Facet represents the content of currently displayed page.
 *
 * ## Show, Clear, Refresh mechanism
 *
 * Use cases:
 *
 * - Display facet with defined arguments.
 * - Switch to facet
 * - Update facet state
 *
 * ## Display facet by route
 *
 * 1. somebody sets route
 * 2. Route is evaluated, arguments extracted.
 * 3. Facet state is updated `set_state(args, pkeys)`.(saves previous state)
 * 4. Facet show() is called
 *
 * ## Display facet with defined arguments
 *
 * 1. Somebody calls navigation.show(xxx);
 * 2. Facet state is updated `set_state(args, pkeys)`.(saves previous state)
 * 3. Route is updated, but the hash change is ignored
 * 4. Facet show() is called.
 *      - First time show
 *          a. creates DOM
 *          b. display DOM
 *          c. refresh();
 *      - Next time
 *          a. display DOM
 *          b. `needs_update()` (compares previous state with current)
 *              - true:
 *                1. clear() - each facet can override to supress clear or
 *                           control the behaviour
 *                2. refresh()
 *
 * ## Swith to facet
 *
 * Same as display facet but only without arguments. Arguments are extracted at
 * step 2.
 *
 * ## Update facet state
 *
 * 1. set_state(args, pkeys?)
 * 2. needs_update()?
 *    - true:
 *       1. clear()
 *       2. refresh()
 * 3. Update route, ignore hash change event
 *
 * ## Updating hash
 * Hash updates are responsibility of navigation component and application
 * controller. Application controller should listen to facet's `state_change`
 * event. And call something like navigation.update_hash(facet).
 *
 * navigation.update_hash should find all the necessary state properties (args,
 * pkeys).
 *
 * ## needs_update method
 * todo
 *
 * @class facet.facet
 * @alternateClassName IPA.facet
 */
exp.facet = IPA.facet = function(spec, no_init) {

    spec = spec || {};

    var that = IPA.object();

    /**
     * Name of preferred facet container
     *
     * Leave unset to use default container.
     * @property {string}
     */
    that.preferred_container = spec.preferred_container;

    /**
     * Entity this facet belongs to
     * @property {entity.entity}
     */
    that.entity = IPA.get_entity(spec.entity);

    /**
     * Facet name
     * @property {string}
     */
    that.name = spec.name;

    /**
     * Facet label
     * @property {string}
     */
    that.label = text.get(spec.label);

    /**
     * Facet title
     * @property {string}
     */
    that.title = text.get(spec.title || that.label);

    /**
     * Facet tab label
     * @property {string}
     */
    that.tab_label = text.get(spec.tab_label || that.label);

    /**
     * Facet element's CSS class
     * @property {string}
     */
    that.display_class = spec.display_class;

    /**
     * Flag. Marks the facet as read-only - doesn't support modify&update
     * operation.
     * @property {boolean}
     */
    that.no_update = spec.no_update;

    /**
     * Breadcrumb navigation is not displayed when set.
     * @property {boolean}
     */
    that.disable_breadcrumb = spec.disable_breadcrumb;

    /**
     * Facet tabs are not displayed when set.
     * @property {boolean}
     */
    that.disable_facet_tabs = spec.disable_facet_tabs;

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
    that.tabs_in_sidebar = spec.tabs_in_sidebar !== undefined ?
        spec.tabs_in_sidebar : false;

    /**
     * State object for actions
     * @property {facet.state}
     */
    that.action_state = builder.build('', spec.state || {}, {}, { $factory: exp.state });

    /**
     * Collection of facet actions
     * @property {facet.action_holder}
     */
    that.actions = builder.build('', { actions: spec.actions }, {}, { $factory: exp.action_holder } );

    /**
     * Array of actions which are displayed in facet header
     * @property {Array.<string>}
     */
    that.header_actions = spec.header_actions || [];

    /**
     * Policies
     * @property {IPA.facet_policies}
     */
    that.policies = IPA.facet_policies({
        container: that,
        policies: spec.policies
    });

    /**
     * Facet header
     * @property {facet.facet_header}
     */
    that.header = builder.build('',  spec.header || {}, {},
        { $pre_ops: [{ facet: that }], $factory: IPA.facet_header });

    /**
     * Hard override for `needs_update()` logic. When set, `needs_update`
     * should always return this value.
     * @property {boolean}
     */
    that._needs_update = spec.needs_update;


    /**
     * Facet is shown
     * @property {Boolean}
     */
    that.is_shown = false;

    /**
     * Marks facet as expired - needs update
     *
     * Difference between `_needs_update` is that `expired_flag` should be
     * cleared after update.
     *
     * @property {boolean}
     */
    that.expired_flag = true;

    /**
     * Last time when facet was updated.
     * @property {Date}
     */
    that.last_updated = null;

    /**
     * Timeout[s] from `last_modified` after which facet should be expired
     * @property {number} expire_timeout=600
     */
    that.expire_timeout = spec.expire_timeout || 600; //[seconds]

    /**
     * Raised when facet gets updated
     * @event
     */
    that.on_update = IPA.observer();

    /**
     * Raised after `load()`
     * @event
     */
    that.post_load = IPA.observer();

    /**
     * Dialogs
     * @property {ordered_map}
     */
    that.dialogs = $.ordered_map();

    /**
     * dom_node of container
     * Suppose to contain dom_node of this and other facets.
     * @property {jQuery}
     */
    that.container_node = spec.container_node;

    /**
     * dom_node which contains all content of a facet.
     * Should contain error content and content. When error is moved to
     * standalone facet it will replace functionality of content.
     * @property {jQuery}
     */
    that.dom_node = null;

    /**
     * Facet groups
     *
     * Entity facet groups are used if not defined
     *
     * @property {IPA.facet_group[]}
     */
    that.facet_groups = builder.build('', spec.facet_groups, {}, {
        $factory: IPA.facet_group
    });

    /**
     * Facet group name
     * @property {string}
     */
    that.facet_group = spec.facet_group;

    /**
     * Redirection target information.
     *
     * Can be facet and/or entity name.
     * @property {Object}
     * @param {string} entity entity name
     * @param {string} facet facet name
     */
    that.redirect_info = spec.redirect_info;

    /**
     * Name of containing facet of containing entity
     *
     * A guide for breadcrumb navigation
     *
     * @property {string}
     */
    that.containing_facet = spec.containing_facet;


    /**
     * Facet requires authenticated user
     * @type {Boolean}
     */
    that.requires_auth = spec.requires_auth !== undefined ? spec.requires_auth : true;

    /**
     * Public state
     * @property {facet.FacetState}
     */
    that.state = new FacetState();


    /**
     * Sets the name of attribute which will be used as primary key in case
     * that primary key is missing in metadata.
     * @type {String}
     */
    that.primary_key_name = spec.primary_key_name;

    that.get_full_name = function() {
        if (that.entity) {
            return that.entity.create_facet_type(that.name);
        }
        return that.name;
    };

    /**
     * Set and normalize pkeys. Merges with existing if present. If keys length
     * differs, the alignment is from the last one to the first one.
     */
    that.set_pkeys = function(pkeys) {

        pkeys = that.get_pkeys(pkeys);
        that.state.set('pkeys', pkeys);
    };

    /**
     * Return THE pkey of this facet. Basically the last one of pkeys list.
     *
     * @return {string} pkey
     */
    that.get_pkey = function() {
        var pkeys = that.get_pkeys();
        if (pkeys.length) {
            return pkeys[pkeys.length-1];
        }
        return '';
    };

    /**
     * Gets copy of pkeys list.
     * It automatically adds empty pkeys ('') for each containing entity if not
     * specified.
     *
     * One can get merge current pkeys with supplied if `pkeys` param is
     * specified.
     *
     * @param {string[]} pkeys new pkeys to merge
     * @return {string[]} pkeys
     */
    that.get_pkeys = function(pkeys) {
        var new_keys = [];
        var cur_keys = that.state.get('pkeys') || [];
        var current_entity = that.entity;
        pkeys = pkeys || [];
        var arg_l = pkeys.length;
        var cur_l = cur_keys.length;
        var tot_c = 0;
        while (current_entity) {
            if (current_entity.defines_key) tot_c++;
            current_entity = current_entity.get_containing_entity();
        }

        if (tot_c < arg_l || tot_c < cur_l) throw {
            error: 'Invalid pkeys count. Supplied more than expected.'
        };

        var arg_off = tot_c - arg_l;
        var cur_off = cur_l - tot_c;

        for (var i=0; i<tot_c; i++) {
            // first try to use supplied
            if (tot_c - arg_l - i <= 0) new_keys[i] = pkeys[i-arg_off];
            // then current
            else if (tot_c - cur_l - i <= 0) new_keys[i] = cur_keys[i-cur_off];
            // then empty
            else new_keys[i] = '';
        }

        return new_keys;
    };

    /**
     * Get pkey prefix.
     *
     * Opposite method to `get_pkey` - get's all pkeys except the last one.
     * @return {Array.<string>}
     */
    that.get_pkey_prefix = function() {
        var pkeys = that.get_pkeys();
        if (pkeys.length > 0) pkeys.pop();

        return pkeys;
    };

    /**
     * Checks if two objects has the same properties with equal values.
     *
     * @param {Object} a
     * @param {Object} b
     * @return {boolean} `a` and `b` are value-equal
     * @protected
     */
    that.state_diff = function(a, b) {
        var diff = false;
        var checked = {};

        var check_diff = function(a, b, skip) {

            var same = true;
            skip = skip || {};

            for (var key in a) {
                if (a.hasOwnProperty(key) && !(key in skip)) {
                    var va = a[key];
                    var vb = b[key];
                    if (lang.isArray(va)) {
                        if (IPA.array_diff(va,vb)) {
                            same = false;
                            skip[a] = true;
                            break;
                        }
                    } else {
                        if (va != vb) {
                            same = false;
                            skip[a] = true;
                            break;
                        }
                    }
                }
            }
            return !same;
        };

        diff = check_diff(a,b, checked);
        diff = diff || check_diff(b,a, checked);
        return diff;
    };

    /**
     * Reset facet state to supplied
     *
     * @param {Object} state state to set
     */
    that.reset_state = function(state) {

        if (state.pkeys) {
            state.pkeys = that.get_pkeys(state.pkeys);
        }
        that.state.reset(state);
    };

    /**
     * Get copy of current state
     *
     * @return {Object} state
     */
    that.get_state = function() {
        return that.state.clone();
    };

    /**
     * Merges state into current and notifies it.
     *
     * @param {Object} state object to merge into current state
     */
    that.set_state = function(state) {

        if (state.pkeys) {
            state.pkeys = that.get_pkeys(state.pkeys);
        }
        that.state.set(state);
    };

    /**
     * Handle state set
     * @param {Object} old_state
     * @param {Object} state
     */
    that.on_state_set = function(old_state, state) {
        that._on_state_change(state);
    };


    /**
     * Handle state change
     * @protected
     */
    that._on_state_change = function(state) {

        // basically a show method without displaying the facet
        // TODO: change to something fine grained

        that._notify_state_change(state);

        var needs_update = that.needs_update(state);
        that.old_state = state;

        // we don't have to reflect any changes if facet dom is not yet created
        if (!that.dom_node || !that.is_shown) {
            if (needs_update) that.set_expired_flag();
            return;
        }

        if (needs_update) {
            that.clear();
        }

        that.show_content();
        that.header.select_tab();

        if (needs_update) {
            that.refresh();
        }
    };

    /**
     * Fires `facet-state-change` event with given state as event parameter.
     *
     * @fires facet-state-change
     * @protected
     * @param {Object} state
     */
    that._notify_state_change =  function(state) {
        that.emit('facet-state-change', {
            facet: that,
            state: state
        });
    };

    /**
     * Get dialog with given name from facet dialog collection
     *
     * @param {string} name
     * @return {IPA.dialog} dialog
     */
    that.get_dialog = function(name) {
        return that.dialogs.get(name);
    };

    /**
     * Add dialog to facet dialog collection
     *
     * @param {IPA.dialog} dialog
     */
    that.dialog = function(dialog) {
        that.dialogs.put(dialog.name, dialog);
        return that;
    };

    /**
     * Create facet's HTML representation
     */
    that.create = function() {

        var entity_name = !!that.entity ? that.entity.name : '';

        if (that.dom_node) {
            that.dom_node.empty();
            that.dom_node.detach();
        } else {
            that.dom_node = $('<div/>', {
                'class': 'facet active-facet container-fluid',
                name: that.name,
                'data-name': that.name,
                'data-entity': entity_name
            });
        }

        var dom_node = that.dom_node;
        that.container = dom_node;

        if (!that.container_node) throw {
            error: 'Can\'t create facet. No container node defined.'
        };
        var node = dom_node[0];
        construct.place(node,that.container_node);

        var row = $('<div/>', {
            'class': 'row'
        }).appendTo(dom_node);
        var content_cont = row;


        // header
        if (that.disable_facet_tabs) {
            dom_node.addClass('no-facet-tabs');
        } else if (that.tabs_in_sidebar) {
            that.sidebar_content_el = $('<div/>', {
                'class': exp.sidebar_content_width
            }).appendTo(row);
            content_cont = $('<div/>', {
                'class': 'row'
            }).appendTo(that.sidebar_content_el);

            that.sidebar_el = $('<div/>', {
                'class': exp.sidebar_class  + exp.sidebar_width
            }).appendTo(row);
        }
        dom_node.addClass(that.display_class);

        that.header_container = $('<div/>', {
            'class': 'facet-header col-sm-12'
        }).appendTo(content_cont);
        that.create_header(that.header_container);

        that.content = $('<div/>', {
            'class': 'facet-content col-sm-12'
        }).appendTo(content_cont);

        that.error_container = $('<div/>', {
            'class': 'facet-content facet-error col-sm-12'
        }).appendTo(content_cont);

        that.create_content(that.content);
        dom_node.removeClass('active-facet');
        that.policies.post_create();
    };

    /**
     * Create facet header
     *
     * @param {jQuery} container
     * @protected
     */
    that.create_header = function(container) {

        that.header.create(container);

        that.controls = $('<div/>', {
            'class': 'facet-controls clearfix'
        }).appendTo(container);

        that.controls_left = $('<div/>', {
            'class': 'facet-controls-left'
        }).appendTo(that.controls);

        that.controls_right = $('<div/>', {
            'class': 'facet-controls-right'
        }).appendTo(that.controls);
    };

    /**
     * Create content
     *
     * @param {jQuery} container
     * @protected
     * @abstract
     */
    that.create_content = function(container) {
    };

    /**
     * Create control buttons
     *
     * @param {jQuery} container
     * @protected
     */
    that.create_control_buttons = function(container) {

        if (that.control_buttons) {
            that.control_buttons.create(container);
        }
    };

    that.create_action_dropdown = function(container) {
        if (that.action_dropdown && that.header_actions && that.header_actions.length > 0) {
            var dropdown = that.action_dropdown.render();
            container.append(dropdown);
        }
    };

    /**
     * Display or hide facet tabs - either in sidebar or facet header
     * @param {boolean} visible
     */
    that.set_tabs_visible = function(visible) {

        if (that.disable_facet_tabs) return;
        if (that.tabs_in_sidebar && that.sidebar_el) {
            var a = visible ? exp.sidebar_content_width : exp.sidebar_content_full_width;
            var r = visible ? exp.sidebar_content_full_width : exp.sidebar_content_width;
            that.sidebar_content_el.removeClass(r);
            that.sidebar_content_el.addClass(a);
            that.sidebar_el.css('display', visible ? '' : 'none');
        }
        that.header.set_tabs_visible(visible);
    };

    /**
     * Update h1 element in title container
     *
     * @deprecated Please update title in facet header or it's widget instead.
     */
    that.set_title = function(container, title) {
        var element = $('h1', that.title_container);
        element.html(title);
    };

    /**
     * Show facet
     *
     * - clear & refresh if needs update
     * - mark itself as active facet
     */
    that.show = function() {

        if (that.is_shown) return;
        that.is_shown = true;

        that.entity.facet = that; // FIXME: remove

        if (!that.dom_node) {
            that.create();
        } else if (!that.dom_node.parentElement) {
            construct.place(that.dom_node[0], that.container_node);
        }

        var state = that.state.clone();
        var needs_update = that.needs_update(state);
        that.old_state = state;

        if (needs_update) {
            that.clear();
        }

        that.dom_node.addClass('active-facet');
        that.show_content();
        that.header.select_tab();

        if (needs_update) {
            that.refresh();
        }
    };

    /**
     * Show content container and hide error container.
     *
     * Opposite to `show_error`.
     * @protected
     */
    that.show_content = function() {
        that.content.css('display', 'block');
        that.error_container.css('display', 'none');
    };

    /**
     * Show error container and hide content container.
     *
     * Opposite to `show_content`
     * @protected
     */
    that.show_error = function() {
        that.content.css('display', 'none');
        that.error_container.css('display', 'block');
    };

    /**
     * Check if error is displayed (instead of content)
     *
     * @return {boolean} error visible
     */
    that.error_displayed = function() {
        return that.error_container &&
                    that.error_container.css('display') === 'block';
    };

    /**
     * Un-mark itself as active facet
     */
    that.hide = function() {
        that.is_shown = false;
        if (that.dom_node[0].parentElement) {
            that.container_node.removeChild(that.dom_node[0]);
        }
        that.dom_node.removeClass('active-facet');
    };

    /**
     * Update widget content with supplied data
     * @param {Object} data
     */
    that.load = function(data) {
        that.data = data;
        that.header.load(data);
    };

    /**
     * Start refresh
     *
     * - get up-to-date data
     * - load the data
     * @abstract
     */
    that.refresh = function() {
    };

    /**
     * Clear all widgets
     * @abstract
     */
    that.clear = function() {
    };

    /**
     * Check if facet needs update
     *
     * That means if:
     *
     * - new state (`state` or supplied state) is different that old_state
     *   (`old_state`)
     * - facet is expired
     *   - `expired_flag` is set or
     *   - expire_timeout takes effect
     * - error is displayed
     *
     *
     * @param {Object} [new_state] supplied state
     * @return {boolean} needs update
     */
    that.needs_update = function(new_state) {

        if (that._needs_update !== undefined) return that._needs_update;

        new_state = new_state || that.state.clone();
        var needs_update = false;

        if (that.expire_timeout && that.expire_timeout > 0) {

            if (!that.last_updated) {
                needs_update = true;
            } else {
                var now = Date.now();
                needs_update = (now - that.last_updated) > that.expire_timeout * 1000;
            }
        }

        needs_update = needs_update || that.expired_flag;
        needs_update = needs_update || that.error_displayed();

        needs_update = needs_update || that.state_diff(that.old_state || {}, new_state);

        return needs_update;
    };

    /**
     * Sets expire flag
     */
    that.set_expired_flag = function() {
        that.expired_flag = true;
    };

    /**
     * Clears `expired_flag` and resets `last_updated`
     */
    that.clear_expired_flag = function() {
        that.expired_flag = false;
        that.last_updated = Date.now();
    };

    /**
     * Check whether the facet is dirty
     *
     * Dirty can mean that value of displayed object was modified but the change
     * was not reflected to data source
     *
     * @returns {boolean}
     */
    that.is_dirty = function() {
        return false;
    };

    /**
     * Whether we can switch to different facet.
     * @returns {boolean}
     */
    that.can_leave = function() {
        return !that.is_dirty();
    };

    /**
     * Get dialog displaying a message explaining why we can't switch facet.
     * User can supply callback which is called when a leave is permitted.
     *
     * TODO: rename to get_leave_dialog
     *
     * @param {Function} permit_callback
     */
    that.show_leave_dialog = function(permit_callback) {

        var dialog = IPA.dirty_dialog({
            facet: that
        });

        dialog.callback = permit_callback;

        return dialog;
    };

    /**
     * Display error page instead of facet content
     *
     * Use this call when unrecoverable error occurs.
     *
     * @param {Object} error_thrown - error to be displayed
     * @param {string} error_thrown.name
     * @param {string} error_thrown.message
     */
    that.report_error = function(error_thrown) {

        var add_option = function(ul, text, handler) {

            var li = $('<li/>').appendTo(ul);
            $('<a />', {
                href: '#',
                text: text,
                click: function() {
                    handler();
                    return false;
                }
            }).appendTo(li);
        };

        var title = text.get('@i18n:error_report.title');
        title = title.replace('${error}', error_thrown.name);

        that.error_container.empty();
        that.error_container.append($('<h1/>', { text: title }));

        var details = $('<div/>', {
            'class': 'error-details'
        }).appendTo(that.error_container);
        details.append($('<p/>', { text: error_thrown.message }));

        $('<div/>', {
            text: text.get('@i18n:error_report.options')
        }).appendTo(that.error_container);

        var options_list = $('<ul/>').appendTo(that.error_container);

        add_option(
            options_list,
            text.get('@i18n:error_report.refresh'),
            function() {
                that.refresh();
            }
        );

        add_option(
            options_list,
            text.get('@i18n:error_report.main_page'),
            function() {
                navigation.show_default();
            }
        );

        add_option(
            options_list,
            text.get('@i18n:error_report.reload'),
            function() {
                window.location.reload(false);
            }
        );

        that.error_container.append($('<p/>', {
            text: text.get('@i18n:error_report.problem_persists')
        }));

        that.show_error();
    };

    /**
     * Get facet based on `redirect_info` and {@link
     * entity.entity.redirect_facet}
     * @return {facet.facet} facet to be redirected to
     */
    that.get_redirect_facet = function() {

        var entity = that.entity;
        while (entity.containing_entity) {
            entity = entity.get_containing_entity();
        }
        var facet_name = that.entity.redirect_facet;
        var entity_name = entity.name;
        var facet;

        if (that.redirect_info) {
            entity_name = that.redirect_info.entity || entity_name;
            facet_name = that.redirect_info.facet || facet_name;
        }

        if (!facet) {
            entity = IPA.get_entity(entity_name);
            facet = entity.get_facet(facet_name);
        }

        return facet;
    };

    /**
     * Redirect to redirection target
     */
    that.redirect = function() {

        var facet = that.get_redirect_facet();
        if (!facet) return;
        navigation.show(facet);
    };

    var redirect_error_codes = [4001];

    /**
     * Redirect if error thrown is
     * @protected
     */
    that.redirect_error = function(error_thrown) {

        /*If the error is in talking to the server, don't attempt to redirect,
          as there is nothing any other facet can do either. */
        for (var i=0; i<redirect_error_codes.length; i++) {
            if (error_thrown.code === redirect_error_codes[i]) {
                that.redirect();
                return;
            }
        }
    };

    /**
     * Initialize facet
     * @protected
     */
    that.init_facet = function() {

        that.action_state.init(that);
        that.actions.init(that);
        that.header.init();
        on(that.state, 'set', that.on_state_set);

        var buttons_spec = {
            $factory: IPA.control_buttons_widget,
            name: 'control-buttons',
            css_class: 'control-buttons',
            buttons: spec.control_buttons
        };

        that.control_buttons = IPA.build(buttons_spec);
        that.control_buttons.init(that);

        that.action_dropdown = IPA.build({
            $ctor: ActionDropdownWidget,
            action_names: that.header_actions,
            name: 'facet_actions',
            'class': 'dropdown facet-actions',
            right_aligned: true,
            toggle_text: text.get('@i18n:actions.title') + ' ',
            toggle_class: 'btn btn-default',
            toggle_icon: 'fa fa-angle-down'
        });
        that.action_dropdown.init(that);

    };

    if (!no_init) that.init_facet();

    // methods that should be invoked by subclasses
    that.facet_create = that.create;
    that.facet_create_header = that.create_header;
    that.facet_create_content = that.create_content;
    that.facet_needs_update = that.needs_update;
    that.facet_show = that.show;
    that.facet_hide = that.hide;
    that.facet_load = that.load;

    return that;
};

/**
 * Facet header which is intended to be used in non-entity facets
 *
 * Widget-like object which purpose is to render facet's header.
 *
 * By default, facet header consists of:
 *
 * - breadcrumb navigation
 * - title
 * - action list
 * - facet tabs
 *
 * @class facet.simple_facet_header
 */
exp.simple_facet_header = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    that.init_group_names = spec.init_group_names != undefined ?
        spec.init_group_names : false;

    /**
     * Facet this header belongs to
     * @property {facet.facet}
     */
    that.facet = spec.facet;

    /**
     * Facet title widget
     * @property {facet.facet_title} title_widget
     */

    /**
     * Initialize facet header
     * @protected
     */
    that.init = function() {

        if (that.facet.header_actions) {

            var widget_builder = IPA.widget_builder({
                widget_options: {
                    entity: that.facet.entity,
                    facet: that.facet
                }
            });
        }

        that.facet.action_state.changed.attach(that.update_summary);

        that.title_widget = IPA.facet_title();

        if (!that.facet.tabs_in_sidebar) {
            that.tabs_widget = new exp.FacetGroupsWidget({
                facet: this.facet,
                init_group_names: that.init_group_names
            });
        } else {
            that.tabs_widget = new exp.FacetGroupsWidget({
                facet: this.facet,
                init_group_names: that.init_group_names,
                css_class: '',
                group_el_type: '<div/>',
                group_class: '',
                group_label_el_type: '<div/>',
                group_label_class: 'nav-category',
                group_label_title_el_type: '<h2/>',
                group_label_title_class: '',
                tab_cont_el_type: '<div/>',
                tab_cont_class: '',
                tab_list_el_type: '<ul/>',
                tab_list_class: 'nav nav-pills nav-stacked',
                tab_el_type: '<li/>',
                tab_class: 't',
                selected_class: 'active'
            });
        }
    };

    /**
     * Display or hide facet tabs
     * @param {boolean} visible
     */
    that.set_tabs_visible = function(visible) {
        if (!this.tabs_widget) return;
        this.tabs_widget.set_visible(visible);
    };

    /**
     * Select tab with the same name as related facet or default
     */
    that.select_tab = function() {
        if (that.facet.disable_facet_tabs) return;
        var facet_name = that.facet.name;
        if (!facet_name || facet_name === 'default') {
            that.tabs_widget.select_first();
        } else {
            that.tabs_widget.select(that.facet.get_full_name());
        }
    };

    /**
     * Set new pkey in title and breadcrumb navigation
     *
     * Limits the pkey if it's too long.
     *
     * @param {string} value pkey
     */
    that.set_pkey = function(value) {

        if (!value) return;

        var pkey_max = that.get_max_pkey_length();
        var limited_value = IPA.limit_text(value, pkey_max);

        that.update_breadcrumb(limited_value);

        var title_info = {
            text: that.facet.label,
            pkey: limited_value,
            pkey_title: value
        };
        that.title_widget.update(title_info);
    };

    that.update_breadcrumb = function(pkey) {
        // doesn't support breadcrumb
        return;
    };


    that.create_facet_groups = function(container) {
        var facet_groups = that.get_facet_groups();
        this.tabs_widget.groups = facet_groups;
        var tabs = this.tabs_widget.render();
        container.append(tabs);
    };

    /**
     * Get facet groups for current facet.
     *
     * @return {Array} Array of facet groups
     */
    that.get_facet_groups = function() {
        if (that.facet.facet_groups) {
            return that.facet.facet_groups;
        }
        return [];
    };

    /**
     * Create header's HTML
     * @param {jQuery} container
     */
    that.create = function(container) {

        that.container = container;

        if (!that.facet.disable_breadcrumb) {
            that.breadcrumb = $('<ol/>', {
                'class': 'breadcrumb'
            }).appendTo(container);
            that.update_breadcrumb('');
        }

        that.title_widget.create(container);
        that.title_widget.update({ text: that.facet.label });

        if (!that.facet.disable_facet_tabs) {

            var tab_cont = container;
            if (that.facet.tabs_in_sidebar) {
                tab_cont = that.facet.sidebar_el;
            }
            that.create_facet_groups(tab_cont);
            $(window).trigger('resize');
        }
    };

    /**
     * Reflect facet's action state summary into title widget class and icon
     * title.
     */
    that.update_summary = function() {
        var summary = that.facet.action_state.summary();

        if (summary.state.length > 0) {
            var css_class = summary.state.join(' ');
            that.title_widget.set_class(css_class);
            that.title_widget.set_icon_title(summary.description);
        }
    };

    /**
     * Compute maximum pkey length to be displayed in header
     * @return {number} length
     */
    that.get_max_pkey_length = function() {

        var label_w, max_pkey_w, max_pkey_l, al, al_w, icon_w, char_w, container_w;

        container_w = that.container.width();
        icon_w = that.title_widget.icon.width();
        label_w = that.title_widget.title.width();
        char_w = label_w / that.title_widget.title.text().length;
        max_pkey_w = container_w - icon_w - label_w;
        max_pkey_w -= 10; //some space correction to be safe
        max_pkey_l = Math.ceil(max_pkey_w / char_w);

        return max_pkey_l;
    };

    /**
     * Clear displayed information
     */
    that.clear = function() {
    };

    that.facet_header_set_pkey = that.set_pkey;

    return that;
};

/**
 * Facet header
 *
 * Widget-like object which purpose is to render facet's header.
 *
 * By default, facet header consists of:
 *
 * - breadcrumb navigation
 * - title
 * - action list
 * - facet tabs
 *
 * @class facet.facet_header
 * @alternateClassName IPA.facet_header
 */
exp.facet_header = IPA.facet_header = function(spec) {

    spec = spec || {};

    var that = exp.simple_facet_header(spec);

    that.update_breadcrumb = function(pkey) {

        if (!that.breadcrumb) return;

        if (pkey === undefined) {
            pkey = that.facet.get_pkey();
            var pkey_max = that.get_max_pkey_length();
            pkey = IPA.limit_text(pkey, pkey_max);
        }

        var items = [];
        var item, i, l, keys, target_facet, target_facet_keys, containing_entity;

        // all pkeys should be available in facet
        keys = that.facet.get_pkeys();

        target_facet_keys = keys;
        containing_entity = that.facet.entity.get_containing_entity();
        target_facet = that.facet;

        while (containing_entity) {
            target_facet = containing_entity.get_facet(
                target_facet.containing_facet || 'default');
            target_facet_keys = target_facet_keys.slice(0, -1);
            items.unshift({
                text: target_facet_keys.slice(-1),
                title: containing_entity.metadata.label_singular,
                handler: function(facet, keys) {
                    return function() {
                        navigation.show(facet, keys);
                        return false;
                    };
                }(target_facet, target_facet_keys)
            });
            containing_entity = containing_entity.get_containing_entity();
        }

        //calculation of breadcrumb keys length
        keys.push(pkey);
        var max_bc_l = 140; //max chars which can fit on one line
        var max_key_l = (max_bc_l / keys.length) - 4; //4 chars as divider
        var bc_l = 0;
        var to_limit = keys.length;
        //count how many won't be limited and how much space they take
        for (i=0; i<keys.length; i++) {
            var key_l = keys[i].length;
            if (key_l <= max_key_l) {
                to_limit--;
                bc_l += key_l + 4;
            }
        }
        max_key_l = ((max_bc_l - bc_l) / to_limit) - 4;

        target_facet = target_facet.get_redirect_facet();
        // main level item
        items.unshift({
            text: target_facet.label,
            handler: function() {
                navigation.show(target_facet);
                return false;
            }
        });

        // recreation
        that.breadcrumb.empty();
        for (i=0, l=items.length; i<l; i++) {
            item = items[i];
            item.text = IPA.limit_text(item.text, max_key_l);
            that.breadcrumb.append(that.create_breadcrumb_item(item));
        }
        that.breadcrumb.append(that.create_breadcrumb_item({ text: pkey }));
    };

    that.create_breadcrumb_item = function(item) {

        var title = item.title || '';

        var bc_item = $('<li/>');
        if (item.handler) {
            var link = $('<a/>', {
                text: item.text,
                title: title,
                click: item.handler
            }).appendTo(bc_item);
        } else {
            bc_item.text(item.text);
        }
        return bc_item;
    };

    /**
     * Get facet groups for current facet.
     *
     * By default facet groups are defined in entity. In certain circumstances
     * it could be overridden, i.e., if different facet contained in the facet
     * groups uses different entity.
     * @return {Array} Array of facet groups
     */
    that.get_facet_groups = function() {
        if (that.facet.facet_groups) {
            return that.facet.facet_groups;
        }
        return that.facet.entity.facet_groups.values;
    };


    /**
     * Update displayed information with new data
     *
     * Data is result of FreeIPA RPC command.
     *
     * Updates (if present in data):
     *
     * - facet group links with number of records
     * - facet group labels with facet's pkey
     *
     * @param {Object} data
     */
    that.load = function(data) {
        if (!data) return;
        var result = data.result.result;
        if (!that.facet.disable_facet_tabs) {
            var pkey = that.facet.get_pkey();

            var facet_groups = that.get_facet_groups();
            for (var i=0; i<facet_groups.length; i++) {
                var facet_group = facet_groups[i];

                var label = facet_group.label;
                if (pkey && label) {
                    var limited_pkey = IPA.limit_text(pkey, 20);
                    label = label.replace('${primary_key}', limited_pkey);
                } else if (!label) {
                    label = '';
                }

                this.tabs_widget.update_group(facet_group.name, label, pkey);

                var facets = facet_group.facets.values;
                for (var j=0; j<facets.length; j++) {
                    var facet =  reg.facet.get(facets[j]);
                    var values = result ? result[facet.name] : null;
                    label = facet.tab_label;
                    if (values) {
                        label = facet.tab_label + ' (' + values.length + ')';
                    }
                    this.tabs_widget.update_tab(facet.get_full_name(), label);
                }
            }
        }
    };

    /**
     * Clear displayed information
     */
    that.clear = function() {
        that.load();
    };

    return that;
};

exp.FacetGroupsWidget = declare([], {

    facet: null,
    groups: null,
    group_els: null,
    el: null,
    visible: true,
    init_group_names: false,
    css_class: 'facet-tabs',
    group_el_type: '<div/>',
    group_class: 'facet-group',
    group_label_el_type: '<div/>',
    group_label_class: 'facet-group-label',
    group_label_title_el_type: '<span/>',
    group_label_title_class: '',
    tab_cont_el_type: '<div/>',
    tab_cont_class: '',
    tab_list_el_type: '<ul/>',
    tab_list_class: 'facet-tab',
    tab_el_type: '<li/>',
    tab_class: 't',
    selected_class: 'selected',

    render: function() {

        this.group_els = {};
        this.tab_els = {};

        this.el = $('<div/>', { 'class': this.css_class });

        for (var i=0; i<this.groups.length; i++) {
            var group = this.groups[i];
            if (group.facets.length) {
                var group_el = this.render_group(group);
                this.el.append(group_el);
            }
        }
        return this.el;
    },

    render_group: function(group) {

        var gr = this.group_els[group.name] = { tab_els: {}};

        gr.group_el = $(this.group_el_type, {
            'class': this.group_class,
            name: group.name
        });

        gr.label_el = $(this.group_label_el_type, {
            'class': this.group_label_class
        }).appendTo(gr.group_el);

        gr.label_title_el = $(this.group_label_title_el_type, {
            'class': this.group_label_title_class,
            text: ''
        }).appendTo(gr.label_el);

        if (this.init_group_names) {
            gr.label_title_el.text(group.label || '');
        }

        var tab_cont = $(this.tab_cont_el_type, { 'class': this.tab_cont_class });
        var tab_list = $(this.tab_list_el_type, { 'class': this.tab_list_class });
        tab_list.appendTo(tab_cont);
        var facets = group.facets.values;
        for (var i=0,l=facets.length; i<l ;i++) {
            var facet = reg.facet.get(facets[i]);
            var tab_el = this.tab_els[facet.get_full_name()] = this.render_tab(facet);
            tab_list.append(tab_el);
        }
        gr.group_el.append(tab_cont);

        return gr.group_el;
    },

    render_tab: function(tab) {
        var self = this;
        var el = $(this.tab_el_type, {
            name: tab.name,
            'class': this.tab_class,
            click: function() {
                if (el.hasClass('entity-facet-disabled')) {
                    return false;
                }
                self.on_click(tab);
                return false;
            }
        });

        $('<a/>', {
            text: tab.tab_label,
            'class': 'tab-link',
            href: "#" + navigation.create_hash(tab, {}),
            name: tab.name
        }).appendTo(el);

        return el;
    },

    hide_tab: function(tab_name) {
        var tab = this.get_tab_el(tab_name);
        if (tab) tab.css('display', 'none');
    },

    show_tab: function(tab_name) {
        var tab = this.get_tab_el(tab_name);
        if (tab) tab.css('display', '');
    },

    get_tab_el: function(tab_name) {
        return this.tab_els[tab_name];
    },

    on_click: function(facet) {
        if (this.facet.get_pkeys) {
            var pkeys = this.facet.get_pkeys();
            navigation.show(facet, pkeys);
        } else {
            navigation.show(facet);
        }
    },

    update_group: function(group_name, text, title) {
        if (!this.group_els[group_name]) return;
        var label_el = this.group_els[group_name].label_title_el;
        label_el.text(text);
        if (title) label_el.attr('title', title);
    },

    update_tab: function(tab_name, text, title) {
        var tab_el = this.tab_els[tab_name];
        var label_el = $('a', tab_el);
        label_el.text(text);
        if (title) label_el.attr('title', title);
    },

    select: function(tab_name) {
        if (!this.el) return;
        var cls = this.selected_class;
        var tab_el = this.tab_els[tab_name];

        this.el.find(this.tab_class).removeClass(cls);
        this.el.find('.tab-link').removeClass(cls);

        tab_el.addClass(cls);
        tab_el.find('.tab-link').addClass(cls);
    },

    select_first: function() {
        if (!this.el) return;
        this.el.find('.tab-link').removeClass(this.selected_class);
        this.el.find(this.tab_class).removeClass(this.selected_class);
        var first = this.el.find('.tab-link:first');
        first.addClass(this.selected_class);
        first.parent().addClass(this.selected_class);
    },

    set_visible: function(visible) {
        this.visible = visible;
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

/**
 * Facet title widget
 *
 * A widget-like object for title representation in a facet header.
 *
 * @class facet.facet_title
 * @alternateClassName IPA.facet_title
 */
exp.facet_title = IPA.facet_title = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    /**
     * Update displayed information with supplied data
     *
     * @param {Object} data
     * @param {string} data.pkey
     * @param {string} data.text
     * @param {string} data.title
     * @param {string} data.icon_title
     * @param {string} data.css_class css class for title container
     */
    that.update = function(data) {

        that.title.text(data.text);
        that.title.prop('title', data.title || '');
        that.title_container.toggleClass('no-pkey', !data.pkey);

        if (data.pkey) {
            that.title.text(data.text + ': ');
            that.pkey.text(data.pkey);
            that.pkey.attr('title', data.pkey_title || data.pkey);
        }

        if (data.css_class) that.set_class(data.css_class);

        that.set_icon_title(data.icon_title || '');
    };

    /**
     * Create HTML elements
     */
    that.create = function(container) {

        that.title_container = $('<div/>', {
            'class': 'facet-title'
        }).appendTo(container);

        var header = $('<h1/>').appendTo(that.title_container);

        that.icon = $('<i />', {
            'class': 'header-icon'
        }).appendTo(header);

        that.title = $('<span/>').appendTo(header);

        that.pkey = $('<span/>', {
            'class': 'facet-pkey'
        }).appendTo(header);
    };

    /**
     * Set maximum width of the widget
     *
     * @param {number|string} width
     */
    that.set_max_width = function(width) {
        that.title_container.css('max-width', width+'px');
    };

    /**
     * Set CSS class
     *
     * Can be used for various purposes like icon change.
     *
     * @param {string} css_class
     */
    that.set_class = function(css_class) {

        if (that.css_class) {
            that.title_container.removeClass(that.css_class);
        }

        if (css_class) {
            that.title_container.addClass(css_class);
        }

        that.css_class = css_class;
    };

    /**
     * Set icon title
     *
     * @param {string} title
     */
    that.set_icon_title = function(title) {
        that.icon.attr('title', title);
    };

    return that;
};

/**
 * Facet which displays information in a table
 *
 * @class facet.table_facet
 * @extends facet.facet
 * @alternateClassName IPA.table_facet
 */
exp.table_facet = IPA.table_facet = function(spec, no_init) {

    spec = spec || {};

    var that = IPA.facet(spec, no_init);

    /**
     * Sets whether table on the facet will or will not show items with the
     * same key.
     *
     * @property {boolean}
     */
    that.show_values_with_dup_key = spec.show_values_with_dup_key || false;

    /**
     * Names of additional row attributes which will be send to another facet
     * during navigation as URL parameters.
     *
     * @property {Array<string>}
     */
    that.additional_navigation_arguments = spec.additional_navigation_arguments;


    /**
     * Entity of data displayed in the table
     * @property {entity.entity}
     */
    that.managed_entity = spec.managed_entity ? IPA.get_entity(spec.managed_entity) : that.entity;

    /**
     * Show pagination control
     * @property {boolean}
     */
    that.pagination = spec.pagination === undefined ? true : spec.pagination;

    /**
     * Get complete records on search, otherwise pkeys only.
     */
    that.search_all_entries = spec.search_all_entries;

    /**
     * Attribute from *_find command which will be used in batch *_show command
     * which is called for each row.
     *
     * @property {String}
     */
    that.show_command_additional_attr = spec.show_command_additional_attr || null;

    /**
     * Member resolution(no_member: true ) in rpc request is skipped by default
     * to improve performance of getting data.
     *
     * Set always_request_members to true to skip this default behavior.
     * @property {boolean}
     */
    that.always_request_members = spec.always_request_members !== undefined ?
        spec.always_request_members : false;

    /**
     * Sort records
     */
    that.sort_enabled = spec.sort_enabled === undefined ? true : spec.sort_enabled;

    /**
     * Records are selectable
     *
     * Ie. by checkboxes
     */
    that.selectable = spec.selectable === undefined ? true : spec.selectable;

    /**
     * Raised when selection changes
     * @event
     */
    that.select_changed = IPA.observer();

    /**
     * Record's attribute name which controls whether row will be displayed
     * as enabled or disabled.
     *
     * Mutually exclusive with `row_disabled_attribute`
     * @property {string}
     */
    that.row_enabled_attribute = spec.row_enabled_attribute;

    /**
     * Same as `row_enabled_attribute`
     * @property {string}
     */
    that.row_disabled_attribute = spec.row_disabled_attribute;

    /**
     * Name of record's details facet
     * @property {string}
     */
    that.details_facet_name = spec.details_facet || 'default';

    /**
     * Name of facet's table
     */
    that.table_name = spec.table_name;

    /**
     * Facet's table columns
     */
    that.columns = $.ordered_map();

    /**
     * Get all columns
     */
    that.get_columns = function() {
        return that.columns.values;
    };

    /**
     * Get column with given name
     * @param {string} name column name
     */
    that.get_column = function(name) {
        return that.columns.get(name);
    };

    /**
     * Add column
     * @param {IPA.column} column
     */
    that.add_column = function(column) {
        column.entity = that.managed_entity;
        column.facet = that;
        that.columns.put(column.name, column);
    };

    /**
     * Create column according to spec and add it to column collection
     * @param {Object} spec  column spec
     */
    that.create_column = function(spec) {
        var column;
        if (spec instanceof Object) {
            var factory = spec.$factory || IPA.column;
        } else {
            factory = IPA.column;
            spec = { name: spec };
        }

        spec.entity = that.managed_entity;
        column = factory(spec);

        that.add_column(column);
        return column;
    };

    /**
     * Same as `create_column`
     * @deprecated
     */
    that.column = function(spec){
        that.create_column(spec);
        return that;
    };

    /**
     * @inheritDoc
     */
    that.create_content = function(container) {
        that.table.create(container);
    };

    /**
     * Transforms data into records and displays them in the end.
     *
     * 1. table is loaded with supplied data
     * 2. expire flag is cleared
     *
     * @fires post_load
     * @param {Object} data
     */
    that.load = function(data) {
        that.facet_load(data);

        if (!data) {
            that.table.empty();
            that.table.summary.text('');
            that.table.pagination_control.css('visibility', 'hidden');
            return;
        }

        that.table.current_page = 1;
        that.table.total_pages = 1;

        if (that.pagination) {
            that.load_page(data);
        } else {
            that.load_all(data);
        }

        that.table.refresh_pagination();
        that.policies.post_load(data);
        that.post_load.notify([data], that);
        that.clear_expired_flag();
    };


    /**
     * Transforms data into records and displays them in the end.
     *
     * It's expected that `data` contain complete records.
     *
     * @protected
     * @param {Object} data
     */
    that.load_all = function(data) {

        var result = data.result.result;
        var records = [];
        for (var i=0; i<result.length; i++) {
            var record = that.table.get_record(result[i], 0);
            records.push(record);
        }
        that.load_records(records);

        if (data.result.truncated) {
            var message = text.get('@i18n:search.truncated');
            message = message.replace('${counter}', data.result.count);
            that.table.summary.text(message);
        } else {
            that.table.summary.text(data.result.summary || '');
        }
    };

    /**
     * Method which is called before adding the record into array which will be
     * displayed. This is place where filters can be implemented. If this
     * method returns true then the record will be shown in table. if returns
     * false then the record won't be shown.
     *
     * It is created to be overridden by child classes.
     *
     * @param records_map {Array} array of already added entries
     * @param pkey {string} primary_key
     * @param record {Object} result from API call response
     * @return {boolean} true when the record should be shown, otherwise false
     */
    that.filter_records = function(records_map, pkey, record) {
        return true;
    };

    /**
     * Create a map with records as values and pkeys as keys
     *
     * Extracts records from data, where data originates from RPC command.
     *
     * @protected
     * @param {Object} data RPC command data
     * @return {Object} ordered_maps with records and with pkeys. keys
     *                              are composed from pkey and index.
     */
    that.get_records_map = function(data) {

        var records_map = $.ordered_map();
        var pkeys_map = $.ordered_map();

        var result = data.result.result;
        var pkey_name = that.managed_entity.metadata.primary_key ||
                                                        that.primary_key_name;
        var adapter = builder.build('adapter', 'adapter', {context: that});

        for (var i=0; i<result.length; i++) {
            var record = result[i];
            var pkey = adapter.load(record, pkey_name)[0];
            if (that.filter_records(records_map, pkey, record)) {
                // This solution allows to show tables where are the same
                // primary keys. (i.e. {User|Service} Vaults)
                var compound_pkey = pkey;
                if (that.show_values_with_dup_key) {
                    compound_pkey = pkey + i;
                }
                records_map.put(compound_pkey, record);
                pkeys_map.put(compound_pkey, pkey);
            }
        }

        return {
            records_map: records_map,
            pkeys_map: pkeys_map
        };
    };

    /**
     * Transforms data into records and displays them in the end.
     *
     * - subset is selected if data contains more than page-size results
     * - page is selected based on `state.page`
     * - get complete records by `get_records()` method when data contains only
     *   pkeys (skipped if table has only one column - pkey)
     *
     * @protected
     * @param {Object} data
     */
    that.load_page = function(data) {

        // get primary keys (and the complete records if search_all_entries is true)
        var records = that.get_records_map(data);
        var records_map = records.records_map;
        var pkeys_map = records.pkeys_map;

        var total = records_map.length;
        that.table.total_pages = total ? Math.ceil(total / that.table.page_length) : 1;

        delete that.table.current_page;

        var page = parseInt(that.state.page, 10) || 1;
        if (page < 1) {
            that.state.set({page: 1});
            return;
        } else if (page > that.table.total_pages) {
            that.state.set({page: that.table.total_pages});
            return;
        }
        that.table.current_page = page;

        if (!total) {
            that.table.summary.text(text.get('@i18n:association.no_entries'));
            that.load_records([]);
            return;
        }

        // calculate the start and end of the current page
        var start = (that.table.current_page - 1) * that.table.page_length + 1;
        var end = that.table.current_page * that.table.page_length;
        end = end > total ? total : end;

        var summary = text.get('@i18n:association.paging');
        summary = summary.replace('${start}', start);
        summary = summary.replace('${end}', end);
        summary = summary.replace('${total}', total);
        that.table.summary.text(summary);

        // sort map based on primary keys
        if (that.sort_enabled) {
            pkeys_map = pkeys_map.sort();
        }

        // trim map leaving the entries visible in the current page only
        pkeys_map = pkeys_map.slice(start-1, end);

        var columns = that.table.columns.values;
        if (columns.length == 1 || that.search_all_entries) {
            // All needed pkeys/objects are already fetched from server,
            // so we just filter and show them.
            that.load_records(pkeys_map.keys.map(function(x) {
                return records_map.get(x);
            }));
            return;
        }

        // get the complete records
        that.get_records(
            records_map,
            pkeys_map,
            function(data, text_status, xhr) {
                var results = data.result.results;
                var show_records_map = $.ordered_map();
                for (var i=0; i<pkeys_map.length; i++) {
                    var pkey = pkeys_map.keys[i];
                    var record = records_map.get(pkey);
                    // merge the record obtained from the refresh()
                    // with the record obtained from get_records()
                    $.extend(record, results[i].result);
                    show_records_map.put(pkey, record);
                }
                that.load_records(show_records_map.values);
            },
            function(xhr, text_status, error_thrown) {
                that.load_records([]);
                var summary = that.table.summary.empty();
                summary.text(error_thrown.name+': '+error_thrown.message);
            }
        );
    };

    /**
     * Clear table and add new rows with supplied records.
     *
     * Select previously selected rows.
     *
     * @param {Array.<Object>} records
     */
    that.load_records = function(records) {
        that.table.empty();
        that.table.records = records;
        for (var i=0; i<records.length; i++) {
            that.add_record(records[i]);
        }
        that.table.set_values(that.selected_values);
    };

    /**
     * Add new row to table
     *
     * Enables/disables row according to `row_enabled_attribute` or
     * `row_disabled_attribute` and optional column formatter for that attr.
     *
     * @protected
     * @param {Object} record
     */
    that.add_record = function(record) {

        var tr = that.table.add_record(record);

        var attribute;
        if (that.row_enabled_attribute) {
            attribute = that.row_enabled_attribute;
        } else if (that.row_disabled_attribute) {
            attribute = that.row_disabled_attribute;
        } else {
            return;
        }

        var value = record[attribute];
        var column = that.table.get_column(attribute);
        if (column.formatter) value = column.formatter.parse(value);

        that.table.set_row_enabled(tr, value);
    };

    /**
     * Get command name used in get_records
     * @protected
     * @return {string} command name
     */
    that.get_records_command_name = function() {
        return that.managed_entity.name+'_get_records';
    };

    /**
     * Create batch RPC command for obtaining complete records for each supplied
     * primary key.
     *
     * @protected
     * @param {Array.<string>} pkeys primary keys
     * @param {Function} on_success command success handler
     * @param {Function} on_failure command error handler
     */
    that.create_get_records_command = function(records, pkeys_list, on_success, on_error) {

        var pkeys = pkeys_list.keys;

        var batch = rpc.batch_command({
            name: that.get_records_command_name(),
            on_success: on_success,
            on_error: on_error
        });

        for (var i=0; i<pkeys.length; i++) {
            var pkey = pkeys[i];
            var call_pkey = pkeys_list.get(pkey);

            var command = rpc.command({
                entity: that.table.entity.name,
                method: 'show',
                args: [call_pkey]
            });

            if (that.show_command_additional_attr) {
                that.extend_get_records_command(command, records, pkey);
            }

            if (!that.always_request_members && that.table.entity.has_members()) {
                command.set_options({no_members: true});
            }

            batch.add_command(command);
        }

        return batch;
    };


    /**
     * This allows to use pagination in situations when for loading whole search
     * page you need *_show command with
     *
     */
    that.extend_get_records_command = function(command, records, pkey) {
        var record = records.get(pkey);
        var item = record[that.show_command_additional_attr];
        if (item) {
            var temp_option = {};
            temp_option[that.show_command_additional_attr] = item;
            command.set_options(temp_option);
        }
    };



    /**
     * Execute command for obtaining complete records
     *
     * @protected
     * @param records_map of all records
     * @param {Function} on_success command success handler
     * @param {Function} on_failure command error handler
     */
    that.get_records = function(records, pkeys, on_success, on_error) {

        var batch = that.create_get_records_command(records, pkeys, on_success, on_error);

        batch.execute();
    };

    /**
     * Get values selected in a table (checked rows)
     * @return {Array.<string>} values
     */
    that.get_selected_values = function() {
        return that.table.get_selected_values();
    };


    /**
     * Extract data from command response and return them.
     *
     * @param pkey {string} primary key of row which is chosen
     * @param attrs {Array} names of attributes which will be extracted
     */
    that.get_row_attribute_values = function(key, attrs) {
        var result = that.data.result.result;
        var options = {};
        var row;

        if (result) {
            for (var i=0, l=result.length; i<l; i++) {
                row = result[i];

                var pkey = row[that.table.name];
                if (pkey == key) break;
            }

            if (row) {
                for (var j=0, le=attrs.length; j<le; j++) {
                    var attr = attrs[j];
                    var new_attr = {};
                    new_attr[attr] = row[attr];
                    $.extend(options, new_attr);
                }
            }
        }

        return options;
    };

    /**
     *
     * Method which will be called after clicking on pkey in table.
     *
     * It can be overridden by child classes for changing afterclick behavior.
     *
     * @param {String} value automatically filed by clicking
     * @param {entity.entity} table entity
     * @return {boolean} false
     */
    that.on_column_link_click = function(value, entity) {
        var pkeys = [value];
        var args;

        var attributes = that.additional_navigation_arguments;
        if (lang.isArray(attributes)) {
            args = that.get_row_attribute_values(value, attributes);
        }

        // for nested entities
        var containing_entity = entity.get_containing_entity();
        if (containing_entity && that.entity.name === containing_entity.name) {
            pkeys = that.get_pkeys();
            pkeys.push(value);
        }

        navigation.show_entity(entity.name, that.details_facet_name, pkeys, args);
        return false;
    };

    /**
     * Create table
     *
     * - reflect facet settings (pagination, scrollable, ...)
     * - create columns
     * - override handler for pagination
     *
     * @protected
     * @param {entity.entity} entity table entity
     */
    that.init_table = function(entity) {

        that.table = IPA.table_widget({
            name: that.table_name || entity.metadata.primary_key,
            label: entity.metadata.label,
            entity: entity,
            pagination: true,
            scrollable: false,
            selectable: that.selectable && !that.read_only
        });

        topic.subscribe("change-pagination", function() {
            that.table.page_length = config.get('table_page_size');

            that.set_expired_flag();

            if (that.is_shown) that.refresh();
        });

        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++) {
            var column = columns[i];

            var metadata = IPA.get_entity_param(entity.name, column.name);
            column.primary_key = metadata && metadata.primary_key ||
                        (that.primary_key_name === column.param);
            if (column.primary_key) {
                column.link = column.link === undefined ? true : column.link;
            }

            if (column.link && column.primary_key) {
                column.link_handler = function(value) {
                    return that.on_column_link_click(value, entity);
                };
            }

            that.table.add_column(column);
        }

        that.table.select_changed = function() {
            that.selected_values = that.get_selected_values();
            that.select_changed.notify([that.selected_values]);
        };

        that.table.prev_page = function() {
            if (that.table.current_page > 1) {
                var page = that.table.current_page - 1;
                that.set_expired_flag();
                that.state.set({page: page});
            }
        };

        that.table.next_page = function() {
            if (that.table.current_page < that.table.total_pages) {
                var page = that.table.current_page + 1;
                that.set_expired_flag();
                that.state.set({page: page});
            }
        };

        that.table.set_page = function(page) {
            if (page < 1) {
                page = 1;
            } else if (page > that.total_pages) {
                page = that.total_pages;
            }
            that.set_expired_flag();
            that.state.set({page: page});
        };
    };

    /**
     * Create and add columns based on spec
     */
    that.init_table_columns = function() {
        var columns = spec.columns || [];
        for (var i=0; i<columns.length; i++) {
            that.create_column(columns[i]);
        }
    };

    that.fetch_records = function() {
        if (!that.table) return null;

        return that.table.records;
    };

    if (!no_init) that.init_table_columns();

    that.table_facet_create_get_records_command = that.create_get_records_command;

    return that;
};

/**
 * Facet group
 *
 * Collection of facets with similar purpose.
 *
 * @class facet.facet_group
 * @alternateClassName IPA.facet_group
 */
exp.facet_group = IPA.facet_group = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    /**
     * Name
     * @property {string}
     */
    that.name = spec.name;

    /**
     * Label
     * @property {string}
     */
    that.label = text.get(spec.label);

    /**
     * Facet collection
     * @property {ordered_map}
     */
    that.facets = $.ordered_map(spec.facets);

    /**
     * Add facet to the map
     * @param {facet.facet} facet
     */
    that.add_facet = function(facet) {
        that.facets.put(facet.name, facet);
    };

    /**
     * Get facet with given name
     * @param {string} name
     * @return {facet.facet/null}
     */
    that.get_facet = function(name) {
        return that.facets.get(name);
    };

    /**
     * Get index of facet with given name
     * @param {string} name
     * @return {facet.facet/null}
     */
    that.get_facet_index = function(name) {
        return that.facets.get_key_index(name);
    };

    /**
     * Get facet by position in collection
     * @param {number} index
     * @return {facet.facet/null}
     */
    that.get_facet_by_index = function(index) {
        return that.facets.get_value_by_index(index);
    };

    /**
     * Get number of facet in collection
     * @return {number} count
     */
    that.get_facet_count = function() {
        return that.facets.length;
    };

    return that;
};

/**
 * Action
 *
 * @class facet.action
 * @alternateClassName IPA.action
 */
exp.action = IPA.action = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    /**
     * Name
     *
     * Action identifier within facet
     * @property {string}
     */
    that.name = spec.name;

    /**
     * Label
     * @property {string}
     */
    that.label = text.get(spec.label);

    /**
     * Enabled
     *
     * Action can't be executed when not enabled.
     * @property {boolean}
     * @readonly
     */
    that.enabled = spec.enabled !== undefined ? spec.enabled : true;

    /**
     * List of states required by action to be enabled
     * @property {Array.<string>}
     */
    that.enable_cond = spec.enable_cond || [];

    /**
     * List of states which makes action disabled
     * @property {Array.<string>}
     */
    that.disable_cond = spec.disable_cond || [];

    /**
     * Value of `enabled` property changed
     * @event
     */
    that.enabled_changed = IPA.observer();

    /**
     * Controls whether action or representing widget should be visible.
     *
     * Action can't be executed when not visible.
     * @property {boolean}
     * @readonly
     */
    that.visible = spec.visible !== undefined ? spec.visible : true;

    /**
     * List of states required by action to be visible
     * @property {Array.<string>}
     */
    that.show_cond = spec.show_cond || [];

    /**
     * List of states which makes action not visible
     * @property {Array.<string>}
     */
    that.hide_cond = spec.hide_cond || [];

    /**
     * Value of `visible` property changed
     * @event
     */
    that.visible_changed = IPA.observer();

    /**
     * Action execution logic
     *
     * One has to set `handler` or override `execute_action` method.
     *
     * @property {Function} handler
     * @property {facet.facet} handler.facet
     * @property {Function} handler.on_success
     * @property {Function} handler.on_error
     */
    that.handler = spec.handler;

    /**
     * Controls whether action must be confirmed.
     *
     * If so, confirm dialog is displayed before actual execution.
     * @property {boolean}
     */
    that.needs_confirm = spec.needs_confirm !== undefined ? spec.needs_confirm : false;

    /**
     * Message to be displayed in confirm dialog
     * @property {string}
     */
    that.confirm_msg = text.get(spec.confirm_msg || '@i18n:actions.confirm');

    /**
     * Spec of confirm dialog
     *
     * Defaults to: {@link IPA.confirm_dialog}
     */
    that.confirm_dialog = spec.confirm_dialog !== undefined ? spec.confirm_dialog :
                                                              IPA.confirm_dialog;

    /**
     * Performs actual action execution
     *
     * - override point
     *
     * @protected
     * @param {facet.facet} facet
     * @param {Function} on_success
     * @param {Function} on_error
     */
    that.execute_action = function(facet, on_success, on_error) {

        if (that.handler) {
            that.handler(facet, on_success, on_error);
        }
    };

    /**
     * Execute action
     *
     * - only if enabled and visible
     * - confirm dialog is display if configured
     *
     * @param {facet.facet} facet
     * @param {Function} on_success
     * @param {Function} on_error
     */
    that.execute = function(facet, on_success, on_error) {

        if (!that.enabled || !that.visible) return;

        if (that.needs_confirm) {

            var confirmed = false;

            if (that.confirm_dialog) {

                that.dialog = IPA.build(that.confirm_dialog);
                that.update_confirm_dialog(facet);
                that.dialog.on_ok = function () {
                    that.execute_action(facet, on_success, on_error);
                };
                that.dialog.open();
            } else {
                var msg = that.get_confirm_message(facet);
                confirmed = IPA.confirm(msg);
            }

            if (!confirmed) return;
        }

        that.execute_action(facet, on_success, on_error);
    };

    /**
     * Set confirm message to confirm dialog
     * @protected
     * @param {facet.facet} facet
     */
    that.update_confirm_dialog = function(facet) {
        that.dialog.message = that.get_confirm_message(facet);
    };

    /**
     * Get confirm message
     *
     * - override point for message modifications
     *
     * @protected
     * @param {facet.facet} facet
     */
    that.get_confirm_message = function(facet) {
        return that.confirm_msg;
    };

    /**
     * Setter for `enabled`
     *
     * @fires enabled_changed
     * @param {boolean} enabled
     */
    that.set_enabled = function(enabled) {

        var old = that.enabled;

        that.enabled = enabled;

        if (old !== that.enabled) {
            that.enabled_changed.notify([that.enabled], that);
        }
    };

    /**
     * Setter for `visible`
     *
     * @fires enabled_changed
     * @param {boolean} visible
     */
    that.set_visible = function(visible) {

        var old = that.visible;

        that.visible = visible;

        if (old !== that.visible) {
            that.visible_changed.notify([that.visible], that);
        }
    };

    return that;
};

/**
 * Action collection and state reflector
 *
 * - sets `enabled` and `visible` action properties at action state change
 *   and facet load
 *
 * @class facet.action_holder
 * @alternateClassName IPA.action_holder
 */
exp.action_holder = IPA.action_holder = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    /**
     * Collection of actions
     * @property {ordered_map}
     * @protected
     */
    that.actions = $.ordered_map();

    /**
     * Build actions defined in spec.
     * Register handlers for facet events(`action_state.changed`, `post_load`)
     * @param {facet.facet} facet
     */
    that.init = function(facet) {

        var i, action, actions;

        that.facet = facet;
        actions = builder.build('action', spec.actions) || [];

        for (i=0; i<actions.length; i++) {
            action = actions[i];
            that.actions.put(action.name, action);
        }

        that.facet.action_state.changed.attach(that.state_changed);
        if (that.facet.post_load) {
            that.facet.post_load.attach(that.on_load);
        } else {
            on(that.facet, 'load', that.on_load);
        }
    };

    /**
     * Evaluate actions `visibility` and `enable` according to action conditions
     * and supplied state
     *
     * @param {Array.<string>} state
     */
    that.state_changed = function(state) {

        var actions, action, i, enabled, visible;

        actions = that.actions.values;

        for (i=0; i<actions.length; i++) {

            action = actions[i];

            enabled = IPA.eval_cond(action.enable_cond, action.disable_cond, state);
            visible = IPA.eval_cond(action.show_cond, action.hide_cond, state);
            action.set_enabled(enabled);
            action.set_visible(visible);
        }
    };

    /**
     * Get action with given named
     * @param {string} name
     * @return {facet.action}
     */
    that.get = function(name) {
        return that.actions.get(name);
    };

    /**
     * Add action to collection
     * @param {facet.action} action
     */
    that.add = function(action) {
        that.actions.put(action.name, action);
    };

    /**
     * Facet load event handler
     *
     * - gets action state and evaluates action conditions
     * @protected
     */
    that.on_load = function() {
        var state = that.facet.action_state.get();
        that.state_changed(state);
    };

    return that;
};

/**
 * Facet action state
 *
 * @class facet.state
 * @alternateClassName IPA.state
 */
exp.state = IPA.state = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    /**
     * State map
     *
     * - key: evaluator's name
     * - value: evaluator's value
     * @property {ordered_map}
     * @protected
     */
    that.state = $.ordered_map();

    /**
     * Raised when state changes.
     *
     * - params: state
     * - context: this
     * @event
     */
    that.changed = IPA.observer();

    /**
     * State evaluators
     * @property {Array.<facet.state_evaluator>}
     */
    that.evaluators = builder.build('state_evaluator', spec.evaluators) || [];

    /**
     * Summary evaluators
     * @property {facet.summary_evaluator}
     */
    that.summary_evaluator = builder.build('', spec.summary_evaluator || IPA.summary_evaluator);

    /**
     * Summary conditions
     * @property {Array.<Object>}
     */
    that.summary_conditions = builder.build('', spec.summary_conditions, {},
                                    { $factory: exp.summary_cond }) || [];

    /**
     * Initializes evaluators
     *
     * @param {facet.facet} facet
     */
    that.init = function(facet) {

        var i, evaluator;

        that.facet = facet;

        for (i=0; i<that.evaluators.length; i++) {
            evaluator = that.evaluators[i];
            evaluator.init(facet);
            evaluator.changed.attach(that.on_eval_changed);
        }
    };

    /**
     * Event handler for evaluator's 'changed' event
     * @protected
     */
    that.on_eval_changed = function() {

        var evaluator = this;
        that.put(evaluator.name, evaluator.state);
    };

    /**
     * Set state and notify
     * @param  {string} name
     * @param  {string} state
     */
    that.put = function(name, state) {
        that.state.put(name, state);
        that.notify();
    };

    /**
     * Get unified state
     *
     * @return {Array.<string>}
     */
    that.get = function() {

        var state, i;

        state = [];

        var values = that.state.values;

        for (i=0; i<values.length; i++) {
            $.merge(state, values[i]);
        }

        return state;
    };

    /**
     * Evaluate and get summary
     * @return {Object} summary
     */
    that.summary = function() {

        var summary = that.summary_evaluator.evaluate(that);
        return summary;
    };

    /**
     * Raise change event with state as parameter
     * @protected
     * @fires changed
     */
    that.notify = function(state) {

        state = state || that.get();

        that.changed.notify([state], that);
    };

    return that;
};

/**
 * Summary condition base class
 *
 * @class facet.summary_cond
 */
exp.summary_cond = function(spec) {

    var that = IPA.object();

    /**
     * State which must be present in order to be positively evaluated
     * @property {string[]}
     */
    that.pos = spec.pos || [];

    /**
     * State which must not be present in order to be positively evaluated
     * @property {string[]}
     */
    that.neg = spec.neg || [];

    /**
     * States which will be set in positive evaluation
     * @property {string[]}
     */
    that.state = spec.state || [];

    /**
     * Description which will be set in positive evaluation
     * @property {string}
     */
    that.description = spec.description || '';

    return that;
};

/**
 * Summary evaluator for {@link facet.state}
 * @class facet.summary_evaluator
 * @alternateClassName IPA.summary_evaluator
 */
exp.summary_evaluator = IPA.summary_evaluator = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    that.evaluate = function(state) {

        var conds, cond, i, summary, state_a;

        conds = state.summary_conditions;
        state_a = state.get();

        for (i=0; i<conds.length; i++) {
            cond = conds[i];
            if (IPA.eval_cond(cond.pos, cond.neg, state_a)) {
                summary = {
                    state: cond.state,
                    description: cond.description
                };
                break;
            }
        }

        summary = summary ||  {
            state: state_a,
            description: ''
        };

        return summary;
    };

    return that;
};

/**
 * State evaluator for {@link facet.state}.
 *
 * - Base class for specific evaluators.
 * - Evaluator observes facet and reflect its state by a list of string tags
 *   (evaluated state).
 * - Default behavior is that evaluator listens to event, specified by
 *   `event_name` property. The event is handled by `on_event` method.
 *   Descendant classes should override this method. Methods like `on_event`
 *   should notify state change using `notify_on_change` method.
 *
 * @class facet.state_evaluator
 * @alternateClassName IPA.state_evaluator
 */
exp.state_evaluator = IPA.state_evaluator = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    /**
     * Name
     * @property {string}
     */
    that.name = spec.name || 'state_evaluator';

    /**
     * Event name
     * @property {string}
     */
    that.event_name = spec.event;

    /**
     * State changes
     *
     * - Params: state
     * - Context: this
     * @event
     * @property {IPA.observer}
     */
    that.changed = IPA.observer();

    /**
     * Evaluated state
     * @property {Array.<string>}
     */
    that.state = [];

    /**
     * State is changed for the first time
     * @property {boolean}
     */
    that.first_pass = true;

    /**
     * Init the evaluator
     *
     * - register event listener
     * @param {facet.facet} facet
     */
    that.init = function(facet) {

        if (!that.event_name) return;

        if (facet[that.event_name] && facet[that.event_name].attach) {
            // facets based on facet.facet
            facet[that.event_name].attach(that.on_event);
        } else if (facet.emit) {
            // facets based on facet/Facet
            on(facet, that.event_name, that.on_event);
        }
    };

    /**
     * Event handler
     *
     * @localdoc - intended to be overridden
     */
    that.on_event = function() {
    };

    /**
     * Notify state change
     * @fires changed
     * @protected
     * @param {Array.<string>} old_state
     */
    that.notify_on_change = function(old_state) {

        if (that.first_pass || IPA.array_diff(that.state, old_state)) {
            that.changed.notify([that.state], that);
            that.first_pass = false;
        }
    };

    return that;
};

/**
 * Noop evaluator always sets the state on post_load on the first time
 * @class facet.noop_state_evaluator
 * @extends facet.state_evaluator
 * @alternateClassName IPA.noop_state_evaluator
 */
exp.noop_state_evaluator = IPA.noop_state_evaluator = function(spec) {

    spec = spec || {};
    spec.event = spec.event || 'post_load';

    var that = IPA.state_evaluator(spec);
    that.name = spec.name || 'noop_state_evaluator';

    /**
     * States to be set
     * @property {string[]}
     */
    that.state = spec.state || [];

    /**
     * @inheritDoc
     */
    that.on_event = function() {
        that.notify_on_change(that.state);
    };

    return that;
};


/**
 * Sets 'dirty' state when facet is dirty
 * @class facet.dirty_state_evaluator
 * @extends facet.state_evaluator
 * @alternateClassName IPA.dirty_state_evaluator
 */
exp.dirty_state_evaluator = IPA.dirty_state_evaluator = function(spec) {

    spec = spec || {};

    spec.event = spec.event || 'dirty_changed';

    var that = IPA.state_evaluator(spec);
    that.name = spec.name || 'dirty_state_evaluator';

    /**
     * Handles 'dirty_changed' event
     * @param {boolean} dirty
     */
    that.on_event = function(dirty) {

        var old_state = that.state;
        that.state = [];

        if (dirty) {
            that.state.push('dirty');
        }

        that.notify_on_change(old_state);
    };

    return that;
};

/**
 * Sets 'item-selected' state when table facets selection changes and some
 * record is selected.
 * @class facet.selected_state_evaluator
 * @extends facet.state_evaluator
 * @alternateClassName IPA.selected_state_evaluator
 */
exp.selected_state_evaluator = IPA.selected_state_evaluator = function(spec) {

    spec = spec || {};

    spec.event = spec.event || 'select_changed';

    var that = IPA.state_evaluator(spec);
    that.name = spec.name || 'selected_state_evaluator';

    /**
     * Handles 'select_changed' event
     * @param {Array} selected
     */
    that.on_event = function(selected) {

        var old_state = that.state;
        that.state = [];

        if (selected && selected.length > 0) {
            that.state.push('item-selected');
        }

        that.notify_on_change(old_state);
    };

    return that;
};

/**
 * Sets 'self-service' state when in self-service mode
 * @class facet.self_service_state_evaluator
 * @extends facet.state_evaluator
 * @alternateClassName IPA.self_service_state_evaluator
 */
exp.self_service_state_evaluator = IPA.self_service_state_evaluator = function(spec) {

    spec = spec || {};

    spec.event = spec.event || 'post_load';

    var that = IPA.state_evaluator(spec);
    that.name = spec.name || 'self_service_state_evaluator';

    /**
     * Evaluates self-service
     */
    that.on_event = function() {

        var old_state = that.state;
        that.state = [];

        if (IPA.is_selfservice) {
            that.state.push('self-service');
        }

        that.notify_on_change(old_state);
    };

    return that;
};

/**
 * Set desired state when facet parameter is equal to desired value after
 * facet event(`post_load` by default).
 *
 * @class facet.facet_attr_state_evaluator
 * @extends facet.state_evaluator
 * @alternateClassName IPA.facet_attr_state_evaluator
 */
exp.facet_attr_state_evaluator = IPA.facet_attr_state_evaluator = function(spec) {

    spec = spec || {};

    spec.event = spec.event || 'post_load';

    var that = IPA.state_evaluator(spec);
    that.name = spec.name || 'facet_attr_se';

    /**
     * Facet attribute name
     * @property {string}
     */
    that.attribute = spec.attribute;

    /**
     * Value to compare
     */
    that.value = spec.value;

    /**
     * State to add when value is equal
     * @property {string}
     */
    that.state_value = spec.state_value;

    /**
     * Compare facet's value with desired and set state if equal.
     */
    that.on_event = function() {

        var old_state = that.state;
        that.state = [];

        var facet = this;

        if (facet[that.attribute] === that.value) {
            that.state.push(that.state_value);
        }

        that.notify_on_change(old_state);
    };

    return that;
};

/**
 * Set `read_only` state when facet is `read_only`
 *
 * @class facet.read_only_state_evaluator
 * @extends facet.facet_attr_state_evaluator
 * @alternateClassName IPA.read_only_state_evaluator
 */
exp.read_only_state_evaluator = IPA.read_only_state_evaluator = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'read_only_se';
    spec.attribute = spec.attribute || 'read_only';
    spec.state_value = spec.state_value || 'read-only';
    spec.value = spec.value !== undefined ? spec.value : true;

    var that = IPA.facet_attr_state_evaluator(spec);
    return that;
};

/**
 * Set `direct` state when facet's association_type property is `direct`
 *
 * @class facet.association_type_state_evaluator
 * @extends facet.facet_attr_state_evaluator
 * @alternateClassName IPA.association_type_state_evaluator
 */
exp.association_type_state_evaluator = IPA.association_type_state_evaluator = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'association_type_se';
    spec.attribute = spec.attribute || 'association_type';
    spec.state_value = spec.state_value || 'direct';
    spec.value = spec.value !== undefined ? spec.value : 'direct';

    var that = IPA.facet_attr_state_evaluator(spec);
    return that;
};

/**
 * Button for executing facet action
 *
 * Usable as facet control button in {@link facet.control_buttons_widget}.
 *
 * @class facet.action_button_widget
 * @extends IPA.widget
 * @alternateClassName IPA.action_button_widget
 */
exp.action_button_widget = IPA.action_button_widget = function(spec) {

    spec = spec || {};

    var that = IPA.button_widget(spec);
    /**
     * Name of action this button should execute
     * @property {string}
     */
    that.action_name = spec.action || that.name;

    /**
     * Subject to removal
     * @deprecated
     */
    that.show_cond = spec.show_cond || [];

    /**
     * Subject to removal
     * @deprecated
     */
    that.hide_cond = spec.hide_cond || [];

    /**
     * Init button
     *
     * - set facet, action
     * - register event listeners
     * @param {facet.facet} facet
     */
    that.init = function(facet) {

        that.facet = facet;
        that.action = that.facet.actions.get(that.action_name);
        that.action.enabled_changed.attach(that.set_enabled);
        that.action.visible_changed.attach(that.set_visible);
    };

    /**
     * @inheritDoc
     */
    that.create = function(container) {

        that.button_widget_create(container);
        that.set_enabled(that.action.enabled);
        that.set_visible(that.action.visible);
    };

    /**
     * Button click handler
     *
     * Executes action by default.
     */
    that.on_click = function() {

        if (!that.enabled) return;

        that.action.execute(that.facet);
    };

    return that;
};

/**
 * Facet button bar
 *
 * @class facet.control_buttons_widget
 * @extends IPA.widget
 * @alternateClassName IPA.control_buttons_widget
 */
exp.control_buttons_widget = IPA.control_buttons_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    /**
     * Buttons
     * @property {Array.<facet.action_button_widget>}
     */
    that.buttons = builder.build('widget', spec.buttons, {},
                                 { $factory: exp.action_button_widget} ) || [];

    /**
     * Initializes buttons
     * @param {facet.facet} facet
     */
    that.init = function(facet) {

        var i;

        for (i=0; i<that.buttons.length; i++) {

            var button = that.buttons[i];
            button.init(facet);
        }
    };

    /**
     * @inheritDoc
     */
    that.create = function(container) {

        that.container = $('<div/>', {}).appendTo(container);
        that.widget_create(that.container);

        for (var i=0; i<that.buttons.length; i++) {

            var button = that.buttons[i];
            button.create(that.container);
        }
    };

    return that;
};

/**
 * Evaluate state by enable and disable condition
 *
 * @member facet
 * @return {boolean} true - all enable condition are met and none disable condition
 *                          is met
 */
exp.eval_cond = IPA.eval_cond = function(enable_cond, disable_cond, state) {

    var i, cond;

    if (disable_cond) {
        for (i=0; i<disable_cond.length; i++) {
            cond = disable_cond[i];
            if (state.indexOf(cond) > -1) {
                return false;
            }
        }
    }

    if (enable_cond) {
        for (i=0; i<enable_cond.length; i++) {
            cond = enable_cond[i];
            if (state.indexOf(cond) < 0) {
                return false;
            }
        }
    }

    return true;
};

/**
 * Facet state
 * @extends Stateful
 * @mixins Evented
 * @class facet.FacetState
 */
var FacetState = exp.FacetState = declare([Stateful, Evented], {

    /**
     * Properties to ignore in clear and clone operation
     */
    _ignore_properties: {_watchCallbacks:1, onset:1,_updating:1, _inherited:1},

    /**
     * Gets object containing shallow copy of state's properties.
     */
    clone: function() {
        var clone = {};
        for(var x in this){
            if (this.hasOwnProperty(x) && !(x in this._ignore_properties)) {
                clone[x] = lang.clone(this[x]);
            }
        }
        return clone;
    },

    /**
     * Unset all properties.
     */
    clear: function() {
        var undefined;
        for(var x in this){
            if (this.hasOwnProperty(x) && !(x in this._ignore_properties)) {
                this.set(x, undefined);
            }
        }
        return this;
    },

    /**
     * Set a property
     *
     * Sets named properties on a stateful object and notifies any watchers of
     * the property. A programmatic setter may be defined in subclasses.
     *
     * Can be called with hash of name/value pairs.
     *
     * @fires set
     */
    set: function(name, value) {

        var old_state;
        var updating = this._updating;
        if (!updating) old_state = this.clone();
        this._updating = true;
        this.inherited(arguments);
        if (!updating) {
            delete this._updating;
            var new_state = this.clone();
            this.emit('set', old_state, new_state);
        }

        return this;
    },

    /**
     * Set completely new state. Old state is cleared.
     *
     * @fires reset
     */
    reset: function(object) {
        var old_state = this.clone();
        this._updating = true;
        this.clear();
        this.set(object);
        delete this._updating;
        var new_state = this.clone();
        this.emit('set', old_state, new_state);
        return this;
    }
});

// Facet builder and registry
var registry = new Singleton_registry();
reg.set('facet', registry);
builder.set('facet', registry.builder);
registry.builder.post_ops.push(construct_utils.init_post_op);

/**
 * Action builder with registry
 * @member facet
 */
exp.action_builder = builder.get('action');
exp.action_builder.factory = exp.action;
reg.set('action', exp.action_builder.registry);

/**
 * State Evaluator builder and registry
 * @member facet
 */
exp.state_evaluator_builder = builder.get('state_evaluator');
exp.state_evaluator.factory = exp.action;
reg.set('state_evaluator', exp.state_evaluator.registry);

/**
 * Register widgets to global registry
 * @member facet
 */
exp.register = function() {
    var w = reg.widget;

    w.register('action_button', exp.action_button_widget);
    w.register('control_buttons', exp.control_buttons_widget);
};

phases.on('registration', exp.register);

return exp;
});
