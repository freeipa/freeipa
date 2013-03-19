/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2012 Red Hat
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

/**
 * Application controller
 *
 * Controls interaction between navigation, menu and facets.
 */

define(['dojo/_base/declare',
        'dojo/_base/lang',
        'dojo/_base/array',
        'dojo/on',
        'dojo/topic',
        'dojo/query',
        'dojo/dom-class',
        './widgets/App',
        './ipa',
       './navigation/Menu',
        './navigation/Router',
        './navigation/menu_spec'
       ],
       function(declare, lang, array, on, topic, query, dom_class,
            App_widget, IPA, Menu, Router, menu_spec) {

    /**
     * Main application
     *
     * This class serves as top level widget. It creates basic UI: controls
     * rendering of header, footer and placeholder for facets.
     */
    var App = declare(null, {

        app_widget: null,

        router: null,

        menu: null,

        initialized: false,

        facet_changing: false,

        init: function() {
            this.menu = new Menu();
            this.router = new Router();
            this.app_widget = new App_widget();
            this.app_widget.menu_widget.set_menu(this.menu);
            this.app_widget.container_node = query('body')[0];

            on(this.app_widget.menu_widget, 'item-select', lang.hitch(this, this.on_menu_click));
            on(this.app_widget, 'profile-click', lang.hitch(this, this.on_profile));
            on(this.app_widget, 'logout-click', lang.hitch(this, this.on_logout));
            on(this.menu, 'selected', lang.hitch(this, this.on_menu_select));

            topic.subscribe('facet-show', lang.hitch(this, this.on_facet_show));
            topic.subscribe('facet-change', lang.hitch(this, this.on_facet_change));
            topic.subscribe('facet-change-canceled', lang.hitch(this, this.on_facet_canceled));
            topic.subscribe('phase-error', lang.hitch(this, this.on_phase_error));
            topic.subscribe('facet-state-change', lang.hitch(this, this.on_facet_state_changed));

            this.app_widget.render();
        },

        /**
         * Gets:
         *  * metadata
         *  * server configuration
         *  * user information
         */
        get_configuration: function(success_handler, error_handler) {
            IPA.init({ on_success: success_handler, on_error: error_handler});
        },

        /**
         * Deduces current application profile - administraion or self-service.
         * Initializes profiles's menu.
         */
        choose_profile: function() {

            // TODO: change IPA.whoami.cn[0] to something readable
            this.update_logged_in(true, IPA.whoami.cn[0]);
            var selfservice = this.is_selfservice();


            this.app_widget.menu_widget.ignore_changes = true;

            if (selfservice) {
                this.menu.name = menu_spec.self_service.name;
                this.menu.add_items(menu_spec.self_service.items);
            } else {
                this.menu.name = menu_spec.admin.name;
                this.menu.add_items(menu_spec.admin.items);
            }

            this.app_widget.menu_widget.ignore_changes = false;
            this.app_widget.menu_widget.render();
            this.app_widget.menu_widget.select(this.menu.selected);

            // now we are ready for displaying a facet
            // cat match a facet if hash is set
            this.router.startup();

            // choose default facet if not defined by route
            if (!this.current_facet) {
                if (selfservice) {
                    this.on_profile();
                } else {
                    this.router.navigate_to_entity_facet('user', 'search');
                }
            }
        },

        is_selfservice: function() {
            var whoami = IPA.whoami;
            var self_service = true;


            if (whoami.hasOwnProperty('memberof_group') &&
                whoami.memberof_group.indexOf('admins') !== -1) {
                self_service = false;
            } else if (whoami.hasOwnProperty('memberofindirect_group')&&
                    whoami.memberofindirect_group.indexOf('admins') !== -1) {
                self_service = false;
            } else if (whoami.hasOwnProperty('memberof_role') &&
                    whoami.memberof_role.length > 0) {
                self_service = false;
            } else if (whoami.hasOwnProperty('memberofindirect_role') &&
                    whoami.memberofindirect_role.length > 0) {
                self_service = false;
            }

            IPA.is_selfservice = self_service; // quite ugly, needed for users

            return self_service;
        },

        update_logged_in: function(logged_in, fullname) {
            this.app_widget.set('logged', logged_in);
            this.app_widget.set('fullname', fullname);
        },

        on_profile: function() {
            this.router.navigate_to_entity_facet('user', 'details', [IPA.whoami.uid[0]]);
        },

        on_logout: function(event) {
            IPA.logout();
        },

        on_phase_error: function(error) {
            // FIXME: CHANGE!!!
            window.alert('Initialization error, have a coffee and relax.');
//             var container = $('#content').empty();
//             container.append('<p>Error: '+error_thrown.name+'</p>');
//             container.append('<p>'+error_thrown.message+'</p>');
        },

        on_facet_change: function(event) {
            //this.facet_changing =  true;
            var new_facet = event.facet;
            var current_facet = this.current_facet;

            if (current_facet && !current_facet.can_leave()) {
                var permit_clb = lang.hitch(this, function() {
                    // Some facet's might not call reset before this call but after
                    // so they are still dirty. Calling reset prevent's opening of
                    // dirty dialog again.
                    if (current_facet.is_dirty()) current_facet.reset(); //TODO change
                    this.router.navigate_to_hash(event.hash, event.facet);
                });

                var dialog = current_facet.show_leave_dialog(permit_clb);
                this.router.canceled = true;
                dialog.open();
            }
        },

        on_facet_canceled: function(event) {
        },

        on_facet_state_changed: function(event) {
            if (event.facet === this.current_facet) {
                var hash = this.router.create_hash(event.facet, event.state);
                this.router.update_hash(hash, true);
            }
        },

        on_facet_show: function(event) {
            var facet = event.facet;

            // update menu
            var menu_item = this._find_menu_item(facet);
            if (menu_item) this.menu.select(menu_item);

            if (!facet.container) {
                facet.container_node = this.app_widget.content_node;
            }
            if (this.current_facet) {
                this.current_facet.hide();
            }
            this.current_facet = facet;
            facet.show();
        },

        _find_menu_item: function(facet) {

            var items;

            // entity facets
            if (facet.entity) {
                items = this.menu.query({ entity: facet.entity.name, facet: facet.name });
            }

            // normal facets
            if (!items.total) {
                items = this.menu.query({ facet: facet.name });
            }

            // entity fallback
            if (!items.total && facet.entity) {
                items = this.menu.query({ entity: facet.entity.name });
            }

            // fallback: Top level item
            if (!items.total) {
                items = this.menu.query({ parent: null });
            }

            // select first
            if (items.total) {
                return items[0];
            }
        },

        /**
         * Tries to find menu item with assigned facet and navigate to it.
         */
        on_menu_click: function(menu_item) {
            this._navigate_to_menu_item(menu_item);
        },

        _navigate_to_menu_item: function(menu_item) {

            var child;

            // always go deeper if child previuosly selected
            if (menu_item.selected_child) {
                child = this.menu.items.get(menu_item.selected_child);
                if (child) {
                    this._navigate_to_menu_item(child);
                }
            }
            if (!child) {
                if(menu_item.entity) {
                    // entity pages
                    this.router.navigate_to_entity_facet(
                        menu_item.entity,
                        menu_item.facet,
                        menu_item.pkeys,
                        menu_item.args);
                } else if (menu_item.facet) {
                    // concrete facets
                    this.router.navigate_to_facet(menu_item.facet, menu_item.args);
                } else {
                    // categories, select first posible child, it may be the last
                    var children = this.menu.query({parent: menu_item.name });
                    if (children.total) {
                        var success = false;
                        for (var i=0; i<children.total;i++) {
                            success = this._navigate_to_menu_item(children[i]);
                            if (success) break;
                        }
                    } else {
                        return false;
                    }
                }
            }

            return true;
        },

        /**
         * Watches menu changes and adjusts facet space when there is
         * a need for larger menu space.
         *
         * Show extended menu space when:
         *     * there is 3+ levels of menu
         *
         * Don't show when:
         *     * all items of levels 3+ are hidden
         */
        on_menu_select: function(select_state) {

            var visible_levels = 0;
            var levels = select_state.new_selection.length;
            for (var i=0; i< levels; i++) {
                var item = select_state.new_selection[i];
                if(!item.hidden) visible_levels++;
            }

            var three_levels = visible_levels >= 3;

            dom_class.toggle(this.app_widget.content_node,
                             'nav-space-3',
                             three_levels);
        }
    });

    return App;
});