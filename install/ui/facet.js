/*jsl:import ipa.js */

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

/* REQUIRES: ipa.js, details.js, search.js, add.js */

IPA.facet = function(spec) {

    spec = spec || {};

    var that = {};

    that.entity = IPA.get_entity(spec.entity);

    that.name = spec.name;
    that.label = spec.label;
    that.title = spec.title || that.label;
    that.tab_label = spec.tab_label || that.label;
    that.display_class = spec.display_class;

    that.disable_breadcrumb = spec.disable_breadcrumb;
    that.disable_facet_tabs = spec.disable_facet_tabs;

    that.header = spec.header || IPA.facet_header({ facet: that });

    that._needs_update = spec.needs_update;
    that.expired_flag = true;
    that.last_updated = null;
    that.expire_timeout = spec.expire_timeout || 600; //[seconds]
    that.on_update = IPA.observer();

    that.dialogs = $.ordered_map();

    // facet group name
    that.facet_group = spec.facet_group;

    that.redirect_info = spec.redirect_info;

    that.state = {};

    that.get_dialog = function(name) {
        return that.dialogs.get(name);
    };

    that.dialog = function(dialog) {
        that.dialogs.put(dialog.name, dialog);
        return that;
    };

    that.create = function(container) {

        that.container = container;

        if (that.disable_facet_tabs) that.container.addClass('no-facet-tabs');
        that.container.addClass(that.display_class);

        that.header_container = $('<div/>', {
            'class': 'facet-header'
        }).appendTo(container);
        that.create_header(that.header_container);

        that.content = $('<div/>', {
            'class': 'facet-content'
        }).appendTo(container);

        that.error_container = $('<div/>', {
            'class': 'facet-content facet-error'
        }).appendTo(container);

        that.create_content(that.content);
    };

    that.create_header = function(container) {

        that.header.create(container);

        that.controls = $('<div/>', {
            'class': 'facet-controls'
        }).appendTo(container);
    };

    that.create_content = function(container) {
    };

    that.set_title = function(container, title) {
        var element = $('h1', that.title_container);
        element.html(title);
    };

    that.show = function() {
        that.container.css('display', 'block');
        that.show_content();
    };

    that.show_content = function() {
        that.content.css('display', 'block');
        that.error_container.css('display', 'none');
    };

    that.show_error = function() {
        that.content.css('display', 'none');
        that.error_container.css('display', 'block');
    };

    that.error_displayed = function() {
        return that.error_container &&
                    that.error_container.css('display') === 'block';
    };

    that.hide = function() {
        that.container.css('display', 'none');
    };

    that.load = function(data) {
        that.data = data;
        that.header.load(data);
    };

    that.refresh = function() {
    };

    that.clear = function() {
    };

    that.needs_update = function() {

        if (that._needs_update !== undefined) return that._needs_update;

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

        return needs_update;
    };

    that.set_expired_flag = function() {
        that.expired_flag = true;
    };

    that.clear_expired_flag = function() {
        that.expired_flag = false;
        that.last_updated = Date.now();
    };

    that.is_dirty = function() {
        return false;
    };

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

        var title = IPA.messages.error_report.title;
        title = title.replace('${error}', error_thrown.name);

        that.error_container.empty();
        that.error_container.append('<h1>'+title+'</h1>');

        var details = $('<div/>', {
            'class': 'error-details'
        }).appendTo(that.error_container);
        details.append('<p>'+error_thrown.message+'</p>');

        $('<div/>', {
            text: IPA.messages.error_report.options
        }).appendTo(that.error_container);

        var options_list = $('<ul/>').appendTo(that.error_container);

        add_option(
            options_list,
            IPA.messages.error_report.refresh,
            function() {
                that.refresh();
            }
        );

        add_option(
            options_list,
            IPA.messages.error_report.main_page,
            function() {
                IPA.nav.show_top_level_page();
            }
        );

        add_option(
            options_list,
            IPA.messages.error_report.reload,
            function() {
                window.location.reload(false);
            }
        );

        that.error_container.append('<p>'+IPA.messages.error_report.problem_persists+'</p>');

        that.show_error();
    };

    that.get_redirect_facet = function() {

        var entity = that.entity;
        while (entity.containing_entity) {
            entity = entity.get_containing_entity();
        }
        var facet_name = that.entity.redirect_facet;
        var entity_name = entity.name;
        var tab_name, facet;

        if (that.redirect_info) {
            entity_name = that.redirect_info.entity || entity_name;
            facet_name = that.redirect_info.facet || facet_name;
            tab_name = that.redirect_info.tab;
        }

        if (tab_name) {
            facet = IPA.nav.get_tab_facet(tab_name);
        }

        if (!facet) {
            entity = IPA.get_entity(entity_name);
            facet = entity.get_facet(facet_name);
        }

        return facet;
    };

    that.redirect = function() {

        var facet = that.get_redirect_facet();
        if (!facet) return;
        IPA.nav.show_page(facet.entity.name, facet.name);
    };

    var redirect_error_codes = [4001];

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

IPA.facet_header = function(spec) {

    spec = spec || {};

    var that = {};

    that.facet = spec.facet;

    that.select_tab = function() {
        if (that.facet.disable_facet_tabs) return;

        $(that.facet_tabs).find('a').removeClass('selected');
        var facet_name = IPA.nav.get_state(that.facet.entity.name+'-facet');

        if (!facet_name || facet_name === 'default') {
            that.facet_tabs.find('a:first').addClass('selected');
        } else {
            that.facet_tabs.find('a#' + facet_name ).addClass('selected');
        }
    };

    that.set_pkey = function(value) {

        if (!value) return;

        var limited_value = IPA.limit_text(value, 60);

        if (!that.facet.disable_breadcrumb) {
            var breadcrumb = [];

            var entity = that.facet.entity.get_containing_entity();

            while (entity) {
                breadcrumb.unshift($('<a/>', {
                    'class': 'breadcrumb-element',
                    text: IPA.nav.get_state(entity.name+'-pkey'),
                    title: entity.metadata.label_singular,
                    click: function(entity) {
                        return function() {
                            IPA.nav.show_page(entity.name, 'default');
                            return false;
                        };
                    }(entity)
                }));

                entity = entity.get_containing_entity();
            }

            that.path.empty();
            var key_max_lenght = 60 / breadcrumb.length;

            for (var i=0; i<breadcrumb.length; i++) {
                var item = breadcrumb[i];

                var entity_key = item.text();
                var limited_entity_key = IPA.limit_text(entity_key, key_max_lenght);
                item.text(limited_entity_key);

                that.path.append(' &raquo; ');
                that.path.append(item);
            }

            that.path.append(' &raquo; ');

            $('<span>', {
                'class': 'breadcrumb-element',
                title: value,
                text: limited_value
            }).appendTo(that.path);
        }

        that.title_container.empty();
        var h3 = $('<h3/>').appendTo(that.title_container);
        h3.append(that.facet.label);
        h3.append(': ');

        $('<span/>', {
            'class': 'facet-pkey',
            title: value,
            text: limited_value
        }).appendTo(h3);
    };

    that.create_facet_link = function(container, other_facet) {

        var li = $('<li/>', {
            name: other_facet.name,
            title: other_facet.name,
            click: function() {
                if (li.hasClass('entity-facet-disabled')) {
                    return false;
                }

                var pkey = IPA.nav.get_state(that.facet.entity.name+'-pkey');
                IPA.nav.show_page(that.facet.entity.name, other_facet.name, pkey);

                return false;
            }
        }).appendTo(container);

        $('<a/>', {
            text: other_facet.tab_label,
            id: other_facet.name
        }).appendTo(li);
    };

    that.create_facet_group = function(container, facet_group) {

        var section = $('<div/>', {
            name: facet_group.name,
            'class': 'facet-group'
        }).appendTo(container);

        $('<div/>', {
            'class': 'facet-group-label'
        }).appendTo(section);

        var ul = $('<ul/>', {
            'class': 'facet-tab'
        }).appendTo(section);

        var facets = facet_group.facets.values;
        for (var i=0; i<facets.length; i++) {
            var facet = facets[i];
            that.create_facet_link(ul, facet);
        }
    };

    that.create = function(container) {

        if (!that.facet.disable_breadcrumb) {
            that.breadcrumb = $('<div/>', {
                'class': 'breadcrumb'
            }).appendTo(container);

            that.back_link = $('<span/>', {
                'class': 'back-link'
            }).appendTo(that.breadcrumb);

            var redirect_facet = that.facet.get_redirect_facet();

            $('<a/>', {
                text: redirect_facet.label,
                click: function() {
                    that.facet.redirect();
                    return false;
                }
            }).appendTo(that.back_link);


            that.path = $('<span/>', {
                'class': 'path'
            }).appendTo(that.breadcrumb);
        }

        that.title_container = $('<div/>', {
            'class': 'facet-title'
        }).appendTo(container);

        var span = $('<h3/>', {
            text: that.facet.label
        }).appendTo(that.title_container);

        if (!that.facet.disable_facet_tabs) {
            that.facet_tabs = $('<div/>', {
                'class': 'facet-tabs'
            }).appendTo(container);

            var facet_groups = that.facet.entity.facet_groups.values;
            for (var i=0; i<facet_groups.length; i++) {
                var facet_group = facet_groups[i];
                if (facet_group.facets.length) {
                    that.create_facet_group(that.facet_tabs, facet_group);
                }
            }
        }
    };

    that.load = function(data) {
        if (!data) return;
        var result = data.result.result;
        if (!that.facet.disable_facet_tabs) {
            var pkey = that.facet.pkey;

            var facet_groups = that.facet.entity.facet_groups.values;
            for (var i=0; i<facet_groups.length; i++) {
                var facet_group = facet_groups[i];

                var span = $('.facet-group[name='+facet_group.name+']', that.facet_tabs);
                if (!span.length) continue;

                var label = facet_group.label;
                if (pkey && label) {
                    var limited_pkey = IPA.limit_text(pkey, 20);
                    label = label.replace('${primary_key}', limited_pkey);
                } else {
                    label = '';
                }

                var label_container = $('.facet-group-label', span);
                label_container.text(label);
                if (pkey) label_container.attr('title', pkey);

                var facets = facet_group.facets.values;
                for (var j=0; j<facets.length; j++) {
                    var facet = facets[j];
                    var link = $('li[name='+facet.name+'] a', span);

                    var values = result ? result[facet.name] : null;
                    if (values) {
                        link.text(facet.tab_label+' ('+values.length+')');
                    } else {
                        link.text(facet.tab_label);
                    }
                }
            }
        }
    };

    that.clear = function() {
        that.load();
    };

    return that;
};

IPA.table_facet = function(spec) {

    spec = spec || {};

    var that = IPA.facet(spec);

    that.managed_entity = spec.managed_entity ? IPA.get_entity(spec.managed_entity) : that.entity;

    that.pagination = spec.pagination === undefined ? true : spec.pagination;
    that.search_all_entries = spec.search_all_entries;
    that.search_all_attributes = spec.search_all_attributes;
    that.selectable = spec.selectable === undefined ? true : spec.selectable;

    that.row_enabled_attribute = spec.row_enabled_attribute;
    that.row_disabled_attribute = spec.row_disabled_attribute;
    that.details_facet_name = spec.details_facet || 'default';

    that.columns = $.ordered_map();

    var init = function() {
        var columns = spec.columns || [];
        for (var i=0; i<columns.length; i++) {
            that.create_column(columns[i]);
        }
    };

    that.get_columns = function() {
        return that.columns.values;
    };

    that.get_column = function(name) {
        return that.columns.get(name);
    };

    that.add_column = function(column) {
        column.entity = that.managed_entity;
        that.columns.put(column.name, column);
    };

    that.create_column = function(spec) {
        var column;
        if (spec instanceof Object) {
            var factory = spec.factory || IPA.column;
        } else {
            factory = IPA.column;
            spec = { name: spec };
        }

        spec.entity = that.managed_entity;
        column = factory(spec);

        that.add_column(column);
        return column;
    };

    that.column = function(spec){
        that.create_column(spec);
        return that;
    };

    that.create_content = function(container) {
        that.table.create(container);
    };

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

        that.table.current_page_input.val(that.table.current_page);
        that.table.total_pages_span.text(that.table.total_pages);

        that.table.pagination_control.css('visibility', 'visible');

        that.clear_expired_flag();
    };


    that.load_all = function(data) {

        var result = data.result.result;
        var records = [];
        for (var i=0; i<result.length; i++) {
            var record = that.table.get_record(result[i], 0);
            records.push(record);
        }
        that.load_records(records);

        if (data.result.truncated) {
            var message = IPA.messages.search.truncated;
            message = message.replace('${counter}', data.result.count);
            that.table.summary.text(message);
        } else {
            that.table.summary.text(data.result.summary);
        }
    };

    that.get_records_map = function(data) {

        var records_map = $.ordered_map();

        var result = data.result.result;
        var pkey_name = that.managed_entity.metadata.primary_key;

        for (var i=0; i<result.length; i++) {
            var record = result[i];
            var pkey = record[pkey_name];
            if (pkey instanceof Array) pkey = pkey[0];
            records_map.put(pkey, record);
        }

        return records_map;
    };

    that.load_page = function(data) {

        // get primary keys (and the complete records if search_all_entries is true)
        var records_map = that.get_records_map(data);

        var total = records_map.length;
        that.table.total_pages = total ? Math.ceil(total / that.table.page_length) : 1;

        delete that.table.current_page;

        var state = {};
        var page = parseInt(IPA.nav.get_state(that.entity.name+'-page'), 10) || 1;
        if (page < 1) {
            state[that.entity.name+'-page'] = 1;
            IPA.nav.push_state(state);
            return;
        } else if (page > that.table.total_pages) {
            state[that.entity.name+'-page'] = that.table.total_pages;
            IPA.nav.push_state(state);
            return;
        }
        that.table.current_page = page;

        if (!total) {
            that.table.summary.text(IPA.messages.association.no_entries);
            that.load_records([]);
            return;
        }

        // calculate the start and end of the current page
        var start = (that.table.current_page - 1) * that.table.page_length + 1;
        var end = that.table.current_page * that.table.page_length;
        end = end > total ? total : end;

        var summary = IPA.messages.association.paging;
        summary = summary.replace('${start}', start);
        summary = summary.replace('${end}', end);
        summary = summary.replace('${total}', total);
        that.table.summary.text(summary);

        // sort map based on primary keys
        records_map = records_map.sort();

        // trim map leaving the entries visible in the current page only
        records_map = records_map.slice(start-1, end);

        var columns = that.table.columns.values;
        if (columns.length == 1) { // show primary keys only
            that.load_records(records_map.values);
            return;
        }

        if (that.search_all_entries) {
            // map contains the primary keys and the complete records
            that.load_records(records_map.values);
            return;
        }

        // get the complete records
        that.get_records(
            records_map.keys,
            function(data, text_status, xhr) {
                var results = data.result.results;
                for (var i=0; i<records_map.length; i++) {
                    var pkey = records_map.keys[i];
                    var record = records_map.get(pkey);
                    // merge the record obtained from the refresh()
                    // with the record obtained from get_records()
                    $.extend(record, results[i].result);
                }
                that.load_records(records_map.values);
            },
            function(xhr, text_status, error_thrown) {
                that.load_records([]);
                var summary = that.table.summary.empty();
                summary.append(error_thrown.name+': '+error_thrown.message);
            }
        );
    };

    that.load_records = function(records) {
        that.table.empty();
        for (var i=0; i<records.length; i++) {
            that.add_record(records[i]);
        }
        that.table.set_values(that.selected_values);
    };

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

    that.get_records_command_name = function() {
        return that.managed_entity.name+'_get_records';
    };

    that.create_get_records_command = function(pkeys, on_success, on_error) {

         var batch = IPA.batch_command({
            name: that.get_records_command_name(),
            on_success: on_success,
            on_error: on_error
        });

        for (var i=0; i<pkeys.length; i++) {
            var pkey = pkeys[i];

            var command = IPA.command({
                entity: that.table.entity.name,
                method: 'show',
                args: [ pkey ],
                options: { all: true }
            });

            batch.add_command(command);
        }

        return batch;
    };

    that.get_records = function(pkeys, on_success, on_error) {

        var batch = that.create_get_records_command(pkeys, on_success, on_error);

        batch.execute();
    };

    that.get_selected_values = function() {
        return that.table.get_selected_values();
    };

    that.select_changed = function() {

        that.selected_values = that.get_selected_values();

        if (that.remove_button) {
            if (that.selected_values.length === 0) {
                that.remove_button.addClass('action-button-disabled');
            } else {
                that.remove_button.removeClass('action-button-disabled');
            }
        }
    };

    that.init_table = function(entity) {

        that.table = IPA.table_widget({
            'class': 'content-table',
            name: entity.metadata.primary_key,
            label: entity.metadata.label,
            entity: entity,
            pagination: true,
            search_all_attributes: that.search_all_attributes,
            scrollable: true,
            selectable: that.selectable && !that.read_only
        });

        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++) {
            var column = columns[i];

            var metadata = IPA.get_entity_param(entity.name, column.name);
            column.primary_key = metadata && metadata.primary_key;
            column.link = (column.link === undefined ? true : column.link) && column.primary_key;

            if (column.link && column.primary_key) {
                column.link_handler = function(value) {
                    IPA.nav.show_page(entity.name, that.details_facet_name, value);
                    return false;
                };
            }

            that.table.add_column(column);
        }

        that.table.select_changed = function() {
            that.select_changed();
        };

        that.table.prev_page = function() {
            if (that.table.current_page > 1) {
                var state = {};
                state[that.entity.name+'-page'] = that.table.current_page - 1;
                that.set_expired_flag();
                IPA.nav.push_state(state);
            }
        };

        that.table.next_page = function() {
            if (that.table.current_page < that.table.total_pages) {
                var state = {};
                state[that.entity.name+'-page'] = that.table.current_page + 1;
                that.set_expired_flag();
                IPA.nav.push_state(state);
            }
        };

        that.table.set_page = function(page) {
            if (page < 1) {
                page = 1;
            } else if (page > that.total_pages) {
                page = that.total_pages;
            }
            var state = {};
            state[that.entity.name+'-page'] = page;
            that.set_expired_flag();
            IPA.nav.push_state(state);
        };
    };

    init();

    that.table_facet_create_get_records_command = that.create_get_records_command;

    return that;
};

IPA.facet_group = function(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.label = spec.label;

    that.facets = $.ordered_map();

    that.add_facet = function(facet) {
        that.facets.put(facet.name, facet);
    };

    that.get_facet = function(name) {
        return that.facets.get(name);
    };

    that.get_facet_index = function(name) {
        return that.facets.get_key_index(name);
    };

    that.get_facet_by_index = function(index) {
        return that.facets.get_value_by_index(index);
    };

    that.get_facet_count = function(index) {
        return that.facets.length;
    };

    return that;
};

IPA.facet_builder = function(entity) {

    var that = {};

    that.prepare_methods = {};

    function init() {
        that.prepare_methods.search = that.prepare_search_spec;
        that.prepare_methods.nested_search = that.prepare_nested_search_spec;
        that.prepare_methods.details = that.prepare_details_spec;
        that.prepare_methods.association = that.prepare_association_spec;
    }

    that.build_facets = function() {

        if(entity.facet_specs && entity.facet_specs.length) {
            var facets = entity.facet_specs;
            for(var i=0; i<facets.length; i++) {
                var facet_spec = facets[i];
                that.build_facet(facet_spec);
            }
        }
    };

    that.build_facet = function(spec) {

        //do common logic
        spec.entity = entity;

        //prepare spec based on type
        var type = spec.type;
        if (type) {
            var prepare_method = that.prepare_methods[type];
            if (prepare_method) {
                prepare_method.call(that, spec);
            }
        }

        //add facet
        var facet = spec.factory(spec);
        entity.add_facet(facet);
    };

    function add_redirect_info(facet_name) {

        facet_name = facet_name || 'search';
        if (!entity.redirect_facet){
            entity.redirect_facet = facet_name;
        }
    }

    that.prepare_search_spec = function(spec) {

        spec.title = spec.title || entity.metadata.label;
        spec.label = spec.label || entity.metadata.label;
        spec.tab_label = spec.tab_label || IPA.messages.facets.search;
        spec.factory = spec.factory || IPA.search_facet;

        add_redirect_info();
        return spec;
    };

    that.prepare_nested_search_spec = function(spec) {

        spec.title = spec.title || entity.metadata.label_singular;
        spec.label = spec.label || entity.metadata.label;
        spec.tab_label = spec.tab_label || IPA.messages.facets.search;
        spec.factory = spec.factory || IPA.nested_search_facet;

        return spec;
    };

    that.prepare_details_spec = function(spec) {
        spec.title = spec.title || entity.metadata.label_singular;
        spec.label = spec.label || entity.metadata.label_singular;
        spec.tab_label = spec.tab_label || IPA.messages.facets.details;
        spec.factory = spec.factory || IPA.details_facet;

        return spec;
    };

    that.prepare_association_spec = function(spec) {

        spec.entity = entity;

        var index = spec.name.indexOf('_');
        spec.attribute_member = spec.attribute_member ||
            spec.name.substring(0, index);
        spec.other_entity = spec.other_entity ||
            spec.name.substring(index+1);

        spec.add_title = IPA.messages.association.add[spec.attribute_member];
        spec.remove_title = IPA.messages.association.remove[spec.attribute_member];

        spec.facet_group = spec.facet_group || spec.attribute_member;

        spec.factory = spec.factory || IPA.association_facet;

        spec.label = spec.label || entity.metadata.label_singular;
        spec.tab_label = spec.tab_label ||
            (IPA.metadata.objects[spec.other_entity] ?
            IPA.metadata.objects[spec.other_entity].label : spec.other_entity);

        if(that.has_indirect_attribute_member(spec)) {

            spec.indirect_attribute_member = spec.attribute_member + 'indirect';
        }

        if (spec.facet_group === 'memberindirect' ||
            spec.facet_group === 'memberofindirect') {

            spec.read_only = true;
        }

        return spec;
    };

    that.has_indirect_attribute_member = function(spec) {

        var indirect_members = entity.metadata.attribute_members[spec.attribute_member + 'indirect'];
        if(indirect_members) {
            if(indirect_members.indexOf(spec.other_entity) > -1) {
                return true;
            }
        }
        return false;
    };

    init();

    return that;
};
