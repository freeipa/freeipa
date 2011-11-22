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

    that.entity = spec.entity;

    that.name = spec.name;
    that.label = spec.label;
    that.title = spec.title || that.label;
    that.display_class = spec.display_class;

    that.disable_breadcrumb = spec.disable_breadcrumb;
    that.disable_facet_tabs = spec.disable_facet_tabs;

    that.header = spec.header || IPA.facet_header({ facet: that });

    that.entity_name = spec.entity_name;
    that._needs_update = spec.needs_update;

    that.dialogs = $.ordered_map();

    // facet group name
    that.facet_group = spec.facet_group;

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
    };

    that.hide = function() {
        that.container.css('display', 'none');
    };

    that.load = function(data) {
        that.data = data;
        that.header.load(data.result.result);
    };

    that.refresh = function() {
    };

    that.clear = function() {
    };

    that.needs_update = function() {
        if (that._needs_update !== undefined) return that._needs_update;
        return true;
    };

    that.is_dirty = function() {
        return false;
    };

    that.report_error = function(error_thrown) {
        // TODO: The error message should be displayed in the facet footer.
        // There should be a standard footer section for all facets.
        that.content.empty();
        that.content.append('<p>'+IPA.get_message('errors.error', 'Error')+': '+error_thrown.name+'</p>');
        that.content.append('<p>'+error_thrown.message+'</p>');
    };

    that.redirect = function() {
        var entity = that.entity;
        while (entity.containing_entity) {
            entity = entity.get_containing_entity();
        }

        IPA.nav.show_page(
            entity.name,
            that.entity.redirect_facet);
    };

    var redirect_error_codes = [4001];

    that.redirect_error = function(error_thrown) {

        /*If the error is in talking to the server, don't attempt to redirect,
          as there is nothing any other facet can do either. */
        if (that.entity.redirect_facet) {
            for (var i=0; i<redirect_error_codes.length; i++) {
                if (error_thrown.code === redirect_error_codes[i]) {
                    that.redirect();
                    return;
                }
            }
        }
    };


    // methods that should be invoked by subclasses
    that.facet_create = that.create;
    that.facet_create_header = that.create_header;
    that.facet_create_content = that.create_content;
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

            for (var i=0; i<breadcrumb.length; i++){
                that.path.append(' &raquo; ');
                that.path.append(breadcrumb[i]);
            }

            that.path.append(' &raquo; ');

            $('<span>', {
                'class': 'breadcrumb-element',
                text: value
            }).appendTo(that.path);
        }

        that.title_container.empty();
        var h3 = $('<h3/>').appendTo(that.title_container);
        h3.append(that.facet.title);
        h3.append(': ');

        $('<span/>', {
            'class': 'facet-pkey',
            text: value
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
            text: other_facet.label,
            id: other_facet.name
        }).appendTo(li);
    };

    that.create_facet_group = function(container, facet_group) {

        var section = $('<span/>', {
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

            var entity = that.facet.entity;
            while (entity.containing_entity) {
                entity = entity.get_containing_entity();
            }

            $('<a/>', {
                text: entity.metadata.label,
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
            text: that.facet.entity.label
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
        if (!that.facet.disable_facet_tabs) {
            var pkey = that.facet.pkey;

            var facet_groups = that.facet.entity.facet_groups.values;
            for (var i=0; i<facet_groups.length; i++) {
                var facet_group = facet_groups[i];

                var span = $('.facet-group[name='+facet_group.name+']', that.facet_tabs);
                if (!span.length) continue;

                var label = facet_group.label;
                if (pkey && label) {
                    label = label.replace('${primary_key}', pkey);
                } else {
                    label = '';
                }

                var label_container = $('.facet-group-label', span);
                label_container.text(label);

                var facets = facet_group.facets.values;
                for (var j=0; j<facets.length; j++) {
                    var facet = facets[j];
                    var link = $('li[name='+facet.name+'] a', span);

                    var values = data ? data[facet.name] : null;
                    if (values) {
                        link.text(facet.label+' ('+values.length+')');
                    } else {
                        link.text(facet.label);
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

    that.managed_entity_name = spec.managed_entity_name || that.entity.name;

    that.pagination = spec.pagination === undefined ? true : spec.pagination;
    that.search_all = spec.search_all;
    that.selectable = spec.selectable === undefined ? true : spec.selectable;

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
        column.entity_name = that.managed_entity_name;
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

        spec.entity_name = that.managed_entity_name;
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

        that.table.current_page = 1;
        that.table.total_pages = 1;

        if (that.pagination) {
            that.load_page(data);
        } else {
            that.load_all(data);
        }

        that.table.current_page_input.val(that.table.current_page);
        that.table.total_pages_span.text(that.table.total_pages);
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

    that.get_pkeys = function(data) {
        return [];
    };

    that.load_page = function(data) {

        that.pkeys = that.get_pkeys(data);

        if (that.pkeys.length) {
            that.table.total_pages =
                Math.ceil(that.pkeys.length / that.table.page_length);
        } else {
            that.table.total_pages = 1;
        }

        delete that.table.current_page;

        var state = {};
        var page = parseInt(IPA.nav.get_state(that.entity_name+'-page'), 10) || 1;
        if (page < 1) {
            state[that.entity_name+'-page'] = 1;
            IPA.nav.push_state(state);
            return;
        } else if (page > that.table.total_pages) {
            state[that.entity_name+'-page'] = that.table.total_pages;
            IPA.nav.push_state(state);
            return;
        }
        that.table.current_page = page;

        if (!that.pkeys || !that.pkeys.length) {
            that.load_records([]);
            that.table.summary.text(IPA.messages.association.no_entries);
            return;
        }

        that.pkeys.sort();
        var total = that.pkeys.length;

        var start = (that.table.current_page - 1) * that.table.page_length + 1;
        var end = that.table.current_page * that.table.page_length;
        end = end > total ? total : end;

        var summary = IPA.messages.association.paging;
        summary = summary.replace('${start}', start);
        summary = summary.replace('${end}', end);
        summary = summary.replace('${total}', total);
        that.table.summary.text(summary);

        that.values = that.pkeys.slice(start-1, end);

        var columns = that.table.columns.values;
        if (columns.length == 1) { // show pkey only
            var name = columns[0].name;
            var records = [];
            for (var i=0; i<that.values.length; i++) {
                var record = {};
                record[name] = that.values[i];
                records.push(record);
            }
            that.load_records(records);
            return;
        }

        // get and show additional fields
        that.get_records(
            function(data, text_status, xhr) {
                var results = data.result.results;
                var records = [];
                for (var i=0; i<results.length; i++) {
                    var record = results[i].result;
                    records.push(record);
                }
                that.load_records(records);
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
            that.table.add_record(records[i]);
        }
        that.table.set_values(that.selected_values);
    };

    that.get_records_command_name = function() {
        return that.managed_entity_name+'_get_records';
    };

    that.get_records = function(on_success, on_error) {

        var length = that.values.length;
        if (!length) return;

        var batch = IPA.batch_command({
            name: that.get_records_command_name(),
            on_success: on_success,
            on_error: on_error
        });

        for (var i=0; i<length; i++) {
            var pkey = that.values[i];

            var command = IPA.command({
                entity: that.table.entity.name,
                method: 'show',
                args: [pkey],
                options: { all: true }
            });

            batch.add_command(command);
        }

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
            search_all: that.search_all,
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
                    IPA.nav.show_page(entity.name, 'default', value);
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
                state[that.entity_name+'-page'] = that.table.current_page - 1;
                IPA.nav.push_state(state);
            }
        };

        that.table.next_page = function() {
            if (that.table.current_page < that.table.total_pages) {
                var state = {};
                state[that.entity_name+'-page'] = that.table.current_page + 1;
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
            state[that.entity_name+'-page'] = page;
            IPA.nav.push_state(state);
        };
    };

    init();

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
        spec.label = spec.label || IPA.messages.facets.search;
        spec.factory = spec.factory || IPA.search_facet;

        add_redirect_info();
        return spec;
    };

    that.prepare_nested_search_spec = function(spec) {

        spec.title = spec.title || entity.metadata.label_singular;
        spec.label = spec.label || IPA.messages.facets.search;
        spec.factory = spec.factory || IPA.nested_search_facet;

        return spec;
    };

    that.prepare_details_spec = function(spec) {
        spec.title = spec.title || entity.metadata.label_singular;
        spec.label = spec.label || IPA.messages.facets.details;
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

        spec.title = spec.label || entity.metadata.label_singular;

        spec.label = spec.label ||
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
