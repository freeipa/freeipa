/*jsl:import ipa.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
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

/* IPA Object Details - populating definiton lists from entry data */

/* REQUIRES: ipa.js */

IPA.expanded_icon = 'expanded-icon';
IPA.collapsed_icon = 'collapsed-icon';

IPA.details_section = function(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name || '';
    that.label = spec.label || '';
    that.entity = spec.entity;
    that.fields = $.ordered_map();

    that.dirty = false;
    that.dirty_changed = IPA.observer();

    that.undo = typeof spec.undo == 'undefined' ? true : spec.undo;

    var init = function() {
        var fields = spec.fields || [];
        that.add_fields(fields);
    };

    that.get_field = function(name) {
        return that.fields.get(name);
    };

    that.add_field = function(field) {
        field.entity = that.entity;
        field.undo = that.undo;
        that.fields.put(field.name, field);
        field.dirty_changed.attach(that.field_dirty_changed);
        return field;
    };

    that.add_fields = function(fields) {
        for (var i=0; i<fields.length; i++) {
            var field_spec = fields[i];
            var field;

            if (field_spec instanceof Object) {
                var factory = field_spec.factory || IPA.text_widget;
                field_spec.entity = that.entity;
                field = factory(field_spec);
                that.add_field(field);

            } else {
                that.text({ name: field_spec });
            }
        }
    };

    that.field = function(field) {
        that.add_field(field);
        return that;
    };

    that.text = function(spec) {
        spec.entity = that.entity;
        var field = IPA.text_widget(spec);
        that.add_field(field);
        return that;
    };

    that.multivalued_text = function(spec) {
        spec.entity = that.entity;
        var field = IPA.multivalued_text_widget(spec);
        that.add_field(field);
        return that;
    };

    that.textarea = function(spec) {
        spec.entity = that.entity;
        var field = IPA.textarea_widget(spec);
        that.add_field(field);
        return that;
    };

    that.radio = function(spec) {
        spec.entity = that.entity;
        var field = IPA.radio_widget(spec);
        that.add_field(field);
        return that;
    };

    that.create = function(container) {
        that.container = container;

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            if (field.hidden) continue;

            var field_container = $('<div/>', {
                name: field.name,
                title: field.label,
                'class': 'field'
            }).appendTo(container);
            field.create(field_container);
        }
    };

    that.load = function(record) {

        that.record = record;

        var fields = that.fields.values;
        for (var j=0; j<fields.length; j++) {
            var field = fields[j];
            field.load(record);
        }
    };

    that.save = function(record) {
        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            record[field.name] = field.save();
        }
    };

    that.reset = function() {
        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            field.reset();
        }
    };

    that.field_dirty_changed = function(dirty) {
        var old = that.dirty;

        if(dirty) {
            that.dirty = true;
        } else {
            that.dirty = that.is_dirty();
        }

        if(old !== that.dirty) {
            that.dirty_changed.notify([that.dirty], that);
        }
    };

    that.is_dirty = function() {
        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            if (field.is_dirty()) {
                return true;
            }
        }
        return false;
    };

    that.is_valid = function() {
        var fields = that.fields.values;
        var valid = true;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            if (!field.valid || !field.check_required()) {
                valid = false;
            }
        }
        return valid;
    };

    that.set_visible = function(visible) {
        if (visible) {
            that.container.show();
        } else {
            that.container.hide();
        }
    };

    init();

    // methods that should be invoked by subclasses
    that.section_create = that.create;
    that.section_load = that.load;
    that.section_reset = that.reset;

    return that;
};

IPA.details_table_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_section(spec);

    that.create = function(container) {
        that.container = container;

        // do not call section_create() here

        var table = $('<table/>', {
            'class': 'section-table'
        }).appendTo(that.container);

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            if (field.hidden) continue;

            var tr = $('<tr/>').appendTo(table);

            var td = $('<td/>', {
                'class': 'section-cell-label'
            }).appendTo(tr);

            $('<label/>', {
                name: field.name,
                title: field.label,
                'class': 'field-label',
                text: field.label+':'
            }).appendTo(td);

            td = $('<td/>', {
                'class': 'section-cell-field'
            }).appendTo(tr);

            var field_container = $('<div/>', {
                name: field.name,
                title: field.label,
                'class': 'field'
            }).appendTo(td);

            field.create(field_container);

            if (field.optional) {
                field_container.css('display', 'none');

                var link = $('<a/>', {
                    text: IPA.messages.widget.optional,
                    href: ''
                }).appendTo(td);

                link.click(function(field_container, link) {
                    return function() {
                        field_container.css('display', 'inline');
                        link.css('display', 'none');
                        return false;
                    };
                }(field_container, link));
            }
        }
    };

    that.table_section_create = that.create;

    return that;
};

IPA.details_facet = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'details';

    var that = IPA.facet(spec);
    that.entity = spec.entity;
    that.pre_execute_hook = spec.pre_execute_hook;
    that.post_update_hook = spec.post_update_hook;

    that.label = spec.label || IPA.messages && IPA.messages.facets && IPA.messages.facets.details;
    that.facet_group = spec.facet_group || 'settings';

    that.sections = $.ordered_map();

    that.dirty = false;

    that.add_section = function(section) {
        section.entity = that.entity;
        that.sections.put(section.name, section);
        section.dirty_changed.attach(that.section_dirty_changed);
        return section;
    };

    that.get_section = function(name) {
        return that.sections.get(name);
    };

    that.create_section = function(spec) {
        spec.entity = that.entity;
        var section = IPA.details_section(spec);
        that.add_section(section);
        return section;
    };

    that.get_fields = function() {
        var fields = [];
        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections.values[i];
            $.merge(fields, section.fields.values);
        }
        return fields;
    };

    /* the primary key used for show and update is built as an array.
       for most entities, this will be a single element long, but for some
       it requires the containing entities primary keys as well.*/
    that.get_primary_key = function(from_url) {

        var pkey = that.entity.get_primary_key_prefix();

        if (from_url) {
            pkey.push(that.pkey);
        } else {
            var pkey_name = that.entity.metadata.primary_key;
            if (!pkey_name){
                return pkey;
            }
            var pkey_val = that.data[pkey_name];
            if (pkey_val instanceof Array) {
                pkey.push(pkey_val[0]);
            } else {
                pkey.push(pkey_val);
            }
        }

        return pkey;
    };

    that.create = function(container) {
        if (that.entity.facets.length == 1) {
            if (that.disable_breadcrumb === undefined) {
                that.disable_breadcrumb = true;
            }
            if (that.disable_facet_tabs === undefined) {
                that.disable_facet_tabs = true;
            }
        }

        that.facet_create(container);
    };

    that.create_controls = function() {

        that.reset_button = IPA.action_button({
            name: 'reset',
            label: IPA.messages.buttons.reset,
            icon: 'reset-icon',
            'class': 'details-reset action-button-disabled',
            click: function() {
                if(!that.update_button.hasClass('action-button-disabled')) {
                    that.reset();
                }
                return false;
            }
        }).appendTo(that.controls);

        that.update_button = IPA.action_button({
            name: 'update',
            label: IPA.messages.buttons.update,
            icon: 'update-icon',
            'class': 'details-update action-button-disabled',
            click: function() {
                if(!that.update_button.hasClass('action-button-disabled')) {
                    that.update();
                }
                return false;
            }
        }).appendTo(that.controls);
    };

    that.create_header = function(container) {

        that.facet_create_header(container);

        that.pkey = IPA.nav.get_state(that.entity.name+'-pkey');

        that.create_controls();

        that.expand_button = IPA.action_button({
            name: 'expand_all',
            href: 'expand_all',
            label: IPA.messages.details.expand_all,
            'class': 'right-aligned-facet-controls',
            style: 'display: none;',
            click: function() {
                that.expand_button.css('display', 'none');
                that.collapse_button.css('display', 'inline');

                var sections = that.sections.values;
                for (var i=0; i<sections.length; i++) {
                    var section = sections[i];
                    that.toggle(section, true);
                }
                return false;
            }
        }).appendTo(that.controls);

        that.collapse_button = IPA.action_button({
            name: 'collapse_all',
            href: 'collapse_all',
            label: IPA.messages.details.collapse_all,
            'class': 'right-aligned-facet-controls',
            click: function() {
                that.expand_button.css('display', 'inline');
                that.collapse_button.css('display', 'none');

                var sections = that.sections.values;
                for (var i=0; i<sections.length; i++) {
                    var section = sections[i];
                    that.toggle(section, false);
                }
                return false;
            }
        }).appendTo(that.controls);
    };

    that.create_content = function(container) {

        that.content = $('<div/>', {
            'class': 'details-content'
        }).appendTo(container);

        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];

            var header = $('<h2/>', {
                name: section.name,
                title: section.label
            }).appendTo(that.content);

            var icon = $('<span/>', {
                name: 'icon',
                'class': 'icon section-expand '+IPA.expanded_icon
            }).appendTo(header);

            header.append(' ');

            header.append(section.label);

            var div = $('<div/>', {
                name: section.name,
                'class': 'details-section'
            }).appendTo(that.content);

            header.click(function(section, div) {
                return function() {
                    var visible = div.is(":visible");
                    that.toggle(section, !visible);
                };
            }(section, div));

            section.create(div);

            if (i < sections.length-1) {
                that.content.append('<hr/>');
            }
        }

        $('<span/>', {
            name: 'summary',
            'class': 'details-summary'
        }).appendTo(container);
    };

    that.show = function() {
        that.facet_show();

        that.pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        that.header.set_pkey(that.pkey);
    };

    that.toggle = function(section, visible) {
        var header = $('h2[name='+section.name+']', that.container);

        var icon = $('span[name=icon]', header);
        icon.toggleClass(IPA.expanded_icon, visible);
        icon.toggleClass(IPA.collapsed_icon, !visible);

        var div = section.container;

        if (visible != div.is(":visible")) {
            div.slideToggle('slow');
        }
    };

    that.needs_update = function() {
        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        return pkey != that.pkey;
    };

    that.section_dirty_changed = function(dirty) {
        if(dirty) {
            that.dirty = true;
        } else {
            that.dirty = that.is_dirty();
        }

        that.enable_update(that.dirty);
    };

    that.is_dirty = function() {
        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            if (sections[i].is_dirty()) {
                return true;
            }
        }
        return false;
    };

    that.enable_update = function(value) {
        if(that.reset_button) {
            if(value) {
                that.reset_button.removeClass('action-button-disabled');
            } else {
                that.reset_button.addClass('action-button-disabled');
            }
        }

        if(that.update_button) {
            if(value) {
                that.update_button.removeClass('action-button-disabled');
            } else {
                that.update_button.addClass('action-button-disabled');
            }
        }
    };

    that.load = function(data) {
        that.facet_load(data);

        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];
            section.load(data);
        }
        that.enable_update(false);
    };

    that.save = function(record) {
        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];
            section.save(record);
        }
    };

    that.reset = function() {
        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];
            section.reset();
        }
        that.enable_update(false);
    };

    that.update = function(on_win, on_fail) {

        function on_success(data, text_status, xhr) {
            if (on_win)
                on_win(data, text_status, xhr);
            if (data.error)
                return;

            if (that.post_update_hook) {
                that.post_update_hook(data, text_status);
                return;
            }

            var result = data.result.result;
            that.load(result);
        }

        function on_error(xhr, text_status, error_thrown) {
            if (on_fail)
                on_fail(xhr, text_status, error_thrown);
        }

        var args = that.get_primary_key();

        var command = IPA.command({
            entity: that.entity.name,
            method: 'mod',
            args: args,
            options: {
                all: true,
                rights: true
            },
            on_success: on_success,
            on_error: on_error
        });

        var record = {};
        that.save(record);

        var fields = that.get_fields();
        for (var i=0; i<fields.length; i++) {
            fields[i].validate();
        }

        var valid = true;

        var sections = that.sections.values;
        for (i=0; i<sections.length; i++) {
            var section = sections[i];

            if (!section.is_valid() || !valid) {
                valid = false;
                continue;
            }

            var section_fields = section.fields.values;
            for (var j=0; j<section_fields.length; j++) {
                var field = section_fields[j];
                if (!field.is_dirty()) continue;

                var values = record[field.name];
                if (!values) continue;

                var param_info = field.param_info;
                if (param_info) {
                    if (param_info.primary_key) continue;
                    if (values.length === 1) {
                        command.set_option(field.name, values[0]);
                    } else if (field.join) {
                        command.set_option(field.name, values.join(','));
                    } else {
                        command.set_option(field.name, values);
                    }
                } else {
                    if (values.length) {
                        command.add_option('setattr', field.name+'='+values[0]);
                    } else {
                        command.add_option('setattr', field.name+'=');
                    }
                    for (var k=1; k<values.length; k++) {
                        command.add_option('addattr', field.name+'='+values[k]);
                    }
                }
            }
        }

        if (!valid) {
            var dialog = IPA.message_dialog({
                title: IPA.messages.dialogs.validation_title,
                message: IPA.messages.dialogs.validation_message
            });
            dialog.open();
            return;
        }

        //alert(JSON.stringify(command.to_json()));

        if (that.pre_execute_hook){
            that.pre_execute_hook(command);
        }

        command.execute();
    };

    that.refresh = function() {

        that.pkey = IPA.nav.get_state(that.entity.name+'-pkey');

        var command = IPA.command({
            entity: that.entity.name,
            method: 'show',
            options: { all: true, rights: true }
        });

        if (IPA.details_refresh_devel_hook) {
            IPA.details_refresh_devel_hook(that.entity.name, command, that.pkey);
        }

        if (that.pkey) {
            command.args = that.get_primary_key(true);

        } else if (that.entity.redirect_facet) {
            that.redirect();
            return;
        }

        command.on_success = function(data, text_status, xhr) {
            that.load(data.result.result);
        };

        command.on_error = that.on_error;

        if (that.pre_execute_hook){
            that.pre_execute_hook(command);
        }

        command.execute();
    };

    that.details_facet_create_content = that.create_content;
    that.details_facet_load = that.load;

    return that;
};

