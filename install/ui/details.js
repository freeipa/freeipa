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

            var field_container = $('<div/>', {
                name: field.name,
                title: field.label,
                'class': 'field'
            });

            if (field.hidden) {
                field_container.css('display', 'none');
            }

            field_container.appendTo(container);

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

    that.validate = function() {
        var valid = true;
        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            valid &= field.validate() && field.validate_required();
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

    that.clear = function() {
        var fields = that.fields.values;

        for (var i=0; i< fields.length; i++) {
            fields[i].clear();
        }
    };

    that.get_update_info = function() {

        var update_info = IPA.update_info_builder.new_update_info();

        var fields = that.fields.values;
        for(var i=0; i < fields.length; i++) {
            update_info = IPA.update_info_builder.merge(
                update_info,
                fields[i].get_update_info());
        }

        return update_info;
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

    that.rows = $.ordered_map();

    that.create = function(container) {
        that.container = container;

        // do not call section_create() here

        var table = $('<table/>', {
            'class': 'section-table'
        }).appendTo(that.container);

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];

            var tr = $('<tr/>');
            that.add_row(field.name, tr);

            if (field.hidden) {
                tr.css('display', 'none');
            }

            tr.appendTo(table);

            var td = $('<td/>', {
                'class': 'section-cell-label',
                title: field.label
            }).appendTo(tr);

            $('<label/>', {
                name: field.name,
                'class': 'field-label',
                text: field.label+':'
            }).appendTo(td);

            field.create_required(td);

            td = $('<td/>', {
                'class': 'section-cell-field',
                title: field.label
            }).appendTo(tr);

            var field_container = $('<div/>', {
                name: field.name,
                'class': 'field'
            }).appendTo(td);

            field.create(field_container);
        }
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
    that.update_command_name = spec.update_command_name || 'mod';
    that.command_mode = spec.command_mode || 'save'; // [save, info]

    that.label = spec.label || IPA.messages && IPA.messages.facets && IPA.messages.facets.details;
    that.facet_group = spec.facet_group || 'settings';

    that.sections = $.ordered_map();

    that.add_sections = function(sections) {

        if(sections) {
            for(var i=0; i < sections.length; i++) {

                    var section_spec = sections[i];
                    section_spec.entity = that.entity;

                    if (!section_spec.label) {
                        var obj_messages = IPA.messages.objects[that.entity.name];
                        section_spec.label = obj_messages[section_spec.name];
                    }

                    section_spec.factory = section_spec.factory || IPA.details_table_section;
                    var section = section_spec.factory(section_spec);

                    that.add_section(section);
            }
        }
    };

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
                if (!that.update_button.hasClass('action-button-disabled')) {
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
                if (that.update_button.hasClass('action-button-disabled')) return false;

                if (!that.validate()) {
                    that.show_validation_error();
                    return false;
                }

                that.update();

                return false;
            }
        }).appendTo(that.controls);
    };

    that.create_header = function(container) {

        that.facet_create_header(container);

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
        if (that._needs_update !== undefined) return that._needs_update;
        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        return pkey !== that.pkey;
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

    that.save_as_update_info = function(only_dirty, require_value) {

        var record = {};
        var update_info = IPA.update_info_builder.new_update_info();
        var sections = that.sections.values;

        that.save(record);

        for (var i=0; i<sections.length; i++) {
            var section = sections[i];

            var section_fields = section.fields.values;
            for (var j=0; j<section_fields.length; j++) {
                var field = section_fields[j];
                if (only_dirty && !field.is_dirty()) continue;

                var values = record[field.name];
                if (require_value && !values) continue;

                update_info.append_field(field, values);
            }
        }

        return update_info;
    };

    that.reset = function() {
        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];
            section.reset();
        }
        that.enable_update(false);
    };


    that.validate = function() {
        var valid = true;
        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];
            valid &= section.validate();
        }
        return valid;
    };


    that.on_update_success = function(data, text_status, xhr) {

        if (data.error)
            return;

        if (that.post_update_hook) {
            that.post_update_hook(data, text_status);
            return;
        }

        var result = data.result.result;
        that.load(result);
    };

    that.on_update_error = function(xhr, text_status, error_thrown) {
    };

    that.add_fields_to_command = function(update_info, command) {

        for (var i=0; i < update_info.fields.length; i++) {
            var field_info = update_info.fields[i];
            var values = field_info.field.save();
            IPA.command_builder.add_field_option(
                command,
                field_info.field,
                values);
        }
    };

    that.create_fields_update_command = function(update_info, on_win, on_fail) {

        var args = that.get_primary_key();
        var command = IPA.command({
            entity: that.entity.name,
            method: that.update_command_name,
            args: args,
            options: {
                all: true,
                rights: true
            },
            on_success: on_win,
            on_error: on_fail
        });

        //set command options
        that.add_fields_to_command(update_info, command);

        return command;
    };

    that.create_batch_update_command = function(update_info, on_win, on_fail) {

        var batch = IPA.batch_command({
            'name': that.entity.name + '_details_update',
            'on_success': on_win,
            'on_error': on_fail
        });

        var new_update_info = IPA.update_info_builder.copy(update_info);

        if (update_info.fields.length > 0) {
            new_update_info.append_command(
                that.create_fields_update_command(update_info),
                IPA.config.default_priority);
        }

        new_update_info.commands.sort(function(a, b) {
            return a.priority - b.priority;
        });

        for (var i=0; i < new_update_info.commands.length; i++) {
            batch.add_command(new_update_info.commands[i].command);
        }

        return batch;
    };

    that.show_validation_error = function() {
        var dialog = IPA.message_dialog({
            title: IPA.messages.dialogs.validation_title,
            message: IPA.messages.dialogs.validation_message
        });
        dialog.open();
    };

    that.update = function(on_win, on_fail) {

        var on_success = function(data, text_status, xhr) {
            that.on_update_success(data, text_status, xhr);
            if (on_win) on_win.call(this, data, text_status, xhr);
        };

        var on_error = function(xhr, text_status, error_thrown) {
            that.on_update_error(xhr, text_status, error_thrown);
            if (on_fail) on_fail.call(this, xhr, text_status, error_thrown);
        };

        var command, update_info;

        if(that.command_mode === 'info') {
            update_info = that.get_update_info();
        } else {
            update_info = that.save_as_update_info(true, true);
        }

        if (update_info.commands.length <= 0) {
            //normal command
            command = that.create_fields_update_command(update_info,
                                                        on_success,
                                                        on_error);
        } else {
            //batch command
            command = that.create_batch_update_command(update_info,
                                                        on_success,
                                                        on_error);
        }

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

        if (that.pre_execute_hook) {
            that.pre_execute_hook(command);
        }

        command.execute();
    };

    that.clear = function() {
        that.header.clear();
        var sections = that.sections.values;

        for (var i=0; i< sections.length; i++) {
            sections[i].clear();
        }
    };

    that.get_update_info = function() {

        var update_info = IPA.update_info_builder.new_update_info();

        for (var i = 0; i < that.sections.length; i++) {
            var section = that.sections.values[i];
            if(section.get_update_info) {
                update_info = IPA.update_info_builder.merge(
                    update_info,
                    section.get_update_info());
            }
        }

        return update_info;
    };

    that.add_sections(spec.sections);

    that.details_facet_create_content = that.create_content;
    that.details_facet_load = that.load;

    return that;
};

IPA.update_info = function(spec) {

    var that = {};

    that.fields = spec.fields || [];
    that.commands = spec.commands || [];

    that.append_field = function(field, value) {
        that.fields.push(IPA.update_info_builder.new_field_info(field, value));
    };

    that.append_command = function (command, priority) {
        that.commands.push(IPA.update_info_builder.new_command_info(command,
                                                                    priority));
    };

    return that;
};

IPA.command_info = function(spec) {

    var that = {};

    that.command = spec.command;
    that.priority = spec.priority || IPA.config.default_priority;

    return that;
};

IPA.field_info = function(spec) {

    var that = {};

    that.field = spec.field;
    that.value = spec.value;

    return that;
};

IPA.update_info_builder = function() {

    var that = {};

    that.new_update_info = function (fields, commands) {
        return IPA.update_info({
            fields: fields,
            commands: commands
        });
    };

    that.new_field_info = function(field, value) {
        return IPA.field_info({
            field: field,
            value: value
        });
    };

    that.new_command_info = function(command, priority) {
        return IPA.command_info({
            command: command,
            priority: priority
        });
    };

    that.merge = function(a, b) {
        return that.new_update_info(
            a.fields.concat(b.fields),
            a.commands.concat(b.commands));
    };

    that.copy = function(original) {
        return that.new_update_info(
            original.fields.concat([]),
            original.commands.concat([]));
    };

    return that;
}();

IPA.command_builder = function() {

    var that = {};

    that.add_field_option = function(command, field, values) {
        if (!field || !values) return;

        if (field.metadata) {
            if (field.metadata.primary_key) return;
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
    };

    return that;
}();
