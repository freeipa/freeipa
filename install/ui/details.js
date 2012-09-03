/*jsl:import ipa.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
 *    Petr Vobornik <pvoborni@redhat.com>
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

IPA.details_builder = function(spec) {

    var that = {};

    that.widgets = spec.container.widgets;
    that.fields = spec.container.fields;

    that.widget_builder = spec.widget_builder || IPA.widget_builder();
    that.field_builder = spec.field_builder || IPA.field_builder();
    that.section_builder = spec.section_builder || IPA.section_builder();

    that.build_widget = function(spec) {

        if (!spec) return;

        that.widget_builder.build_widget(spec, that.widgets);
    };

    that.build_widgets = function(specs) {

        if (!specs) return;

        that.widget_builder.build_widgets(specs, that.widgets);
    };

    that.build_field = function(spec) {

        if (!spec) return;

        that.field_builder.build_field(spec, that.fields);
    };

    that.build_fields = function(specs) {

        if (!specs) return;

        that.field_builder.build_fields(specs, that.fields);
    };

    that.build_sections = function(specs) {

        if (!specs) return;

        that.section_builder.build_sections(specs);
    };

    that.build = function(spec) {

        if (spec.sections) {
            that.build_sections(spec.sections);

        } else if (spec.fields && !spec.widgets) {

            var sections = [
                {
                    fields: spec.fields
                }
            ];

            that.build_sections(sections);

        } else {
            that.build_fields(spec.fields);
            that.build_widgets(spec.widgets);
        }
    };

    return that;
};

IPA.section_builder = function(spec) {

    spec = spec || {};

    var that = {};

    that.container = spec.container;
    that.section_factory = spec.section_factory || IPA.details_table_section;

    that.field_builder = spec.field_builder;
    that.widget_builder = spec.widget_builder;

    that.build_sections = function(sections) {

        if(!sections) return;

        for (var i=0; i < sections.length; i++) {
            that.build_section(sections[i], i);
        }
    };

    that.build_section = function(section_spec, index) {
        section_spec.entity = that.container.entity;
        section_spec.facet = that.container;

        if (!section_spec.label && section_spec.name && that.container.entity) {
            var obj_messages = IPA.messages.objects[that.container.entity.name];
            section_spec.label = obj_messages[section_spec.name];
        }

        if(!section_spec.name) section_spec.name = 'section'+index;

        section_spec.factory = section_spec.factory || that.section_factory;
        var section = section_spec.factory(section_spec);

        that.container.widgets.add_widget(section);

        that.create_fields(section, section_spec.fields);
    };

    that.create_fields = function(section, fields_spec) {

        for (var i=0; i < fields_spec.length; i++) {
            that.create_field(section, fields_spec[i]);
        }
    };

    that.create_field = function(section, field_spec) {

        var widget = that.widget_builder.build_widget(field_spec, section.widgets);

        //spec.factory refers to widget factory
        if(field_spec.factory) delete field_spec.factory;

        var field = that.field_builder.build_field(field_spec, that.container.fields);

        if(widget && field) {
            field.widget_name = section.name+'.'+widget.name;
        }
    };

    return that;
};

IPA.facet_policy = function() {

    var that = {};

    that.init = function() {
    };

    that.post_create = function() {
    };

    that.post_load = function(data) {
    };

    return that;
};

IPA.facet_policies = function(spec) {

    var that = {};

    that.container = spec.container;
    that.policies = [];

    that.add_policy = function(policy) {

        policy.container = that.container;
        that.policies.push(policy);
    };

    that.add_policies = function(policies) {

        if (!policies) return;

        for (var i=0; i<policies.length; i++) {
            that.add_policy(policies[i]);
        }
    };

    that.init = function() {

        for (var i=0; i<that.policies.length; i++) {
            that.policies[i].init();
        }
    };

    that.post_create = function() {

         for (var i=0; i<that.policies.length; i++) {
            that.policies[i].post_create();
        }
    };

    that.post_load = function(data) {

         for (var i=0; i<that.policies.length; i++) {
            that.policies[i].post_load(data);
        }
    };

    that.add_policies(spec.policies);

    return that;
};

IPA.details_facet = function(spec, no_init) {

    spec = spec || {};
    spec.name = spec.name || 'details';

    spec.actions = spec.actions || [];
    spec.actions.unshift(
        IPA.refresh_action,
        IPA.reset_action,
        IPA.update_action);

    spec.control_buttons = spec.control_buttons || [];
    spec.control_buttons.unshift(
        {
            name: 'refresh',
            label: IPA.messages.buttons.refresh,
            icon: 'reset-icon'
        },
        {
            name: 'reset',
            label: IPA.messages.buttons.reset,
            icon: 'reset-icon'
        },
        {
            name: 'update',
            label: IPA.messages.buttons.update,
            icon: 'update-icon'
        });

    spec.state = spec.state || {};
    spec.state.evaluators = spec.state.evaluators || [];
    spec.state.evaluators.push(IPA.dirty_state_evaluator);

    var that = IPA.facet(spec, true);

    that.entity = IPA.get_entity(spec.entity);
    that.update_command_name = spec.update_command_name || 'mod';
    that.command_mode = spec.command_mode || 'save'; // [save, info]
    that.check_rights = spec.check_rights !== undefined ? spec.check_rights : true;

    that.label = spec.label || IPA.messages && IPA.messages.facets && IPA.messages.facets.details;
    that.facet_group = spec.facet_group || 'settings';

    that.widgets = IPA.widget_container();
    that.fields = IPA.field_container({ container: that });
    that.policies = IPA.facet_policies({
        container: that,
        policies: spec.policies
    });

    that.fields.add_field = function(field) {

        if (field.dirty_changed) {
            field.dirty_changed.attach(that.field_dirty_changed);
        }
        that.fields.container_add_field(field);
    };

    that.dirty = false;
    that.dirty_changed = IPA.observer();

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
            var pkey_val = that.data.result.result[pkey_name];
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
        that.policies.post_create();
    };

    that.create_controls = function() {

        that.create_control_buttons(that.controls);
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
                that.collapse_button.css('display', 'inline-block');

                var widgets = that.widgets.get_widgets();
                for (var i=0; i<widgets.length; i++) {
                    var widget = widgets[i];
                    if(widget.toggle) {
                        widget.toggle(true);
                    }
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
                that.expand_button.css('display', 'inline-block');
                that.collapse_button.css('display', 'none');

                var widgets = that.widgets.get_widgets();
                for (var i=0; i<widgets.length; i++) {
                    var widget = widgets[i];
                    if(widget.toggle) {
                        widget.toggle(false);
                    }
                }
                return false;
            }
        }).appendTo(that.controls);
    };

    that.widgets.create_widget_delimiter = function(container) {
        container.append('<hr/>');
    };

    that.create_content = function(container) {

        that.content = $('<div/>', {
            'class': 'details-content'
        }).appendTo(container);

        that.widgets.create(that.content);

        $('<span/>', {
            name: 'summary',
            'class': 'details-summary'
        }).appendTo(container);
    };

    that.show = function() {
        that.facet_show();

        that.pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        that.old_key_prefix = that.entity.get_primary_key_prefix();
        that.header.set_pkey(that.pkey);
    };

    that.needs_update = function() {
        if (that._needs_update !== undefined) return that._needs_update;

        var needs_update = that.facet_needs_update();

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        var key_prefix = that.entity.get_primary_key_prefix();

        needs_update = needs_update || pkey !== that.pkey;
        needs_update = needs_update || IPA.array_diff(key_prefix, that.old_key_prefix);

        return needs_update;
    };

    that.field_dirty_changed = function(dirty) {

        var old_dirty = that.dirty;

        if (dirty) {
            that.dirty = true;
        } else {
            that.dirty = that.is_dirty();
        }

        if (old_dirty !== that.dirty) {
            that.dirty_changed.notify([that.dirty]);
        }
    };

    that.is_dirty = function() {
        var fields = that.fields.get_fields();
        for (var i=0; i<fields.length; i++) {
            if (fields[i].is_dirty()) {
                return true;
            }
        }
        return false;
    };

    that.load = function(data) {
        that.facet_load(data);

        var fields = that.fields.get_fields();
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            field.load(data.result.result);
        }
        that.policies.post_load(data);
        that.post_load.notify([data], that);
        that.clear_expired_flag();
    };

    that.save = function(record) {
        var fields = that.fields.get_fields();
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            field.save(record);
        }
    };

    that.save_as_update_info = function(only_dirty, require_value) {

        var record = {};
        var update_info = IPA.update_info_builder.new_update_info();
        var fields = that.fields.get_fields();

        that.save(record);

        for (var i=0; i<fields.length; i++) {
            var field = fields[i];

            if (only_dirty && !field.is_dirty()) continue;

            var values = record[field.param];
            if (require_value && !values) continue;

            update_info.append_field(field, values);
        }

        return update_info;
    };

    that.reset = function() {
        var fields = that.fields.get_fields();
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            field.reset();
        }
    };


    that.validate = function() {
        var valid = true;
        var fields = that.fields.get_fields();
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            valid = field.validate() && field.validate_required() && valid;
        }
        return valid;
    };

    that.nofify_update_success = function() {
        var msg = IPA.messages.details.updated;
        var key = that.get_primary_key();
        key = key[key.length -1] || '';
        msg = msg.replace('${entity}', that.entity.metadata.label_singular);
        msg = msg.replace('${primary_key}', key);
        IPA.notify_success(msg);
    };


    that.update_on_success = function(data, text_status, xhr) {
        that.load(data);
        that.on_update.notify();
        that.nofify_update_success();
    };

    that.update_on_error = function(xhr, text_status, error_thrown) {
    };

    that.add_fields_to_command = function(update_info, command) {

        for (var i=0; i < update_info.fields.length; i++) {
            var field_info = update_info.fields[i];
            if (field_info.field.flags.indexOf('no_command') > -1) continue;
            var values = field_info.field.save();
            IPA.command_builder.add_field_option(
                command,
                field_info.field,
                values);
        }
    };

    that.create_fields_update_command = function(update_info) {

        var args = that.get_primary_key();

        var options = { all: true };
        if (that.check_rights) options.rights = true;

        var command = IPA.command({
            entity: that.entity.name,
            method: that.update_command_name,
            args: args,
            options: options
        });

        //set command options
        that.add_fields_to_command(update_info, command);

        return command;
    };

    that.create_batch_update_command = function(update_info) {

        var batch = IPA.batch_command({
            name: that.entity.name + '_details_update'
        });

        var new_update_info = IPA.update_info_builder.copy(update_info);

        if (update_info.fields.length > 0) {
            var command = that.create_fields_update_command(update_info);
            new_update_info.append_command(command, IPA.config.default_priority);
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
            name: 'validation_error',
            title: IPA.messages.dialogs.validation_title,
            message: IPA.messages.dialogs.validation_message
        });
        dialog.open();
    };

    that.create_update_command = function() {

        var command, update_info;

        if (that.command_mode === 'info') {
            update_info = that.get_update_info();
        } else {
            update_info = that.save_as_update_info(true, true);
        }

        if (update_info.commands.length <= 0) {
            //normal command
            command = that.create_fields_update_command(update_info);
        } else {
            //batch command
            command = that.create_batch_update_command(update_info);
        }

        return command;
    };

    that.update = function(on_success, on_error) {

        var command = that.create_update_command();

        command.on_success = function(data, text_status, xhr) {
            that.update_on_success(data, text_status, xhr);
            if (on_success) on_success.call(this, data, text_status, xhr);
        };

        command.on_error = function(xhr, text_status, error_thrown) {
            that.update_on_error(xhr, text_status, error_thrown);
            if (on_error) on_error.call(this, xhr, text_status, error_thrown);
        };

        command.execute();
    };

    that.get_refresh_command_name = function() {
        return that.entity.name+'_show';
    };

    that.create_refresh_command = function() {

        var options = { all: true };
        if (that.check_rights) options.rights = true;

        var command = IPA.command({
            name: that.get_refresh_command_name(),
            entity: that.entity.name,
            method: 'show',
            options: options
        });

        if (that.pkey) {
            command.args = that.get_primary_key(true);
        }

        return command;
    };

    that.refresh_on_success = function(data, text_status, xhr) {
        that.load(data);
        that.show_content();
    };

    that.refresh_on_error = function(xhr, text_status, error_thrown) {
        that.redirect_error(error_thrown);
        that.report_error(error_thrown);
    };

    that.refresh = function(on_success, on_error) {

        that.pkey = IPA.nav.get_state(that.entity.name+'-pkey');

        if (!that.pkey && that.entity.redirect_facet) {
            that.redirect();
            return;
        }

        var command = that.create_refresh_command();

        command.on_success = function(data, text_status, xhr) {
            that.refresh_on_success(data, text_status, xhr);
            if (on_success) on_success.call(this, data, text_status, xhr);
        };

        command.on_error = function(xhr, text_status, error_thrown) {
            that.refresh_on_error(xhr, text_status, error_thrown);
            if (on_error) on_error.call(this, xhr, text_status, error_thrown);
        };

        command.execute();
    };

    that.clear = function() {
        that.header.clear();

        that.widgets.clear();
    };

    that.get_update_info = function() {

        var update_info = IPA.update_info_builder.new_update_info();

        var fields = that.fields.get_fields();
        for (var i = 0; i < fields.length; i++) {
            var field = fields[i];
            if (field.get_update_info) {
                var ui = field.get_update_info();
                update_info = IPA.update_info_builder.merge(update_info, ui);
            }
        }

        return update_info;
    };

    that.create_builder = function() {

        var widget_builder = IPA.widget_builder({
            widget_options: {
                entity: that.entity,
                facet: that
            }
        });
        var field_builder = IPA.field_builder({
            field_options: {
                entity: that.entity
            }
        });
        var section_builder = IPA.section_builder({
            container: that,
            widget_builder: widget_builder,
            field_builder: field_builder
        });

        that.builder = IPA.details_builder({
            container: that,
            widget_builder: widget_builder,
            field_builder: field_builder,
            section_builder: section_builder
        });
    };

    that.init_details_facet = function() {

        that.init_facet();
        that.create_builder();
        that.builder.build(spec);
        that.fields.widgets_created();
        that.policies.init();
    };

    if (!no_init) that.init_details_facet();

    // methods that should be invoked by subclasses
    that.details_facet_create_update_command = that.create_update_command;
    that.details_facet_create_refresh_command = that.create_refresh_command;
    that.details_facet_refresh_on_success = that.refresh_on_success;
    that.details_facet_load = that.load;

    return that;
};

IPA.update_info = function(spec) {

    var that = {};

    that.fields = spec.fields || [];
    that.commands = spec.commands || [];

    that.append_field = function(field, value) {
        var field_info = IPA.update_info_builder.new_field_info(field, value);
        that.fields.push(field_info);
    };

    that.append_command = function (command, priority) {
        var command_info = IPA.update_info_builder.new_command_info(command, priority);
        that.commands.push(command_info);
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

        var name = field.param;

        if (field.metadata) {
            if (field.metadata.primary_key) return;
            if (values.length === 1) {
                command.set_option(name, values[0]);
            } else {
                command.set_option(name, values);
            }
        } else {
            if (values.length) {
                command.add_option('setattr', name+'='+values[0]);
            } else {
                command.add_option('setattr', name+'=');
            }
            for (var k=1; k<values.length; k++) {
                command.add_option('addattr', name+'='+values[k]);
            }
        }
    };

    return that;
}();

IPA.select_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'select_action';
    spec.label = spec.label || '-- select action --';

    var that = IPA.action(spec);

    that.execute_action = function(facet) {
    };

    return that;
};

IPA.refresh_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'refresh';
    spec.label = spec.label || IPA.messages.buttons.refresh;

    var that = IPA.action(spec);

    that.execute_action = function(facet) {
        facet.refresh();
    };

    return that;
};

IPA.reset_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'reset';
    spec.label = spec.label || IPA.messages.buttons.reset;
    spec.enable_cond = spec.enable_cond || ['dirty'];

    var that = IPA.action(spec);

    that.execute_action = function(facet) {
        facet.reset();
    };

    return that;
};

IPA.update_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'update';
    spec.label = spec.label || IPA.messages.buttons.update;
    spec.needs_confirm = spec.needs_confirm !== undefined ? spec.needs_confirm : false;
    spec.enable_cond = spec.enable_cond || ['dirty'];

    var that = IPA.action(spec);

    that.execute_action = function(facet) {

        if (!facet.validate()) {
            facet.show_validation_error();
            return;
        }

        facet.update();
    };

    return that;
};

IPA.boolean_state_evaluator = function(spec) {

    spec = spec || {};

    spec.event = spec.event || 'post_load';

    var that = IPA.state_evaluator(spec);

    that.name = spec.name || 'boolean_state_evaluator';
    that.field = spec.field;
    that.true_state = spec.true_state || that.field_name + '-true';
    that.false_state = spec.false_state || that.field_name + '-false';
    that.invert_value = spec.invert_value;
    that.parser = IPA.build({
        factory: spec.parser || IPA.boolean_formatter,
        invert_value: that.invert_value
    });

    that.on_event = function(data) {

        var old_state = that.state;
        var record = data.result.result;
        that.state = [];

        var value = that.parser.parse(record[that.field]);

        if (value === true) {
            that.state.push(that.true_state);
        } else {
            that.state.push(that.false_state);
        }

        that.notify_on_change(old_state);
    };

    return that;
};

IPA.enable_state_evaluator = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'enable_state_evaluator';
    spec.true_state = spec.true_state || 'enabled';
    spec.false_state = spec.false_state || 'disabled';

    var that = IPA.boolean_state_evaluator(spec);

    return that;
};

IPA.acl_state_evaluator = function(spec) {

    spec.name = spec.name || 'acl_state_evaluator';
    spec.event = spec.event || 'post_load';

    var that = IPA.state_evaluator(spec);
    that.attribute = spec.attribute;

    that.on_event = function(data) {

        var old_state, record, rights, i, state;

        old_state = that.state;
        record = data.result.result;

        that.state = [];

        if (record.attributelevelrights) {
            rights = record.attributelevelrights[that.attribute];
        }

        // Full rights if we don't know the rights.  Better to allow action and
        // then to show error dialog than not be able to do something.
        rights = rights || 'rscwo';

        for (i=0; i<rights.length; i++) {
            state = that.attribute + '_' + rights.charAt(i);
            that.state.push(state);
        }

        that.notify_on_change(old_state);
    };

    return that;
};

IPA.value_state_evaluator = function(spec) {

    spec.name = spec.name || 'value_state_evaluator';
    spec.event = spec.event || 'post_load';

    var that = IPA.state_evaluator(spec);
    that.attribute = spec.attribute;
    that.value = spec.value;
    that.representation = spec.representation;

    that.on_event = function(data) {

        var old_state, record, state, value, loaded_value;

        old_state = that.state;
        record = data.result.result;
        value = that.normalize_value(that.value);
        loaded_value = record[that.attribute];
        loaded_value = that.normalize_value(loaded_value);

        that.state = [];

        if (!IPA.array_diff(value, loaded_value)) {
            that.state.push(that.get_state_text());
        }

        that.notify_on_change(old_state);
    };

    that.normalize_value = function(original) {

        var value = original;

        if (!(value instanceof Array)) {
            value = [value];
        }
        return value;
    };

    that.get_state_text = function() {

        var representation, value;

        representation = that.representation;

        if (!representation) {
            value = that.normalize_value(that.value);
            representation = that.attribute + '_' + value[0];
        }

        return representation;
    };

    return that;
};

IPA.object_class_evaluator = function(spec) {

    spec.name = spec.name || 'object_class_evaluator';
    spec.event = spec.event || 'post_load';

    var that = IPA.state_evaluator(spec);


    that.on_event = function(data) {

        var old_state, classes, i;

        old_state = that.state;
        classes = data.result.result.objectclass;

        that.state = [];

        for (i=0; i<classes.length; i++) {
            that.state.push('oc_'+classes[i]);
        }

        that.notify_on_change(old_state);
    };

    return that;
};

IPA.object_action = function(spec) {

    spec = spec || {};

    var that = IPA.action(spec);

    that.method = spec.method;
    that.confirm_msg = spec.confirm_msg || IPA.messages.actions.confirm;
    that.options = spec.options || {};

    that.execute_action = function(facet, on_success, on_error) {

        var entity_name = facet.entity.name;
        var pkey = IPA.nav.get_state(entity_name+'-pkey');

        IPA.command({
            entity: entity_name,
            method: that.method,
            args: [pkey],
            options: that.options,
            on_success: that.get_on_success(facet, on_success),
            on_error: that.get_on_error(facet, on_error)
        }).execute();
    };

    that.on_success = function(facet, data, text_status, xhr) {

        IPA.notify_success(data.result.summary);
        facet.on_update.notify();
    };

    that.on_error = function(facet, xhr, text_status, error_thrown) {
    };

    that.get_on_success = function(facet, on_success) {
        return function(data, text_status, xhr) {
            that.on_success(facet, data, text_status, xhr);
            if (on_success) on_success.call(this, data, text_status, xhr);
        };
    };

    that.get_on_error = function(facet, on_error) {
        return function(xhr, text_status, error_thrown) {
            that.on_error(facet, xhr, text_status, error_thrown);
            if (on_error) on_error.call(this, xhr, text_status, error_thrown);
        };
    };

    that.get_confirm_message = function(facet) {
        var pkey = IPA.nav.get_state(facet.entity.name+'-pkey');
        var msg = that.confirm_msg.replace('${object}', pkey);
        return msg;
    };

    that.object_execute_action = that.execute_action;

    return that;
};

IPA.enable_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'enable';
    spec.method = spec.method || 'enable';
    spec.confirm_msg = spec.confirm_msg || IPA.messages.actions.enable_confirm;
    spec.label = spec.label || IPA.messages.buttons.enable;
    spec.disable_cond = spec.disable_cond || ['enabled'];

    var that = IPA.object_action(spec);

    return that;
};

IPA.disable_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'disable';
    spec.method = spec.method || 'disable';
    spec.confirm_msg = spec.confirm_msg || IPA.messages.actions.disable_confirm;
    spec.label = spec.label || IPA.messages.buttons.disable;
    spec.enable_cond = spec.enable_cond || ['enabled'];

    var that = IPA.object_action(spec);

    return that;
};

IPA.delete_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'delete';
    spec.method = spec.method || 'del';
    spec.confirm_msg = spec.confirm_msg || IPA.messages.actions.delete_confirm;
    spec.label = spec.label || IPA.messages.buttons.remove;

    var that = IPA.object_action(spec);

    that.execute_action = function(facet, on_success, on_error) {

        if (facet.is_dirty()) facet.reset();

        that.object_execute_action(facet, on_success, on_error);
    };

    that.on_success = function(facet, data, text_status, xhr) {

        IPA.notify_success(data.result.summary);
        facet.on_update.notify();
        facet.redirect();
    };

    return that;
};


IPA.enabled_summary_cond = function() {
    return {
        pos: ['enabled'],
        neg: [],
        description: IPA.messages.status.enabled,
        state: ['enabled']
    };
};

IPA.disabled_summary_cond = function() {
    return {
        pos: [],
        neg: ['enabled'],
        description: IPA.messages.status.disabled,
        state: ['disabled']
    };
};
