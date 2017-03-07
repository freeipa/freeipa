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

define([
        'dojo/_base/lang',
        './builder',
        './ipa',
        './jquery',
        './phases',
        './reg',
        './rpc',
        './spec_util',
        './text',
        './widget',
        './facet',
        './add'],
    function(lang, builder, IPA, $, phases, reg, rpc, su, text, widget_mod,
             facet_mod) {

/**
 * Details module
 *
 * @class details
 * @singleton
 */
var exp = {};

/**
 * CSS classes for defining basic layout of sections in details facets
 * @type {String}
 */
exp.details_section_layout_class = 'col-sm-12 col-md-6';

/**
 * Details builder
 *
 * Processes containers spec and builds sections, widget and fields according
 * to that spec. Container is usually a details facet or a dialog. For its task
 * it uses `section_builder`, `widget_builder` and  `field_builder` each
 * builder can be configured. Otherwise it uses default builders.
 *
 * @class details.details_builder
 * @alternateClassName IPA.details_builder
 */
exp.details_builder = IPA.details_builder = function(spec) {

    var that = IPA.object();

    /**
     * Container's widget collection
     * @protected
     */
    that.widgets = spec.container.widgets;

    /**
     * Container's field collection
     * @protected
     */
    that.fields = spec.container.fields;

    /**
     * Widget builder
     * @property {IPA.widget_builder}
     */
    that.widget_builder = spec.widget_builder || IPA.widget_builder();

    /**
     * Fields builder
     * @property {IPA.field_builder}
     */
    that.field_builder = spec.field_builder || IPA.field_builder();

    /**
     * Section builder
     * @property {details.section_builder}
     */
    that.section_builder = spec.section_builder || IPA.section_builder();

    /**
     * Build single widget  according to its spec and add it to widget collection.
     * @param {Object} spec widget spec
     */
    that.build_widget = function(spec) {

        if (!spec) return;

        that.widget_builder.build_widget(spec, that.widgets);
    };

    /**
     * Build multiple widgets and add them to widget collection.
     * @param {Array.<Object>} specs widget specs
     */
    that.build_widgets = function(specs) {

        if (!specs) return;

        that.widget_builder.build_widgets(specs, that.widgets);
    };

    /**
     * Build single field and add it to field collection.
     * @param {Object} spec field spec
     */
    that.build_field = function(spec) {

        if (!spec) return;

        that.field_builder.build_field(spec, that.fields);
    };

    /**
     * Build multiple fields and add them to field collection.
     * @param {Array.<Object>} specs field spec
     */
    that.build_fields = function(specs) {

        if (!specs) return;

        that.field_builder.build_fields(specs, that.fields);
    };

    /**
     * Build sections
     * @param {Array.<Object>} specs section specs
     */
    that.build_sections = function(specs) {

        if (!specs) return;

        that.section_builder.build_sections(specs);
    };

    /**
     * Build section, fields and widgets.
     * @param {Object} spec facet or dialog spec
     */
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

/**
 * Section builder
 *
 * Section is a layout unit of details facet or a dialog.
 *
 * @class details.section_builder
 * @alternateClassName IPA.section_builder
 */
exp.section_builder = IPA.section_builder = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    /**
     * Container
     * @property {IPA.facet|IPA.dialog}
     */
    that.container = spec.container;

    /**
     * Default section factory
     *
     * @property {IPA.composite_widget|Object}
     */
    that.section_spec = spec.section_spec || IPA.details_section;

    /**
     * Field builder
     * @property {IPA.field_builder}
     */
    that.field_builder = spec.field_builder;

    /**
     * Widget builder
     * @property {IPA.widget_builder}
     */
    that.widget_builder = spec.widget_builder;

    /**
     * Build multiple sections
     * @param {Array.<Object>} sections section specs
     */
    that.build_sections = function(sections) {

        if(!sections) return;

        for (var i=0; i < sections.length; i++) {
            that.build_section(sections[i], i);
        }
    };

    /**
     * Build single section
     * @param {Object} section_spec
     * @param {number|string} index value which is used in section name if name
     *                        is not specified in spec
     */
    that.build_section = function(section_spec, index) {

        var spec = {};
        var overrides = {};
        var spec_type = typeof that.section_spec;
        if (spec_type === 'object') {
            spec = lang.mixin({}, that.section_spec);
        } else if (spec_type === "function") {
            overrides = that.section_spec;
        }
        spec = lang.mixin(spec, section_spec);

        if (!spec.label && spec.name && that.container.entity) {
            var section_label = '@i18n:objects.'+that.container.entity.name+
                    '.' + spec.name;
            spec.label = section_label;
        }

        if (!spec.name) spec.name = 'section'+index;

        var section = builder.build('widget', spec, {
            entity: that.container.entity,
            facet: that.container
        }, overrides);

        that.container.widgets.add_widget(section);
        section.$field_adapter = spec.field_adapter;
        that.create_fields(section, spec.fields);
        delete section.$field_adapter;
    };

    /**
     * Create fields and associated widgets
     * @param {IPA.composite_widget} section
     * @param {Array.<Object>} field_specs
     */
    that.create_fields = function(section, fields_specs) {

        for (var i=0; i < fields_specs.length; i++) {
            that.create_field(section, fields_specs[i]);
        }
    };

    /**
     * Create field and associated widget
     * @param {IPA.composite_widget} section
     * @param {Object} field_spec
     */
    that.create_field = function(section, field_spec) {

        if (typeof field_spec === 'string') {
            field_spec = {
                name: field_spec
            };
        }

        var widget = that.widget_builder.build_widget(field_spec, section.widgets);

        if (field_spec.field === false) {
            // widget doesn't have field, skip
            return;
        }

        if (section.$field_adapter && !field_spec.adapter) {
            field_spec.adapter = section.$field_adapter;
        }

        //spec.$factory refers to widget factory
        if(field_spec.$factory) delete field_spec.$factory;

        var field = that.field_builder.build_field(field_spec, that.container.fields);

        if(widget && field) {
            field.widget_name = section.name+'.'+widget.name;
        }
    };

    return that;
};

/**
 * Facet policy
 *
 * Object which extends container's (facet or dialog) logic.
 *
 * @class details.facet_policy
 * @alternateClassName IPA.facet_policy
 */
exp.facet_policy = IPA.facet_policy = function() {

    var that = IPA.object();

    /**
     * Container
     * @property {IPA.facet|IPA.dialog}
     */
    that.container = null;

    /**
     * Init handler.
     *
     * Should be executed in container's init.
     */
    that.init = function() {
    };

    /**
     * Post Create Handler
     *
     * Should be executed at the end of container's create
     */
    that.post_create = function() {
    };

    /**
     * Post Load Handler
     *
     * Should be executed at the end of container's load
     * @param {Object} data
     */
    that.post_load = function(data) {
    };

    return that;
};

/**
 * Facet policy collection
 *
 * @class details.facet_policies
 * @alternateClassName IPA.facet_policies
 */
exp.facet_policies = IPA.facet_policies = function(spec) {

    var that = IPA.object();

    /**
     * Container
     * @property {IPA.facet|IPA.dialog}
     */
    that.container = spec.container;

    /**
     * Facet Policies
     * @readonly
     * @property {Array.<details.facet_policy>}
     */
    that.policies = [];

    /**
     * Add policy
     * @param {details.facet_policy} policy
     */
    that.add_policy = function(policy) {

        policy.container = that.container;
        that.policies.push(policy);
    };

    /**
     * Add multiple policies
     * @param {Array.<details.facet_policy>} policies
     */
    that.add_policies = function(policies) {

        if (!policies) return;

        for (var i=0; i<policies.length; i++) {
            that.add_policy(policies[i]);
        }
    };

    /**
     * Init handler
     *
     * Calls init handlers of all policies
     */
    that.init = function() {

        for (var i=0; i<that.policies.length; i++) {
            that.policies[i].init();
        }
    };

    /**
     * Post Create handler
     *
     * Calls post create handlers of all policies
     */
    that.post_create = function() {

         for (var i=0; i<that.policies.length; i++) {
            that.policies[i].post_create();
        }
    };

    /**
     * Post Load handler
     *
     * Calls post load handlers of all policies
     */
    that.post_load = function(data) {

         for (var i=0; i<that.policies.length; i++) {
            that.policies[i].post_load(data);
        }
    };

    var policies = builder.build('', spec.policies, {},
                                  { $factory: exp.facet_policy }) || [];
    that.add_policies(policies);

    return that;
};

/**
 * Details facet build pre_op
 *
 * It
 * - sets name, title, label if not present
 * - adds default actions and related buttons
 *   - refresh
 *   - revert
 *   - save
 * - adds dirty state evaluator
 *
 * @member details
 */
exp.details_facet_pre_op = function(spec, context) {

    su.context_entity(spec, context);
    var entity = reg.entity.get(spec.entity);

    spec.name = spec.name || 'details';
    spec.title = spec.title || entity.metadata.label_singular;
    spec.label = spec.label || entity.metadata.label_singular;
    spec.tab_label = spec.tab_label || '@i18n:facets.details';

    spec.actions = spec.actions || [];
    spec.actions.unshift(
        'refresh',
        'revert',
        'save');

    spec.control_buttons = spec.control_buttons || [];

    if (!spec.no_update) {
        spec.control_buttons.unshift(
            {
                name: 'revert',
                title: '@i18n:buttons.revert_title',
                label: '@i18n:buttons.revert',
                icon: 'fa-undo'
            },
            {
                name: 'save',
                label: '@i18n:buttons.save',
                icon: 'fa-upload'
            });
    }
    spec.control_buttons.unshift(
        {
            name: 'refresh',
            title: '@i18n:buttons.refresh_title',
            label: '@i18n:buttons.refresh',
            icon: 'fa-refresh'
        });

    spec.state = spec.state || {};
    spec.state.evaluators = spec.state.evaluators || [];
    spec.state.evaluators.push(IPA.dirty_state_evaluator);
    return spec;
};

/**
 * Details facet
 * @class details.details_facet
 * @alternateClassName IPA.details_facet
 * @extends facet.facet
 */
exp.details_facet = IPA.details_facet = function(spec, no_init) {

    spec = spec || {};

    var that = IPA.facet(spec, true);

    /**
     * Entity
     * @property {IPA.entity}
     */
    that.entity = IPA.get_entity(spec.entity);


    /**
     * Name of refresh RPC command
     *
     * - defaults to 'show'
     * @property {string}
     */
    that.refresh_command_name = spec.refresh_command_name || 'show';

    /**
     * Name of update command
     *
     * - defaults to 'mod'
     * @property {string}
     */
    that.update_command_name = spec.update_command_name || 'mod';

    /**
     * Command mode
     * Command mode determines how update information on update is collected.
     * There are two modes:
     *
     * - `save` this uses field's `save()` method
     * - `info` works with `details.update_info`. Update info is collected by
     *    `get_update_info()` method.
     * @property {string}
     */
    that.command_mode = spec.command_mode || 'save'; // [save, info]

    /**
     * Check rights
     *
     * Controls obtaining of attribute level rights on refresh and update
     *
     * @property {boolean}
     */
    that.check_rights = spec.check_rights !== undefined ? spec.check_rights : true;

    /**
     * Get all fields
     *
     * Controls obtaining of all attributes on refresh and update
     *
     * @property {boolean}
     */
    that.get_all_attrs = spec.get_all_attrs !== undefined ? spec.get_all_attrs: true;

    /**
     * Facet label
     * @property {string}
     */
    that.label = text.get(spec.label) || text.get('facets.details');

    /**
     * Facet group
     * @property {string}
     */
    that.facet_group = spec.facet_group || 'settings';

    /**
     * Widgets
     * @property {IPA.widget_container}
     */
    that.widgets = IPA.widget_container();

    /**
     * Fields
     * @property {IPA.field_container}
     */
    that.fields = IPA.field_container({ container: that });

    that.fields.add_field = function(field) {

        if (field.dirty_changed) {
            field.dirty_changed.attach(that.field_dirty_changed);
        }
        that.fields.container_add_field(field);
    };

    /**
     * Class for details section, defines layout
     * @property {string}
     */
    that.section_layout_class = spec.section_layout_class || exp.details_section_layout_class;

    /**
     * Dirty
     *
     * - true if any field is dirty
     * @property {boolean}
     */
    that.dirty = false;

    /**
     * Dirty changed
     * @event
     */
    that.dirty_changed = IPA.observer();

    /**
     * Get field
     * @param {string} name Field name
     * @returns {IPA.field}
     */
    that.get_field = function(name) {
        return that.fields.get_field(name);
    };

    /**
     * @inheritDoc
     */
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

    /**
     * Create header controls
     *
     * - ie control buttons
     */
    that.create_controls = function() {

        that.create_control_buttons(that.controls_left);
        that.create_action_dropdown(that.controls_left);
    };

    /**
     * @inheritDoc
     */
    that.create_header = function(container) {

        that.facet_create_header(container);

        that.create_controls();
    };

    /**
     * @inheritDoc
     */
    that.create_content = function(container) {

        that.content = $('<div/>', {
            'class': 'details-content row'
        }).appendTo(container);

        that.widgets.create(that.content);
    };

    /**
     * @inheritDoc
     */
    that.show = function() {
        that.facet_show();
        var pkey = that.get_pkey();
        that.header.set_pkey(pkey);
    };

    /**
     * Field's dirty event handler
     *
     * Sets this dirty state
     *
     * @protected
     * @param {boolean} dirty
     */
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

    /**
     * Evaluates if facet is dirty.
     *
     * Facet is dirty if any child widget is dirty.
     * @return {boolean} dirty
     */
    that.is_dirty = function() {
        var fields = that.fields.get_fields();
        for (var i=0; i<fields.length; i++) {
            if (fields[i].enabled && fields[i].dirty) {
                return true;
            }
        }
        return false;
    };

    /**
     * @inheritDoc
     */
    that.load = function(data) {
        that.facet_load(data);

        var fields = that.fields.get_fields();
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];

            if (field.autoload_value) field.load(data);
        }
        that.policies.post_load(data);
        that.post_load.notify([data], that);
        that.clear_expired_flag();
    };

    /**
     * Save fields' values into record
     * @param {Object} record
     */
    that.save = function(record) {
        var fields = that.fields.get_fields();
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            field.save(record);
        }
    };

    /**
     * Creates update info
     *
     * - used when in 'save' command mode
     *
     * This update info consists of fields' update information
     *
     * @param {boolean} [only_dirty=false] collect update information only from
     *                                     dirty fields
     * @param {boolean} [require_value=false] collect update information from
     *                                        fields which has value
     * @return {details.update_info}
     */
    that.save_as_update_info = function(only_dirty, require_value) {

        var update_info = IPA.update_info_builder.new_update_info();
        var fields = that.fields.get_fields();

        for (var i=0; i<fields.length; i++) {
            var field = fields[i];

            if (!field.enabled || only_dirty && !field.dirty) continue;

            var values = field.save();
            if (require_value && !values) continue;

            update_info.append_field(field, values);
        }

        return update_info;
    };

    /**
     * Reset facet
     */
    that.reset = function() {
        var fields = that.fields.get_fields();
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            field.reset();
        }
    };

    /**
     * Validate all fields
     * @return {boolean} all fields are valid
     */
    that.validate = function() {
        var valid = true;
        var fields = that.fields.get_fields();
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            valid = field.validate() && field.validate_required() && valid;
        }
        return valid;
    };

    /**
     * Notifies successful update
     * @protected
     */
    that.nofify_update_success = function() {
        var msg = text.get('@i18n:details.updated');
        var key = that.get_pkey();
        msg = msg.replace('${entity}', that.entity.metadata.label_singular);
        msg = msg.replace('${primary_key}', key);
        IPA.notify_success(msg);
    };

    /**
     * Update success handler
     *
     * Invokes Load by default.
     *
     * This is the method to override if different actions need to be taken
     * on update success.
     *
     * @protected
     * @param {Object} data
     * @param {string} text_status
     * @param {XMLHttpRequest} xhr
     */
    that.update_on_success = function(data, text_status, xhr) {
        that.load(data);
        that.on_update.notify();
        that.nofify_update_success();
    };

    /**
     * Update error handler
     *
     * This is the method to override if different actions need to be taken
     * on update error.
     *
     * @protected
     * @param {XMLHttpRequest} xhr
     * @param {string} text_status
     * @param {Object} error_thrown
     */
    that.update_on_error = function(xhr, text_status, error_thrown) {
    };

    /**
     * Adds update info as command options
     * @protected
     * @param {details.update_info} update_info
     * @param {rpc.command} command
     */
    that.add_fields_to_command = function(update_info, command) {

        for (var i=0; i < update_info.fields.length; i++) {
            var field_info = update_info.fields[i];
            if (field_info.field.flags.indexOf('no_command') > -1) continue;
            var values = field_info.field.save();
            exp.command_builder.add_field_option(
                command,
                field_info.field,
                values);
        }
    };

    /**
     * Create update command based on field part of update info
     * @protected
     * @param {details.update_info} update_info
     * @return {rpc.command}
     */
    that.create_fields_update_command = function(update_info) {

        var args = that.get_pkeys();

        var options = {};
        if (that.get_all_attrs) options.all = true;
        if (that.check_rights) options.rights = true;

        var command = rpc.command({
            entity: that.entity.name,
            method: that.update_command_name,
            args: args,
            options: options
        });

        //set command options
        that.add_fields_to_command(update_info, command);

        return command;
    };

    /**
     * Create batch command from update info
     *
     * Created batch command consists of update info's commands and a mod command
     * to reflect field part of update info (if present).
     * @protected
     * @param {details.update_info} update_info
     * @return {rpc.batch_command}
     */
    that.create_batch_update_command = function(update_info) {

        var batch = rpc.batch_command({
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

    /**
     * Show validation error
     * @protected
     */
    that.show_validation_error = function() {
        IPA.notify('@i18n:dialogs.validation_message', 'error');
    };

    /**
     * Create update command
     * @protected
     * @return {rpc.command|rpc.batch_command}
     */
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

    /**
     * Perform update operation
     *
     * Update reflects current state into data store.
     *
     * @param {Function} on_success success handler
     * @param {Function} on_error error handler
     */
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

    /**
     * Get refresh command name
     * @protected
     * @return {string}
     */
    that.get_refresh_command_name = function() {
        return that.entity.name+'_'+that.refresh_command_name;
    };

    /**
     * Create refresh command
     * @protected
     * @return {rpc.command}
     */
    that.create_refresh_command = function() {

        var options = {};
        if (that.get_all_attrs) options.all = true;
        if (that.check_rights) options.rights = true;

        var command = rpc.command({
            name: that.get_refresh_command_name(),
            entity: that.entity.name,
            method: that.refresh_command_name,
            options: options
        });

        if (that.get_pkey()) {
            command.args = that.get_pkeys();
        }

        return command;
    };

    /**
     * Refresh success handler
     * @protected
     * @param {Object} data
     * @param {string} text_status
     * @param {XMLHttpRequest} xhr
     */
    that.refresh_on_success = function(data, text_status, xhr) {
        that.load(data);
        that.show_content();
    };

    /**
     * Refresh error handler
     * @protected
     * @param {XMLHttpRequest} xhr
     * @param {string} text_status
     * @param {Object} error_thrown
     */
    that.refresh_on_error = function(xhr, text_status, error_thrown) {
        that.redirect_error(error_thrown);
        that.report_error(error_thrown);
    };

    /**
     * @inheritDoc
     */
    that.refresh = function(on_success, on_error) {

        if (!that.get_pkey() && that.entity.redirect_facet) {
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

    /**
     * @inheritDoc
     */
    that.clear = function() {
        that.header.clear();

        that.widgets.clear();
    };

    /**
     * Create update info
     *
     * - used in `update_info` command mode
     * @protected
     * @return {details.update_info}
     */
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

    /**
     * Create builders needed for initialization
     * @protected
     */
    that.create_builder = function() {

        var widget_builder = IPA.widget_builder({
            widget_options: {
                entity: that.entity,
                facet: that
            }
        });
        var field_builder = IPA.field_builder({
            field_options: {
                entity: that.entity,
                facet: that
            }
        });
        var section_builder = IPA.section_builder({
            container: that,
            widget_builder: widget_builder,
            field_builder: field_builder,
            section_spec: {
                $factory: IPA.details_section,
                layout_css_class: that.section_layout_class
            }
        });

        that.builder = IPA.details_builder({
            container: that,
            widget_builder: widget_builder,
            field_builder: field_builder,
            section_builder: section_builder
        });
    };

    /**
     * Initialize details facet
     *
     * - called automatically if `no_init==true` is not present
     *
     * @protected
     */
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

/**
 * Update info
 * @class details.update_info
 * @alternateClassName IPA.update_info
 */
exp.update_info = IPA.update_info = function(spec) {

    var that = IPA.object();

    /**
     * Fields update info
     * @property {Array.<details.field_info>}
     */
    that.fields = spec.fields || [];

    /**
     * Update commands info
     * @property {Array.<details.command_info>}
     */
    that.commands = spec.commands || [];

    /**
     * Create new field info and add it to collection
     * @param {IPA.field} field
     * @param {Object} value field's value
     */
    that.append_field = function(field, value) {
        var field_info = IPA.update_info_builder.new_field_info(field, value);
        that.fields.push(field_info);
    };

    /**
     * Create new command info and add it to collection
     * @param {rpc.command} command
     * @param {number} priority
     */
    that.append_command = function (command, priority) {
        var command_info = IPA.update_info_builder.new_command_info(command, priority);
        that.commands.push(command_info);
    };

    return that;
};

/**
 * Command info
 * @class details.command_info
 * @alternateClassName IPA.command_info
 */
exp.command_info = IPA.command_info = function(spec) {

    var that = IPA.object();

    /**
     * Command
     * @property {rpc.command}
     */
    that.command = spec.command;

    /**
     * Priority
     *
     * - controls command execution order
     * @property {number}
     */
    that.priority = spec.priority || IPA.config.default_priority;

    return that;
};

/**
 * Field update info
 * @class details.field_info
 * @alternateClassName IPA.field_info
 */
exp.field_info = IPA.field_info = function(spec) {

    var that = IPA.object();

    /**
     * Field
     * @property {IPA.field}
     */
    that.field = spec.field;

    /**
     * Value
     * @property {Object}
     */
    that.value = spec.value;

    return that;
};

/**
 * Update info builder
 * @class details.update_info_builder
 * @alternateClassName IPA.update_info_builder
 * @singleton
 */
exp.update_info_builder = IPA.update_info_builder = function() {

    var that = IPA.object();

    /**
     * Create update info from field and command infos
     * @param {Array.<details.field_info>} fields
     * @param {Array.<details.command_info>} commands
     * @return {details.update_info}
     */
    that.new_update_info = function (fields, commands) {
        return IPA.update_info({
            fields: fields,
            commands: commands
        });
    };

    /**
     * Create field info
     * @param {details.field_info} field
     * @param {Object} value
     * @return {details.field_info}
     */
    that.new_field_info = function(field, value) {
        return IPA.field_info({
            field: field,
            value: value
        });
    };

    /**
     * Create new command info
     * @param {rpc.command} command
     * @param {number} priority
     * @return {details.command_info}
     */
    that.new_command_info = function(command, priority) {
        return IPA.command_info({
            command: command,
            priority: priority
        });
    };

    /**
     * Merge two commands info into new one
     * @param {details.command_info} a
     * @param {details.command_info} b
     * @return {details.command_info}
     */
    that.merge = function(a, b) {
        return that.new_update_info(
            a.fields.concat(b.fields),
            a.commands.concat(b.commands));
    };

    /**
     * Create copy of command info
     * @param {details.command_info} original
     * @return {details.command_info} copy
     */
    that.copy = function(original) {
        return that.new_update_info(
            original.fields.concat([]),
            original.commands.concat([]));
    };

    return that;
}();

/**
 * Field add/mod command builder
 *
 * @class details.command_builder
 * @singleton
 */
exp.command_builder = function() {

    var that = IPA.object();

    /**
     * Add option to command with field values
     * @param {rpc.command} command
     * @param {IPA.field} field
     * @param {Array} values
     */
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

/**
 * Invokes `facet.refresh`
 * @class details.refresh_action
 * @alternateClassName IPA.refresh_action
 * @extends facet.action
 */
exp.refresh_action = IPA.refresh_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'refresh';
    spec.label = spec.label || '@i18n:buttons.refresh';

    var that = IPA.action(spec);

    that.execute_action = function(facet) {
        facet.refresh();
    };

    return that;
};

/**
 * Invokes `facet.reset`
 * @class details.reset_action
 * @alternateClassName IPA.reset_action
 * @extends facet.action
 */
exp.reset_action = IPA.reset_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'revert';
    spec.label = spec.label || '@i18n:buttons.revert';
    spec.enable_cond = spec.enable_cond || ['dirty'];

    var that = IPA.action(spec);

    that.execute_action = function(facet) {
        facet.reset();
    };

    return that;
};

/**
 * Invokes validation and then `facet.update`
 * @class details.update_action
 * @alternateClassName IPA.update_action
 * @extends facet.action
 */
exp.update_action = IPA.update_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'save';
    spec.label = spec.label || '@i18n:buttons.save';
    spec.needs_confirm = spec.needs_confirm !== undefined ? spec.needs_confirm : false;
    spec.enable_cond = spec.enable_cond || ['dirty'];

    var that = IPA.action(spec);

    that.execute_action = function(facet) {

        if (!facet.validate()) {
            facet.show_validation_error();
            widget_mod.focus_invalid(facet);
            return;
        }

        facet.update();
    };

    return that;
};

/**
 * Sets state based on value of loaded boolean attribute.
 * - evaluated on post load by default
 *
 * @class details.boolean_state_evaluator
 * @alternateClassName IPA.boolean_state_evaluator
 * @extends facet.state_evaluator
 */
exp.boolean_state_evaluator = IPA.boolean_state_evaluator = function(spec) {

    spec = spec || {};

    spec.event = spec.event || 'post_load';

    var that = IPA.state_evaluator(spec);

    /**
     * @inheritDoc
     */
    that.name = spec.name || 'boolean_state_evaluator';

    /**
     * Attribute's name
     *
     * - spec name: `field`
     * @property {string}
     */
    that.field_name = spec.field;

    that.param = spec.param || that.field_name;

    that.adapter = builder.build('adapter', spec.adapter || 'adapter', { context: that });

    /**
     * State to set when value is `true`
     * @property {string}
     */
    that.true_state = spec.true_state || that.field_name + '-true';

    /**
     * State to set when value is `false`
     * @property {string}
     */
    that.false_state = spec.false_state || that.field_name + '-false';

    /**
     * Inverts evaluation logic
     *
     * NOTE: is ignored when custom parser is set
     *
     * @property {boolean}
     */
    that.invert_value = spec.invert_value;

    /**
     * Value parser
     *
     * @property {IPA.boolean_formatter}
     */
    that.parser = IPA.build(spec.parser || {
        $factory: IPA.boolean_formatter,
        invert_value: that.invert_value
    });

    /**
     * @inheritDoc
     */
    that.on_event = function(data) {

        var old_state = that.state;
        that.state = [];

        var value = that.adapter.load(data);
        value = that.parser.parse(value);

        if (value === true) {
            that.state.push(that.true_state);
        } else {
            that.state.push(that.false_state);
        }

        that.notify_on_change(old_state);
    };

    return that;
};

/**
 * Evaluates enabled/disabled state
 *
 *      // in facet spec
 *      evaluators: [
 *          {
 *              $factory: IPA.enable_state_evaluator,
 *              field: 'ipaenabledflag'
 *          }
 *      ],
 *
 * @class details.enable_state_evaluator
 * @alternateClassName IPA.enable_state_evaluator
 * @extends details.boolean_state_evaluator
 */
exp.enable_state_evaluator = IPA.enable_state_evaluator = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'enable_state_evaluator';
    spec.true_state = spec.true_state || 'enabled';
    spec.false_state = spec.false_state || 'disabled';

    var that = IPA.boolean_state_evaluator(spec);

    return that;
};

/**
 * Create state for each attribute level right user has for specific attribute
 *
 * - on post load
 * - state value is $(ATTR_NAME)_$(RIGHT) where right is a letter (one of 'rscwo')
 *
 * @class details.acl_state_evaluator
 * @alternateClassName IPA.acl_state_evaluator
 * @extends facet.state_evaluator
 */
exp.acl_state_evaluator = IPA.acl_state_evaluator = function(spec) {

    spec.name = spec.name || 'acl_state_evaluator';
    spec.event = spec.event || 'post_load';

    var that = IPA.state_evaluator(spec);
    /**
     * Attribute name
     * @property {string}
     */
    that.attribute = spec.attribute;

    that.param = spec.param || 'attributelevelrights';

    that.adapter = builder.build('adapter', spec.adapter || 'adapter', { context: that });

    /**
     * @inheritDoc
     */
    that.on_event = function(data) {

        var old_state, record, all_rights, rights, i, state;

        old_state = that.state;
        that.state = [];

        all_rights = that.adapter.load(data);
        if (all_rights) {
            rights = all_rights[that.attribute];
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

/**
 * Evaluator which sets state when loaded value of specific attribute is equal
 * to desired value.
 *
 * @class details.value_state_evaluator
 * @alternateClassName IPA.value_state_evaluator
 * @extends facet.state_evaluator
 */
exp.value_state_evaluator = IPA.value_state_evaluator = function(spec) {

    spec.name = spec.name || 'value_state_evaluator';
    spec.event = spec.event || 'post_load';
    spec.adapter = spec.adapter || {};

    var that = IPA.state_evaluator(spec);

    /**
     * Attribute name
     * @property {string}
     */
    that.attribute = spec.attribute;

    /**
     * Desired value
     * @property {Mixed}
     */
    that.value = spec.value;

    /**
     * State to set
     *
     * If not set, state is created from attribute name and value:
     *      `$(ATTR_NAME)_$(VALUE)`
     * @property {string}
     */
    that.representation = spec.representation;

    that.adapter = builder.build('adapter',
                    spec.adapter, { context: that });

    that.param = spec.param;

    /**
     * @inheritDoc
     */
    that.on_event = function(data) {

        var old_state, value, loaded_value;

        old_state = that.state;
        value = that.normalize_value(that.value);
        that.state = [];

        loaded_value = that.adapter.load(data, spec.attribute);

        if(!IPA.array_diff(value, loaded_value)) {
            that.state.push(that.get_state_text());
        }

        that.notify_on_change(old_state);
    };

    /**
     * Normalize value
     *
     * - it's expected that value will be in array (to work with multivalued
     *   attributes)
     * - override point
     * @protected
     * @return {Mixed} value
     */
    that.normalize_value = function(original) {

        var value = original;

        if (!(value instanceof Array)) {
            value = [value];
        }
        return value;
    };

    /**
     * Create state
     *
     * If `representation` is not set, state is created from attribute name
     * and value:
     *      `$(ATTR_NAME)_$(VALUE)`
     *
     * @protected
     * @return {string} state
     */
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


/**
 * has_keytab evaluator
 *
 * @class details.has_keytab_evaluator
 * @alternateClassName IPA.has_keytab_evaluator
 * @extends facet.value_state_evaluator
 */
exp.has_keytab_evaluator = IPA.has_keytab_evaluator = function(spec) {

    spec.name = spec.name || 'has_keytab_evaluator';
    spec.attribute = spec.attribute || 'has_keytab';
    spec.value = spec.value || [true];
    spec.representation = spec.representation || 'has_keytab';
    spec.param = spec.param || 'has_keytab';
    spec.adapter = spec.adapter || { $type: 'adapter' };

    var that = IPA.value_state_evaluator(spec);

    return that;
};

/**
 * Object class evaluator
 *
 * Set state for each object class which loaded record has.
 *
 * State name is `oc_$(class)`
 *
 * @class details.object_class_evaluator
 * @alternateClassName IPA.object_class_evaluator
 * @extends facet.state_evaluator
 */
exp.object_class_evaluator = IPA.object_class_evaluator = function(spec) {

    spec.name = spec.name || 'object_class_evaluator';
    spec.event = spec.event || 'post_load';

    var that = IPA.state_evaluator(spec);


    /**
     * @inheritDoc
     */
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

/**
 * Base class for executing specific entity methods
 * - command options can be set
 * - facet pkeys are set as command arguments
 * - entity is fetched from facet
 * @class details.object_action
 * @alternateClassName IPA.object_action
 * @extends facet.action
 */
exp.object_action = IPA.object_action = function(spec) {

    spec = spec || {};

    var that = IPA.action(spec);

    /**
     * Method name
     * @property {string}
     */
    that.method = spec.method;

    /**
     * @inheritDoc
     */
    that.confirm_msg = text.get(spec.confirm_msg || '@i18n:actions.confirm');

    /**
     * Command options
     * @property {Object}
     */
    that.options = spec.options || {};

    /**
     * @protected
     * @inheritDoc
     */
    that.execute_action = function(facet, on_success, on_error) {

        var entity_name = facet.entity.name;
        var pkeys = facet.get_pkeys();

        rpc.command({
            entity: entity_name,
            method: that.method,
            args: pkeys,
            options: that.options,
            on_success: that.get_on_success(facet, on_success),
            on_error: that.get_on_error(facet, on_error)
        }).execute();
    };

    /**
     * Command success handler
     * @protected
     * @param {facet.facet} facet
     * @param {Object} data
     * @param {string} text_status
     * @param {XMLHttpRequest} xhr
     */
    that.on_success = function(facet, data, text_status, xhr) {

        IPA.notify_success(data.result.summary);
        facet.on_update.notify();
        facet.refresh();
    };

    /**
     * Command error handler
     * @protected
     * @param {facet.facet} facet
     * @param {XMLHttpRequest} xhr
     * @param {string} text_status
     * @param {Object} error_thrown
     */
    that.on_error = function(facet, xhr, text_status, error_thrown) {
        facet.refresh();
    };

    /**
     * Combines given success handler with action success handler so both
     * can be called.
     * @protected
     * @param {facet.facet} facet
     * @param {Function} on_success success handler
     */
    that.get_on_success = function(facet, on_success) {
        return function(data, text_status, xhr) {
            that.on_success(facet, data, text_status, xhr);
            if (on_success) on_success.call(this, data, text_status, xhr);
        };
    };

    /**
     * Combines given error handler with action error handler so both
     * can be called.
     * @protected
     * @param {facet.facet} facet
     * @param {Function} on_error error handler
     */
    that.get_on_error = function(facet, on_error) {
        return function(xhr, text_status, error_thrown) {
            that.on_error(facet, xhr, text_status, error_thrown);
            if (on_error) on_error.call(this, xhr, text_status, error_thrown);
        };
    };

    /**
     * @protected
     * @inheritDoc
     */
    that.get_confirm_message = function(facet) {
        var pkey = facet.get_pkey();
        var msg = that.confirm_msg.replace('${object}', pkey);
        return msg;
    };

    that.object_execute_action = that.execute_action;

    return that;
};

/**
 * Call 'enable' method of current entity
 * @class details.enable_action
 * @alternateClassName IPA.enable_action
 * @extends details.object_action
 */
exp.enable_action = IPA.enable_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'enable';
    spec.method = spec.method || 'enable';
    spec.needs_confirm = spec.needs_confirm !== undefined ? spec.needs_confirm : true;
    spec.confirm_msg = spec.confirm_msg || '@i18n:actions.enable_confirm';
    spec.label = spec.label || '@i18n:buttons.enable';
    spec.disable_cond = spec.disable_cond || ['enabled'];

    var that = IPA.object_action(spec);

    return that;
};

/**
 * Call 'disable' method of current entity
 * @class details.disable_action
 * @alternateClassName IPA.disable_action
 * @extends details.object_action
 */
exp.disable_action = IPA.disable_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'disable';
    spec.method = spec.method || 'disable';
    spec.needs_confirm = spec.needs_confirm !== undefined ? spec.needs_confirm : true;
    spec.confirm_msg = spec.confirm_msg || '@i18n:actions.disable_confirm';
    spec.label = spec.label || '@i18n:buttons.disable';
    spec.enable_cond = spec.enable_cond || ['enabled'];

    var that = IPA.object_action(spec);

    return that;
};

/**
 * Call 'delete' method of current entity
 *
 * Redirects to facet's redirect target on success by default.
 *
 * @class details.delete_action
 * @alternateClassName IPA.delete_action
 * @extends details.object_action
 */
exp.delete_action = IPA.delete_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'delete';
    spec.method = spec.method || 'del';
    spec.needs_confirm = spec.needs_confirm !== undefined ? spec.needs_confirm : true;
    spec.confirm_msg = spec.confirm_msg || '@i18n:actions.delete_confirm';
    spec.label = spec.label || '@i18n:buttons.remove';

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

/**
 * Summary condition for 'enabled' state
 *
 * @class details.enabled_summary_cond
 * @alternateClassName IPA.enabled_summary_cond
 * @extends facet.summary_cond
 */
exp.enabled_summary_cond = IPA.enabled_summary_cond = function() {

    var that = facet_mod.summary_cond ({
        pos: ['enabled'],
        neg: [],
        description: text.get('@i18n:status.enabled'),
        state: ['enabled']
    });
    return that;
};

/**
 * Summary condition for 'disabled' state
 *
 * @class details.disabled_summary_cond
 * @alternateClassName IPA.disabled_summary_cond
 * @extends facet.summary_cond
 */
exp.disabled_summary_cond = IPA.disabled_summary_cond = function() {
    var that = facet_mod.summary_cond({
        pos: [],
        neg: ['enabled'],
        description: text.get('@i18n:status.disabled'),
        state: ['disabled']
    });
    return that;
};

/**
 * Register facet and actions.
 *
 * @member details
 */
exp.register = function() {
    var a = reg.action;
    var f = reg.facet;

    a.register('refresh', exp.refresh_action);
    a.register('revert', exp.reset_action);
    a.register('save', exp.update_action);
    a.register('object', exp.object_action);
    a.register('enable', exp.enable_action);
    a.register('disable', exp.disable_action);
    a.register('delete', exp.delete_action);

    f.register({
        type: 'details',
        factory: IPA.details_facet,
        pre_ops: [
            exp.details_facet_pre_op
        ],
        spec: { name: 'details' }
    });
};

phases.on('registration', exp.register);

return exp;
});
