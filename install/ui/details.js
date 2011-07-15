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
    that.template = spec.template;
    that._entity_name = spec.entity_name;

    that.fields = $.ordered_map();

    that.__defineGetter__('entity_name', function() {
        return that._entity_name;
    });

    that.__defineSetter__('entity_name', function(entity_name) {
        that._entity_name = entity_name;

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            fields[i].entity_name = entity_name;
        }
    });

    that.get_field = function(name) {
        return that.fields.get(name);
    };

    that.add_field = function(field) {
        field.entity_name = that.entity_name;
        that.fields.put(field.name, field);
        return field;
    };

    that.field = function(field) {
        that.add_field(field);
        return that;
    };

    that.text = function(spec) {
        var field = IPA.text_widget(spec);
        that.add_field(field);
        return that;
    };

    that.multivalued_text = function(spec) {
        spec.entity_name = that.entity_name;
        var field = IPA.multivalued_text_widget(spec);
        that.add_field(field);
        return that;
    };

    that.textarea = function(spec) {
        var field = IPA.textarea_widget(spec);
        that.add_field(field);
        return that;
    };

    that.radio = function(spec) {
        var field = IPA.radio_widget(spec);
        that.add_field(field);
        return that;
    };

    that.init = function() {
        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            field.init();
        }
    };

    that.create = function(container) {

        if (that.template) return;

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];

            var field_container = $('<div/>', {
                name: field.name,
                'class': 'details-field'
            }).appendTo(container);
            field.create(field_container);
        }
    };

    that.setup = function(container) {

        that.container = container;

        if (that.template) return;

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];

            var field_container = $('.details-field[name='+field.name+']', this.container).first();
            field.setup(field_container);
        }
    };

    that.load = function(record) {

        that.record = record;

        var fields = that.fields.values;

        if (that.template) {
            var template = IPA.get_template(that.template);
            this.container.load(
                template,
                function(data, text_status, xhr) {
                    for (var i=0; i<fields.length; i++) {
                        var field = fields[i];
                        var span = $('span[name='+field.name+']', this.container).first();
                        field.setup(span);
                        field.load(record);
                    }
                }
            );
            return;
        }

        for (var j=0; j<fields.length; j++) {
            var field = fields[j];
            field.load(record);
        }
    };

    that.reset = function() {
        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];
            field.reset();
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

    // methods that should be invoked by subclasses
    that.section_init = that.init;
    that.section_create = that.create;
    that.section_setup = that.setup;
    that.section_load = that.load;
    that.section_reset = that.reset;

    return that;
};


/**
 * This class creates a details section formatted as a list of
 * attributes names and values. The list is defined using a <dl> tag.
 * The attribute name is defined inside a <dt> tag. The attribute
 * value is specified within a <span> inside a <dd> tag. If the
 * attribute has multiple values the <span> will contain be
 * duplicated to display each value.
 *
 * Example:
 *   <dl class="entryattrs">
 *
 *     <dt title="givenname">First Name:</dt>
 *     <dd>
 *       <span name="givenname">
 *         John Smith
 *       </span>
 *     </dd>
 *
 *     <dt title="telephonenumber">Telephone Number:</dt>
 *     <dd>
 *       <span name="telephonenumber">
 *         <div name="value">111-1111</div>
 *         <div name="value">222-2222</div>
 *       </span>
 *     </dd>
 *
 *   </dl>
 */
IPA.details_list_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_section(spec);

    that.create = function(container) {

        // do not call section_create() here

        if (that.template) return;

        var dl = $('<dl/>', {
            'id': that.name,
            'class': 'entryattrs'
        }).appendTo(container);

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];

            var label = field.label || '';

            $('<dt/>', {
                html: label+':',
                title: label
            }).appendTo(dl);

            var dd = $('<dd/>').appendTo(dl);

            var field_container = $('<div/>', {
                name: field.name,
                'class': 'details-field'
            }).appendTo(dd);
            field.create(field_container);
        }
    };

    return that;
};

IPA.details_facet = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'details';

    var that = IPA.facet(spec);

    that.pre_execute_hook = spec.pre_execute_hook;

    that.label = spec.label || IPA.messages && IPA.messages.facets && IPA.messages.facets.details;
    that.facet_group = spec.facet_group || 'settings';

    that.sections = $.ordered_map();

    that.__defineGetter__("entity_name", function(){
        return that._entity_name;
    });

    that.__defineSetter__("entity_name", function(entity_name){
        that._entity_name = entity_name;

        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            sections[i].entity_name = entity_name;
        }
    });

    that.add_section = function(section) {
        section.entity_name = that.entity_name;
        that.sections.put(section.name, section);
        return section;
    };

    that.get_section = function(name) {
        return that.sections.get(name);
    };

    that.create_section = function(spec) {
        var section = IPA.details_section(spec);
        that.add_section(section);
        return section;
    };

    that.init = function() {

        that.facet_init();

        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];
            section.init();
        }
    };

    /* the primary key used for show and update is built as an array.
       for most entities, this will be a single element long, but for some
       it requires the containing entities primary keys as well.*/
    that.get_primary_key = function(from_url) {

        var pkey = IPA.get_entity(that.entity_name).get_primary_key_prefix();

        if (from_url) {
            pkey.push(that.pkey);
        } else {
            var pkey_name = IPA.metadata.objects[that.entity_name].primary_key;
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
            'class': 'details-reset',
            click: function() {
                that.reset();
                return false;
            }
        }).appendTo(that.controls);

        that.update_button = IPA.action_button({
            name: 'update',
            label: IPA.messages.buttons.update,
            icon: 'update-icon',
            'class': 'details-update',
            click: function() {
                that.update();
                return false;
            }
        }).appendTo(that.controls);
    };

    that.create_header = function(container) {

        that.facet_create_header(container);

        that.pkey = IPA.nav.get_state(that.entity_name+'-pkey');

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

    that.setup = function(container) {

        that.facet_setup(container);

        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];

            var div = $('.details-section[name='+section.name+']', that.container);

            section.setup(div);
        }
    };

    that.show = function() {
        that.facet_show();

        that.pkey = IPA.nav.get_state(that.entity_name+'-pkey');
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

    function new_key(){
        var pkey = IPA.nav.get_state(that.entity_name+'-pkey');
        return pkey != that.pkey;
    }
    that.new_key = new_key;


    that.is_dirty = function() {
        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            if (sections[i].is_dirty()) {
                return true;
            }
        }
        return false;
    };

    that.load = function(data) {
        that.facet_load(data);

        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];
            section.load(data);
        }
    };

    that.reset = function() {
        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];
            section.reset();
        }
    };

    that.update = function(on_win, on_fail) {

        var entity_name = that.entity_name;

        function on_success(data, text_status, xhr) {
            if (on_win)
                on_win(data, text_status, xhr);
            if (data.error)
                return;

            var result = data.result.result;
            that.load(result);
        }

        function on_error(xhr, text_status, error_thrown) {
            if (on_fail)
                on_fail(xhr, text_status, error_thrown);
        }

        var args = that.get_primary_key();

        var command = IPA.command({
            entity: entity_name,
            method: 'mod',
            args: args,
            options: {
                all: true,
                rights: true
            },
            on_success: on_success,
            on_error: on_error
        });

        var values;

        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];

            if (section.save) {
                section.save(command.options);
                continue;
            }

            var section_fields = section.fields.values;
            for (var j=0; j<section_fields.length; j++) {
                var field = section_fields[j];
                if (!field.is_dirty()) continue;

                values = field.save();
                if (!values) continue;

                var param_info =  field.param_info;
                if (param_info) {
                    if (param_info.primary_key) continue;
                    if (values.length === 1) {
                        command.set_option(field.name, values[0]);
                    } else if (field.join) {
                        command.set_option(field.name, values.join(','));
                    } else {
                        command.set_option(field.name, values);
                    }
                }  else {
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

        //alert(JSON.stringify(command.to_json()));

        if (that.pre_execute_hook){
            that.pre_execute_hook(command);
        }

        command.execute();
    };

    that.refresh = function() {

        that.pkey = IPA.nav.get_state(that.entity_name+'-pkey');

        var command = IPA.command({
            entity: that.entity_name,
            method: 'show',
            options: { all: true, rights: true }
        });

        if (IPA.details_refresh_devel_hook) {
            IPA.details_refresh_devel_hook(that.entity_name, command, that.pkey);
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

    that.details_facet_init = that.init;
    that.details_facet_create_content = that.create_content;
    that.details_facet_load = that.load;
    that.details_facet_setup = that.setup;

    return that;
};

IPA.action_button = function(spec) {
    var button = IPA.button(spec);
    button.removeClass("ui-state-default").addClass("action-button");
    return button;
};

IPA.button = function(spec) {

    spec = spec || {};

    var button = $('<a/>', {
        id: spec.id,
        name: spec.name,
        href: spec.href || '#' + (spec.name || 'button'),
        title: spec.title || spec.label,
        'class': 'ui-state-default ui-corner-all input_link',
        style: spec.style,
        click: spec.click,
        blur: spec.blur
    });

    if (spec['class']) button.addClass(spec['class']);

    if (spec.icon) {
        $('<span/>', {
            'class': 'icon '+spec.icon
        }).appendTo(button);
    }

    if (spec.label) {
        $('<span/>', {
            'class': 'button-label',
            html: spec.label
        }).appendTo(button);
    }

    return button;
};
