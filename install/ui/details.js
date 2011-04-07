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

IPA.expand_icon = 'ui-icon-minus';
IPA.collapse_icon = 'ui-icon-plus';

IPA.details_section = function(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name || '';
    that.label = spec.label || '';
    that.template = spec.template;
    that._entity_name = spec.entity_name;

    that.fields = [];
    that.fields_by_name = {};

    that.__defineGetter__('entity_name', function() {
        return that._entity_name;
    });

    that.__defineSetter__('entity_name', function(entity_name) {
        that._entity_name = entity_name;

        for (var i=0; i<that.fields.length; i++) {
            that.fields[i].entity_name = entity_name;
        }
    });

    that.get_field = function(name) {
        return that.fields_by_name[name];
    };

    that.add_field = function(field) {
        field.entity_name = that.entity_name;
        that.fields.push(field);
        that.fields_by_name[field.name] = field;
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
        for (var i=0; i<that.fields.length; i++) {
            var field = that.fields[i];
            field.init();
        }
    };

    that.create = function(container) {

        if (that.template) return;

        var fields = that.fields;
        for (var i = 0; i < fields.length; ++i) {
            var field = fields[i];

            var span = $('<span/>', { 'name': field.name }).appendTo(container);
            field.create(span);
        }
    };

    that.setup = function(container) {

        that.container = container;

        if (that.template) return;

        var fields = that.fields;
        for (var i = 0; i < fields.length; ++i) {
            var field = fields[i];

            var span = $('span[name='+field.name+']', this.container).first();
            field.setup(span);
        }
    };

    that.load = function(record) {

        that.record = record;

        var fields = that.fields;

        if (that.template) {
            var template = IPA.get_template(that.template);
            this.container.load(
                template,
                function(data, text_status, xhr) {
                    for (var i = 0; i < fields.length; ++i) {
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
            var span = $('span[name='+field.name+']', this.container).first();
            field.load(record);
        }
    };

    that.reset = function() {
        for (var i=0; i<that.fields.length; i++) {
            var field = that.fields[i];
            var span = $('span[name='+field.name+']', this.container).first();
            field.reset();
        }
    };

    that.is_dirty = function() {
        for (var i=0; i<that.fields.length; i++) {
            var field = that.fields[i];
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

        var fields = that.fields;
        for (var i = 0; i < fields.length; ++i) {
            var field = fields[i];

            var label = field.label || '';

            $('<dt/>', {
                html: label+':',
                title: label
            }).appendTo(dl);

            var dd = $('<dd/>', {
                'class': 'first'
            }).appendTo(dl);

            var span = $('<span/>', { 'name': field.name }).appendTo(dd);
            field.create(span);
        }
    };

    return that;
};

IPA.details_facet = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'details';

    var that = IPA.facet(spec);

    that.label =  ( IPA.messages && IPA.messages.facets &&  IPA.messages.facets.details)  || spec.label;
    that.is_dirty = spec.is_dirty || is_dirty;
    that.create_content = spec.create_content || create_content;
    that.setup = spec.setup || setup;
    that.load = spec.load || load;
    that.update = spec.update || IPA.details_update;
    that.reset = spec.reset || reset;
    that.refresh = spec.refresh || IPA.details_refresh;

    that.sections = [];

    that.__defineGetter__("entity_name", function(){
        return that._entity_name;
    });

    that.__defineSetter__("entity_name", function(entity_name){
        that._entity_name = entity_name;

        for (var i=0; i<that.sections.length; i++) {
            that.sections[i].entity_name = entity_name;
        }
    });

    that.add_section = function(section) {
        section.entity_name = that.entity_name;
        that.sections.push(section);
        return section;
    };

    that.section = function(section) {
        that.add_section(section);
        return that;
    };

    that.create_section = function(spec) {
        var section = IPA.details_section(spec);
        that.add_section(section);
        return section;
    };

    that.init = function() {

        that.facet_init();

        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections[i];
            section.init();
        }
    };

    that.get_primary_key = function() {
        var pkey_name = IPA.metadata.objects[that.entity_name].primary_key;
        if (that.record[pkey_name] instanceof Array){
            return that.record[pkey_name][0];
        }else{
            return that.record[pkey_name];
        }
    };

    function create_content(container) {

        var label = IPA.metadata.objects[that.entity_name].label;

        var title = IPA.messages.details.settings;
        title = title.replace('${entity}', label);

        $('<h1/>',{
            html: "<span id='headerpkey' />"+title
        }).append(IPA.create_network_spinner()).
            appendTo(container);

        var details = $('<div/>', {
            'name': 'details'
        }).appendTo(container);

        $('<a/>', {
            name: 'expand_all',
            href: 'expand_all',
            text: 'Expand All',
            'class': 'expand-collapse-all',
            style: 'display: none;'
        }).appendTo(details);

        $('<a/>', {
            name: 'collapse_all',
            href: 'collapse_all',
            text: 'Collapse All',
            'class': 'expand-collapse-all'
        }).appendTo(details);

        details.append('<br/>');

        var action_panel = that.get_action_panel();

        var ul = $('ul', action_panel);
        var buttons = $('.action-controls',action_panel);

        $('<input/>', {
            'type': 'text',
            'name': 'reset'
        }).appendTo(buttons);

        $('<input/>', {
            'type': 'text',
            'name': 'update'
        }).appendTo(buttons);


        for (var i = 0; i < that.sections.length; ++i) {
            var section = that.sections[i];

            var header = $('<h2/>', {
                name: section.name,
                title: section.label
            }).appendTo(details);

            var icon = $('<span/>', {
                name: 'icon',
                'class': 'ui-icon section-expand '+IPA.expand_icon
            }).appendTo(header);

            header.append(' ');

            header.append(section.label);

            var div = $('<div/>', {
                name: section.name,
                'class': 'details-section'
            }).appendTo(details);

            section.create(div);

            details.append('<hr/>');
        }
    }

    function setup(container) {

        that.facet_setup(container);

        var button = $('input[name=reset]', that.container);
        that.reset_button = IPA.action_button({
            'label': 'Reset',
            'icon': 'ui-icon-refresh',
            'class': 'details-reset',
            'click': function() {
                that.reset();
                return false;
            }
        });
        button.replaceWith(that.reset_button);

        button = $('input[name=update]', that.container);
        that.update_button = IPA.action_button({
            'label': 'Update',
            'icon': 'ui-icon-check',
            'class': 'details-update',
            'click': function() {
                that.update();
                return false;
            }
        });
        button.replaceWith(that.update_button);

        var details = $('div[name=details]', that.container);

        var expand_all = $('a[name=expand_all]', details);
        expand_all.click(function() {
            expand_all.css('display', 'none');
            collapse_all.css('display', 'inline');

            for (var i=0; i<that.sections.length; i++) {
                var section = that.sections[i];
                toggle(section, true);
            }

            return false;
        });

        var collapse_all = $('a[name=collapse_all]', details);
        collapse_all.click(function() {
            expand_all.css('display', 'inline');
            collapse_all.css('display', 'none');

            for (var i=0; i<that.sections.length; i++) {
                var section = that.sections[i];
                toggle(section, false);
            }

            return false;
        });

        for (var i = 0; i < that.sections.length; ++i) {
            var section = that.sections[i];

            var header = $('h2[name='+section.name+']', that.container);
            var div = $('div.details-section[name='+section.name+']', that.container);

            header.click(function(section, div) {
                return function() {
                    var visible = div.is(":visible");
                    toggle(section, !visible);
                };
            }(section, div));

            section.setup(div);
        }
    }

    function toggle(section, visible) {
        var header = $('h2[name='+section.name+']', that.container);

        var icon = $('span[name=icon]', header);
        icon.toggleClass(IPA.expand_icon, visible);
        icon.toggleClass(IPA.collapse_icon, !visible);

        var div = section.container;

        if (visible != div.is(":visible")) {
            div.slideToggle();
        }
    }

    function new_key(){
        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        return pkey != that.pkey;
    }
    that.new_key = new_key;


    function is_dirty() {

        var i;
        for ( i =0; i <   that.sections.length; i +=1 ){
            if (that.sections[i].is_dirty()){
                return true;
            }
        }

        return false;
    }

    function load(record) {
        that.record = record;
        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections[i];
            section.load(record);
        }
        if (that.pkey){
            $('h1 #headerpkey',that.container).html(that.pkey+": ");
        }
    }

    function reset() {

        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections[i];
            section.reset();
        }
    }

    that.details_facet_init = that.init;
    that.details_facet_create_content = that.create_content;
    that.details_facet_load = that.load;

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
        html: spec.label,
        title: spec.title || spec.label,
        'class': 'ui-state-default ui-corner-all'
    });

    if (spec.click) {
        button.click(spec.click);
    }

    if (spec['class']) button.addClass(spec['class']);

    if (spec.icon) {
        button.addClass('input_link');
        button.append('<span class="ui-icon '+spec.icon+'" ></span> ');
    } else {
        button.addClass('button-without-icon');
    }

    return button;
};

IPA.details_refresh = function() {

    var that = this;

    that.pkey = $.bbq.getState(that.entity_name + '-pkey', true) ;

    var command = IPA.command({
        method: that.entity_name+'_show',
        args:  [],
        options: { 'all': true, 'rights': true }
    });
    
    if (IPA.details_refresh_devel_hook){
        IPA.details_refresh_devel_hook(that.entity_name,command,that.pkey);
    }


    if (that.pkey){
        command.args =  [that.pkey];
    }

    command.on_success = function(data, text_status, xhr) {
        that.load(data.result.result);
    };

    command.on_error = function(xhr, text_status, error_thrown) {
        var details = $('.details', that.container).empty();
        details.append('<p>Error: '+error_thrown.name+'</p>');
        details.append('<p>'+error_thrown.title+'</p>');
        details.append('<p>'+error_thrown.message+'</p>');
    };

    command.execute();
};

IPA.details_update = function(on_win, on_fail) {
    var that = this;
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

    var values;
    var modlist = {'all': true, 'setattr': [], 'addattr': [], 'rights': true};
    var attrs_wo_option = {};

    for (var i=0; i<that.sections.length; i++) {
        var section = that.sections[i];

        if (section.save){
            section.save(modlist);
            continue;
        }

        for (var j=0; j<section.fields.length; j++) {
            var field = section.fields[j];

            var span = $('span[name='+field.name+']', section.container).first();
            values = field.save();
            if (!values) continue;

            var param_info = IPA.get_entity_param(entity_name, field.name);
            if (param_info) {
                if (param_info['primary_key']) continue;
                if (values.length === 1) {
                    modlist[field.name] = values[0];
                } else if (values.length > 1){
                    if (field.join) {
                        modlist[field.name] = values.join(',');
                    } else {
                        modlist[field.name] = values;
                    }
                } else if (param_info['multivalue']){
                    modlist[field.name] = [];
                }
            } else {
                if (values.length) attrs_wo_option[field.name] = values;
            }
        }
    }

    for (var attr in attrs_wo_option) {
        values = attrs_wo_option[attr];
        modlist['setattr'].push(attr + '=' + values[0]);
        for (var k = 1; k < values.length; ++k){
            modlist['addattr'].push(attr + '=' + values[k]);
        }
    }

    var pkey = that.get_primary_key();

    var args = pkey ? [pkey] : [];

    var command = IPA.command({
        method: entity_name+'_mod',
        args: args,
        options: modlist,
        on_success: on_success,
        on_error: on_error
    });

    //alert(JSON.stringify(command.to_json()));

    command.execute();
};
