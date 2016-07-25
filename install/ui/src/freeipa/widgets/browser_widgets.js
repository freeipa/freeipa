//
// Copyright (C) 2015  FreeIPA Contributors see COPYING for license
//

//
// Contains API browser widgets
//

define([
    'dojo/_base/declare',
    'dojo/_base/lang',
    'dojo/on',
    'dojo/Evented',
    'dojo/Stateful',
    '../jquery',
    '../ipa',
    '../metadata',
    '../navigation',
    '../reg',
    '../text',
    '../util'
], function(declare, lang, on, Evented, Stateful, $, IPA, metadata, navigation,
     reg, text, util) {

var widgets = { browser_widgets: {} }; //namespace

var apibrowser_facet = 'apibrowser';

/**
 * Browser Widget Base
 *
 * Candidate for a base class for all widgets
 *
 * @class
 */
widgets.browser_widgets.Base = declare([Stateful, Evented], {

    // nodes
    el: null,

    /**
     * Render widget's HTML
     * @return {jQuery} base node
     */
    render: function() {
        this.el = $('<div/>', { 'class': this.css_class });
        this.render_content();
        return this.el;
    },

    /**
     * Should be overridden
     */
    render_content: function() {
    },

    constructor: function(spec) {
        lang.mixin(this, spec);
    }
});

/**
 * Detail Base
 *
 * A base class for showing details of various API objects
 *
 * @class
 * @extends {widgets.browser_widgets.Base}
 */
widgets.browser_widgets.DetailBase = declare([widgets.browser_widgets.Base], {

    /**
     * Item to be displayed
     * @property {Object}
     */
    item: null,

    common_options: [
        'all', 'rights', 'raw', 'version', 'addattr', 'setattr', 'delattr',
        'getattr', 'timelimit', 'sizelimit', 'pkey_only'
    ],

    _itemSetter: function(value) {
        this.item = value;
        if (this.el) {
            this.render_content();
        }
    },

    _get_object: function(obj_name) {
        var obj = metadata.get('@mo:' + obj_name);
        if (!obj || obj.only_webui) return null;
        return obj;
    },

    _get_command_object: function(command_name) {
        var obj_name = command_name.split('_')[0];
        var obj = this._get_object(obj_name);
        return obj;
    },

    _get_objectparam: function(command_name, param_name) {
        var obj = this._get_command_object(command_name);
        if (!obj) return null;
        var param = metadata.get('@mo-param:' + obj.name + ':' + param_name);
        return param;
    },

    _get_cli_option: function(name) {
        if (!name) return name;
        return '--' + name.replace('_', '-');
    },

    render_object_link: function(obj_name, text) {
        var facet = reg.facet.get(apibrowser_facet);
        var link = $('<a/>', {
            href: "#" + navigation.create_hash(facet, {
                type: 'object',
                name: obj_name
            }),
            text: text || obj_name
        });
        return link;
    },

    render_command_link: function(command_name, text) {
        var facet = reg.facet.get(apibrowser_facet);
        var link = $('<a/>', {
            href: "#" + navigation.create_hash(facet, {
                type: 'command',
                name: command_name
            }),
            text: text || command_name
        });
        return link;
    },

    render_param_link: function(obj_name, param_name, text) {
        var name = obj_name + ':' + param_name;
        var facet = reg.facet.get(apibrowser_facet);
        var link = $('<a/>', {
            href: "#" + navigation.create_hash(facet, {
                type: 'param',
                name: name
            }),
            text: text || param_name
        });
        return link;
    },


    render_title: function(type, text) {
        var title = $('<h1/>', { 'class': 'api-title' });
        $('<span/>', {
            'class': 'api-title-type',
            text: type
        }).appendTo(title);
        $('<span/>', {
            'class': 'api-title-text',
            text: text
        }).appendTo(title);
        return title;
    },

    render_doc: function(text) {
        return $('<p/>', { text: text });
    },

    render_section_header: function(text, link) {
        return $('<h2/>', {
            text: text,
            id: link
        });
    },

    render_value_container: function() {
        return $('<div/>', {
            'class': 'properties'
        });
    },

    render_value: function(label, value_node, container) {
        if (!text) return $('');

        var row = $('<div/>', {
            'class': 'row'
        });
        $('<div/>', {
            'class': 'col-sm-4 prop-label',
            text: label
        }).appendTo(row);
        $('<div/>', {
            'class': 'col-sm-8 prop-value'
        }).append(value_node).appendTo(row);

        if (container) {
            container.append(row);
        }
        return row;
    },

    render_text_all: function(label, text, container) {
        if (text === null || text === undefined) return $('');
        var node = document.createTextNode(text);
        return this.render_value(label, node, container);
    },

    render_text: function(label, text, container) {
        if (!text) return $('');
        var node = document.createTextNode(text);
        return this.render_value(label, node, container);
    },

    render_array: function(label, value, container) {
        if (!value || value.length === 0) return $('');
        var text = value.join(', ');
        return this.render_text(label, text, container);
    },

    render_object: function(label, obj, container) {
        if (obj === undefined || obj === null) return $('');
        var text = JSON.stringify(obj);
        return this.render_text(label, text, container);
    },

    render_command_object_link: function(label, command_name, container) {
        var obj = this._get_command_object(command_name);
        if (!obj) return $('');
        var link = this.render_object_link(obj.name, obj.label_singular);
        return this.render_value(label, link, container);
    },


    render_flags: function(flags, cnt) {
        if (!flags) return null;
        if (!cnt) cnt = $('<div/>');
        for (var i=0,l=flags.length; i<l; i++) {
            $('<span/>', {
                'class': 'label label-default',
                text: flags[i]
            }).appendTo(cnt);
        }
        return cnt;
    },

    render_param: function(param, is_arg, container) {
        var prop_cnt = this.render_value_container();
        var header = $('<h3/>', {
            text: param.name
        });
        header.appendTo(prop_cnt);
        this.render_param_properties(param, is_arg, prop_cnt, header);
        if (container) {
            container.append(prop_cnt);
        }
        return prop_cnt;
    },

    render_param_properties: function(param, is_arg, container, flags_container) {

        var flags = [];
        if (param.required) flags.push('required');
        if (param.multivalue) flags.push('multivalued');
        //if (param.primary_key) flags.push('primary key');

        this.render_doc(param.doc).appendTo(container);
        this.render_flags(flags, flags_container);
        if (param.label && param.label[0] !== '<') {
            this.render_text("label", param.label, container);
        }
        this.render_text("type", param.type, container);
        this.render_text_all("default value", param['default'], container);
        this.render_array("default value created from", param['default_from'], container);
        if (param.values) {
            this.render_array("possible values", param.values, container);
        }

        // Str values
        this.render_text("minimum length", param.minlength, container);
        this.render_text("maximum length", param.maxlength, container);
        this.render_text("pattern", param.pattern, container);

        // Int, Decimal
        this.render_text("minimum value", param.minvalue, container);
        this.render_text("maximum value", param.maxvalue, container);
        this.render_text("precision", param.precision, container);

        // CLI
        if (!is_arg) {
            this.render_text("CLI option name", this._get_cli_option(param.cli_name), container);
        }

        this.render_text("option_group", param.option_group, container);
    }
});

var base = widgets.browser_widgets.DetailBase;

/**
 * Object detail
 * @class
 * @extends {widgets.browser_widgets.DetailBase
 */
widgets.browser_widgets.ObjectDetailWidget = declare([base], {

    render_content: function() {
        var link, obj;
        this.el.empty();
        if (!this.item) {
            this.el.append('No object selected');
            return;
        }
        var item = this.item;
        this.render_title('Object: ', item.name).appendTo(this.el);
        if (item.doc) this.render_doc(item.doc).appendTo(this.el);
        if (item.parent_object) {
            obj = this._get_object(item.parent_object);
            if (obj) {
                link = this.render_object_link(item.parent_object, obj.label_singular);
                this.render_value('parent_object', link, this.el);
            }
        }
        //this.render_text("parent_object", item.parent_object, this.el);
        this.render_text("label", item.label, this.el);
        this.render_text("label_singular", item.label_singular, this.el);
        this.render_text("container_dn", item.container_dn, this.el);
        this.render_text("object_class", item.object_class, this.el);
        this.render_text("object_class_config", item.object_class_config, this.el);
        this.render_text("object_name", item.object_name, this.el);
        this.render_text("object_name_plural", item.object_name_plural, this.el);
        this.render_text("uuid_attribute", item.uuid_attribute, this.el);
        this.render_text("rdn_attribute", item.rdn_attribute, this.el);
        this.render_text("bindable", item.bindable, this.el);
        this.render_array("aciattrs", item.aciattrs, this.el);
        this.render_text("can_have_permissions", item.can_have_permissions, this.el);
        this.render_array("default_attributes", item.default_attributes, this.el);
        this.render_array("hidden_attributes", item.hidden_attributes, this.el);
        this.render_object("attribute_members", item.attribute_members, this.el);
        this.render_object("relationships", item.relationships, this.el);

        if (item.methods) {
            this.render_section_header('Methods').appendTo(this.el);
            var cnt = $('<div/>');
            for (i=0, l=item.methods.length; i<l; i++) {
                var method_name = item.methods[i];
                if (i>0) {
                    cnt.append(', ');
                }
                var command_name = item.name + '_' + method_name;
                link = this.render_command_link(command_name, method_name);
                cnt.append(link);
            }
            this.render_value('', cnt, this.el);
        }

        if (item.takes_params) {
            this.render_section_header('Params').appendTo(this.el);
            for (var i=0,l=item.takes_params.length; i<l; i++) {
                var opt = item.takes_params[i];
                this.render_param(opt, true).appendTo(this.el);
            }
        }
    }
});

/**
 * Command Detail
 * @class
 * @extends {widgets.browser_widgets.DetailBase
 */
widgets.browser_widgets.CommandDetailWidget = declare([base], {

    render_content: function() {
        var i = 0, l = 0;
        this.el.empty();
        if (!this.item) {
            this.el.append('No command selected');
            return;
        }
        var item = this.item;
        var obj = this._get_command_object(item.name);
        this.render_title('Command: ', item.name).appendTo(this.el);
        if (item.doc) this.render_doc(item.doc).appendTo(this.el);
        this.render_command_object_link('object', item.name, this.el);
        if (item.takes_args && item.takes_args.length > 0) {
            this.render_section_header('Arguments').appendTo(this.el);
            for (i=0, l=item.takes_args.length; i<l; i++) {
                var arg = item.takes_args[i];
                this.render_param(arg, true).appendTo(this.el);
            }
        }
        if (item.takes_options && item.takes_options.length > 0) {
            var options = [];
            var common_options = [];

            for (i=0, l=item.takes_options.length; i<l; i++) {
                var opt = item.takes_options[i];
                if (opt.include && opt.include.indexOf('server') === -1) continue;
                if (opt.exclude && opt.exclude.indexOf('server') > -1) continue;
                if (this.common_options.indexOf(opt.name) > -1) {
                    common_options.push(opt);
                } else {
                    options.push(opt);
                }
            }

            if (options.length) {
                this.render_section_header('Options').appendTo(this.el);
            }
            for (i=0, l=options.length; i<l; i++) {
                this.render_param(options[i], false).appendTo(this.el);
            }

            if (common_options.length) {
                this.render_section_header('Common Options').appendTo(this.el);
            }
            for (i=0, l=common_options.length; i<l; i++) {
                this.render_param(common_options[i], false).appendTo(this.el);
            }
        }
        if (item.output_params && item.output_params.length > 0) {
            this.render_section_header('Output Params').appendTo(this.el);
            var out_params_cnt = $('<div/>');
            for (i=0, l=item.output_params.length; i<l; i++) {
                var param_name = item.output_params[i];
                var param = this._get_objectparam(item.name, param_name);
                if (i>0) {
                    out_params_cnt.append(', ');
                }
                if (param && obj) {
                    var link = this.render_param_link(obj.name, param_name);
                    out_params_cnt.append(link);
                } else {
                    out_params_cnt.append(param_name);
                }
            }
            out_params_cnt.appendTo(this.el);
        }
    }
});

/**
 * Param Detail
 * @class
 * @extends {widgets.browser_widgets.DetailBase
 */
widgets.browser_widgets.ParamDetailWidget = declare([base], {

    render_content: function() {
        this.el.empty();
        if (!this.item) {
            this.el.append('No param selected');
            return;
        }
        var item = this.item;
        this.render_title('Param: ', item.name).appendTo(this.el);
        var flags = $('<div/>').appendTo(this.el);
        this.render_param_properties(item, this.el, flags);
    }
});

/**
 * Filter input
 *
 * @class
 * @extends {widgets.browser_widgets.DetailBase
 */
widgets.browser_widgets.FilterWidget = declare([widgets.browser_widgets.Base], {

    /**
     * Filter text
     * @property {String}
     */
    filter: '',

    _filter_el: null,

    _filterSetter: function(value) {
        this.filter = value;
        if (this.el) {
            this._filter_el.val(value);
        }
    },

    render_content: function() {
        this.el.empty();
        this._filter_el = $('<input/>', {
            type: 'text',
            name: 'filter',
            placeholder: 'type to filter...',
            title: 'accepts case insensitive regular expression'
        });
        this._filter_el.bind('input', function() {
            var filter = this._filter_el.val();
            this.set('filter', filter);
        }.bind(this));
        this._filter_el.appendTo(this.el);
    }
});


    return widgets.browser_widgets;
});
