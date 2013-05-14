/*  Authors:
 *    Adam Young <ayoung@redhat.com>
 *    Endi S. Dewata <edewata@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

define([
    './metadata',
    './ipa',
    './jquery',
    './phases',
    './reg',
    './text',
    './details',
    './search',
    './association',
    './entity'],
        function(metadata_provider, IPA, $, phases, reg, text) {

var exp = IPA.aci = {};

var make_permission_spec = function() {

return {
    name: 'permission',
    facet_groups: ['settings', 'privilege'],
    facets: [
        {
            $type: 'search',
            columns: [ 'cn' ]
        },
        {
            $factory: IPA.aci.permission_details_facet,
            $type: 'details',
            fields: [
                {
                    name:'cn',
                    widget: 'identity.cn'
                },
                {
                    $type: 'rights',
                    name: 'permissions',
                    widget: 'rights.permissions'
                },
                {
                    $type: 'select',
                    name: 'target',
                    widget: 'target.target',
                    enabled: false
                },
                {
                    name: 'filter',
                    widget: 'target.filter',
                    enabled: false
                },
                {
                    $type: 'entity_select',
                    name: 'memberof',
                    widget: 'target.memberof',
                    enabled: false
                },
                {
                    name: 'subtree',
                    widget: 'target.subtree',
                    enabled: false
                },
                {
                    $type: 'entity_select',
                    name: 'targetgroup',
                    widget: 'target.targetgroup',
                    enabled: false
                },
                {
                    $type: 'select',
                    name: 'type',
                    widget: 'target.type',
                    enabled: false
                },
                {
                    name: 'attrs',
                    widget: 'target.attrs',
                    enabled: false
                },
                {
                    name: 'attrs_multi',
                    param: 'attrs',
                    $type: 'multivalued',
                    widget: 'target.attrs_multi',
                    enabled: false
                }
            ],
            widgets: [
                {
                    $type: 'details_table_section',
                    name: 'identity',
                    label: '@i18n:objects.permission.identity',
                    widgets: [
                        'cn'
                    ]
                },
                {
                    $type: 'details_table_section',
                    name: 'rights',
                    label: '@i18n:objects.permission.rights',
                    widgets: [
                        {
                            $type: 'rights',
                            name: 'permissions'
                        }
                    ]
                },
                {
                    $type: 'permission_target',
                    container_factory: IPA.details_table_section,
                    label: '@i18n:objects.permission.target',
                    name: 'target',
                    show_target: false
                }
            ],
            policies: [
                {
                    $factory: IPA.permission_target_policy,
                    widget_name: 'target'
                }
            ]
        },
        {
            $type: 'association',
            name: 'member_privilege',
            facet_group: 'privilege'
        }
    ],
    adder_dialog: {
        height: 450,
        fields: [
            {
                name:'cn',
                widget: 'general.cn'
            },
            {
                $type: 'rights',
                name: 'permissions',
                widget: 'general.permissions'
            },
            {
                $type: 'select',
                name: 'target',
                widget: 'target.target',
                enabled: false
            },
            {
                name: 'filter',
                widget: 'target.filter',
                enabled: false
            },
            {
                $type: 'entity_select',
                name: 'memberof',
                widget: 'target.memberof',
                enabled: false
            },
            {
                name: 'subtree',
                widget: 'target.subtree',
                enabled: false
            },
            {
                $type: 'entity_select',
                name: 'targetgroup',
                widget: 'target.targetgroup',
                enabled: false
            },
            {
                $type: 'select',
                name: 'type',
                widget: 'target.type',
                enabled: false
            },
            {
                name: 'attrs',
                widget: 'target.attrs',
                enabled: false
            },
            {
                name: 'attrs_multi',
                $type: 'multivalued',
                param: 'attrs',
                widget: 'target.attrs_multi',
                enabled: false
            }
        ],
        widgets: [
            {
                $type: 'details_table_section_nc',
                name: 'general',
                widgets: [
                    'cn',
                    {
                        $type: 'rights',
                        name: 'permissions'
                    }
                ]
            },
            {
                $type: 'permission_target',
                name:'target',
                show_target: true
            }
        ],
        policies: [
            {
                $factory: IPA.permission_target_policy,
                widget_name: 'target'
            }
        ]
    }
};};

IPA.aci.permission_details_facet = function(spec) {

    var that = IPA.details_facet(spec);

    that.get_refresh_command_name = function() {
        return that.entity.name+'_show_'+that.get_pkey();
    };

    return that;
};

var make_privilege_spec = function() {
return {
    name: 'privilege',
    facet_groups: ['permission', 'settings', 'role'],
    facets: [
        {
            $type: 'search',
            columns: [
                'cn',
                'description'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'identity',
                    label: '@i18n:details.identity',
                    fields: [
                        'cn',
                        {
                            $type: 'textarea',
                            name: 'description'
                        }
                    ]
                }
            ]
        },
        {
            $type: 'association',
            name: 'member_role',
            facet_group: 'role',
            add_method: 'add_privilege',
            remove_method: 'remove_privilege',
            associator: IPA.serial_associator
        },
        {
            $type: 'association',
            name: 'memberof_permission',
            facet_group: 'permission',
            add_method: 'add_permission',
            remove_method: 'remove_permission'
        }
    ],
    standard_association_facets: true,
    adder_dialog: {
        fields: [
            'cn',
            {
                $type: 'textarea',
                name: 'description'
            }
        ]
    }
};};

var make_role_spec = function() {
return {
    name: 'role',
    facet_groups: ['member', 'privilege', 'settings'],
    facets: [
        {
            $type: 'search',
            columns: [
                'cn',
                'description'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'identity',
                    label: '@i18n:objects.role.identity',
                    fields: [
                        'cn',
                        {
                            $type: 'textarea',
                            name: 'description'
                        }
                    ]
                }
            ]
        },
        {
            $type: 'association',
            name: 'memberof_privilege',
            facet_group: 'privilege',
            add_method: 'add_privilege',
            remove_method: 'remove_privilege'
        }
    ],
    standard_association_facets: true,
    adder_dialog: {
        fields: [
            'cn',
            {
                $type: 'textarea',
                name: 'description'
            }
        ]
    }
};};

var make_selfservice_spec = function() {
return {
    name: 'selfservice',
    facets: [
        {
            $type: 'search',
            columns: [ 'aciname' ],
            pagination: false
        },
        {
            $type: 'details',
            check_rights: false,
            sections: [
                {
                    name: 'general',
                    label: '@i18n:details.general',
                    fields: [
                        'aciname',
                        {
                            $type: 'attributes',
                            object_type: 'user',
                            name: 'attrs'
                        }
                    ]
                }
            ]
        }
    ],
    adder_dialog: {
        fields: [
            'aciname',
            {
                $type: 'attributes',
                object_type: 'user',
                name: 'attrs'
            }
        ]
    }
};};


var make_delegation_spec = function() {
return {
    name: 'delegation',
    facets: [
        {
            $type: 'search',
            columns: [ 'aciname' ],
            pagination: false
        },
        {
            $type: 'details',
            check_rights: false,
            sections: [
                {
                    name: 'general',
                    label: '@i18n:details.general',
                    fields: [
                        'aciname',
                        {
                            $type: 'checkboxes',
                            name: 'permissions',
                            required: true,
                            options: IPA.create_options(['read', 'write'])
                        },
                        {
                            $type: 'entity_select',
                            name: 'group',
                            other_entity: 'group',
                            other_field: 'cn'
                        },
                        {
                            $type: 'entity_select',
                            name: 'memberof',
                            other_entity: 'group',
                            other_field: 'cn'
                        },
                        {
                            $type: 'attributes',
                            name: 'attrs',
                            object_type: 'user'
                        }
                    ]
                }
            ]
        }
    ],
    standard_association_facets: false,
    adder_dialog: {
        fields: [
            'aciname',
            {
                $type: 'checkboxes',
                name: 'permissions',
                options: IPA.create_options(['read', 'write'])
            },
            {
                $type: 'entity_select',
                name: 'group',
                other_entity: 'group',
                other_field: 'cn'
            },
            {
                $type: 'entity_select',
                name: 'memberof',
                other_entity: 'group',
                other_field: 'cn'
            },
            {
                $type: 'attributes',
                name: 'attrs',
                object_type: 'user'
            }
        ]
    }
};};


IPA.attributes_widget = function(spec) {

    spec = spec || {};

    var that = IPA.checkboxes_widget(spec);

    that.object_type = spec.object_type;
    that.skip_unmatched = spec.skip_unmatched === undefined ? false : spec.skip_unmatched;

    var id = spec.name;

    that.create = function(container) {
        that.container = container;

        var attr_container = $('<div/>', {
            'class': 'aci-attribute-table-container'
        }).appendTo(container);

        that.$node = that.table = $('<table/>', {
            id:id,
            'class':'search-table aci-attribute-table scrollable'
        }).
            append('<thead/>').
            append('<tbody/>').
            appendTo(attr_container);

        var tr = $('<tr></tr>').appendTo($('thead', that.table));

        tr.append($('<th/>', {
            html: $('<input/>', {
                type: "checkbox",
                click: function() {
                    $('.aci-attribute', that.table).
                        prop('checked', $(this).prop('checked'));
                    that.value_changed.notify([], that);
                }
            })
        })).append($('<th/>', {
            'class': 'aci-attribute-column',
            html: text.get('@i18n:objects.aci.attribute')
        }));

        if (that.undo) {
            that.create_undo(container);
        }

        if (that.object_type) {
            that.populate(that.object_type);
        }

        that.create_error_link(container);
    };

    that.create_options = function(options) {
        var tbody = $('tbody', that.table);

        for (var i=0; i<options.length ; i++){
            var value = options[i].toLowerCase();
            var tr = $('<tr/>').appendTo(tbody);

            var td =  $('<td/>').appendTo(tr);
            var name = that.get_input_name();
            var id = that.option_next_id + name;
            td.append($('<input/>',{
                id: id,
                type: 'checkbox',
                name: name,
                value: value,
                'class': 'aci-attribute',
                change: function() {
                    that.value_changed.notify([], that);
                }
            }));
            td = $('<td/>').appendTo(tr);
            td.append($('<label/>',{
                text: value,
                'for': id
            }));
            that.new_option_id();
        }
    };

    that.update = function(values) {

        that.values = [];

        values = values || [];
        for (var i=0; i<values.length; i++) {

            var value = values[i];

            if (!value || value === '') continue;

            value = value.toLowerCase();
            that.values.push(value);
        }

        that.populate(that.object_type);
        that.append();
        that.owb_update(values);
    };

    that.populate = function(object_type) {

        $('tbody tr', that.table).remove();

        if (!object_type || object_type === '') return;

        var metadata = metadata_provider.get('@mo:'+object_type);
        if (!metadata) return;

        var aciattrs = metadata.aciattrs;

        that.options = that.prepare_options(aciattrs);
        that.create_options(aciattrs);
    };

    that.append = function() {

        if (!that.values) return;

        var unmatched = [];

        for (var i=0; i<that.values.length; i++) {
            var input = $('input[name="'+that.name+'"]'+
                          '[value="'+that.values[i]+'"]', that.container);
            if (!input.length) {
                unmatched.push(that.values[i]);
            }
        }

        if (unmatched.length > 0 && !that.skip_unmatched) {
            that.options.push.apply(that.options, that.prepare_options(unmatched));
            that.create_options(unmatched);
        }
    };

    that.show_undo = function() {
        $(that.undo_span).css('display', 'inline-block');
    };

    return that;
};

IPA.rights_widget = function(spec) {

    var that = IPA.checkboxes_widget(spec);

    that.rights = ['write', 'add', 'delete'];
    for (var i=0; i<that.rights.length; i++) {
        var right = that.rights[i];
        that.add_option({label: right, value: right});
    }

    return that;
};

IPA.permission_target_widget = function(spec) {

    spec = spec || {};

    var factory = spec.container_factory || IPA.details_table_section_nc;

    var that = factory(spec);

    that.group_entity = IPA.get_entity(spec.group_entity || 'group');

    that.targets = [ 'filter', 'subtree', 'targetgroup', 'type' ];
    that.target = that.targets[0];
    that.show_target = spec.show_target;

    var init = function() {

        that.target_select = IPA.select_widget({
            entity: that.entity,
            name: 'target',
            label: '@i18n:objects.permission.target',
            hidden: !that.show_target
        });

        for (var i=0; i<that.targets.length; i++) {
            var target = that.targets[i];
            var target_param = IPA.get_entity_param('permission', target);

            that.target_select.options.push({
                label: target_param.label,
                value: target
            });
        }

        that.widgets.add_widget(that.target_select);


        that.memberof_select = IPA.entity_select_widget({
            entity: that.entity,
            name: 'memberof',
            other_entity: that.group_entity,
            other_field: 'cn',
            hidden: true
        });

        that.widgets.add_widget(that.memberof_select);

        that.filter_text = IPA.text_widget({
            entity: that.entity,
            name: 'filter',
            hidden: true
        });

        that.widgets.add_widget(that.filter_text);

        that.subtree_textarea = IPA.textarea_widget({
            entity: that.entity,
            name: 'subtree',
            hidden: true
        });

        that.widgets.add_widget(that.subtree_textarea);

        that.group_select = IPA.entity_select_widget({
            entity: that.entity,
            name: 'targetgroup',
            other_entity: that.group_entity,
            other_field: 'cn',
            hidden: true
        });

        that.widgets.add_widget(that.group_select);

        that.type_select = IPA.select_widget({
            entity: that.entity,
            name: 'type',
            hidden: true
        });

        var type_param = IPA.get_entity_param('permission', 'type');

        for (var j=0; j<type_param.values.length; j++) {
            var type_name = type_param.values[j];
            var type_label = metadata_provider.get('@mo:'+type_name+'.label_singular');

            that.type_select.options.push({
                label: type_label,
                value: type_name
            });
        }

        that.widgets.add_widget(that.type_select);

        that.attribute_table = IPA.attributes_widget({
            entity: that.entity,
            name: 'attrs',
            object_type: type_param.values[0],
            hidden: true
        });

        that.widgets.add_widget(that.attribute_table);

        that.attribute_multivalued = IPA.multivalued_widget({
            entity: that.entity,
            name: 'attrs_multi',
            hidden: true
        });

        that.widgets.add_widget(that.attribute_multivalued);
    };

    init();

    return that;
};

IPA.permission_target_policy = function (spec) {

    var that = IPA.facet_policy();
    that.widget_name = spec.widget_name;

    that.init = function() {

        that.permission_target = that.container.widgets.get_widget(that.widget_name);
        var widgets = that.permission_target.widgets;

        var target_select = widgets.get_widget('target');
        target_select.value_changed.attach(function() {
            var target = target_select.save()[0];
            that.select_target(target);
        });

        var type_select = widgets.get_widget('type');

        type_select.value_changed.attach(function() {
            var type = type_select.save()[0];
            that.set_attrs_type(type, true);
        });

        type_select.undo_clicked.attach(function() {
            var type = type_select.save()[0];
            that.set_attrs_type(type, true);
        });
    };

    that.set_attrs_type = function(type, skip_unmatched) {
        var attribute_field = that.container.fields.get_field('attrs');
        var attribute_table = that.permission_target.widgets.get_widget('attrs');
        var skip_unmatched_org = attribute_table.skip_unmatched;
        attribute_table.object_type = type;
        // skip values which don't belong to new type. Bug #2617
        attribute_table.skip_unmatched =  skip_unmatched || skip_unmatched_org;
        attribute_field.reset();
        // force value_change to update dirty status if some unmatched values were skipped
        attribute_table.value_changed.notify([], attribute_table);
        attribute_table.skip_unmatched = skip_unmatched_org;
    };

    that.update_attrs = function() {

        var type_select = that.permission_target.widgets.get_widget('type');
        var type = type_select.save()[0];
        that.set_attrs_type(type, false);
    };

    that.post_create = function() {
        that.select_target(that.permission_target.targets[0]);
    };

    that.post_load = function(data) {

        var displayed_target;

        for (var target in that.target_mapping) {

            if (data.result.result[target]) {
                displayed_target = target;
            } else {
                that.set_target_visible(target, false);
            }
        }

        if (displayed_target) {
            that.permission_target.target = displayed_target;
            that.set_target_visible(displayed_target, true);
        }
    };

    that.select_target = function(target) {
        that.set_target_visible(that.permission_target.target, false);
        that.permission_target.target = target;
        that.set_target_visible(that.permission_target.target, true);
    };

    that.set_target_visible = function(target, visible) {

        var target_info = that.target_mapping[target];
        that.set_target_visible_core(target_info, visible);
    };

    that.set_target_visible_core = function(target_info, visible) {
        var widget = that.permission_target.widgets.get_widget(target_info.name);
        var field = that.container.fields.get_field(target_info.name);
        that.permission_target.set_row_visible(target_info.name, visible);
        field.enabled = visible;
        field.set_required(visible && target_info.required);
        widget.hidden = !visible;

        if (target_info.additional) {
            for (var i=0; i<target_info.additional.length; i++) {
                var nested_info = target_info.additional[i];
                that.set_target_visible_core(nested_info, visible);
            }
        }

        if (visible && target_info.action) target_info.action();
    };


    that.target_mapping = {
        filter: {
            name: 'filter',
            required: true,
            additional: [
                {
                    name: 'attrs_multi'
                }
            ]
        },
        subtree: {
            name: 'subtree',
            required: true,
            additional: [
                {
                    name: 'memberof'
                },
                {
                    name: 'attrs_multi'
                }
            ]
        },
        targetgroup: {
            name: 'targetgroup',
            required: true,
            additional: [
                {
                    name: 'attrs'
                }
            ],
            action: function() {
                that.set_attrs_type('group', false);
            }
        },
        type: {
            name: 'type',
            additional: [
                {
                    name: 'memberof'
                },
                {
                    name: 'attrs'
                }
            ],
            action: function() {
                that.update_attrs();
            }
        }
    };


    return that;
};

exp.permission_entity_spec = make_permission_spec();
exp.privilege_entity_spec = make_privilege_spec();
exp.role_entity_spec = make_role_spec();
exp.selfservice_entity_spec = make_selfservice_spec();
exp.delegation_entity_spec = make_delegation_spec();

exp.register = function() {
    var e = reg.entity;
    var w = reg.widget;
    var f = reg.field;

    e.register({ type: 'permission', spec: exp.permission_entity_spec });
    e.register({ type: 'privilege', spec: exp.privilege_entity_spec });
    e.register({ type: 'role', spec: exp.role_entity_spec });
    e.register({ type: 'selfservice', spec: exp.selfservice_entity_spec });
    e.register({ type: 'delegation', spec: exp.delegation_entity_spec });

    w.register('attributes', IPA.attributes_widget);
    f.register('attributes', IPA.checkboxes_field);
    w.register('rights', IPA.rights_widget);
    f.register('rights', IPA.checkboxes_field);
    w.register('permission_target', IPA.permission_target_widget);
};

phases.on('registration', exp.register);

return exp;
});