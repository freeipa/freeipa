/*jsl:import ipa.js */

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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.aci = {};

IPA.aci.permission_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function(params) {

        params.builder.facet_groups([ 'privilege' , 'settings' ]).
        search_facet({
            columns: [ 'cn' ]
        }).
        details_facet({
            sections: [
                {
                    name: 'identity',
                    fields: [ 'cn' ]
                },
                {
                    name: 'rights',
                    label: IPA.messages.objects.permission.rights,
                    fields: [
                        {
                            factory: IPA.rights_widget,
                            name: 'permissions',
                            join: true
                        }
                    ]
                },
                {
                    factory: IPA.permission_target_section,
                    name: 'target',
                    label: IPA.messages.objects.permission.target
                }
            ]
        }).
        association_facet({
            name: 'member_privilege',
            facet_group: 'privilege'
        }).
        adder_dialog({
            height: 450,
            sections: [
                {
                    name: 'general',
                    fields: [
                        'cn',
                        {
                            factory: IPA.rights_widget,
                            name: 'permissions',
                            join: true
                        }
                    ]
                },
                {
                    factory: IPA.permission_target_section,
                    name: 'target',
                    label: IPA.messages.objects.permission.target,
                    show_target: true
                }
            ]
        });
    };

    return that;
};

IPA.aci.privilege_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function(params) {

        params.builder.facet_groups([ 'role', 'settings', 'permission' ]).
        search_facet({
            columns: [
                'cn',
                'description'
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'identity',
                    label: IPA.messages.details.identity,
                    fields: [
                        'cn',
                        {
                            factory: IPA.textarea_widget,
                            name: 'description'
                        }
                    ]
                }
            ]
        }).
        association_facet({
            name: 'member_role',
            facet_group: 'role',
            add_method: 'add_privilege',
            remove_method: 'remove_privilege',
            associator: IPA.serial_associator
        }).
        association_facet({
            name: 'memberof_permission',
            facet_group: 'permission',
            add_method: 'add_permission',
            remove_method: 'remove_permission'
        }).
        standard_association_facets().
        adder_dialog({
            fields: [
                'cn',
                {
                    factory: IPA.textarea_widget,
                    name: 'description'
                }
            ]
        });
    };

    return that;
};

IPA.aci.role_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function(params) {

        params.builder.facet_groups([ 'member', 'settings', 'privilege' ]).
        search_facet({
            columns: [
                'cn',
                'description'
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'identity',
                    label: IPA.messages.objects.role.identity,
                    fields: [
                        'cn',
                        {
                            factory: IPA.textarea_widget,
                            name: 'description'
                        }
                    ]
                }
            ]
        }).
        association_facet({
            name: 'memberof_privilege',
            facet_group: 'privilege',
            add_method: 'add_privilege',
            remove_method: 'remove_privilege'
        }).
        standard_association_facets().
        adder_dialog({
            fields: [
                'cn',
                {
                    factory: IPA.textarea_widget,
                    name: 'description'
                }
            ]
        });
    };

    return that;
};

IPA.aci.selfservice_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function(params) {

        params.builder.search_facet({
            pagination: false,
            columns: [ 'aciname' ]
        }).
        details_facet({
            sections: [
                {
                    name: 'general',
                    label: IPA.messages.details.general,
                    fields: [
                        'aciname',
                        {
                            factory: IPA.attributes_widget,
                            object_type: 'user',
                            name: 'attrs'
                        }
                    ]
                }
            ]
        }).
        adder_dialog({
            fields: [
                'aciname',
                {
                    factory: IPA.attributes_widget,
                    object_type: 'user',
                    name: 'attrs'
                }
            ]
        });
    };

    return that;
};

IPA.aci.delegation_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function(params) {

        params.builder.search_facet({
            pagination: false,
            columns: [ 'aciname' ]
        }).
        details_facet({
            sections: [
                {
                    name: 'general',
                    label: IPA.messages.details.general,
                    fields: [
                        'aciname',
                        {
                            factory: IPA.entity_select_widget,
                            name: 'group',
                            other_entity: 'group',
                            other_field: 'cn'
                        },
                        {
                            factory: IPA.entity_select_widget,
                            name: 'memberof',
                            other_entity: 'group',
                            other_field: 'cn',
                            join: true
                        },
                        {
                            factory: IPA.attributes_widget,
                            name: 'attrs', object_type: 'user',
                            join: true
                        }
                    ]
                }
            ]
        }).
        standard_association_facets().
        adder_dialog({
            fields: [
                'aciname',
                {
                    factory: IPA.entity_select_widget,
                    name: 'group',
                    other_entity: 'group',
                    other_field: 'cn'
                },
                {
                    factory: IPA.entity_select_widget,
                    name: 'memberof',
                    other_entity: 'group',
                    other_field: 'cn',
                    join: true
                },
                {
                    factory: IPA.attributes_widget,
                    name: 'attrs',
                    object_type: 'user',
                    join: true
                }
            ]
        });
    };

    return that;
};


IPA.attributes_widget = function(spec) {

    spec = spec || {};

    var that = IPA.checkboxes_widget(spec);

    that.object_type = spec.object_type;

    var id = spec.name;

    that.create = function(container) {
        that.container = container;

        that.table = $('<table/>', {
            id:id,
            'class':'search-table aci-attribute-table scrollable'
        }).
            append('<thead/>').
            append('<tbody/>').
            appendTo(container);

        var tr = $('<tr></tr>').appendTo($('thead', that.table));

        tr.append($('<th/>', {
            html: $('<input/>', {
                type: "checkbox",
                click: function() {
                    $('.aci-attribute', that.table).
                        attr('checked', $(this).attr('checked'));
                    that.set_dirty(that.test_dirty());
                }
            })
        })).append($('<th/>', {
            'class': 'aci-attribute-column',
            html: IPA.messages.objects.aci.attribute
        }));

        if (that.undo) {
            that.create_undo(container);
        }

        if (that.object_type) {
            that.populate(that.object_type);
        }

        that.create_error_link(container);
    };

    that.load = function(record) {

        that.record = record;
        that.values = [];

        var values = record[that.name] || [];
        for (var i=0; i<values.length; i++) {
            var value = values[i].toLowerCase();
            that.values.push(value);
        }

        that.reset();
    };

    that.update = function() {
        that.populate(that.object_type);
        that.append();
        that.checkboxes_update();
    };

    that.populate = function(object_type) {

        $('tbody tr', that.table).remove();

        if (!object_type || object_type === '') return;

        var metadata = IPA.metadata.objects[object_type];
        if (!metadata) return;

        var aciattrs = metadata.aciattrs;

        var tbody = $('tbody', that.table);

        for (var i=0; i<aciattrs.length ; i++){
            var value = aciattrs[i].toLowerCase();
            var aci_tr = $('<tr/>').appendTo(tbody);

            var td =  $('<td/>').appendTo(aci_tr);
            td.append($('<input/>',{
                type: 'checkbox',
                name: that.name,
                value: value,
                'class': 'aci-attribute',
                click: function() {
                    that.set_dirty(that.test_dirty());
                }
            }));
            td =  $('<td/>').appendTo(aci_tr);
            td.append($('<label/>',{
                text:value}));
        }
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

        if (unmatched.length > 0) {
            var tbody = $('tbody', that.table);

            for (var j=0; j<unmatched.length; j++) {
                var value = unmatched[j].toLowerCase();
                var tr = $('<tr/>').appendTo(tbody);

                var td = $('<td/>').appendTo(tr);
                td.append($('<input/>', {
                    type: 'checkbox',
                    name: that.name,
                    value: value,
                    'class': 'aci-attribute',
                    change: function() {
                        that.set_dirty(that.test_dirty());
                    }
                }));

                td = $('<td/>').appendTo(tr);
                td.append($('<label/>', {
                    text: value
                }));
            }
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

IPA.permission_target_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_table_section(spec);

    that.targets = [ 'filter', 'subtree', 'targetgroup', 'type' ];
    that.target = that.targets[0];
    that.show_target = spec.show_target;

    var init = function() {

        that.target_select = IPA.select_widget({
            entity: that.entity,
            name: 'target',
            label: IPA.messages.objects.permission.target,
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

        that.target_select.value_changed.attach(function(value) {
            that.select_target(value);
        });

        that.add_field(that.target_select);

        that.filter_text = IPA.text_widget({
            entity: that.entity,
            name: 'filter',
            hidden: true
        });

        that.add_field(that.filter_text);

        that.subtree_textarea = IPA.textarea_widget({
            entity: that.entity,
            name: 'subtree',
            cols: 30,
            rows: 1,
            hidden: true
        });

        that.add_field(that.subtree_textarea);

        that.group_select = IPA.entity_select_widget({
            entity: that.entity,
            name: 'targetgroup',
            other_entity: 'group',
            other_field: 'cn',
            hidden: true
        });

        that.add_field(that.group_select);

        that.type_select = IPA.select_widget({
            entity: that.entity,
            name: 'type',
            hidden: true
        });

        var type_param = IPA.get_entity_param('permission', 'type');

        for (var j=0; j<type_param.values.length; j++) {
            var type_name = type_param.values[j];
            var type_label = IPA.metadata.objects[type_name].label_singular;

            that.type_select.options.push({
                label: type_label,
                value: type_name
            });
        }

        that.type_select.value_changed.attach(function(value) {
            that.attribute_table.object_type = value;
            that.attribute_table.reset();
        });

        that.add_field(that.type_select);

        that.attribute_table = IPA.attributes_widget({
            entity: that.entity,
            name: 'attrs',
            object_type: type_param.values[0],
            hidden: true
        });

        that.add_field(that.attribute_table);
    };

    that.select_target = function(target) {
        that.set_target_visible(that.target, false);
        that.target = target;
        that.set_target_visible(that.target, true);
    };

    that.set_target_visible = function(target, visible) {

        var field = that.get_field(that.target);
        field.hidden = !visible;
        that.set_row_visible(that.target, visible);

        if (that.target == 'type') {
            field = that.get_field('attrs');
            field.hidden = !visible;
            that.set_row_visible('attrs', visible);

        } else {
            field.set_required(visible);
        }
    };

    that.create = function(container) {
        that.table_section_create(container);
        that.select_target(that.targets[0]);
    };

    that.load = function(record) {

        var options = that.target_select.options;
        for (var i=0; i<options.length; i++) {
            var option = options[i];
            var target = option.value;
            if (record[target]) {
                record.target = target;
                break;
            }
        }

        if (!record.target) {
            alert(IPA.messages.objects.permission.invalid_target);
            return;
        }

        that.select_target(record.target);
        that.section_load(record);
    };

    that.save = function(record) {

        var field = that.get_field(that.target);
        record[field.name] = field.save();

        if (that.target == 'type') {
            field = that.get_field('attrs');
            record[field.name] = field.save();
        }
    };

    init();

    return that;
};

IPA.register('permission', IPA.aci.permission_entity);
IPA.register('privilege', IPA.aci.privilege_entity);
IPA.register('role', IPA.aci.role_entity);
IPA.register('selfservice', IPA.aci.selfservice_entity);
IPA.register('delegation', IPA.aci.delegation_entity);
