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

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */

IPA.entity_factories.permission = function() {

    return IPA.entity_builder().
        entity('permission').
        facet_groups([ 'privilege' , 'settings' ]).
        search_facet({
            columns:['cn']
        }).
        details_facet({sections:[
            {
                name: 'identity',
                fields: [
                    {
                        factory: IPA.text_widget,
                        name: 'cn',
                        read_only: true
                    }
                ]
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
                factory: IPA.target_section,
                name: 'target',
                label: IPA.messages.objects.permission.target
            }]}).
        association_facet({
            name: 'member_privilege',
            facet_group: 'privilege'
        }).
        adder_dialog({
            height: 400,
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
                    factory: IPA.target_section,
                    name: 'target',
                    label: IPA.messages.objects.permission.target
                }
            ]
        }).
        build();
};


IPA.entity_factories.privilege = function() {
    return IPA.entity_builder().
        entity('privilege').
        facet_groups([ 'role', 'settings', 'permission' ]).
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
        }).
        build();

};


IPA.entity_factories.role = function() {
    return  IPA.entity_builder().
        entity('role').
        facet_groups([ 'member', 'settings', 'privilege' ]).
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
        }).
        build();
};


IPA.entity_factories.selfservice = function() {
    return IPA.entity_builder().
        entity('selfservice').
        search_facet({
            columns:['aciname']}).
        details_facet({
            sections:[{
                name:'general',
                label: IPA.messages.details.general,
                fields: [
                    'aciname',
                    {
                        factory:IPA.attributes_widget,
                        object_type:'user',
                        name:'attrs'
                    }]}]}).
        adder_dialog({
            fields:[
                'aciname',
                {factory:IPA.attributes_widget,
                 object_type:'user',
                 name:'attrs'
                }]
        }).
        build();
};


IPA.entity_factories.delegation = function() {
    return IPA.entity_builder().
        entity('delegation').
        search_facet({
            columns:['aciname']}).
        details_facet({sections:[
            {
                name:'general',
                label: IPA.messages.details.general,
                fields:[
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
                        factory:IPA.attributes_widget,
                        name: 'attrs', object_type: 'user',
                        join: true
                    }]}]}).
        standard_association_facets().
        adder_dialog({
            fields:[
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
                }]
        }).
        build();
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

IPA.target_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_section(spec);

    var target_types = [
        {
            name: 'filter',
            label: IPA.messages.objects.permission.filter,
            create: function(container) {
                that.filter_text.create(container);
            },
            load: function(record) {
                that.filter_text.load(record);
            },
            save: function(record) {
                record.filter = that.filter_text.save();
            }
        },
        {
            name: 'subtree',
            label: IPA.messages.objects.permission.subtree,
            create: function(container) {
                that.subtree_textarea.create(container);
            },
            load: function(record) {
                that.subtree_textarea.load(record);
            },
            save: function(record) {
                record.subtree = that.subtree_textarea.save();
            }
        },
        {
            name: 'targetgroup',
            label: IPA.messages.objects.permission.targetgroup,
            create: function(container) {
                that.group_select.create(container);
            },
            load: function(record) {
                that.group_select.list.val(record.targetgroup);
            },
            save: function(record) {
                record.targetgroup = that.group_select.save();
            }
        },
        {
            name: 'type',
            label: IPA.messages.objects.permission.type,
            create: function(container) {

                var span = $('<span/>', {
                    name: 'type'
                }).appendTo(container);

                that.type_select.create(span);

                span = $('<span/>', {
                    name: 'attrs'
                }).appendTo(container);

                that.attribute_table.create(span);

                var select = that.type_select.select;

                select.change(function() {
                    that.attribute_table.object_type =
                        that.type_select.save()[0];
                    that.attribute_table.reset();
                });

                select.append($('<option/>', {
                    value: '',
                    text: ''
                }));

                var type_params = IPA.get_entity_param('permission', 'type');

                for (var i=0; i<type_params.values.length; i++) {
                    select.append($('<option/>', {
                        value: type_params.values[i],
                        text: type_params.values[i]
                    }));
                }

                that.type_select.update = function() {
                    that.type_select.select_update();
                    that.attribute_table.object_type =
                        that.type_select.save()[0];
                    that.attribute_table.reset();
                };
            },
            load: function(record) {
                that.type_select.load(record);
                that.attribute_table.object_type = record.type;
                that.attribute_table.reset();
            },
            save: function(record) {
                record.type = that.type_select.save();
                record.attrs = that.attribute_table.save();
            }
        }] ;

    var target_type = target_types[0];

    var init = function() {
        that.filter_text = IPA.text_widget({
            name: 'filter',
            entity: spec.entity
        });
        that.subtree_textarea = IPA.textarea_widget({
            entity: spec.entity,
            name: 'subtree',
            cols: 30, rows: 1
        });
        that.group_select = IPA.entity_select_widget({
            entity: spec.entity,
            name: 'targetgroup',
            other_entity: 'group',
            other_field: 'cn'
        });
        that.type_select = IPA.select_widget({
            entity: spec.entity,
            name: 'type'
        });
        that.attribute_table = IPA.attributes_widget({
            entity: spec.entity,
            name: 'attrs'
        });

        that.add_field(that.filter_text);
        that.add_field(that.subtree_textarea);
        that.add_field(that.group_select );
        that.add_field(that.type_select);
        that.add_field(that.attribute_table);

        /*TODO these next two functions are work arounds for missing attribute
          permissions for the filter text.  Remove them once that has been fixed */
        that.filter_text.update = function() {
            var value = that.filter_text.values && that.filter_text.values.length ?
                that.filter_text.values[0] : '';
            $('input[name="'+that.filter_text.name+'"]',
              that.filter_text.container).val(value);

            var label = $('label[name="'+that.filter_text.name+'"]',
                          that.filter_text.container);
            var input = $('input[name="'+that.filter_text.name+'"]',
                          that.filter_text.container);
            label.css('display', 'none');
            input.css('display', 'inline');
        };

        that.filter_text.save = function(){
            var input = $('input[name="'+that.filter_text.name+'"]',
                          that.filter_text.container);
            var value = input.val();
            return value === '' ? [] : [value];
        };
    };

    function show_target_type(type_to_show) {
        for (var i=0; i<target_types.length; i++) {
            if (target_types[i].name === type_to_show) {
                target_type = target_types[i];
                target_type.container.css('display', '');
            } else {
                target_types[i].container.css('display', 'none');
            }
        }
    }

    that.create = function(container) {
        that.container = container;

        var table = $('<table/>', {
            'class': 'section-table'
        }).appendTo(that.container);

        var tr = $('<tr/>').appendTo(table);

        var td = $('<td/>', {
            'class': 'section-cell-label'
        }).appendTo(tr);

        $('<label/>', {
            name: 'target',
            title: IPA.messages.objects.permission.target,
            'class': 'field-label',
            text: IPA.messages.objects.permission.target+':'
        }).appendTo(td);

        if (that.undo) {
            tr.css('display', 'none');
        }

        td = $('<td/>', {
            'class': 'section-cell-field'
        }).appendTo(tr);

        var field_container = $('<div/>', {
            name: 'target',
            'class': 'field'
        }).appendTo(td);

        that.target_type_select = $('<select/>', {
            change: function() {
                show_target_type(this.value);
            }
        }).appendTo(field_container);

        for (var i=0 ; i<target_types.length; i++) {
            target_type = target_types[i];

            $('<option/>', {
                text: target_type.name,
                value : target_type.name
            }).appendTo(that.target_type_select);

            tr = $('<tr/>', {
                style: 'display: none'
            }).appendTo(table);

            td = $('<td/>', {
                'class': 'section-cell-label'
            }).appendTo(tr);

            $('<label/>', {
                name: target_type.name,
                title: target_type.label,
                'class': 'field-label',
                text: target_type.label+':'
            }).appendTo(td);

            td = $('<td/>', {
                'class': 'section-cell-field'
            }).appendTo(tr);

            field_container = $('<div/>', {
                name: target_type.name,
                title: target_type.label,
                'class': 'field'
            }).appendTo(td);

            target_type.create(field_container);
            target_type.container = tr;
        }
    };

    function reset_target_widgets() {
        that.filter_text.record = null;
        that.subtree_textarea.record = null;
        that.group_select.record = null;
        that.type_select.record = null;
        that.attribute_table.record = null;

        that.filter_text.reset();
        that.subtree_textarea.reset();
        that.group_select.reset();
        that.type_select.reset();
        that.attribute_table.reset();
    }

    function set_target_type(record) {

        reset_target_widgets();

        var target_type_name ;
        for (var i=0; i<target_types.length; i++) {
            target_type = target_types[i];
            if (record[target_type.name]) {
                target_type_name = target_type.name;
                break;
            }
        }
        if (!target_type_name) {
            alert(IPA.messages.objects.permission.invalid_target);
            return;
        }

        that.target_type_select.val(target_type_name);
        show_target_type(target_type_name);
        target_type.load(record);
    }

    that.load = function(record){
        that.section_load(record);
        that.reset();
    };

    that.reset = function() {
        that.section_reset();

        if (that.record) {
            set_target_type(that.record);
            that.attribute_table.object_type = that.record.type;

        } else {
            reset_target_widgets();
            that.target_type_select.val(target_types[0].name);
            show_target_type(target_types[0].name);
        }
    };

    that.save = function(record) {
        target_type.save(record);
    };

    init();

    return that;
};
