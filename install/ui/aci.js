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
        search_facet({
            columns:['cn'],
            add_fields:[
                'cn',
                {
                    factory:IPA.rights_widget,
                    name: 'permissions',
                    join: true, undo: false
                },
                {
                    factory: IPA.target_section,
                    name: 'target',
                    label: IPA.messages.objects.permission.target,
                    undo: false
                }]}).
        details_facet({sections:[
            {
                name:'identity',
                fields: [{
                    factory: IPA.text_widget,
                    name: 'cn',
                    read_only: true
                }]
            },
            {
                name:'rights',
                factory:IPA.rights_section
            },
            {
                name:'target',
                factory:IPA.target_section,
                label: IPA.messages.objects.permission.target
            }]}).
        standard_association_facets().
        build();
};


IPA.entity_factories.privilege = function() {
    return IPA.entity_builder().
        entity('privilege').
        search_facet({
            columns:['cn','description'],
            add_fields:['cn', 'description']}).
        details_facet({
            sections:
            [{
                name:'identity',
                label: IPA.messages.details.identity,
                fields:['cn','description']
            }]}).
        association_facet({
            name: 'member_role',
            add_method: 'add_privilege',
            remove_method: 'remove_privilege',
            associator: IPA.serial_associator
        }).
        association_facet({
                name: 'memberof_permission',
                add_method: 'add_permission',
                remove_method: 'remove_permission'
        }).
        standard_association_facets().
        build();

};


IPA.entity_factories.role = function() {
    return  IPA.entity_builder().
        entity('role').
        search_facet({
            columns:['cn','description'],
            add_fields:['cn', 'description']}).
        details_facet({sections:[
            {
                name:'identity',
                label:IPA.messages.objects.role.identity,
                fields:['cn','description']}]}).
        association_facet({
                name: 'memberof_privilege',
                add_method: 'add_privilege',
                remove_method: 'remove_privilege'
        }).
        standard_association_facets().
        build();
};


IPA.entity_factories.selfservice = function() {
    return IPA.entity_builder().
        entity('selfservice').
        search_facet({
            columns:['aciname'],
            add_fields:[
                'aciname',
                {factory:IPA.attributes_widget,
                 object_type:'user',
                 name:'attrs',
                 undo: false
                }]}).
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
        build();
};


IPA.entity_factories.delegation = function() {
    return IPA.entity_builder().
        entity('delegation').
        search_facet({
            columns:['aciname'],
            add_fields:[
                'aciname',
                {
                    factory:IPA.entity_select_widget,
                    name: 'group', entity: 'group', undo: false
                },
                {
                    factory:IPA.entity_select_widget,
                    name: 'memberof', entity: 'group',
                    join: true, undo: false
                },
                {
                    factory:IPA.attributes_widget,
                    name: 'attrs', object_type: 'user',
                    join: true, undo: false
                }]}).
        details_facet({sections:[
            {
                name:'general',
                label: IPA.messages.details.general,
                fields:[
                    'aciname',
                    {
                        factory:IPA.entity_select_widget,
                        name: 'group', entity: 'group'
                    },
                    {
                        factory:IPA.entity_select_widget,
                        name: 'memberof', entity: 'group',
                        join: true
                    },
                    {
                        factory:IPA.attributes_widget,
                        name: 'attrs', object_type: 'user',
                        join: true
                    }]}]}).
        standard_association_facets().
        build();
};


IPA.attributes_widget = function(spec) {

    spec = spec || {};

    var that = IPA.checkboxes_widget(spec);

    that.object_type = spec.object_type;

    var id = spec.name;

    that.setup = function() {
    };

    that.create = function(container) {
        that.container = container;

        that.table = $('<table/>', {
            id:id,
            'class':'search-table aci-attribute-table'
        }).
            append('<thead/>').
            append('<tbody/>').
            appendTo(container);

        var tr = $('<tr></tr>').appendTo($('thead', that.table));

        tr.append($('<th/>', {
            style:"height:2em; vertical-align:bottom;",
            html:$('<input/>',{
                type: "checkbox",
                click: function(){
                    $('.aci-attribute', that.table).
                        attr('checked', $(this).attr('checked'));
                    that.show_undo();
                }
            })
        })).append($('<th/>', {
            'class': 'aci-attribute-column',
            html: IPA.messages.objects.aci.attribute
        }));

        if (that.undo) {
            that.create_undo(container);
            that.get_undo().click(function(){
                that.reset();
                that.hide_undo();
            });
        }

        if (that.object_type){
            that.populate (that.object_type);
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
                    that.show_undo();
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
                        that.show_undo();
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

    that.init = function() {

        that.widget_init();

        for (var i=0; i<that.rights.length; i++) {
            var right = that.rights[i];
            that.add_option({label: right, value: right});
        }
    };

    return that;
};


IPA.rights_section = function() {

    var spec = {
        name: 'rights',
        label: IPA.messages.objects.permission.rights
    };

    var that = IPA.details_section(spec);

    that.add_field(IPA.rights_widget({
        name: 'permissions',
        join: true
    }));

    return that;
};


IPA.target_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_section(spec);
    that.undo = typeof spec.undo == 'undefined' ? true : spec.undo;

    that.filter_text = IPA.text_widget({name: 'filter', undo: that.undo});
    that.subtree_textarea = IPA.textarea_widget({
        name: 'subtree',
        cols: 30, rows: 1,
        undo: that.undo
    });
    that.group_select = IPA.entity_select_widget(
        {name: 'targetgroup', entity:'group', undo: that.undo});
    that.type_select = IPA.select_widget({name: 'type', undo: that.undo});
    that.attribute_table = IPA.attributes_widget({
        name: 'attrs', undo: that.undo});

    that.add_field(that.filter_text);
    that.add_field(that.subtree_textarea);
    that.add_field(that.group_select );
    that.add_field(that.type_select);
    that.add_field(that.attribute_table);


    /*TODO these next two functions are work arounds for missing attribute
      permissions for the filter text.  Remove them once that has been fixed */
    that.filter_text.update = function(){
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
        var value = $.trim(input.val());
        return value === '' ? [] : [value];
    };

    var target_types = [
        {
            name:'filter',
            create: function(dl){

                $('<dt/>').
                    append($('<label/>', {
                        text: IPA.messages.objects.permission.filter+':'
                    })).
                    appendTo(dl);

                var dd = $('<dd/>', {
                    'class': 'aci_by_filter first'
                }).appendTo(dl);

                var span = $('<span/>', {
                    name: 'filter'
                }).appendTo(dd);

                that.filter_text.create(span);
            },
            load: function(record){
                that.filter_text.load(record);
            },
            save: function(record){
                record.filter = that.filter_text.save()[0];
            }
        },
        {
            name:'subtree',
            create:function(dl) {
                $('<dt/>').
                    append($('<label/>', {
                        text: IPA.messages.objects.permission.subtree+':'
                    })).
                    appendTo(dl);
                var dd = $('<dd/>', {
                    'class': 'aci_by_query first'
                }).appendTo(dl);
                var span = $('<span/>', {
                    name: 'subtree'
                }).appendTo(dd);
                that.subtree_textarea.create(span);
            },
            load: function(record){
                that.subtree_textarea.load(record);
            },
            save: function(record){
                record.subtree = that.subtree_textarea.save()[0];
            }
        },
        {
            name:'targetgroup',
            create:  function (dl) {
                $('<dt/>').
                    append($('<label/>', {
                        text: IPA.messages.objects.permission.targetgroup+':'
                    })).
                    appendTo(dl);
                var dd = $('<dd/>', {
                    'class': 'aci_by_group first'
                }).appendTo(dl);
                var span = $('<span/>', {
                    name: 'targetgroup'
                }).appendTo(dd);
                that.group_select.create(span);
            },
            load: function(record){
                that.group_select.entity_select.val(record.targetgroup);
            },
            save: function(record){
                record.targetgroup = that.group_select.save()[0];
            }
        },
        {
            name:'type',
            create:   function(dl) {
                $('<dt/>').
                    append($('<label/>', {
                        text: IPA.messages.objects.permission.type+':'
                    })).
                    appendTo(dl);
                var dd = $('<dd/>', {
                    'class': 'aci_by_type first'
                }).appendTo(dl);
                var span = $('<span/>', {
                    name: 'type'
                }).appendTo(dd);
                that.type_select.create(span);
                that.type_select.setup(span);

                span = $('<dd/>', {
                    name: 'attrs',
                    'class':'other'
                }).appendTo(dl);

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
                for (var i=0; i<type_params.values.length; i++){
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
            load: function(record){
                that.type_select.load(record);
                that.attribute_table.object_type = record.type;
                that.attribute_table.reset();
            },
            save: function(record){
                record.type = that.type_select.save()[0];
                record.attrs =  that.attribute_table.save().join(',');
            }
        }] ;

    var target_type = target_types[0];

    function show_target_type(type_to_show){
        for (var i =0 ; i < target_types.length; i +=1){
            if ( target_types[i].name === type_to_show){
                target_type = target_types[i];
                target_type.container.css('display', 'block');
            }else{
                target_types[i].container.css('display', 'none');
            }
        }

    }
    that.create = function(container) {

        var dl =  $('<dl/>', {
            'class': 'aci-target'
        }).appendTo(container);
        $('<dt>Target:</dt>').appendTo(dl);

        if (that.undo){
            dl.css('display','none');
        }
        that.target_type_select =  $('<select></select>',{
            change:function(){
                show_target_type(this.value);
            }});

        $('<dd/>',
          {"class":"first"}).
            append(that.target_type_select).appendTo(dl);

        for (var i = 0 ; i < target_types.length; i += 1){
            target_type = target_types[i];
            dl =  $('<dl/>', {
                'class': 'aci-target' ,
                id:  target_type.name,
                style: 'display:none'
            }).appendTo(container);

            that.target_type_select.append($('<option/>',{
                text: target_type.name,
                value : target_type.name
            }));
            target_type.create(dl);
            target_type.container = dl;
        }
        /*
           default for the add dialog
        */
        target_type = target_types[0];
        that.target_type_select.val( target_type.name);
        target_type.container.css('display', 'block');
    };

    function reset_target_widgets(){
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
        for (var i = 0 ; i < target_types.length; i += 1){
            target_type = target_types[i];
            if (record[target_type.name]){
                target_type_name = target_type.name;
                break;
            }
        }
        if (!target_type_name){
            alert(IPA.messages.objects.permission.invalid_target);
            return;
        }

        target_type.container.css('display', 'block');
        that.target_type_select.val( target_type_name);
        target_type.load(record);
    }
    that.load = function(record){
        that.section_load(record);
        that.reset();
    };
    that.reset = function() {
        that.section_reset();

        for (var i = 0 ; i < target_types.length ; i +=1 ){
            target_types[i].container.css('display', 'none');
        }
        if (that.record){
            set_target_type(that.record);
            that.attribute_table.object_type = that.record.type;
        }else{
            reset_target_widgets();
        }
    };

    that.save = function(record) {
        target_type.save(record);
    };

    return that;
};

IPA.permission_details_facet = function(spec) {

    spec = spec || {};

    var that = IPA.details_facet(spec);

    return that;
};
