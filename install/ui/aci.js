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


IPA.attributes_widget = function(spec) {

    spec = spec || {};

    var that = IPA.checkboxes_widget(spec);

    that.object_type = spec.object_type;

    var id = spec.name;
    var dd_class = "other";

    that.create = function(container) {

        var dd = $('<dd/>', {
            'class': dd_class
        }).appendTo(container);

        that.table = $('<table/>', {
            id:id,
            'class':'search-table aci-attribute-table'
        }).
            append('<thead/>').
            append('<tbody/>').
            appendTo(dd);

        var tr = $('<tr></tr>').appendTo($('thead', that.table));
        tr.append($('<th/>', {
            style:"height:2em; vertical-align:bottom;",
            html:$('<input/>',{
                type: "checkbox",
                click: function(){
                    $('.aci-attribute').
                        attr('checked', $(this).attr('checked'));
                },
                change: function() {
                    that.show_undo();
                }
            })
        })).
            append('<th class="aci-attribute-column">Attribute</th>');

        if (that.undo) {
            that.create_undo(dd);
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

        var metadata = IPA.metadata[object_type];
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
                change: function() {
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
            var input = $('input[name="'+that.name+'"][value="'+that.values[i]+'"]', that.container);
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

    that.create = function(container){

        for (var i = 0; i<that.rights.length; i++) {
            $('<dd/>').
            append($('<input/>', {
                type: 'checkbox',
                name: that.name,
                value: that.rights[i],
                'class': that.entity_name +'_'+ that.name
            })).
            append($('<label/>', {
                text: that.rights[i]
            })).
            appendTo(container);
        }

        if (that.undo) {
            var dd = $('<dd/>').appendTo(container);
            that.create_undo(dd);
        }
    };

    return that;
};


IPA.hidden_widget = function(spec) {
    spec.label = '';
    var that = IPA.widget(spec);
    that.id = spec.id;
    var value = spec.value || '';
    that.create = function(container){
        $('<input/>',{
            type:'hidden',
            'id':that.id,
            value: value
        }).
            appendTo(container);
    };

    that.save = function(){
        return [value];
    };
    that.reset = function(){

    };
    return that;
};


IPA.rights_section = function() {
    var spec =  {
        'name':'rights',
        'label': 'Rights'
    };
    var that = IPA.details_section(spec);
    that.add_field(IPA.rights_widget({name: 'permissions', label: 'Permissions', join: true}));

    return that;
};


IPA.target_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_section(spec);

    that.undo = typeof spec.undo == 'undefined' ? true : spec.undo;

    var groupings = ['aci_by_type',  'aci_by_query', 'aci_by_group',
                     'aci_by_filter' ];
    var inputs = ['input', 'select', 'textarea'];

    function disable_inputs() {
        for (var g = 0; g < groupings.length; g += 1 ){
            for (var t = 0 ; t < inputs.length; t += 1){
                $('.' + groupings[g] + ' '+ inputs[t]).
                    attr('disabled', 'disabled');
            }
        }
    }
    function enable_by(grouping) {
        for (var t = 0 ; t < inputs.length; t += 1){
            $('.' + grouping + ' '+ inputs[t]).
                attr('disabled', '');
        }
    }

    function display_filter_target(dl) {
        $('<dt/>').
        append($('<input/>', {
            type: 'radio',
            name: 'aci_type',
            checked: 'true',
            id: 'aci_by_filter'
        })).
        append($('<label/>', {
            text: 'Filter'
        })).
        appendTo(dl);

        var span = $('<span/>', {
            name: 'filter'
        }).
        appendTo(dl);

        var dd = $('<dd/>', {
            'class': 'aci_by_filter first'
        }).
        appendTo(span);

        that.filter_text.create(dd);
    }


    function display_type_target(dl) {
        $('<dt/>').
        append($('<input/>', {
            type: 'radio',
            name: 'aci_type',
            checked: 'true',
            id: 'aci_by_type'
        })).
        append($('<label/>', {
            text: 'Object By Type'
        })).
        appendTo(dl);

        var dd = $('<dd/>', {
            'class': 'aci_by_type first'
        }).appendTo(dl);

        var span = $('<span/>', {
            name: 'type'
        }).appendTo(dd);

        that.type_select.create(span);

        span = $('<span/>', {
            name: 'attrs'
        }).appendTo(dl);

        that.attribute_table.create(span);
    }

    function display_query_target(dl) {
        $('<dt/>').
        append($('<input/>', {
            type: 'radio',
            name: 'aci_type',
            id: 'aci_by_query'
        })).
        append($('<label/>', {
            text: 'By Subtree'
        })).
        appendTo(dl);

        var span = $('<span/>', {
            name: 'subtree'
        }).appendTo(dl);

        var dd = $('<dd/>', {
            'class': 'aci_by_query first'
        }).appendTo(span);

        that.subtree_textarea.create(dd);
    }

    function display_group_target(dl) {
        $('<dt/>').
            append($('<input />', {
                type: 'radio',
                name: 'aci_type',
                id: 'aci_by_group'
            })).
            append($('<label/>', {
                text: 'Target Group'
            })).
            appendTo(dl);

        var span = $('<span/>', {
            name: 'targetgroup'
        }).appendTo(dl);

        var dd = $('<dd/>', {
            'class': 'aci_by_group first'
        }).
        appendTo(span);

        that.group_select.create(dd);
    }

    that.create = function(container) {
        var dl =  $('<dl/>', {
            'class': 'aci-target'
        }).appendTo(container);

        display_filter_target(dl);
        display_query_target(dl);
        display_group_target(dl);
        display_type_target(dl);

        $('#aci_by_filter', dl).click(function() {
            disable_inputs();
            enable_by(groupings[3]);
        });

        $('#aci_by_type', dl).click(function() {
            disable_inputs();
            enable_by(groupings[0]);
        });

        $('#aci_by_query', dl).click(function() {
            disable_inputs();
            enable_by(groupings[1]);
        });

        $('#aci_by_group', dl).click(function() {
            disable_inputs();
            enable_by(groupings[2]);
        });

        $('#aci_by_type', dl).click();
    };

    that.setup = function(container) {
        that.section_setup(container);

        var select = that.type_select.select;

        select.change(function() {
            that.attribute_table.object_type = that.type_select.save()[0];
            that.attribute_table.reset();
        });

        select.append($('<option/>', {
            value: '',
            text: ''
        }));

        var type_params = IPA.get_param_info('permission', 'type');
        for (var i=0; i<type_params.values.length; i++){
            select.append($('<option/>', {
                value: type_params.values[i],
                text: type_params.values[i]
            }));
        }

        that.type_select.update = function() {
            that.type_select.select_update();
            that.attribute_table.object_type = that.type_select.save()[0];
            that.attribute_table.reset();
        };
    };

    function set_aci_type(record) {
        if (record.filter) {
            $('#aci_by_filter').click();

        } else if (record.subtree) {
            $('#aci_by_query').click();

        } else if (record.targetgroup) {
            $('#aci_by_group').click();

        } else if (record.type) {
            $('#aci_by_type').click();

        } else {
            alert('permission with invalid target specification');
        }
    }

    that.load = function(record) {

        set_aci_type(record);
        that.attribute_table.object_type = record.type;

        that.section_load(record);
    };

    that.reset = function() {

        set_aci_type(that.record);
        that.attribute_table.object_type = that.record.type;

        that.section_reset();
    };

    that.init = function() {
        that.filter_text = IPA.text_widget({name: 'filter', undo: that.undo});
        that.add_field(that.filter_text);

        that.subtree_textarea = IPA.textarea_widget({
            name: 'subtree',
            cols: 30, rows: 1,
            undo: that.undo
        });
        that.add_field(that.subtree_textarea);

        that.group_select = IPA.entity_select_widget(
            {name: 'targetgroup', entity:'group', undo: that.undo});
        that.add_field(that.group_select);

        that.type_select = IPA.select_widget({name: 'type', undo: that.undo});
        that.add_field(that.type_select);

        that.attribute_table = IPA.attributes_widget({name: 'attrs', undo: that.undo});
        that.add_field(that.attribute_table);
    };

    that.save = function(record) {

        var record_type = $("input[name='aci_type']:checked").attr('id');

        if (record_type === 'aci_by_group') {
            record.targetgroup = that.group_select.save()[0];

        } else if (record_type === 'aci_by_type') {
            record.type = that.type_select.save()[0];
            record.attrs =   that.attribute_table.save().join(',');

        } else if (record_type === 'aci_by_query') {
            record.subtree = that.subtree_textarea.save([0]);

        } else if (record_type === 'aci_by_filter') {
            record.filter = that.filter_text.save()[0];
        }
    };

    return that;
};

IPA.permission_details_facet = function(spec) {

    spec = spec || {};

    var that = IPA.details_facet(spec);

    that.refresh = function() {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var command = IPA.command({
            'name': that.entity_name+'_show_'+pkey,
            'method': that.entity_name+'_show',
            'args': [pkey],
            'options': { 'all': true, 'rights': true }
        });

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

    return that;
};

IPA.entity_factories.permission = function() {

    return IPA.entity({
        'name': 'permission'
    }).add_dialog(
        IPA.add_dialog({
            name: 'add',
            title: 'Add New Permission',
            width: '700px'
        }).
            field(IPA.text_widget({
                name: 'cn',
                undo: false
            })).
            field(IPA.rights_widget({name: 'permissions', label: 'Permissions', join: true, undo: false})).
            section(IPA.target_section({name: 'target', label: 'Target', undo: false}))).
        facet(IPA.search_facet().
              column({name:'cn'})).
        facet(IPA.permission_details_facet({ name: 'details' }).
              section(
                  IPA.stanza({name:'identity', label:'Identity'}).
                      input({name: 'cn', 'read_only': true})).
              section(IPA.rights_section()).
              section(IPA.target_section({name: 'target', label: 'Target'})));

};


IPA.entity_factories.privilege = function() {
    var that = IPA.entity({
        'name': 'privilege'
    }).
        facet(
            IPA.search_facet().
                column({name:'cn'}).
                column({name:'description'})).
        facet(
            IPA.details_facet({name:'details'}).
                section(
                    IPA.stanza({name:'identity', label:'Privilege Settings'}).
                        input({name:'cn'}).
                        input({name: 'description'}))).
        add_dialog(
            IPA.add_dialog({
                name: 'add',
                title: 'Add Privilege'}).
                field(IPA.text_widget({ name: 'cn', undo: false})).
                field(IPA.text_widget({ name: 'description', undo: false}))).
    association({
        name: 'permission',
        other_entity: 'privilege',
        add_method: 'add_permission',
        remove_method: 'remove_permission'
    }).

    standard_associations();


    return that;
};


IPA.entity_factories.role = function() {
    return  IPA.entity({
        'name': 'role'
    }).
        facet(IPA.search_facet().
              column({name:'cn'}).
              column({name:'description'})).
        facet(
            IPA.details_facet({name:'details'}).
                section(
                    IPA.stanza({name:'identity', label:'Role Settings'}).
                        input({name:'cn'}).
                        input({name: 'description'}))).
        add_dialog(
            IPA.add_dialog({
                name: 'add',
                title: 'Add Role'
            }).
                field(IPA.text_widget({ name: 'cn', undo: false})).
                field(IPA.text_widget({ name: 'description', undo: false}))).
        association({
            name: 'privilege',
            add_method: 'add_privilege',
            remove_method: 'remove_privilege'
        }).
        standard_associations();
};


IPA.entity_factories.selfservice = function() {
    return IPA.entity({
        'name': 'selfservice'
    }).
        facet(IPA.search_facet().
              column({name:'aciname'})).
        facet(
            IPA.details_facet({'name':'details'}).
                section(
                    IPA.stanza({name:'general', label:'General'}).
                        input({name:'aciname'}).
                        custom_input(IPA.attributes_widget({
                            object_type:'user',
                            name:'attrs'
                        })))).
        add_dialog(
            IPA.add_dialog({
                name: 'add',
                title: 'Add Self Service Definition'
            }).
                field(IPA.text_widget({ name: 'aciname', undo: false})).
                field(IPA.attributes_widget({
                    object_type:'user',
                    name:'attrs'
                })));
};


IPA.entity_factories.delegation = function() {
    var that = IPA.entity({
        'name': 'delegation'
    }).facet(
        IPA.search_facet().
            column({name:'aciname'})).
        facet(
            IPA.details_facet().
                section(
                    IPA.stanza({name:'general', label:'General'}).
                        input({name:'aciname'}).
                        custom_input(IPA.entity_select_widget(
                            {name:'group', entity:'group'})).
                        custom_input(IPA.entity_select_widget(
                            {name:'memberof', label: 'Member Group',
                             entity:'group', join: true})).
                        custom_input(
                            IPA.rights_widget({name: 'permissions', label: 'Permissions',
                                join: true})).
                        custom_input(
                            IPA.attributes_widget({
                                name:'attrs', object_type:'user', join: true})))).
        add_dialog(IPA.add_dialog({
            name: 'add',
            title: 'Add Delegation',
            width: '700px'
        }).
            field(IPA.text_widget({ name: 'aciname', undo: false})).
            field(IPA.entity_select_widget({name:'group',
                entity:'group', undo: false})).
            field(IPA.entity_select_widget({name:'memberof', entity:'group',
                join: true, undo: false})).
            field(IPA.attributes_widget({ name: 'attrs', object_type:'user',
                join: true, undo: false}))).
        standard_associations();
    return that;

};
