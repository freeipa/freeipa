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


IPA.attribute_table_widget = function(spec) {

    spec = spec || {};

    var that = IPA.checkboxes_widget(spec);

    that.object_type = spec.object_type;

    var id = spec.name;
    var dd_class = "other";

    that.create = function(container){

        var dd = $('<dd/>', {
            'class': dd_class
        }).appendTo(container);

        var span = $('<span/>', {
            name: 'attrs'
        }).appendTo(dd);

        that.table = $('<table/>', {
            id:id,
            'class':'search-table aci-attribute-table'}).
            append('<thead/>').
            append($('<tbody/>')).
            appendTo(span);

        var tr = $('<tr></tr>').appendTo($('thead', that.table));
        tr.append($('<th/>',{
            style:"height:2em; vertical-align:bottom;",
            html:$('<input/>',{
                type: "checkbox",
                click: function(){
                    $('.aci-attribute').
                        attr('checked', $(this).attr('checked'));
                }})
        })).
            append('<th class="aci-attribute-column">Attribute</th>');
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
        that.checkboxes_update();
        that.append();
    };

    that.populate = function(object_type){

        $('tbody tr', that.table).remove();

        if (!object_type || object_type === '') return;

        var metadata = IPA.metadata[object_type];
        if (!metadata) return;

        var aciattrs = metadata.aciattrs;

        var attr_per_col = 400;
        var col_span = aciattrs.length / attr_per_col + 1;

        var tbody = $('tbody', that.table);
        var td;
        for (var a = 0; a < aciattrs.length ; a += 1){
            var value = aciattrs[a].toLowerCase();
            var aci_tr =  $('<tr/>').appendTo(tbody);

            td =  $('<td/>').appendTo(aci_tr);
            td.append($('<input/>',{
                type: 'checkbox',
                id: 'aciattr-'+value,
                name: 'attrs',
                value: value,
                'class': 'aci-attribute'
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
            var cb = $('#aciattr-'+that.values[i]);
            if (!cb.length){
                unmatched.push(that.values[i]);
            }
            cb.attr('checked',true);
        }

        if (unmatched.length > 0){
            var tbody = $('tbody', that.table);

            for (var j=0; j<unmatched.length; j++) {
                var value = unmatched[j].toLowerCase();
                var tr = $('<tr/>').appendTo(tbody);

                var td = $('<td/>').appendTo(tr);
                td.append($('<input/>', {
                    type: 'checkbox',
                    checked: true,
                    id: 'aciattr-'+value,
                    name: 'attrs',
                    value: value,
                    'class': 'aci-attribute'
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

IPA.targetgroup_widget = function(spec) {

    spec = spec || {};

    var that = IPA.select_widget(spec);

    that.filter = spec.filter || '';

    that.create = function(container) {
        that.select = $('<select/>', {
            name: that.name,
            id: 'aci_target_group_select'
        }).appendTo(container);
    };

    that.load = function(record) {

        that.empty();

        that.select.append($('<option/>', {
            text: '',
            value: ''
        }));

        var command = IPA.command({
            method: 'group_find',
            args: [that.filter],
            options: {}
        });

        command.on_success = function(data, text_status, xhr) {

            var groups = data.result.result;

            for (var i=0; i<data.result.count; i++) {
                var option = groups[i].cn[0];
                that.select.append($('<option/>', {
                    text: groups[i].cn[0],
                    value: groups[i].cn[0]
                }));
            }

            that.select_load(record);
        };

        command.execute();
    };

    return that;
};

IPA.type_widget = function(spec) {

    spec = spec || {};

    var that = IPA.select_widget(spec);

    that.filter = spec.filter || '';

    that.create = function(container) {
        that.select = $('<select/>', {
            name: that.name,
            id: 'object_type_select'
        }).appendTo(container);
    };

    return that;
};

IPA.entity_select_widget = function(spec){

    var that = IPA.widget(spec);
    var entity = spec.entity || 'group';

    function populate_select(value){
        function find_success(result){
            $('option', that.entity_select).remove();
            var entities = result.result.result;
            for (var i =0; i < result.result.count; i +=1){
                var option =
                    that.entity_select.append($('<option/>',{
                        text:entities[i].cn[0],
                        value:entities[i].cn[0]
                    }));
                if (value === entities[i].cn[0]){
                    option.attr('selected','selected');
                }
            }
        }
        function find_error(err){
        }
        IPA.command({
            method: entity+'_find',
            args:[that.entity_filter.val()],
            options:{},
            on_success:find_success,
            on_error:find_error
        }).execute();
    }

    that.create = function(container){
        var dd = $('<dd/>').appendTo(container);

        that.entity_select = $('<select/>', {
            id: that.name + '-entity-select',
            change: function(){

            }
        }).appendTo(dd);


        that.entity_filter = $('<input/>',{
            size:10,
            type: 'text',
            id: 'entity_filter',
            style: 'display: none;',
            keypress: function(){
                populate_select();
            }
        }).appendTo(dd);

        $('<a />',{
            href:"",
            text: 'add ' +entity + ' filter: ',
            click:function(){
                that.entity_filter.css('display','inline');
                $(this).css('display','none');
                return false;
            }
        }).appendTo(dd);
        populate_select();
    };
    that.reset = function(){
        that.entity_filter.val(that.values[0]);
        populate_select(that.values[0]);

    };
    that.load = function(record){
        var value = record[that.name];
        if (value instanceof Array) {
            that.values = value;
        } else {
            that.values = value ? [value] : [''];
        }
        that.reset();
    };

    that.save = function(){
        return [$('option:selected', that.entity_select).val()];
    };

    return that;
};

IPA.rights_widget = function(spec){
    var rights = ['write','add','delete'];

    var that = IPA.widget({name:'permissions',label:'Permissions'});
    that.id = spec.id;

    that.create = function(container){
        for (var i =0; i < rights.length; i += 1){
            $("<dd/>").
                append($('<input/>',{
                    type:'checkbox',
                    'class':that.entity_name +"_"+ that.name,
                    'id':rights[i],
                    value:rights[i]
                })).
                append($('<label/>',{
                    text:rights[i]
                })).
                appendTo(container);
        }

    };
    var values = [];

    function get_selector(){
        return  '.'+ that.entity_name +"_"+ that.name;
    }

    that.is_dirty = function(){

        var checkboxes = $(get_selector());
        var checked = {};

        checkboxes.each(function (){
            checked[this.id] = this.checked;
        });

        for (var i = 0; i < values.length; i +=1){
            var key = values[i];

            if ( !checked[key] ){
                return true;
            }
            checked[key] = false;
        }

        for (key in checked){
            if (checked[key] ){
                return true;
            }
        }

        return false;
    };

    that.reset = function(){

        var checkboxes = $(get_selector());

        for (var i = 0; i < checkboxes.length; i +=1){
            checkboxes.attr('checked','');
        }

        for (var j = 0; j < values.length; j +=1){
            var value = values[j];
            var cb = $('#'+value+ get_selector());
            cb.attr('checked', 'checked');
        }

    };

    that.load = function(record) {
        values = record[that.name] || [];
        that.reset();
    };

    that.save = function(){
        var rights_input =  $(get_selector()+":checked");
        var retval = "";
        for (var i =0; i < rights_input.length; i+=1){
            if (i > 0) {
                retval += ',';
            }
            retval += rights_input[i].value;
        }
        return [retval];
    };

    return that;
};


IPA.hidden_widget = function(spec){
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


IPA.rights_section = function () {
    var spec =  {
        'name':'rights',
        'label': 'Rights'
    };
    var that = IPA.details_section(spec);
    that.add_field(IPA.rights_widget({name:'permissions'}));

    return that;
};


IPA.target_section = function () {

    var spec =  {
        'name':'target',
        'label': 'Target'
    };

    var that = IPA.details_section(spec);

    var groupings = ['aci_by_type',  'aci_by_query', 'aci_by_group',
                     'aci_by_filter' ];
    var inputs = ['input', 'select', 'textarea'];

    function disable_inputs(){
        for (var g = 0; g < groupings.length; g += 1 ){
            for (var t = 0 ; t < inputs.length; t += 1){
                $('.' + groupings[g] + ' '+ inputs[t]).
                    attr('disabled', 'disabled');
            }
        }
    }
    function enable_by(grouping){
        for (var t = 0 ; t < inputs.length; t += 1){
            $('.' + grouping + ' '+ inputs[t]).
                attr('disabled', '');
        }
    }

    function display_filter_target(dl){
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

        $('<dd/>', {
            'class': 'aci_by_filter first'
        }).
        append(
            $('<span/>', {
                name: 'filter'
            }).
            append(
                $('<input/>', {
                    name: 'filter',
                    disabled: 'true',
                    type: 'text',
                    id: 'aci_filter'
                }))).
        appendTo(dl);
    }


    function display_type_target(dl){
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

        var select = that.type_select.select;
        select.change(function() {
            that.attribute_table.object_type = this.options[this.selectedIndex].value;
            that.attribute_table.reset();
        });

        select.append($('<option/>', {
            value: '',
            text: ''
        }));

        var type_params = IPA.get_param_info('permission', 'type');
        for (var pc =0; pc <  type_params.values.length; pc += 1){
            select.append($('<option/>', {
                value: type_params.values[pc],
                text: type_params.values[pc]
            }));
        }

        that.attribute_table = that.get_field('attrs');

        that.attribute_table.create(dl);
    }

    function display_query_target(dl){
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

        $('<dd/>', {
            'class': 'aci_by_query first'
        }).append(
            $('<span/>', {
                name: 'subtree'
            }).append(
                $('<textarea/>', {
                    name: 'subtree',
                    id: 'aci_query_text',
                    cols: '30',
                    rows: '1'
                }))).
        appendTo(dl);
    }

    function display_group_target(dl){
        $('<dt/>' ).
            append($('<input />', {
                type: 'radio',
                name: 'aci_type',
                id: 'aci_by_group'
            })).
            append($('<label/>', {
                text: 'Target Group'
            })).
            appendTo(dl);

        that.group_filter = $('<input/>',{
            type: 'text',
            id: 'group_filter' });

        var span = $('<span/>', {
            name: 'targetgroup'
        }).appendTo(dl);

        $('<dd/>', {
            'class': 'aci_by_group first'
        }).
        append(that.group_filter).
        append($('<label>Group Filter</label>')).
        appendTo(span);

        var dd = $('<dd/>', {
            'class': 'aci_by_group other'
        }).appendTo(span);

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

        $('#aci_by_filter', dl).click(function (){
            disable_inputs();
            enable_by(groupings[3]);
        });

        $('#aci_by_type', dl).click(function (){
            disable_inputs();
            enable_by(groupings[0]);
        });

        $('#aci_by_query', dl).click(function (){
            disable_inputs();
            enable_by(groupings[1]);
        });

        $('#aci_by_group', dl).click(function (){
            disable_inputs();
            enable_by(groupings[2]);
        });

        $('#aci_by_type', dl).click();
    };

    that.setup = function(container) {
        that.section_setup(container);
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
        that.group_select.filter = that.group_filter.val();
        that.attribute_table.object_type = record.type;

        that.section_load(record);
    };

    that.reset = function() {

        set_aci_type(that.record);
        that.attribute_table.object_type = that.record.type;

        that.section_reset();
    };

    that.init = function() {
        that.add_field(IPA.text_widget({name: 'filter'}));
        that.add_field(IPA.textarea_widget({name: 'subtree'}));

        that.group_select = IPA.targetgroup_widget({name: 'targetgroup'});
        that.add_field(that.group_select);

        that.type_select = IPA.type_widget({name: 'type'});
        that.add_field(that.type_select);

        that.attribute_table = IPA.attribute_table_widget({name: 'attrs'});
        that.add_field(that.attribute_table);
    };

    that.save = function (record){

        var record_type = $("input[name='aci_type']:checked").attr('id');

        if (record_type === 'aci_by_group'){
            record.targetgroup = that.group_select.save()[0];
        }else if (record_type === 'aci_by_type'){
            record.type = $('#object_type_select option:selected').val();
            record.attrs =   that.attribute_table.save().join(',');
        }else if (record_type === 'aci_by_query'){
            record.subtree = $('#aci_query_text').val();
        }else if (record_type === 'aci_by_filter'){
            var filter =  $('#aci_filter').val();
            record.filter = filter;
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

IPA.entity_factories.permission = function () {

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
            field(IPA.text_widget({
                name: 'description',
                undo: false
            })).
            field(IPA.rights_widget({name:'permissions'})).
            section(IPA.target_section())).
        facet(IPA.search_facet().
              column({name:'cn'}).
              column({name:'description'})).
        facet(IPA.permission_details_facet({ name: 'details' }).
              section(
                  IPA.stanza({
                name:'identity',label:'Identity'  }).
                      input({ name: 'cn', 'read_only': true }).
                      input({ name: 'description'})).
              section(IPA.rights_section()).
              section(IPA.target_section()));

};


IPA.entity_factories.privilege =  function() {
    var that = IPA.entity({
        'name': 'privilege'
    });
    that.init = function() {

        var search_facet = IPA.search_facet({
            name: 'search',
            label: 'Search',
            entity_name: that.name
        });
        search_facet.create_column({name:'cn'});
        search_facet.create_column({name:'description'});
        that.add_facet(search_facet);

        that.add_facet(function() {
            var that = IPA.details_facet({name:'details'});
            that.add_section(
                IPA.stanza({name:'identity', label:'Privilege Settings'}).
                    input({name:'cn'}).
                    input({name: 'description'}));
            return that;
        }());


        var dialog = IPA.add_dialog({
            name: 'add',
            title: 'Add Privilege',
            entity_name: that.entity
        });
        that.add_dialog(dialog);

        dialog.add_field(IPA.text_widget({ name: 'cn', undo: false}));
        dialog.add_field(IPA.text_widget({ name: 'description', undo: false}));
        dialog.init();

        that.create_association_facets();
        that.entity_init();
    };
    return that;
};


IPA.entity_factories.role =  function() {
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
        standard_associations();
};


IPA.entity_factories.selfservice =  function() {
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
                        custom_input(IPA.attribute_table_widget({
                            object_type:'user',
                            name:'attrs'
                        })))).
        add_dialog(
            IPA.add_dialog({
                name: 'add',
                title: 'Add Self Service Definition'
            }).
                field(IPA.text_widget({ name: 'aciname', undo: false})).
                field(IPA.attribute_table_widget({
                    object_type:'user',
                    name:'attrs'
                })));
};


IPA.entity_factories.delegation =  function() {
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
                            {name:'memberof', entity:'group', join: true})).
                        custom_input(
                            IPA.rights_widget({
                                id:'delegation_rights'})).
                        custom_input(
                            IPA.attribute_table_widget({
                                name:'attrs', object_type:'user', join: true})))).
        add_dialog(IPA.add_dialog({
            name: 'add',
            title: 'Add Delegation'
        }).
                   field(IPA.text_widget({ name: 'aciname', undo: false})).
                   field(IPA.entity_select_widget({name:'group',
                                                   entity:'group'})).
                   field(IPA.entity_select_widget({name:'memberof',
                                                   entity:'group', join: true})).
                   field(IPA.attribute_table_widget({ name: 'attrs', object_type:'user', join: true}))).
        standard_associations();
    return that;

};
