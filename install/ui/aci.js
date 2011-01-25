/*jsl:import ipa.js */

/*  Authors:
 *    Adam Young <ayoung@redhat.com>
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


/*TODO Merge this code into  the attribtue table widget */
IPA.populate_attribute_table = function (table, entity){
    var attr_per_col = 400;
    var aciattrs =  IPA.metadata[entity].aciattrs;
    var col_span = aciattrs.length / attr_per_col + 1;

    $('tbody tr', table).remove();

    var tbody = $('tbody',table);
    var td;
    for (var a = 0; a < aciattrs.length ; a += 1){
        var aci_tr =  $('<tr/>').appendTo(tbody);

        td =  $('<td/>').appendTo(aci_tr);
        td.append($('<input/>',{
            type:"checkbox",
            id:'aciattr-'+aciattrs[a].toLowerCase(),
            "class":'aci-attribute'
        }));
        td =  $('<td/>').appendTo(aci_tr);
        td.append($('<label/>',{
            text:aciattrs[a].toLowerCase()}));
    }
};

IPA.attribute_table_widget= function (spec){
    var id = spec.name;
    var that = IPA.widget(spec);
    var object_type = spec.objecttype || 'user';
    var table;

    that.create = function(container){

        var dd  = $('<dd/>').appendTo(container);
        table =   $('<table/>',{
            id:id,
            'class':'search-table aci-attribute-table'}).
            append('<thead/>').
            append($('<tbody/>')).
            appendTo(dd);

        var tr = $('<tr></tr>').appendTo($('thead', table));
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

        IPA.populate_attribute_table(table, object_type);
    };

    that.save = function(){
        var attrs_boxes  =  $('table#'+id+" td :checked");
        if (!attrs_boxes.length){
            return [];
        }
        var retval = "";
        for (var i = 0; i < attrs_boxes.length; i += 1){
            if (i > 0){
                retval += ',';
            }
            retval += attrs_boxes[i].id.substring("aciattr-".length);
        }

        return [retval];
    };

    var attrs = [];
    that.reset =function(){
        $('input[type=checkbox]', table).attr('checked','');
        for (var i = 0; i < attrs.length; i+=1){
            $(attrs[i], table).attr('checked','checked');
        }
    };

    that.load = function(record){
        if (!record.attrs) return;
        attrs = [];
        for (var i = 0; i < record.attrs.length; i+=1){
            attrs.push('#aciattr-' +record.attrs[i]);
        }
        that.reset();
    };

    return that;
};

IPA.entity_select_widget = function(spec){

    var that = IPA.widget(spec);
    var entity = spec.entity || 'group';

    function populate_select(value){
        var selected = value;
        function find_success(result){
            $('option', that.entity_select).remove();
            var entities = result.result.result;
            for (var i =0; i < result.result.count; i +=1){
                var option =
                    that.entity_select.append($('<option/>',{
                        text:entities[i].cn[0],
                        value:entities[i].cn[0]
                    }));
                if (selected === entities[i].cn[0]){
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
            text: 'filter: ',
            click:function(){
                that.entity_filter.css('display','inline');
                $(this).css('display','none');
                return false;
            }
        }).appendTo(dd);
        populate_select();
    };
    var value = '';
    that.reset = function(){
        that.entity_filter.val(value );
        populate_select(value);

    };
    that.load = function(record){
        value = record[that.name];
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

    that.reset = function(){
        var selector = '.'+ that.entity_name +"_"+ that.name;

        var checkboxes = $(selector);

        for (var i = 0; i < checkboxes.length; i +=1){
            checkboxes.attr('checked','');
        }

        for (var j = 0; j < values.length; j +=1){
            var value = values[j];
            var cb = $('#'+value+ selector);
            cb.attr('checked', 'checked');
        }

    };

    that.load = function(record) {
        values = record[that.name] || [];
        that.reset();
    };

    that.save = function(){
        var rights_input =  $('.'+ that.entity_name +"_"+ that.name);
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
    var    spec =  {
        'name':'rights',
        'label': 'Rights'
    };
    var that = IPA.details_section(spec);
    that.add_field(IPA.rights_widget({name:'permissions'}));

    return that;
};


IPA.target_section = function () {
    var    spec =  {
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
        $("<dt/>").
            append($("<label/>",{
                text:  "Filter" })).
            append($('<input/>',{
                type:"radio",
                name:"type",
                checked:"true",
                id:"aci_by_filter"
            })).
            appendTo(dl);

        $('<dd/>',{
            'class': 'aci_by_filter first'}).
            append($('<input />',{

                disabled:'true',
                type:'text',
                id:'aci_filter'
            })).
            appendTo(dl);
    }


    function display_type_target(dl){
        $("<dt/>").
            append($("<label/>",{
                text:  "Object By Type " })).
            append($('<input/>',{
                type:"radio",
                name:"type",
                checked:"true",
                id:"aci_by_type" })).
            appendTo(dl);

        var dd = $('<dd/>',{
            "class":"aci_by_type first" }).
            appendTo(dl);

        var type_select = $('<select/>', {
            id: 'object_type_select',
            change: function(){
                var attribute_table = $('#aci_attributes_table');
                IPA.populate_attribute_table(
                    attribute_table, this.options[this.selectedIndex].value);
            }
        }).appendTo(dd);
        var type_params=IPA.get_param_info("permission","type");
        for (var pc =0; pc <  type_params.values.length; pc += 1){
            type_select.append($('<option/>',{
                value:  type_params.values[pc],
                text:  type_params.values[pc]
            }));
        }
        dd = $('<dd />',{
            "class":"aci_by_type other"}).appendTo(dl);

        var attribute_table = IPA.attribute_table_widget(
            {name:'aci_attributes_table',object_type:'user'});

        attribute_table.create(dl);


    }

    function display_query_target(dl){
        $('<dt/>').
            append($('<label />',{ html: 'By Subtree'} )).
            append($('<input />',{
                type:"radio",
                name:"type",
            id:"aci_by_query" })).
            appendTo(dl);

        $("<dd/>",{
            "class":'aci_by_query first'}).append($('<textarea />',{
                id: 'aci_query_text',
                cols:'30',
                rows:'1'})) .appendTo(dl);
    }

    function populate_target_group_select(){
        function find_success(result){
            var groups = result.result.result;
            for (var i =0; i < result.result.count; i +=1){
                var option = groups[i].cn[0];
                that.group_select.append($('<option/>',{
                    text:groups[i].cn[0],
                    value:groups[i].cn[0]
                }));
            }
        }
        function find_error(err){
        }

        $('option', that.group_select).remove();
        IPA.command({
            method:'group_find',
            args:[that.group_filter.val()],
            options:{},
            on_success:find_success,
            on_error:find_error}).execute();
    }

    function display_group_target(dl){
        $('<dt/>' ).
            append($('<label />',{
                html: 'Target Group'} )).
            append($('<input />',{
                type:"radio",
                name:"type",
                id:"aci_by_group" })).
            appendTo(dl);

        that.group_filter = $('<input/>',{
            type: 'text',
            id: 'group_filter' });
        that.group_select = $('<select/>', {
            id: 'aci_target_group_select',
            change: function(){
            }
        });

        $("<dd/>",{
            'class':'aci_by_group first'
        }).
            append(that.group_filter).
            append($('<label>Group Filter</label>')).
            appendTo(dl);

        $("<dd/>",{
            'class':'aci_by_group other'
        }).
            append(that.group_select).
            appendTo(dl);
    }




    that.create = function(container) {
        var dl =  $('<dl class="entryattrs"/>').appendTo(container);

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
            populate_target_group_select();
        });

        $('#aci_by_query', dl).click();


    };

    that.setup = function(container) {
    };

    that.load = function(result) {
        if(result.subtree){
            $('#aci_query_text').val(result.subtree);
            $('#aci_by_query').click();
        }else if(result.type){
            $('#aci_by_type').click();
            $('#object_type_select').val(result.type);
            IPA.populate_attribute_table($('#aci_attributes_table'),
                                         result.type);
            if (result.attrs){
                for (var a = 0; a < result.attrs.length; a += 1){
                    var cb =  $('#aciattr-'+result.attrs[a]);
                    if (!cb.length){
                        alert('unmatched:'+result.attrs[a]);
                    }
                    cb.attr('checked',true);
                }
            }
        }else if (result.targetgroup){
            var segments =    result.targetgroup.split(/,/);
            var targetgroup=segments[0].split(/=/)[1];
            that.group_filter.val( targetgroup);
            $('#aci_by_group').click();
        }else if (result.filter){
            $('#aci_by_filter').click();
            $('#aci_filter').val(result.filter);
        }else{
            alert('permission with invalid target specification');
        }
    };

    that.reset = function() {
    };

    that.save = function (record){

        var record_type = $("input[name='type']:checked").attr('id');

        if (record_type === 'aci_by_group'){
            record.targetgroup =
                $('#aci_target_group_select option:selected').val();
        }else if (record_type === 'aci_by_type'){
            record.type = $('#object_type_select option:selected').val();
        }else if (record_type === 'aci_by_query'){
            record.subtree = $('#aci_query_text').val();
        }else if (record_type === 'aci_by_filter'){
            var filter =  $('#aci_filter').val();
            record.filter = filter;
        }

        var attrs = $('.aci-attribute:checked').each(function(){
            var id = this.id.split('-')[1];

            if (!record.attributes){
                record.attributes = "";
            }else{
                record.attributes += ",";
            }
            record.attributes += id;
        });
    };
    return that;
};


IPA.permission = function () {

    var that = IPA.entity({
        'name': 'permission'
    });

    that.init = function() {

        var dialog = IPA.permission_add_dialog({
            name: 'add',
            title: 'Add New Permission',
            entity_name: 'permission'
        });
        that.add_dialog(dialog);
        dialog.init();

        var facet = IPA.permission_search_facet({
            name: 'search',
            label: 'Search'
        });
        that.add_facet(facet);

        facet = IPA.permission_details_facet();
        that.add_facet(facet);

        that.entity_init();
    };

    return that;
};


IPA.add_entity(IPA.permission());



IPA.permission_add_dialog =  function (spec) {

    spec = spec || {};

    var that = IPA.add_dialog(spec);

    that.init = function() {

        that.add_field(IPA.text_widget({
            name: 'cn',
            undo: false
        }));

        that.add_field(IPA.text_widget({
            name: 'description',
            undo: false
        }));

        that.add_field(IPA.rights_widget({name:'permissions'}));
        that.add_field(IPA.hidden_widget({name:'filter','value':'objectClass=changethisvalue'}));
        that.add_dialog_init();
    };


    return that;
};


IPA.permission_search_facet =  function (spec) {

    spec = spec || {};
    var that = IPA.search_facet(spec);
    that.init = function() {
        that.create_column({name:'cn'});
        that.create_column({name:'description'});
        that.search_facet_init();
    };
    return that;
};


IPA.permission_details_facet = function () {

    var spec = {
            name: 'details'
    };
    var that = IPA.details_facet(spec);

    that.init = function() {

        var section = that.add_section(IPA.details_list_section({
            name:'identity',label:'Identity'  }));
        section.create_field({ name: 'cn', 'read_only': true });
        section.create_field({ name: 'description'});

        that.rights_section = IPA.rights_section();
        that.add_section(that.rights_section);

        that.target_section = IPA.target_section();

        that.add_section(that.target_section);
        that.details_facet_init();
    };

    that.superior_load = that.load;

    that.load = function(result) {
        that.superior_load(result);
    };

    that.superior_update = that.update;
    that.update = function(on_win, on_fail){
        that.superior_update(on_win, on_fail);
    };
    return that;
};


IPA.add_entity( function() {
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
}());


IPA.add_entity( function() {
    var that = IPA.entity({
        'name': 'role'
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
                IPA.stanza({name:'identity', label:'Role Settings'}).
                    input({name:'cn'}).
                    input({name: 'description'}));
            return that;
        }());

        var dialog = IPA.add_dialog({
            name: 'add',
            title: 'Add Role'
        });
        that.add_dialog(dialog);

        dialog.add_field(IPA.text_widget({ name: 'cn', undo: false}));
        dialog.add_field(IPA.text_widget({ name: 'description', undo: false}));
        dialog.init();

        that.create_association_facets();

        that.entity_init();
    };
    return that;
}());


IPA.add_entity( function() {
    var that = IPA.entity({
        'name': 'selfservice'
    });

    that.add_facet(function () {
        var spec = {
            name: 'search',
            label: 'Search'
        };
        var that = IPA.search_facet(spec);
        that.init = function() {
            that.create_column({name:'aciname'});
            that.search_facet_init();
        };
        return that;
    }());


    that.add_facet(function(){
        var that = IPA.details_facet({'name':'details'});

        that.init = function() {
            that.add_section(
                IPA.stanza({name:'general', label:'General'}).
                    input({name:'aciname'}).
                    custom_input(IPA.attribute_table_widget({
                        object_type:'user',
                        name:'attrs'
                    })));
        };
        return that;
    }());


    that.parent_init = that.init;
    that.init = function(){
        that.parent_init();
        var dialog = IPA.add_dialog({
            name: 'add',
            title: 'Add Self Service Definition'
        });
        that.add_dialog(dialog);
        dialog.add_field(IPA.text_widget({ name: 'aciname', undo: false}));
        dialog.add_field(IPA.attribute_table_widget({
            object_type:'user',
            name:'attrs'
        }));
        dialog.init();
    };
    return that;
}());


IPA.add_entity( function() {
    var that = IPA.entity({
        'name': 'delegation'
    });

    that.add_facet(function () {
            var spec = {
                name: 'search',
                label: 'Search'
            };
            var that = IPA.search_facet(spec);
            that.init = function() {
                that.create_column({name:'aciname'});
                that.search_facet_init();
            };
            return that;
        }());
    that.add_facet(function(){
        var that = IPA.details_facet({'name':'details'});
        var section =
            IPA.stanza({name:'general', label:'General'}).
            input({name:'aciname'}).
            custom_input(IPA.entity_select_widget(
                {name:'group', entity:'group'})).
            custom_input(IPA.entity_select_widget(
                {name:'memberof', entity:'group'})).
            custom_input(
                IPA.rights_widget({
                    id:'delegation_rights'})).
            custom_input(
                IPA.attribute_table_widget({
                    name:'attrs'}));
            that.add_section(section);
        return that;
    }());

    that.super_init = that.init;
    that.init = function(){
        that.super_init();
        var dialog = IPA.add_dialog({
            name: 'add',
            title: 'Add Delegation',
            entity_name: that.entity
        });
        that.add_dialog(dialog);
        dialog.add_field(IPA.text_widget({ name: 'aciname', undo: false}));
        dialog.add_field(IPA.entity_select_widget({name:'group',
                                                   entity:'group'}));
        dialog.add_field(IPA.entity_select_widget({name:'memberof',
                                                   entity:'group'}));
        dialog.add_field(IPA.attribute_table_widget({ name: 'attrs'}));

        dialog.init();
        that.create_association_facets();
    };

    return that;
}());