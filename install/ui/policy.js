/*jsl:import ipa.js */
/*jsl:import search.js */

/*  Authors:
 *    Adam Young <ayoung@redhat.com>
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

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */

/* DNS */
IPA.entity_factories.dnszone = function() {

    var that = IPA.entity({
        name: 'dnszone'
    });

    that.init = function() {

        that.facet(
            IPA.search_facet({
                name: 'search',
                label: IPA.messages.facets.search,
                entity_name: that.name
            }).
                column({name:'idnsname'}).
                dialog(
                    IPA.add_dialog({
                        name: 'add',
                        title: IPA.messages.objects.dnszone.add
                    }).
                        field(IPA.text_widget({ name: 'idnsname', undo: false})).
                        field(IPA.text_widget({ name: 'idnssoamname', undo: false})).
                        field(IPA.text_widget({ name: 'idnssoarname', undo: false}))));

        that.facet(
            IPA.details_facet({name:'details'}).
                section(
                    IPA.stanza({
                        name: 'identity',
                        label: IPA.messages.objects.dnszone.identity
                    }).
                        input({name:'idnsname'}).
                        input({name:'idnszoneactive'}).
                        input({name:'idnssoamname'}).
                        input({name:'idnssoarname'}).
                        input({name:'idnssoaserial'}).
                        input({name:'idnssoarefresh'}).
                        input({name:'idnssoaretry'}).
                        input({name:'idnssoaexpire'}).
                        input({name:'idnssoaminimum'}).
                        input({name:'dnsttl'}).
                        input({name:'dnsclass'}).
                        input({name:'idnsallowdynupdate'}).
                        input({name:'idnsupdatepolicy'})));

        that.facet(
            IPA.records_facet({
                'name': 'records',
                'label': IPA.metadata.objects.dnsrecord.label
            }));

        that.create_association_facets();
        that.entity_init();
    };

    return that;
};


IPA.records_facet = function (spec){

    spec = spec || {};

    var that = IPA.facet(spec);

    that.record = null;

    var record_types =[ 'a', 'aaaa', 'dname', 'cname', 'mx', 'ns', 'ptr',
                        'srv', 'txt', 'a6', 'afsdb', 'cert', 'ds',
                        'key', 'kx', 'loc',  'naptr', 'nsec',
                        'rrsig', 'sshfp'];

    function create_type_select(id,add_none) {
        var type_select = $('<select/>',{
            id: id
        });

        if (add_none){
            type_select.append($('<option/>',{
                text: '(any)',
                value: ''
            }));
        }
        for (var t = 0 ; t < record_types.length ; t += 1){
            var record_type = record_types[t].toUpperCase();

            type_select.append($('<option/>',{
                text: record_type,
                value: record_type
            }));
        }
        return type_select;
    }


    var  entry_attrs = {};


    function add_click(){

        var add_dialog = $('<div/>',{
            id: 'add_dns_resource_record',
            title: IPA.messages.objects.dnsrecord.add
        });
        var dl = $('<dl></dl>').appendTo(add_dialog);
        dl.append('<dt>'+IPA.messages.objects.dnsrecord.resource+'</dt>');
        dl.append( $('<dd/>').
                   append($('<input type="text" id="dns-record-resource" />')));
        dl.append('<dt>'+IPA.messages.objects.dnsrecord.type+'</dt>');
        dl.append(  $('<dd/>').append(create_type_select('dns-record-type')));
        dl.append('<dt>'+IPA.messages.objects.dnsrecord.data+'</dt>');
        dl.append($('<dd/>').append($('<textarea/>',{
            id: 'dns-record-data',
            rows:"8",
            cols:"20"
        })));


        function add(evt, called_from_add_and_edit) {
            var params = [];
            var options = {};
            function add_win(data, text_status, xhr) {
                reload();
            }

            function add_fail(data, text_status, xhr) {
            }

            params.push(  $.bbq.getState(that.entity_name+'-pkey', true));
            params.push(add_dialog.find('#dns-record-resource').val());

            var key =  add_dialog.find('#dns-record-type').val().toLowerCase()+
                "record";
            var value = add_dialog.find('#dns-record-data').val();
            options[key] = value;


            IPA.cmd('dnsrecord_add', params, options, add_win, add_fail);
            //add_dialog.dialog('close');
        }

        function add_and_close(evt) {
            add(evt, true);
            add_dialog.dialog('close');
        }

        function cancel() {
            add_dialog.dialog('close');
        }

        var buttons = {};

        buttons[IPA.messages.buttons.add_many] = add;
        buttons[IPA.messages.buttons.add_and_close] = add_and_close;
        buttons[IPA.messages.buttons.cancel] = cancel;

        add_dialog.dialog({
            modal: true,
            buttons: buttons
        });
    }


    function delete_records(records_table){

        var zone = $.bbq.getState('dnszone-pkey', true);

        var thead = records_table.find('thead');
        thead.find("INPUT[type='checkbox']").
            attr('checked', false);

        var i = 0;

        var tbody = records_table.find('tbody');


        var delete_dialog = $('<div/>', {
            title: IPA.messages.buttons.remove
        });
        var to_delete_table =
            $('<table class="search-table" >'+
              '<thead><tr><th>Resource</th><th>Type</th></tr></thead>'+
              '<tbody></tbody></table>').appendTo(delete_dialog);

        var to_delete_body =  to_delete_table.find('tbody');
        var delete_list = [];
        tbody.find("INPUT[type='checkbox']").each(
            function(index, box){
                if (box.checked){
                    var tr = $(box).parents('tr');
                    var resource = $(tr).find('[title="idnsname"]').text();
                    var type = $(tr).find('[title="type"]').
                        text().toLowerCase();
                    var data = $(tr).find('[title="data"]').text();
                    var rectype=type+"record";

                    var options = {};
                    options[rectype]=data;

                    var command = {
                        "method":"dnsrecord_del",
                        "params":[[zone,resource], options]};
                    delete_list.push(command);
                    to_delete_body.append(
                        $('<tr></tr>').
                            append($('<td></td>',{html:resource}).
                                   after($('<td></td>',{html:type}))));
                }
            }
        );

        function delete_on_click() {
            var delete_count = delete_list.length;
            function delete_complete(){
                    reload();
                    delete_dialog.dialog('close');
            }

            IPA.cmd('batch', delete_list, {},
                    delete_complete,delete_complete);
        }

        function cancel_on_click() {
            delete_dialog.dialog('close');
        }


        if (delete_list.length === 0){
            return;
        }
        delete_dialog.append($('<P/>',
                               {text: IPA.messages.search.delete_confirm}));

        var buttons = {};

        buttons[IPA.messages.buttons.remove] = delete_on_click;
        buttons[IPA.messages.buttons.cancel] = cancel_on_click;

        delete_dialog.dialog({
            modal: true,
            buttons: buttons
        });


    }

    that.is_dirty = function() {
        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var record = $.bbq.getState(that.entity_name + '-record', true) || '';
        return pkey != that.pkey || record != that.record;
    };

    function create(container) {

        container.attr('title', that.entity_name);

        $('<h1/>',{
        }).append(IPA.create_network_spinner()).
            appendTo(container);

        var details = $('<div/>', {
            'class': 'content'
        }).appendTo(container);

        var div = $('<div class="search-controls"></div>').
            appendTo(details);

        var control_span =$('<span class="record-filter"></span>').appendTo(div);
        control_span.append(IPA.messages.objects.dnsrecord.resource);
        control_span.append($('<input />',{
            type: "text",
            id: 'dns-record-resource-filter',
            name: 'search-' + that.entity_name + '-filter'
        }));

        /*
          THe OLD DNS plugin allowed for search based on record type.
          This one does not.  If the plugin gets modified to support
          Record type searches, uncomment the followin lines and
          adjust the code that modifies the search parameters.

          control_span.append('Type');
          create_type_select('dns-record-type-filter',true).
          appendTo(control_span);
        */

        IPA.button({
            'label': IPA.messages.buttons.find,
            'icon': 'ui-icon-search',
            'click': function(){refresh();}
        }).appendTo(control_span);

        var action_panel_ul = $('.action-panel .entity-facet', that.container).
            last();

        var action_controls =  $('<li/>',{
            "class":"action-controls"}).appendTo(action_panel_ul);


        IPA.action_button({
            'label': IPA.messages.buttons.add,
            'icon': 'ui-icon-plus',
            'click': add_click
        }).appendTo(action_controls);

        IPA.action_button({
            'label': IPA.messages.buttons.remove,
            'icon': 'ui-icon-trash',
            'click': function(){delete_records(records_table);}
        }).appendTo(action_controls);

        div.append('<span class="records-buttons"></span>');

        var records_results = $('<div/>', {
            'class': 'records-results'
        }).appendTo(details);

        var records_table = $('<table/>', {
            'class': 'search-table'
        }).appendTo(records_results);

        var thead = $('<thead><tr></tr></thead>').appendTo(records_table);
        var tbody = $('<tbody></tbody>').appendTo(records_table);
        var tfoot = $('<tfoot></tfoot>').appendTo(records_table);

        var tr = thead.find('tr');
        tr.append($('<th style="width: 15px" />').append(
            $('<input />',{
                type: 'checkbox',
                click : function (evt){
                    tbody.find("INPUT[type='checkbox']").
                        attr('checked', this.checked);
                }
            })));
        tr.append($('<th/>',{
            text: IPA.get_entity_param("dnsrecord", "idnsname").label  }));
         tr.append($('<th>Record Type</th>'));
        tr.append($('<th>Data</th>'));

    }

    function setup(container){

        that.facet_setup(container);

        that.pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        that.record = $.bbq.getState(that.entity_name + '-record', true) || '';


        $('h1',container).
            html("<span id='headerpkey' />"+IPA.messages.objects.dnsrecord.title+":" + that.pkey);


        //commented out until data is searchable
        //control_span.append('Data');
        //control_span.append($('<input />',{
        //    type: "text",
        //    id: 'dns-record-data-filter',
        //    name: 'search-' + obj_name + '-filter'
        //}));



        refresh();
    }


    function load_on_win(data){
        display(that.entity_name,data);
    }

    function load_on_fail(data){
        display(that.entity_name,data);
    }

    function  reload(){
        refresh();
    }


    function  refresh(){

        var options = {};

        var resource_filter = that.container.
            find("#dns-record-resource-filter").val();
//        if (resource_filter){
//            options.idnsname = resource_filter;
//        }

        var type_filter = that.container.find("#dns-record-type-filter").val();
        if (type_filter){
            options.type = type_filter;
        }

        var data_filter = that.container.find("#dns-record-data-filter").val();
        if (data_filter){
            options.data = data_filter;
        }

        var pkey = [$.bbq.getState(that.entity_name + '-pkey', true)];

        if (resource_filter){
            pkey.push(resource_filter);
        }
        IPA.cmd('dnsrecord_find',pkey,options,load_on_win, load_on_fail);

    }


    function generate_tr(thead, tbody, result){
        function generate_checkbox_td(tr, pkey) {
            var checkbox = $('<input />', {
                name: pkey,
                title: pkey,
                type: 'checkbox',
                'class': 'search-selector'
            });
            var td = $('<td></td>');

            td.append(checkbox);
            tr.append(td);
        }

        var tr = $('<tr></tr>').appendTo(tbody);

        generate_checkbox_td(tr, /*pkey_value*/ '');

        //TODO get this fixed on the back end.  For now, workaround

        if (result.idnsname){
        tr.append($('<td/>',{
            title:'idnsname',
            text: result.idnsname[0]
        }));
        }else{
            tr.append($('<td/>',{
                title:'idnsname',
                text: result.dn.split(',')[0].split('=')[1]
            }));

        }

        for (var i = 0; i < record_types.length; i += 1){
            var field_name =  record_types[i];
            var field = result[field_name+'record'];
            if ( field ){
                var record_type = field_name;
                var record_data = field[0];
                break;
            }
        }

        tr.append($('<td/>',{
            title:'type',
            text: record_type
        }));
        tr.append($('<td/>',{
            title:'data',
            text: record_data
        }));
    }

    //TODO this is cut and pasted from search, we need to unify
    function display(obj_name, data){
        var selector = '.entity-container[title=' + obj_name + ']';
        var thead = $(selector + ' thead');
        var tbody = $(selector + ' tbody');
        var tfoot = $(selector + ' tfoot');

        tbody.find('tr').remove();

        var result = data.result.result;
        for (var i = 0; i < result.length; ++i){
            generate_tr(thead, tbody, result[i]);
        }

        if (data.result.truncated) {
            var message = IPA.messages.search.truncated;
            message = message.replace('${counter}', data.result.count);
            tfoot.text(message);
        } else {
            tfoot.text(data.result.summary);
        }

    }

    that.create = create;
    that.setup = setup;
    that.refresh = refresh;

    return that;
};


/**Automount*/

IPA.entity_factories.automountlocation = function() {

    var that = IPA.entity({
        name: 'automountlocation'
    });

    that.init = function() {

        that.facet(
            IPA.search_facet({
                name: 'search',
                label: IPA.messages.facets.search,
                entity_name: that.name
            }).
                column({name:'cn'}).
                dialog(
                    IPA.add_dialog({
                        name: 'add',
                        title: IPA.messages.objects.automountlocation.add
                    }).
                        field(IPA.text_widget({ name: 'cn', undo: false}))));

        that.facet(
            IPA.details_facet({name:'details'}).
                section(
                    IPA.stanza({
                        name: 'identity',
                        label: IPA.messages.objects.automountlocation.identity
                    }).
                        input({name:'cn'})));

        that.create_association_facets();
        that.entity_init();
    };

    return that;
};


/**pwpolicy*/


IPA.entity_factories.pwpolicy = function() {

    var that = IPA.entity({
        name: 'pwpolicy'
    });

    that.init = function() {

        that.facet(
            IPA.search_facet({
                name: 'search',
                label: IPA.messages.facets.search,
                entity_name: that.name
            }).
                column({name:'cn'}).
                dialog(
                    IPA.add_dialog({
                        name: 'add',
                        title: IPA.messages.objects.pwpolicy.add,
                        entity_name:'pwpolicy'
                    }).
                        field(IPA.text_widget({name: 'cn', undo: false}))));

        that.facet(
            IPA.details_facet({name:'details'}).
                section(
                    IPA.stanza({
                        name: 'identity',
                        label: IPA.messages.objects.pwpolicy.identity
                    }).
                        input({name:'krbmaxpwdlife'}).
                        input({name:'krbminpwdlife'}).
                        input({name:'krbpwdhistorylength'}).
                        input({name:'krbpwdmindiffchars'}).
                        input({name:'krbpwdminlength'})));

        that.create_association_facets();
        that.entity_init();

    };

    return that;
};



/**
   krbtpolicy
   Does not have search
*/
IPA.entity_factories.krbtpolicy =  function() {

    var that = IPA.entity({
        name: 'krbtpolicy'
    });

    that.facet(
        IPA.details_facet({
            name: 'details'
        }).
            section(
                IPA.stanza({
                    name: 'identity',
                    label: IPA.messages.objects.krbtpolicy.identity
                }).
                    //input({name: 'uid',label:' '}).
                    input({name: 'krbmaxrenewableage'}).
                    input({name: 'krbmaxticketlife'})));

    return that;
};
