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

    return  IPA.entity_builder().
        entity('dnszone').
        search_facet({
            columns:['idnsname'],
            add_fields: ['idnsname','idnssoamname','idnssoarname']
        }).
        details_facet({sections:[{
            name:'identity',
            fields:[
                'idnsname',
                'idnszoneactive',
                'idnssoamname',
                'idnssoarname',
                'idnssoaserial',
                'idnssoarefresh',
                'idnssoaretry',
                'idnssoaexpire',
                'idnssoaminimum',
                'dnsttl',
                'dnsclass',
                'idnsallowdynupdate',
                'idnsupdatepolicy']}]}).
        facet(IPA.records_facet({
            'name': 'records',
            'label': IPA.metadata.objects.dnsrecord.label
        })).
        standard_association_facets().
        build();
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

        var dialog = IPA.dialog({
            title: IPA.messages.objects.dnsrecord.add
        });

        dialog.create = function() {

            var dl = $('<dl/>').appendTo(dialog.container);

            $('<dt/>', {
                html: IPA.messages.objects.dnsrecord.resource
            }).appendTo(dl);

            var dd = $('<dd/>').appendTo(dl);

            dialog.resource = $('<input/>', {
                type: 'text'
            }).appendTo(dd);

            $('<dt/>', {
                html: IPA.messages.objects.dnsrecord.type
            }).appendTo(dl);

            dd = $('<dd/>').appendTo(dl);

            dialog.type = create_type_select('dns-record-type').appendTo(dd);

            $('<dt/>', {
                html: IPA.messages.objects.dnsrecord.data
            }).appendTo(dl);

            dd = $('<dd/>').appendTo(dl);

            dialog.data = $('<textarea/>', {
                rows: 8,
                cols: 20
            }).appendTo(dd);
        };

        dialog.add_button(IPA.messages.buttons.add_many, function() {
            dialog.add();
        });

        dialog.add_button(IPA.messages.buttons.add_and_close, function() {
            dialog.add();
            dialog.close();
        });

        dialog.add_button(IPA.messages.buttons.cancel, function() {
            dialog.close();
        });

        dialog.add = function() {

            var pkey = $.bbq.getState(that.entity_name+'-pkey', true);
            var resource = dialog.resource.val();

            var options = {};
            var key =  dialog.type.val().toLowerCase()+'record';
            options[key] = dialog.data.val();

            var command = IPA.command({
                method: 'dnsrecord_add',
                args: [pkey, resource],
                options: options,
                on_success: function(data, text_status, xhr) {
                    reload();
                }
            });

            command.execute();
        };

        dialog.init();

        dialog.open(that.container);
    }

    function delete_records(records_table){

        var zone = $.bbq.getState('dnszone-pkey', true);

        var thead = records_table.find('thead');
        thead.find("INPUT[type='checkbox']").
            attr('checked', false);

        var tbody = records_table.find('tbody');

        var records = [];

        $('input[type=checkbox]:checked', tbody).each(
            function(index, input){
                var tr = $(input).parents('tr');
                var resource = $('[title=idnsname]', tr).text();
                var type = $('[title=type]', tr).text().toLowerCase();
                var data = $('[title=data]', tr).text();

                records.push({
                    resource: resource,
                    type: type,
                    data: data
                });
            }
        );

        if (records.length === 0){
            return;
        }

        var dialog = IPA.dialog({
            title: IPA.messages.buttons.remove
        });

        dialog.create = function() {

            var to_delete_table =
                $('<table class="search-table" >'+
                  '<thead><tr><th>Resource</th><th>Type</th></tr></thead>'+
                  '<tbody></tbody></table>').appendTo(dialog.container);

            var to_delete_body =  to_delete_table.find('tbody');

            for (var i=0; i<records.length; i++) {
                var record = records[i];

                var tr = $('<tr></tr>').appendTo(to_delete_body);

                $('<td/>', {
                    html: record.resource
                }).appendTo(tr);

                $('<td/>', {
                    html: record.type
                }).appendTo(tr);
            }

            $('<p/>', {
                text: IPA.messages.search.delete_confirm
            }).appendTo(dialog.container);
        };

        dialog.add_button(IPA.messages.buttons.remove, function() {

            var batch = IPA.batch_command({
                on_success: function() {
                    reload();
                    dialog.close();
                },
                on_error: function() {
                    reload();
                    dialog.close();
                }
            });

            for (var i=0; i<records.length; i++) {
                var record = records[i];

                var command = IPA.command({
                    method: 'dnsrecord_del',
                    args: [zone, record.resource]
                });

                command.set_option(record.type+'record', record.data);

                batch.add_command(command);
            }

            batch.execute();
        });

        dialog.add_button(IPA.messages.buttons.cancel, function() {
            dialog.close();
        });

        dialog.init();

        dialog.open(that.container);
    }

    that.is_dirty = function() {
        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var record = $.bbq.getState(that.entity_name + '-record', true) || '';
        return pkey != that.pkey || record != that.record;
    };

    function create_content(container) {

        $('<h1/>',{
        }).append(IPA.create_network_spinner()).
            appendTo(container);

        var details = $('<div/>', {
            'name': 'details'
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
            label: IPA.messages.buttons.remove,
            icon: 'ui-icon-trash',
            click: function(){ delete_records(records_table); }
        }).appendTo(action_controls);

        IPA.action_button({
            label: IPA.messages.buttons.add,
            icon: 'ui-icon-plus',
            click: add_click
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

        tfoot.find('td').remove();
        if (data.result.truncated) {
            var message = IPA.messages.search.truncated;
            message = message.replace('${counter}', data.result.count);
            tfoot.append($('<td />',{
                colspan:2,
                text:message}));
        } else {
            tfoot.append($('<td/>',{
                colspan:2,
                text:data.result.summary}));
        }

    }

    that.create_content = create_content;
    that.setup = setup;
    that.refresh = refresh;

    return that;
};

