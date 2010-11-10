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

/* DNS */
ipa_entity_set_search_definition('dns', [
    ['idnsname', 'Zone Name', null],
    ['quick_links', 'Quick Links', ipa_entity_quick_links]
]);


ipa_entity_set_add_definition('dns', [
    'dialog-add-dns', 'Add New Zone', [
        ['idnsname', 'Name', null],
        ['idnssoamname', 'Authoritative name server'],
        ['idnssoarname','administrator e-mail address']
    ]
]);

ipa_entity_set_details_definition('dns', [
    ipa_stanza({name:'identity', label:'DNS Zone Details'}).
        input({name:'idnsname', label:'DNS Name'}).
        input({name:'idnszoneactive', label:'Zone Active'}).
        input({name:'idnssoamname', label:'Authoritative name server'}).
        input({name:'idnssoarname', label:'administrator e-mail address'}).
        input({name:'idnssoaserial', label:'SOA serial'}).
        input({name:'idnssoarefresh', label:'SOA refresh'}).
        input({name:'idnssoaretry', label:'SOA retry'}).
        input({name:'idnssoaexpire', label:'SOA expire'}).
        input({name:'idnssoaminimum', label:'SOA minimum'}).
        input({name:'dnsttl', label:'SOA time to live'}).
        input({name:'dnsclass', label:'SOA class'}).
        input({name:'idnsallowdynupdate', label:'allow dynamic update?'}).
        input({name:'idnsupdatepolicy', label:'BIND update policy'})
]);

ipa_entity_set_association_definition('dns', {
});


ipa_entity_set_facet_definition('dns', [
    ipa_records_facet({
        'name': 'records',
        'label': 'Records'
    })]
);

function ipa_records_facet(spec){

    spec = spec || {};

    var that = ipa_facet(spec);

    that.record = null;

    var record_types =[ 'a', 'aaaa', 'dname', 'cname', 'mx', 'ns', 'ptr',
                        'srv', 'txt', 'a6', 'afsdb', 'cert', 'ds', 'hinfo',
                        'key', 'kx', 'loc', 'md', 'minfo', 'naptr', 'nsec',
                        'nxt', 'rrsig', 'sshfp'];

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
            title: 'Add DNS Resource Record'
        });
        var dl = $('<dl></dl>').appendTo(add_dialog);
        dl.append('<dt>Resource</dt>');
        dl.append( $('<dd/>').
                   append($('<input type="text" id="dns-record-resource" />')));
        dl.append('<dt>Type</dt>');
        dl.append(  $('<dd/>').append(create_type_select('dns-record-type')));
        dl.append('<dt>Data</dt>');
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
                if (called_from_add_and_edit) {
                }
            }

            function add_fail(data, text_status, xhr) {
            }

            params.push(  $.bbq.getState('dns-pkey', true));
            params.push(add_dialog.find('#dns-record-resource').val());
            params.push(add_dialog.find('#dns-record-type').val());
            params.push(add_dialog.find('#dns-record-data').val());

            ipa_cmd('dns_add_rr', params, options, add_win, add_fail);
            //add_dialog.dialog('close');
        }

        function add_and_close(evt) {
            add(evt, true);
            add_dialog.dialog('close');
        }

        function cancel() {
            add_dialog.dialog('close');
        }


        add_dialog.dialog({
            modal: true,
            buttons: {
                'Add many': add,
                'Add and Close': add_and_close,
                'Cancel': cancel
            }
        });
    }



    function delete_records(records_table){

        var zone = $.bbq.getState('dns-pkey', true);

        var thead = records_table.find('thead');
        thead.find("INPUT[type='checkbox']").
            attr('checked', false);

        var i = 0;

        var tbody = records_table.find('tbody');


        var delete_dialog = $('<div/>', {
            title: IPA.messages.button.remove
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
                        text().toUpperCase();
                    var data = $(tr).find('[title="data"]').text();
                    var params = [zone, resource, type, data];
                    delete_list.push(params);
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
                delete_count -= 1;
                if (delete_count === 0 ){
                    reload();
                    delete_dialog.dialog('close');
                }
            }
            for (var i = 0; i < delete_list.length; i += 1){
                ipa_cmd('dns_del_rr',delete_list[i],{},
                        delete_complete,delete_complete);
            }
        }

        function cancel_on_click() {
            delete_dialog.dialog('close');
        }


        if (delete_list.length == 0)
            return;

        delete_dialog.append($('<P/>',
                               {text: IPA.messages.search.delete_confirm}));

        delete_dialog.dialog({
            modal: true,
            buttons: {
                'Delete': delete_on_click,
                'Cancel': cancel_on_click
            }
        });


    }

    that.is_dirty = function() {
        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var record = $.bbq.getState(that.entity_name + '-record', true) || '';
        return pkey != that.pkey || record != that.record;
    };

    function create(container) {
//        that.setup_views(container);
    }

    function setup(container, unspecified){

        that.pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        that.record = $.bbq.getState(that.entity_name + '-record', true) || '';

        that.container = container;

        container.attr('title', that.entity_name);

        var h2 = $('<h2></h2>',{
            text: "Records for DNS Zone:" + that.pkey
        }).appendTo(container);


        var div = $('<div class="search-controls"></div>')
            .appendTo(container);

        var control_span =$('<span class="record-filter"></span>').appendTo(div);

        control_span.append('Resource');
        control_span.append($('<input />',{
            type: "text",
            id: 'dns-record-resource-filter',
            name: 'search-' + that.entity_name + '-filter'
        }));

        control_span.append('Type');

        create_type_select('dns-record-type-filter',true).
            appendTo(control_span);
        //commented out until data is searchable
        //control_span.append('Data');
        //control_span.append($('<input />',{
        //    type: "text",
        //    id: 'dns-record-data-filter',
        //    name: 'search-' + obj_name + '-filter'
        //}));


        ipa_button({
            'label': IPA.messages.button.find,
            'icon': 'ui-icon-search',
            'click': function(){load(container)}
        }).appendTo(control_span);

        ipa_button({
            'label': IPA.messages.button.add,
            'icon': 'ui-icon-plus',
            'click': add_click
        }).appendTo(control_span);

        ipa_button({
            'label': IPA.messages.button.remove,
            'icon': 'ui-icon-trash',
            'click': function(){delete_records(records_table);}
        }).appendTo(control_span);


        div.append('<span class="records-buttons"></span>');

        var records_results = $('<div/>', {
            'class': 'records-results'
        }).appendTo(container);

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
            })
        ));
        tr.append($('<th>Resource</th>'));
        tr.append($('<th>Record Type</th>'));
        tr.append($('<th>Data</th>'));

        load(container);
    }


    function load_on_win(data){
        display('dns',data);
    }

    function load_on_fail(data){
        display('dns',data);
    }

    function  reload(){
        load(that.container);
    }


    function  load(container){

        var options = {};

        var resource_filter = container.find("#dns-record-resource-filter")
            .val();
        if (resource_filter){
            options.idnsname = resource_filter;
        }

        var type_filter = container.find("#dns-record-type-filter").val();
        if (type_filter){
            options.type = type_filter;
        }

        var data_filter = container.find("#dns-record-data-filter").val();
        if (data_filter){
            options.data = data_filter;
        }


        var pkey = $.bbq.getState('dns' + '-pkey', true);
        ipa_cmd('dns_find_rr',[pkey],options,load_on_win, load_on_fail);

    }


    function generate_tr(thead, tbody, result){
        var tr = $('<tr></tr>').appendTo(tbody);

        search_generate_checkbox_td(tr, /*pkey_value*/ '');

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
            tfoot.text(
                'Query returned results than configured size limit will show.' +
                    'First ' + data.result.count + ' results shown.'
            );
        } else {
            tfoot.text(data.result.summary);
        }

    }

    that.create = create;
    that.setup = setup;
    that.load = load;

    return that;
}


/**Automount*/

ipa_entity_set_search_definition('automountlocation', [
    ['cn', 'Name', null],
    ['quick_links', 'Quick Links', ipa_entity_quick_links]

]);

ipa_entity_set_add_definition('automountlocation', [
    'dialog-add-location', 'Add New Location', [
        ['cn', 'Name', null]
    ]
]);

ipa_entity_set_details_definition('automountlocation', [
    ipa_stanza({name:'identity', label:'Automount Location Details'}).
        input({name:'cn', label:'Automount Location'})
]);

ipa_entity_set_association_definition('automountlocation', {
});


/**pwpolicy*/

ipa_entity_set_search_definition('pwpolicy', [
    ['cn', 'Name', null],
    ['quick_links', 'Quick Links', ipa_entity_quick_links]

]);

ipa_entity_set_add_definition('pwpolicy', [
    'dialog-add-dns', 'Add New Location', [
        ['cn', 'Name', null]
    ]
]);

ipa_entity_set_details_definition('pwpolicy', [
    ipa_stanza({name:'identity', label:'Password Policy'}).
        input({name:'krbmaxpwdlife',label:'Max Password Life'}).
        input({name:'krbminpwdlife',label:'Min Password Life'}).
        input({name:'krbpwdhistorylength',label:'Password History Length'}).
        input({name:'krbpwdmindiffchars',
                   label:'Min Different Characters'}).
        input({name:'krbpwdminlength', label:'Password Minimum Length'})
]);

ipa_entity_set_association_definition('pwpolicy', {
});


/**
   krbtpolicy
   Does not have search
*/

ipa_entity_set_details_definition('krbtpolicy', [
    ipa_stanza({name:'identity', label:'Krbtpolicy Location Details'}).
        input({name:'cn', label:'Krbtpolicy Location'}).
        input({name:'krbmaxrenewableage', label:'Max Renewable Age'}).
        input({name:'krbmaxticketlife', label:'Max Ticket Life'})
]);

ipa_entity_set_association_definition('krbtpolicy', {
});
