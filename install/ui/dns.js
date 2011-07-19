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

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js, widget.js */

/* DNS */
IPA.entity_factories.dnszone = function() {

    if (!IPA.dns_enabled) {
        throw "DNS not enabled on server";
    }

    return IPA.entity_builder().
        entity('dnszone').
        search_facet({
            title: IPA.metadata.objects.dnszone.label,
            columns:['idnsname']
        }).
        details_facet({
            sections:[{
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
                    'idnsupdatepolicy']}]
        }).
        nested_search_facet({
            facet_group: 'member',
            nested_entity : 'dnsrecord',
            name: 'records',
            title: IPA.metadata.objects.dnszone.label_singular,
            label: IPA.metadata.objects.dnsrecord.label,
            load: IPA.dns_record_search_load,
            get_values: IPA.dnsrecord_get_delete_values,
            columns:[
                {
                    name: 'idnsname',
                    label: IPA.get_entity_param('dnsrecord', 'idnsname').label,
                    primary_key: true
                },
                {
                    name: 'type',
                    label: IPA.messages.objects.dnsrecord.type
                },
                {
                    name: 'data',
                    label: IPA.messages.objects.dnsrecord.data
                }
            ]
        }).
        standard_association_facets().
        adder_dialog({
            factory: IPA.dnszone_adder_dialog,
            width: 500,
            height: 300,
            fields: [
                'idnsname',
                {
                    factory: IPA.checkbox_widget,
                    name: 'name_from_ip',
                    undo: false
                },
                'idnssoamname',
                'idnssoarname',
                {
                    factory: IPA.force_dnszone_add_checkbox_widget
                }
            ]
        }).
        build();
};

IPA.dnszone_adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.add_dialog(spec);

    that.create = function() {

        var table = $('<table/>').appendTo(that.container);

        var field = that.fields.get('idnsname');
        var tr = $('<tr/>').appendTo(table);

        var td = $('<td/>', {
            style: 'vertical-align: top;',
            title: field.label
        }).appendTo(tr);

        td.append($('<label/>', {
            text: field.label+':'
        }));

        td = $('<td/>', {
            style: 'vertical-align: top;'
        }).appendTo(tr);

        var span = $('<span/>', {
            name: field.name
        }).appendTo(td);

        field.create(span);
        field.field_span = span;

        field = that.fields.get('name_from_ip');
        tr = $('<tr/>').appendTo(table);

        td = $('<td/>', {
            style: 'vertical-align: top;',
            title: field.label
        }).appendTo(tr);

        td = $('<td/>', {
            style: 'vertical-align: top;'
        }).appendTo(tr);

        span = $('<span/>', {
            name: field.name
        }).appendTo(td);

        td.append($('<label/>', {
            text: field.label
        }));

        field.create(span);
        field.field_span = span;

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>', {
            colspan: 2,
            html: '&nbsp;'
        }).appendTo(tr);

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            field = fields[i];
            if (field.name == 'idnsname' || field.name == 'name_from_ip') continue;
            if (field.hidden) continue;

            tr = $('<tr/>').appendTo(table);

            td = $('<td/>', {
                style: 'vertical-align: top;',
                title: field.label
            }).appendTo(tr);

            td.append($('<label/>', {
                text: field.label+':'
            }));

            td = $('<td/>', {
                style: 'vertical-align: top;'
            }).appendTo(tr);

            span = $('<span/>', {
                name: field.name
            }).appendTo(td);

            field.create(span);
            field.field_span = span;
        }
    };

    that.save = function(record) {

        var idnsname;
        var name_from_ip;

        var fields = that.fields.values;
        for (var i=0; i<fields.length; i++) {
            var field = fields[i];

            if (field.name == 'idnsname') {

                idnsname = field.save()[0];

            } else if (field.name == 'name_from_ip') {

                name_from_ip = field.save()[0];
                if (name_from_ip) {
                    record.name_from_ip = idnsname;
                } else {
                    record.idnsname = idnsname;
                }

            } else if (field.name == 'idnssoarname') {

                field.optional = name_from_ip;

            } else {
                var values = field.save();
                record[field.name] = values.join(',');
            }
        }
    };

    return that;
};

IPA.dns_record_search_load = function (result) {
    this.table.empty();
    var normalized_record;
    var dns_record_types = IPA.dns_record_types();
    for (var i = 0; i<result.length; i++) {
        var record = result[i];
        for (var j =0; j < dns_record_types.length; j += 1){
            var record_type = dns_record_types[j].value;
            if (record[record_type]){
                var record_of_type = record[record_type];
                for (var k =0;
                     k < record_of_type.length;
                     k+=1)
                {
                    normalized_record = {
                        idnsname:record.idnsname,
                        type:record_type,
                        data:record_of_type[k]
                    };
                    this.table.add_record(normalized_record);

                }
            }
        }
    }
};

IPA.entity_factories.dnsrecord = function() {

    if (!IPA.dns_enabled) {
        throw "DNS not enabled on server";
    }

    return IPA.entity_builder().
        entity('dnsrecord').
        containing_entity('dnszone').
        details_facet({
            disable_breadcrumb: false,
            sections:[
               {
                   name:'identity',
                   label: IPA.messages.details.identity,
                   fields:[
                       {
                           factory:IPA.dnsrecord_host_link_widget,
                           name: 'idnsname',
                           other_entity:'host',
                           label:'Record Name'
                       }
                   ]
               },
                {
                    name:'standard',
                    label:'Standard Records',
                    fields:[
                        { factory: IPA.multivalued_text_widget,
                          name: 'arecord',
                          param_info: {primary_key: false},
                          label:'A'
                        },
                        { factory: IPA.multivalued_text_widget,
                          name: 'aaaarecord',
                          param_info: {primary_key: false},
                          label:'AAAA'
                        },
                        { factory: IPA.multivalued_text_widget,
                          name: 'ptrrecord',
                          param_info: {primary_key: false},
                          label:'PTR'
                        },
                        { factory: IPA.multivalued_text_widget,
                          name: 'srvrecord',
                          param_info: {primary_key: false},
                          label:'SRV'
                        },
                        { factory: IPA.multivalued_text_widget,
                          name: 'txtrecord',
                          param_info: {primary_key: false},
                          label:'TXT'
                        },
                        { factory: IPA.multivalued_text_widget,
                          name: 'cnamerecord',
                          param_info: {primary_key: false},
                          label:'CNAME'
                        },
                        { factory: IPA.multivalued_text_widget,
                          label:'MX',
                          param_info: {primary_key: false},
                          name:"mxrecord"
                        },
                        { factory: IPA.multivalued_text_widget,
                          label:'NS',
                          param_info: {primary_key: false},
                          name:"nsrecord"
                        }

                    ]
                },
                {
                    name:'unusual',
                    label:'Other Record Types',
                    fields:[
                        { factory: IPA.multivalued_text_widget,
                          label:'AFSDB',
                          param_info: {primary_key: false},
                          name: "afsdbrecord"
                        },
                        { factory: IPA.multivalued_text_widget,
                          label:'CERT',
                          param_info: {primary_key: false},
                          name:"certrecord"
                        },
                        { factory: IPA.multivalued_text_widget,
                          label:'DNAME',
                          param_info: {primary_key: false},
                          name:"dnamerecord"
                        },
                        { factory: IPA.multivalued_text_widget,
                          label:'DSRECORD',
                          param_info: {primary_key: false},
                          name:"dsrecord"
                        },
                        { factory: IPA.multivalued_text_widget,
                          label:'KEY',
                          param_info: {primary_key: false},
                          name:"keyrecord"
                        },
                        { factory: IPA.multivalued_text_widget,
                          label:'KX',
                          param_info: {primary_key: false},
                          name:"kxrecord"
                        },
                        { factory: IPA.multivalued_text_widget,
                          label:'LOC',
                          param_info: {primary_key: false},
                          name:"locrecord"
                        },
                        { factory: IPA.multivalued_text_widget,
                          label:'NAPTR',
                          name:"naptrrecord"
                        },
                        { factory: IPA.multivalued_text_widget,
                          label:'NSEC',
                          param_info: {primary_key: false},
                          name:"nsecrecord"
                        },
                        { factory: IPA.multivalued_text_widget,
                          label:'RRSIG',
                          param_info: {primary_key: false},
                          name:"rrsigrecord"
                        },
                        { factory: IPA.multivalued_text_widget,
                          label:'SIG',
                          param_info: {primary_key: false},
                          name:"sigrecord"
                        },
                        { factory: IPA.multivalued_text_widget,
                          label:'SSHFP',
                          param_info: {primary_key: false},
                          name:"sshfprecord"
                        }
                    ]
                }
            ]
        }).
        adder_dialog({
            pre_execute_hook:function(command){
                var record_type = command.options.record_type;
                var record_data = command.options.record_data;

                delete  command.options.record_type;
                delete  command.options.record_data;
                command.options[record_type] = record_data;
            },
            fields: [
                'idnsname',
                {
                    name:'record_type',
                    label:IPA.messages.objects.dnsrecord.type,
                    factory:IPA.dnsrecord_type_widget,
                    undo: false
                },
                {
                    name:'record_data',
                    label:IPA.messages.objects.dnsrecord.data,
                    factory:IPA.text_widget,
                    param_info:{required:true},
                    undo: false
                }
            ]
        }).
        build();
};

IPA.dnsrecord_host_link_widget = function(spec){
    var that = IPA.entity_link_widget(spec);
    that.other_pkeys = function(){
        var entity = IPA.get_entity(that.entity_name);
        var pkey = entity.get_primary_key();
        return [pkey[0]+'.'+pkey[1]];
    };
    return that;
};

IPA.dns_record_types = function(){
    var attrs = IPA.metadata.objects.dnsrecord.default_attributes;
    var record_types = [];
    for (var i =0; i < attrs.length; i+=1){
        var attr = attrs[i];
        var index = attr.search('record$');
        if (index > -1){
            var rec_type = {
                label:   attr.substring(0,index).toUpperCase(),
                value:   attr
            };
            record_types.push(rec_type);
        }
    }
    return record_types;
};

IPA.dnsrecord_type_widget = function (spec){

    spec.options = IPA.dns_record_types();
    var that = IPA.select_widget(spec);
    return that;
};

IPA.force_dnszone_add_checkbox_widget = function(spec) {
    var param_info = IPA.get_method_option('dnszone_add', 'force');
    spec.name = 'force';
    spec.label = param_info.label;
    spec.tooltip = param_info.doc;
    spec.undo = false;
    return  IPA.checkbox_widget(spec);
};


IPA.dnsrecord_get_delete_values = function(){

    var records = {};
    var value;
    var record_type;
    $('input[name="select"]:checked', this.table.tbody).each(function() {

        $('span',$(this).parent().parent()).each(function(){
            var name = this.attributes['name'].value;

            if (name === 'idnsname'){
                value = records[$(this).text()];
                if (!value){
                    value = {pkey:$(this).text()};
                    records[$(this).text()] = value;
                }
            }else if (name === 'type'){
                record_type = $(this).text();
            }else if (name === 'data'){
                if (!value[record_type]){
                    value[record_type] = $(this).text();
                }else{
                     value[record_type] += "," + $(this).text();
                }
            }
        });
    });

    var value_array = [];
    for (var key in records){
        value_array.push(records[key]);
    }

    return value_array;
};
