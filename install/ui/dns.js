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
        facet({
            factory: IPA.records_facet,
            name: 'records',
            facet_group: 'member',
            label: IPA.metadata.objects.dnsrecord.label,
            columns: [
                {
                    name: 'idnsname',
                    label: IPA.get_entity_param('dnsrecord', 'idnsname').label,
                    primary_key: true
                },
                {
                    name: 'type',
                    label: 'Record Type'
                },
                {
                    name: 'data',
                    label: 'Data'
                }
            ]
        }).
        standard_association_facets().
        adder_dialog({
            fields: [
                'idnsname',
                'idnssoamname',
                'idnssoarname',
                {factory:IPA.force_dnszone_add_checkbox_widget}]
        }).
        build();
};

IPA.force_dnszone_add_checkbox_widget = function(spec) {
    var param_info = IPA.get_method_option('dnszone_add', 'force');
    spec.name = 'force';
    spec.label = param_info.label;
    spec.tooltip = param_info.doc;
    spec.undo = false;
    return  IPA.checkbox_widget(spec);
};

IPA.records_facet = function(spec) {

    spec = spec || {};

    var that = IPA.search_facet(spec);

    var record_types = [
        'a', 'aaaa', 'dname', 'cname', 'mx', 'ns', 'ptr',
        'srv', 'txt', 'a6', 'afsdb', 'cert', 'ds',
        'key', 'kx', 'loc',  'naptr', 'nsec',
        'rrsig', 'sshfp'
    ];

    that.init = function() {

        that.facet_init();

        that.table = IPA.table_widget({
            name: 'search',
            label: IPA.metadata.objects[that.entity_name].label,
            entity_name: that.entity_name
        });

        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++) {
            var column = columns[i];
            that.table.add_column(column);
        }

        that.table.select_changed = function() {
            that.select_changed();
        };

        that.table.refresh = function() {
            that.refresh();
        };

        that.table.init();
    };

    function create_type_select(id,add_none) {
        var type_select = $('<select/>',{
            id: id
        });

        if (add_none){
            type_select.append($('<option/>', {
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

    that.add = function() {

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

        dialog.add_button(IPA.messages.buttons.add, function() {
            dialog.add();
            dialog.close();
        });

        dialog.add_button(IPA.messages.buttons.add_and_add_another, function() {
            dialog.add();
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
                entity: 'dnsrecord',
                method: 'add',
                args: [pkey, resource],
                options: options,
                on_success: function(data, text_status, xhr) {
                    that.refresh();
                }
            });

            command.execute();
        };

        dialog.init();

        dialog.open(that.container);
    };

    that.remove = function() {

        var values = that.table.get_selected_rows();

        if (!values.length) {
            return;
        }

        var zone = $.bbq.getState('dnszone-pkey', true);

        var records = [];

        values.each(function() {
            var tr = $(this);

            records.push({
                resource: $('span[name=idnsname]', tr).text(),
                type: $('span[name=type]', tr).text().toLowerCase(),
                data: $('span[name=data]', tr).text()
            });
        });

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
                    that.refresh();
                    dialog.close();
                },
                on_error: function() {
                    that.refresh();
                    dialog.close();
                }
            });

            for (var i=0; i<records.length; i++) {
                var record = records[i];

                var command = IPA.command({
                    entity: 'dnsrecord',
                    method: 'del',
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
    };

    that.is_dirty = function() {
        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var record = $.bbq.getState(that.entity_name + '-record', true) || '';
        return pkey != that.pkey || record != that.record;
    };

    that.create_header = function(container) {

        that.facet_create_header(container);

        that.filter = $('<input/>', {
            type: 'text',
            name: 'filter'
        }).appendTo(that.controls);

        that.filter.keypress(function(e) {
            /* if the key pressed is the enter key */
            if (e.which == 13) {
                that.find();
            }
        });

        /*
          The old DNS plugin allowed for search based on record type.
          This one does not. If the plugin gets modified to support
          Record type searches, uncomment the following lines and
          adjust the code that modifies the search parameters.

          that.controls.append('Type');
          create_type_select('dns-record-type-filter',true).
          appendTo(that.controls);
        */

        that.find_button = IPA.button({
            label: IPA.messages.buttons.find,
            icon: 'ui-icon-search',
            click: function(){
                that.find();
                return false;
            }
        }).appendTo(that.controls);

        that.controls.append(IPA.create_network_spinner());

        that.remove_button = IPA.action_button({
            label: IPA.messages.buttons.remove,
            icon: 'ui-icon-trash',
            click: function() {
                if (that.remove_button.hasClass('input_link_disabled')) return false;
                that.remove();
                return false;
            }
        }).appendTo(that.controls);

        that.add_button = IPA.action_button({
            label: IPA.messages.buttons.add,
            icon: 'ui-icon-plus',
            click: function() {
                that.add();
                return false;
            }
        }).appendTo(that.controls);
    };

    that.create_content = function(container) {

        that.table.create(container);
        that.table.setup(container);
    };

    that.setup = function(container) {

        that.facet_setup(container);

        //commented out until data is searchable
        //control_span.append('Data');
        //control_span.append($('<input />',{
        //    type: "text",
        //    id: 'dns-record-data-filter',
        //    name: 'search-' + obj_name + '-filter'
        //}));
    };

    that.show = function() {
        that.facet_show();

        that.record = $.bbq.getState(that.entity_name + '-record', true) || '';
        that.pkey = $.bbq.getState(that.entity_name+'-pkey', true) || '';
        that.entity.header.set_pkey(that.pkey);

        that.entity.header.back_link.css('visibility', 'visible');
        that.entity.header.facet_tabs.css('visibility', 'visible');

        var title = IPA.messages.objects.dnsrecord.title+': '+that.pkey;
        that.set_title(this.container, title);
    };

    that.get_record = function(result, index) {
        var record = {};

        if (result.idnsname) {
            record.idnsname = result.idnsname[0];
        } else {
            record.idnsname = result.dn.split(',')[0].split('=')[1];
        }

        for (var i=0; i<record_types.length; i++){
            var type = record_types[i];
            var data = result[type+'record'];
            if (data) {
                record.type = type;
                record.data = data[0];
                break;
            }
        }

        return record;
    };

    that.refresh = function() {

        function on_success(data, text_status, xhr) {

            that.table.empty();

            var result = data.result.result;
            for (var i = 0; i<result.length; i++) {
                var record = that.get_record(result[i], 0);
                that.table.add_record(record);
            }

            var summary = $('span[name=summary]', that.table.tfoot);
            if (data.result.truncated) {
                var message = IPA.messages.search.truncated;
                message = message.replace('${counter}', data.result.count);
                summary.text(message);
            } else {
                summary.text(data.result.summary);
            }

            that.filter.focus();
            that.select_changed();
        }

        function on_error(xhr, text_status, error_thrown) {
            var summary = $('span[name=summary]', that.table.tfoot).empty();
            summary.append('<p>Error: '+error_thrown.name+'</p>');
            summary.append('<p>'+error_thrown.title+'</p>');
            summary.append('<p>'+error_thrown.message+'</p>');
        }

        var options = {};

        var filter = that.filter.val();
/*
        if (filter){
            options.idnsname = filter;
        }

        var type_filter = that.container.find("#dns-record-type-filter").val();
        if (type_filter){
            options.type = type_filter;
        }

        var data_filter = that.container.find("#dns-record-data-filter").val();
        if (data_filter){
            options.data = data_filter;
        }
*/
        var args = [$.bbq.getState(that.entity_name + '-pkey', true)];

        if (filter) {
            args.push(filter);
        }

        IPA.command({
            entity: 'dnsrecord',
            method: 'find',
            args: args,
            options: options,
            on_success: on_success,
            on_error: on_error
        }).execute();
    };

    return that;
};

