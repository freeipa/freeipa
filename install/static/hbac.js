/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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

function ipa_hbac() {

    var that = ipa_entity({
        'name': 'hbac'
    });

    that.superior_init = that.superior('init');

    that.init = function() {

        var dialog = ipa_hbac_add_dialog({
            'name': 'add',
            'title': 'Add New Rule'
        });
        that.add_dialog(dialog);
        dialog.init();

        var facet = ipa_hbac_search_facet({
            'name': 'search',
            'label': 'Search'
        });
        that.add_facet(facet);

        facet = ipa_hbac_details_facet({
            'name': 'details',
            'label': 'Details'
        });
        that.add_facet(facet);

        that.superior_init();
    };

    return that;
}

IPA.add_entity(ipa_hbac());

function ipa_hbac_add_dialog(spec) {

    spec = spec || {};

    var that = ipa_add_dialog(spec);

    that.superior_init = that.superior('init');

    that.init = function() {

        that.superior_init();

        that.add_field(ipa_text_widget({
            'name': 'cn',
            'label': 'Rule Name'
        }));

        that.add_field(ipa_text_widget({
            'name': 'accessruletype',
            'label': 'Rule type (allow/deny)'
        }));
    };

    return that;
}

function ipa_hbac_search_facet(spec) {

    spec = spec || {};

    var that = ipa_search_facet(spec);

    that.superior_init = that.superior('init');
    that.superior_create = that.superior('create');
    that.superior_setup = that.superior('setup');

    that.init = function() {

        that.create_column({name:'cn', label:'Rule Name'});
        that.create_column({name:'usercategory', label:'Who'});
        that.create_column({name:'hostcategory', label:'Accessing'});
        that.create_column({name:'ipaenabledflag', label:'Active'});
        that.create_column({name:'servicecategory', label:'Via Service'});
        that.create_column({name:'sourcehostcategory', label:'From'});

        that.create_column({
            name: 'quick_links',
            label: 'Quick Links',
            setup: ipa_hbac_quick_links
        });

        that.superior_init();
    };

    that.create = function(container) {

        var that = this;

        // TODO: replace with IPA.metadata[that.entity_name].label
        $('<h2/>', { 'html': 'HBAC Rules' }).appendTo(container);

/*
        // Not yet implemented

        var left_buttons = $('<span/>', {
            'style': 'float: left;'
        }).appendTo(container);

        left_buttons.append(ipa_button({
            'label': 'Troubleshoot Rules'
        }));

        left_buttons.append(ipa_button({
            'label': 'Cull Disabled Rules'
        }));
*/
        var right_buttons = $('<span/>', {
            'style': 'float: right;'
        }).appendTo(container);

        right_buttons.append(ipa_button({
            'label': 'HBAC Services',
            'click': function() {
                var state = {};
                state['entity'] = 'hbacsvc';
                nav_push_state(state);
                return false;
            }
        }));

        right_buttons.append(ipa_button({
            'label': 'HBAC Service Groups',
            'click': function() {
                var state = {};
                state['entity'] = 'hbacsvcgroup';
                nav_push_state(state);
                return false;
            }
        }));

        container.append('<br/><br/>');

        that.superior_create(container);
    };

    return that;
}

function ipa_hbac_quick_links(container, name, value, record) {

    var column = this;
    var facet = column.facet;

    var pkey = IPA.metadata[column.entity_name].primary_key;
    var pkey_value = record[pkey];

    var span = $('span[name='+name+']', container);

    $('<a/>', {
        'href': '#details',
        'title': 'Details',
        'text': 'Details',
        'click': function() {
            var state = {};
            state[column.entity_name+'-facet'] = 'details';
            state[column.entity_name+'-pkey'] = pkey_value;
            nav_push_state(state);
            return false;
        }
    }).appendTo(span);

    span.append(' | ');

    $('<a/>', {
        'href': '#test-rule',
        'title': 'Test Rule',
        'text': 'Test Rule',
        'click': function() {
            var state = {};
            state[column.entity_name+'-facet'] = 'test-rule';
            state[column.entity_name+'-pkey'] = pkey_value;
            nav_push_state(state);
            return false;
        }
    }).appendTo(span);
}

function ipa_hbac_details_facet(spec) {

    spec = spec || {};

    var that = ipa_details_facet(spec);

    that.superior_init = that.superior('init');
    that.superior_create = that.superior('create');
    that.superior_setup = that.superior('setup');

    that.init = function() {

        var section;

        if (IPA.layout) {
            section = that.create_section({
                'name': 'general',
                'label': 'General',
                'template': 'hbac-details-general.html #contents'
            });

        } else {
            section = ipa_hbac_details_general_section({
                'name': 'general',
                'label': 'General'
            });
            that.add_section(section);
        }

        section.create_text({ 'name': 'cn', 'label': 'Name' });
        section.create_radio({ 'name': 'accessruletype', 'label': 'Rule Type' });
        section.create_textarea({ 'name': 'description', 'label': 'Description' });
        section.create_radio({ 'name': 'ipaenabledflag', 'label': 'Enabled' });

        if (IPA.layout) {
            section = that.create_section({
                'name': 'user',
                'label': 'Who',
                'template': 'hbac-details-user.html #contents'
            });

        } else {
            section = ipa_hbac_details_tables_section({
                'name': 'user',
                'label': 'Who',
                'text': 'Rule applies when access is requested by:',
                'field_name': 'usercategory',
                'options': [
                    { 'value': 'all', 'label': 'Anyone' },
                    { 'value': '', 'label': 'Specified Users and Groups' }
                ],
                'tables': [
                    { 'field_name': 'memberuser_user' },
                    { 'field_name': 'memberuser_group' }
                ]
            });
            that.add_section(section);
        }

        section.create_radio({ name: 'usercategory', label: 'User category' });
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-memberuser_user',
            'name': 'memberuser_user', 'label': 'Users',
            'other_entity': 'user', 'add_method': 'add_user', 'delete_method': 'remove_user'
        }));
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-memberuser_group',
            'name': 'memberuser_group', 'label': 'Groups',
            'other_entity': 'group', 'add_method': 'add_user', 'delete_method': 'remove_user'
        }));

        if (IPA.layout) {
            section = that.create_section({
                'name': 'host',
                'label': 'Accessing',
                'template': 'hbac-details-host.html #contents'
            });

        } else {
            section = ipa_hbac_details_tables_section({
                'name': 'host',
                'label': 'Accessing',
                'text': 'Rule applies when access is requested to:',
                'field_name': 'hostcategory',
                'options': [
                    { 'value': 'all', 'label': 'Any Host' },
                    { 'value': '', 'label': 'Specified Hosts and Groups' }
                ],
                'tables': [
                    { 'field_name': 'memberhost_host' },
                    { 'field_name': 'memberhost_hostgroup' }
                ]
            });
            that.add_section(section);
        }

        section.create_radio({ 'name': 'hostcategory', 'label': 'Host category' });
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-memberhost_host',
            'name': 'memberhost_host', 'label': 'Hosts',
            'other_entity': 'host', 'add_method': 'add_host', 'delete_method': 'remove_host'
        }));
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-memberhost_hostgroup',
            'name': 'memberhost_hostgroup', 'label': 'Host Groups',
            'other_entity': 'hostgroup', 'add_method': 'add_host', 'delete_method': 'remove_host'
        }));

        if (IPA.layout) {
            section = that.create_section({
                'name': 'service',
                'label': 'Via Service',
                'template': 'hbac-details-service.html #contents'
            });

        } else {
            section = ipa_hbac_details_tables_section({
                'name': 'service',
                'label': 'Via Service',
                'text': 'Rule applies when access is requested via:',
                'field_name': 'servicecategory',
                'options': [
                    { 'value': 'all', 'label': 'Any Service' },
                    { 'value': '', 'label': 'Specified Services and Groups' }
                ],
                'tables': [
                    { 'field_name': 'memberservice_hbacsvc' },
                    { 'field_name': 'memberservice_hbacsvcgroup' }
                ]
            });
            that.add_section(section);
        }

        section.create_radio({ 'name': 'servicecategory', 'label': 'Service category' });
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-memberservice_hbacsvc',
            'name': 'memberservice_hbacsvc', 'label': 'Services',
            'other_entity': 'hbacsvc', 'add_method': 'add_service', 'delete_method': 'remove_service'
        }));
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-memberservice_hbacsvcgroup',
            'name': 'memberservice_hbacsvcgroup', 'label': 'Service Groups',
            'other_entity': 'hbacsvcgroup', 'add_method': 'add_service', 'delete_method': 'remove_service'
        }));

        if (IPA.layout) {
            section = that.create_section({
                'name': 'sourcehost',
                'label': 'From',
                'template': 'hbac-details-sourcehost.html #contents'
            });

        } else {
            section = ipa_hbac_details_tables_section({
                'name': 'sourcehost',
                'label': 'From',
                'text': 'Rule applies when access is being initiated from:',
                'field_name': 'sourcehostcategory',
                'options': [
                    { 'value': 'all', 'label': 'Any Host' },
                    { 'value': '', 'label': 'Specified Hosts and Groups' }
                ],
                'tables': [
                    { 'field_name': 'sourcehost_host' },
                    { 'field_name': 'sourcehost_hostgroup' }
                ]
            });
            that.add_section(section);
        }

        section.create_radio({ 'name': 'sourcehostcategory', 'label': 'Source host category' });
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-sourcehost_host',
            'name': 'sourcehost_host', 'label': 'Host',
            'other_entity': 'host', 'add_method': 'add_sourcehost', 'delete_method': 'remove_sourcehost'
        }));
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-sourcehost_hostgroup',
            'name': 'sourcehost_hostgroup', 'label': 'Host Groups',
            'other_entity': 'hostgroup', 'add_method': 'add_sourcehost', 'delete_method': 'remove_sourcehost'
        }));

        if (IPA.layout) {
            section = that.create_section({
                'name': 'accesstime',
                'label': 'When',
                'template': 'hbac-details-accesstime.html #contents'
            });

        } else {
            section = ipa_hbac_details_tables_section({
                'name': 'accesstime',
                'label': 'When',
                'text': 'Rule applies when access is being requested at:',
                'field_name': 'accesstime',
                'options': [
                    { 'value': 'all', 'label': 'Any Time' },
                    { 'value': '', 'label': 'Specified Times' }
                ],
                'tables': [
                    { 'field_name': 'accesstime' }
                ]
            });
            that.add_section(section);
        }

        section.add_field(ipa_hbac_accesstime_widget({
            'id': that.entity_name+'-accesstime',
            'name': 'accesstime', 'label': 'Access Time'
        }));

        that.superior_init();
    };

    return that;
}

function ipa_hbac_details_general_section(spec){

    spec = spec || {};

    var that = ipa_details_section(spec);

    that.create = function(container) {

        var table = $('<table/>', {
            'style': 'width: 100%;'
        }).appendTo(container);

        var tr = $('<tr/>', {
        }).appendTo(table);

        var td = $('<td/>', {
            'style': 'width: 100px; text-align: right;',
            'html': 'Name:'
        }).appendTo(tr);

        td = $('<td/>').appendTo(tr);

        $('<input/>', {
            'type': 'text',
            'name': 'cn',
            'size': 30
        }).appendTo(td);

        td = $('<td/>', {
            'style': 'text-align: right;'
        }).appendTo(tr);

        td.append('Rule type:');

        $('<input/>', {
            'type': 'radio',
            'name': 'accessruletype',
            'value': 'allow'
        }).appendTo(td);

        td.append('Allow');

        $('<input/>', {
            'type': 'radio',
            'name': 'accessruletype',
            'value': 'deny'
        }).appendTo(td);

        td.append('Deny');

        tr = $('<tr/>', {
        }).appendTo(table);

        td = $('<td/>', {
            'style': 'text-align: right; vertical-align: top;',
            'html': 'Description:'
        }).appendTo(tr);

        td = $('<td/>', {
            'colspan': 2
        }).appendTo(tr);

        $('<textarea/>', {
            'name': 'description',
            'rows': 5,
            'style': 'width: 100%'
        }).appendTo(td);

        tr = $('<tr/>', {
        }).appendTo(table);

        td = $('<td/>', {
            'style': 'text-align: right; vertical-align: top;',
            'html': 'Rule status:'
        }).appendTo(tr);

        td = $('<td/>', {
            'colspan': 2
        }).appendTo(tr);

        $('<input/>', {
            'type': 'radio',
            'name': 'ipaenabledflag',
            'value': 'TRUE'
        }).appendTo(td);

        td.append('Active');

        $('<input/>', {
            'type': 'radio',
            'name': 'ipaenabledflag',
            'value': 'FALSE'
        }).appendTo(td);

        td.append('Inactive');
    };

    return that;
}

function ipa_hbac_details_tables_section(spec){

    spec = spec || {};

    var that = ipa_details_section(spec);

    that.text = spec.text;
    that.field_name = spec.field_name;
    that.options = spec.options;
    that.tables = spec.tables;
    that.columns = spec.columns;

    that.superior_setup = that.superior('setup');

    that.create = function(container) {

        if (that.template) return;

        container.append(that.text);

        for (var i=0; i<that.options.length; i++) {
            var option = that.options[i];

            $('<input/>', {
                'type': 'radio',
                'name': that.field_name,
                'value': option.value
            }).appendTo(container);

            container.append(option.label);
        }

        container.append('<br/>');

        for (var i=0; i<that.tables.length; i++) {
            var table = that.tables[i];

            $('<div/>', {
                'id': that.entity_name+'-'+table.field_name
            }).appendTo(container);
        }

        var fields = that.fields;
        for (var i = 0; i < fields.length; ++i) {
            var field = fields[i];
            field.create(container);
        }
    };

    return that;
}

function ipa_hbac_association_widget(spec) {

    spec = spec || {};

    var that = ipa_table_widget(spec);

    that.other_entity = spec.other_entity;

    that.add_method = spec.add_method;
    that.delete_method = spec.delete_method;

    that.superior_init = that.superior('init');
    that.superior_create = that.superior('create');
    that.superior_setup = that.superior('setup');

    that.init = function() {
        // create a column if none defined
        if (!that.columns.length) {
            that.create_column({
                'name': that.name,
                'label': IPA.metadata[that.other_entity].label,
                'primary_key': true
            });
        }

        that.superior_init();
    };

    that.create = function(container) {

        that.superior_create(container);

        var div = $('#'+that.id, container);

        var buttons = $('span[name=buttons]', div);

        $('<input/>', {
            'type': 'button',
            'name': 'remove',
            'value': 'Remove '+that.label
        }).appendTo(buttons);

        $('<input/>', {
            'type': 'button',
            'name': 'add',
            'value': 'Add '+that.label
        }).appendTo(buttons);
    };

    that.setup = function(container) {

        that.superior_setup(container);

        var entity = IPA.get_entity(that.entity_name);
        var association = entity.get_association(that.other_entity);

        if (association && association.associator == 'serial') {
            that.associator = serial_associator;
        } else {
            that.associator = bulk_associator;
        }
    };

    that.add = function(container) {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var label = IPA.metadata[that.other_entity].label;
        var title = 'Add '+label+' to '+that.entity_name+' '+pkey;

        var dialog = ipa_association_adder_dialog({
            'title': title,
            'entity_name': that.entity_name,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'associator': that.associator,
            'method': that.add_method,
            'on_success': function() {
                that.refresh(container);
                dialog.close();
            },
            'on_error': function() {
                that.refresh(container);
                dialog.close();
            }
        });

        dialog.init();

        dialog.open(container);
    };

    that.remove = function(container) {

        var values = that.get_selected_values();

        if (!values.length) {
            alert('Select '+that.label+' to be removed.');
            return;
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var label = IPA.metadata[that.other_entity].label;
        var title = 'Remove '+label+' from '+that.entity_name+' '+pkey;

        var dialog = ipa_association_deleter_dialog({
            'title': title,
            'entity_name': that.entity_name,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'values': values,
            'associator': that.associator,
            'method': that.delete_method,
            'on_success': function() {
                that.refresh(container);
                dialog.close();
            },
            'on_error': function() {
                that.refresh(container);
                dialog.close();
            }
        });

        dialog.init();

        dialog.open(container);
    };

    that.refresh = function(container) {

        function on_success(data, text_status, xhr) {

            that.tbody.empty();

            var column_name = that.columns[0].name;
            var values = data.result.result[column_name];
            //TODO, this is masking an error where the wrong
            //direction association is presented upon page reload.
            //if the values is unset, it is because
            //form.associationColumns[0] doesn't exist in the results
            if (!values) return;

            for (var i = 0; i<values.length; i++){
                var record = that.get_record(data.result.result, i);
                that.add_row(container, record);
            }
        }

        function on_error(xhr, text_status, error_thrown) {
            var div = $('#'+that.id, container).empty();
            div.append('<p>Error: '+error_thrown.name+'</p>');
            div.append('<p>'+error_thrown.title+'</p>');
            div.append('<p>'+error_thrown.message+'</p>');
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        ipa_cmd('show', [pkey], {'rights': true}, on_success, on_error, that.entity_name);
    };

    that.save = function(container) {
        return [];
    };

    return that;
}

function ipa_hbac_accesstime_widget(spec) {

    spec = spec || {};

    var that = ipa_table_widget(spec);

    that.superior_init = that.superior('init');
    that.superior_create = that.superior('create');
    that.superior_setup = that.superior('setup');

    that.init = function() {
        // create a column if none defined
        if (!that.columns.length) {
            that.create_column({
                'name': that.name,
                'label': that.label,
                'primary_key': true
            });
        }

        that.superior_init();
    };

    that.create = function(container) {

        that.superior_create(container);

        var div = $('#'+that.id);

        var buttons = $('span[name=buttons]', div);

        $('<input/>', {
            'type': 'button',
            'name': 'remove',
            'value': 'Remove '+that.label
        }).appendTo(buttons);

        $('<input/>', {
            'type': 'button',
            'name': 'add',
            'value': 'Add '+that.label
        }).appendTo(buttons);
    };

    that.load = function(container, result) {
        var values = result[that.name] || '';
        if (values) {
            $('input[name="'+that.name+'"][value=""]', container).attr('checked', 'checked');
        } else {
            $('input[name="'+that.name+'"][value="all"]', container).attr('checked', 'checked');
        }

        that.tbody.empty();
        for (var i=0; i<values.length; i++) {
            var tr = that.row.clone();
            $('input[name="select"]', tr).val(values[i]);
            $('span[name="'+that.name+'"]', tr).html(values[i]);
            tr.appendTo(that.tbody);
        }
    };

    that.add = function(container) {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var title = 'Add '+that.label+' to '+that.entity_name+' '+pkey;

        var dialog = ipa_dialog({
            'title': title
        });

        dialog.add_field(ipa_text_widget({
            'name': that.name,
            'label': that.label
        }));

        dialog.create = function() {
            var table = $('<table/>').appendTo(dialog.container);

            var tr = $('<tr/>').appendTo(table);

            var td = $('<td/>', {
                'style': 'vertical-align: top;'
            }).appendTo(tr);
            td.append(that.label+': ');

            td = $('<td/>').appendTo(tr);
            $('<input/>', {
                'type': 'text',
                'name': that.name,
                'size': 40
            }).appendTo(td);

            tr = $('<tr/>').appendTo(table);

            td = $('<td/>', {
                'style': 'vertical-align: top;'
            }).appendTo(tr);
            td.append('Example:');

            td = $('<td/>').appendTo(tr);

            td.append('<b>Every day between 0800 and 1400:</b><br/>');
            td.append('periodic daily 0800-1400<br/><br/>');

            td.append('<b>December 16, 2010 from 10:32 until 10:33:</b><br/>');
            td.append('absolute 201012161032 ~ 201012161033<td/>');
        };

        function add(on_success, on_error) {

            var field = dialog.get_field(that.name);
            var value = field.save(dialog.container)[0];

            var command = ipa_command({
                'method': that.entity_name+'_add_'+that.name
            });
            command.add_arg(pkey);
            command.set_option(that.name, value);

            command.execute(
                function() {
                    that.refresh(container);
                    if (on_success) on_success();
                },
                function() {
                    that.refresh(container);
                    if (on_error) on_error();
                }
            );
        }

        dialog.add_button('Add', function() {
            add(
                function() { dialog.clear(container); }
            );
        });

        dialog.add_button('Add and Close', function() {
            add(
                function() { dialog.close(); },
                function() { dialog.close(); }
            );
        });

        dialog.add_button('Cancel', function() {
            dialog.close();
        });

        dialog.init();

        dialog.open(container);
    };

    that.remove = function(container) {

        var values = that.get_selected_values();

        if (!values.length) {
            alert('Select '+that.label+' to be removed.');
            return;
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var title = 'Remove '+that.label+' from '+that.entity_name+' '+pkey;

        var dialog = ipa_deleter_dialog({
            'title': title,
            'values': values
        });

        dialog.remove = function() {
            var batch = ipa_batch_command();

            for (var i=0; i<values.length; i++) {
                var command = ipa_command({
                    'method': that.entity_name+'_remove_'+that.name
                });
                command.add_arg(pkey);
                command.set_option(that.name, values[i]);
                batch.add_command(command);
            }

            batch.execute(
                function() {
                    that.refresh(container);
                    dialog.close();
                },
                function() {
                    that.refresh(container);
                    dialog.close();
                }
            );
        };

        dialog.init();

        dialog.open(container);
    };

    that.refresh = function(container) {

        function on_success(data, text_status, xhr) {

            that.tbody.empty();

            var column_name = that.columns[0].name;
            var values = data.result.result[column_name];
            if (!values) return;

            for (var i = 0; i<values.length; i++){
                var record = that.get_record(data.result.result, i);
                that.add_row(container, record);
            }
        }

        function on_error(xhr, text_status, error_thrown) {
            var div = $('#'+that.id, container).empty();
            div.append('<p>Error: '+error_thrown.name+'</p>');
            div.append('<p>'+error_thrown.title+'</p>');
            div.append('<p>'+error_thrown.message+'</p>');
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        ipa_cmd('show', [pkey], {'rights': true}, on_success, on_error, that.entity_name);
    };

    that.save = function(container) {
        return [];
    };

    return that;
}
