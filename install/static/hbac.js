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
            'label': 'Rule Name',
            'undo': false
        }));

        that.add_field(ipa_text_widget({
            'name': 'accessruletype',
            'label': 'Rule type (allow/deny)',
            'undo': false
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
        var ul = $('.action-panel ul');

        $('<li/>', {
            title: 'hbacsvc',
            text: 'HBAC Services',
            'click': function() {
                var state = {};
                state['entity'] = 'hbacsvc';
                nav_push_state(state);
                return false;
            }
        }).appendTo(ul);

        $('<li/>', {
            title: 'hbacsvcgroup',
            text: 'HBAC Service Groups',
            'click': function() {
                var state = {};
                state['entity'] = 'hbacsvcgroup';
                nav_push_state(state);
                return false;
            }
        }).appendTo(ul);

        that.superior_create(container);
    };

    return that;
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

        section.create_text({ 'name': 'cn', 'label': 'Name', 'read_only': true });
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

        var category = section.create_radio({ name: 'usercategory', label: 'User category' });
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-memberuser_user',
            'name': 'memberuser_user', 'label': 'Users', 'category': category,
            'other_entity': 'user', 'add_method': 'add_user', 'delete_method': 'remove_user'
        }));
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-memberuser_group',
            'name': 'memberuser_group', 'label': 'Groups', 'category': category,
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

        category = section.create_radio({ 'name': 'hostcategory', 'label': 'Host category' });
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-memberhost_host',
            'name': 'memberhost_host', 'label': 'Hosts', 'category': category,
            'other_entity': 'host', 'add_method': 'add_host', 'delete_method': 'remove_host'
        }));
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-memberhost_hostgroup',
            'name': 'memberhost_hostgroup', 'label': 'Host Groups', 'category': category,
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

        category = section.create_radio({ 'name': 'servicecategory', 'label': 'Service category' });
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-memberservice_hbacsvc',
            'name': 'memberservice_hbacsvc', 'label': 'Services', 'category': category,
            'other_entity': 'hbacsvc', 'add_method': 'add_service', 'delete_method': 'remove_service'
        }));
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-memberservice_hbacsvcgroup',
            'name': 'memberservice_hbacsvcgroup', 'label': 'Service Groups', 'category': category,
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

        category = section.create_radio({ 'name': 'sourcehostcategory', 'label': 'Source host category' });
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-sourcehost_host',
            'name': 'sourcehost_host', 'label': 'Host', 'category': category,
            'other_entity': 'host', 'add_method': 'add_sourcehost', 'delete_method': 'remove_sourcehost'
        }));
        section.add_field(ipa_hbac_association_widget({
            'id': that.entity_name+'-sourcehost_hostgroup',
            'name': 'sourcehost_hostgroup', 'label': 'Host Groups', 'category': category,
            'other_entity': 'hostgroup', 'add_method': 'add_sourcehost', 'delete_method': 'remove_sourcehost'
        }));

        if (IPA.layout) {
            section = that.create_section({
                'name': 'accesstime',
                'label': 'When',
                'template': 'hbac-details-accesstime.html #contents'
            });

        } else {
            section = that.create_section({
                'name': 'accesstime',
                'label': 'When'
            });
/*
            section = ipa_hbac_details_tables_section({
                'name': 'accesstime',
                'label': 'When',
                'text': 'Rule applies when access is being requested at:',
                'field_name': 'accesstimecategory',
                'tables': [
                    { 'field_name': 'accesstime' }
                ]
            });
            that.add_section(section);
*/
        }

        section.add_field(ipa_hbac_accesstime_widget({
            'id': 'accesstime',
            'name': 'accesstime', 'label': 'Access Time',
            'text': 'Rule applies when access is being requested at:',
            'options': [
                { 'value': 'all', 'label': 'Any Time' },
                { 'value': '', 'label': 'Specified Times' }
            ]
        }));

        that.superior_init();
    };

    that.update = function(container) {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var modify_operation = {
            'execute': false,
            'command': ipa_command({
                'method': that.entity_name+'_mod',
                'args': [pkey],
                'options': {'all': true, 'rights': true}
            })
        };

        var remove_accesstime = {
            'template': ipa_command({
                'method': that.entity_name+'_remove_accesstime',
                'args': [pkey],
                'options': {'all': true, 'rights': true}
            }),
            'commands': []
        };

        var member_category = {
            'usercategory': 'memberuser',
            'hostcategory': 'memberhost',
            'servicecategory': 'memberservice',
            'sourcehostcategory': 'sourcehost'
        };

        var remove_members = {
            'memberuser': {
                'category_changed': false,
                'has_values': false,
                'command': ipa_command({
                    'method': that.entity_name+'_remove_user',
                    'args': [pkey],
                    'options': {'all': true, 'rights': true}
                })
            },
            'memberhost': {
                'category_changed': false,
                'has_values': false,
                'command': ipa_command({
                    'method': that.entity_name+'_remove_host',
                    'args': [pkey],
                    'options': {'all': true, 'rights': true}
                })
            },
            'memberservice': {
                'category_changed': false,
                'has_values': false,
                'command': ipa_command({
                    'method': that.entity_name+'_remove_service',
                    'args': [pkey],
                    'options': {'all': true, 'rights': true}
                })
            },
            'sourcehost': {
                'category_changed': false,
                'has_values': false,
                'command': ipa_command({
                    'method': that.entity_name+'_remove_sourcehost',
                    'args': [pkey],
                    'options': {'all': true, 'rights': true}
                })
            }
        };

        var enable_operation = {
            'execute': false,
            'command': ipa_command({
                'method': that.entity_name+'_enable',
                'args': [pkey],
                'options': {'all': true, 'rights': true}
            })
        };

        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections[i];

            var div = $('#'+that.entity_name+'-'+that.name+'-'+section.name, container);

            for (var j=0; j<section.fields.length; j++) {
                var field = section.fields[j];

                var span = $('span[name='+field.name+']', div).first();
                var values = field.save(span);

                var param_info = ipa_get_param_info(that.entity_name, field.name);

                // skip primary key
                if (param_info && param_info['primary_key']) continue;

                var p = field.name.indexOf('_');
                if (p >= 0) {
                    // prepare command to remove members if needed
                    var attribute = field.name.substring(0, p);
                    var other_entity = field.name.substring(p+1);

                    if (values.length) {
                        remove_members[attribute].command.set_option(other_entity, values.join(','));
                        remove_members[attribute].has_values = true;
                    }
                    continue;
                }

                // skip unchanged field
                if (!field.is_dirty(span)) continue;

                // check enable/disable
                if (field.name == 'ipaenabledflag') {
                    if (values[0] == 'FALSE') enable_operation.command.method = that.entity_name+'_disable';
                    enable_operation.execute = true;
                    continue;
                }

                if (field.name == 'accesstime') {
                    // if accesstime is dirty, it means 'Any Time' is selected,
                    // so existing values have to be removed
                    for (var k=0; k<field.values.length; k++) {
                        var command = ipa_command(remove_accesstime.template);
                        command.set_option(field.name, field.values[k]);
                        remove_accesstime.commands.push(command);
                    }
                    continue;
                }

                // use setattr/addattr if param_info not available
                if (!param_info) {
                    for (var k=0; k<values.length; k++) {
                        modify_operation.set_option(
                            k == 0 ? 'setattr' : 'addattr',
                            field.name+'='+values[k]
                        );
                        modify_operation.execute = true;
                    }
                    continue;
                }

                var attribute = member_category[field.name];
                if (attribute) {
                    // if category is dirty, it means 'Any *' is selected,
                    // so existing values have to be removed
                    remove_members[attribute].category_changed = true;

                    // fall through to trigger modify operation
                }

                // set modify options
                if (values.length == 1) {
                    modify_operation.command.set_option(field.name, values[0]);
                } else {
                    modify_operation.command.set_option(field.name, values);
                }
                modify_operation.execute = true;
            }
        }

        var batch = ipa_batch_command({
            'on_success': function success_handler(data, text_status, xhr) {
                that.load(container);
            },
            'on_error': function(xhr, text_status, error_thrown) {
                that.load(container);
            }
        });

        for (var attribute in remove_members) {
            if (remove_members[attribute].has_values &&
                remove_members[attribute].category_changed) {
                batch.add_command(remove_members[attribute].command);
            }
        }

        batch.add_commands(remove_accesstime.commands);

        if (modify_operation.execute) batch.add_command(modify_operation.command);
        if (enable_operation.execute) batch.add_command(enable_operation.command);

        if (!batch.args.length) {
            that.load(container);
            return;
        }

        //alert(JSON.stringify(batch.to_json()));

        batch.execute();
    };

    that.reset = function() {
        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections[i];
            section.reset();
        }
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

        var span = $('<span/>', { 'name': 'cn' }).appendTo(td);

        $('<input/>', {
            'type': 'text',
            'name': 'cn',
            'size': 30
        }).appendTo(span);

        span.append(' ');

        $('<span/>', {
            'name': 'undo',
            'class': 'ui-state-highlight ui-corner-all',
            'style': 'display: none;',
            'html': 'undo'
        }).appendTo(span);

        td = $('<td/>', {
            'style': 'text-align: right;'
        }).appendTo(tr);

        td.append('Rule type:');

        span = $('<span/>', { 'name': 'accessruletype' }).appendTo(td);

        $('<input/>', {
            'type': 'radio',
            'name': 'accessruletype',
            'value': 'allow'
        }).appendTo(span);

        span.append('Allow');

        $('<input/>', {
            'type': 'radio',
            'name': 'accessruletype',
            'value': 'deny'
        }).appendTo(span);

        span.append('Deny');

        span.append(' ');

        $('<span/>', {
            'name': 'undo',
            'class': 'ui-state-highlight ui-corner-all',
            'style': 'display: none;',
            'html': 'undo'
        }).appendTo(span);

        tr = $('<tr/>', {
        }).appendTo(table);

        td = $('<td/>', {
            'style': 'text-align: right; vertical-align: top;',
            'html': 'Description:'
        }).appendTo(tr);

        td = $('<td/>', {
            'colspan': 2
        }).appendTo(tr);

        span = $('<span/>', { 'name': 'description' }).appendTo(td);

        $('<textarea/>', {
            'name': 'description',
            'rows': 5,
            'style': 'width: 100%'
        }).appendTo(span);

        span.append(' ');

        $('<span/>', {
            'name': 'undo',
            'class': 'ui-state-highlight ui-corner-all',
            'style': 'display: none;',
            'html': 'undo'
        }).appendTo(span);

        tr = $('<tr/>', {
        }).appendTo(table);

        td = $('<td/>', {
            'style': 'text-align: right; vertical-align: top;',
            'html': 'Rule status:'
        }).appendTo(tr);

        td = $('<td/>', {
            'colspan': 2
        }).appendTo(tr);

        span = $('<span/>', { 'name': 'ipaenabledflag' }).appendTo(td);

        $('<input/>', {
            'type': 'radio',
            'name': 'ipaenabledflag',
            'value': 'TRUE'
        }).appendTo(span);

        span.append('Active');

        $('<input/>', {
            'type': 'radio',
            'name': 'ipaenabledflag',
            'value': 'FALSE'
        }).appendTo(span);

        span.append('Inactive');

        span.append(' ');

        $('<span/>', {
            'name': 'undo',
            'class': 'ui-state-highlight ui-corner-all',
            'style': 'display: none;',
            'html': 'undo'
        }).appendTo(span);
    };

    return that;
}

function ipa_hbac_details_tables_section(spec){

    spec = spec || {};

    var that = ipa_details_section(spec);

    that.text = spec.text;
    that.field_name = spec.field_name;
    that.options = spec.options || [];
    that.tables = spec.tables || [];
    that.columns = spec.columns;

    that.superior_setup = that.superior('setup');

    that.create = function(container) {

        if (that.template) return;

        container.append(that.text);

        var span = $('<span/>', { 'name': that.field_name }).appendTo(container);

        for (var i=0; i<that.options.length; i++) {
            var option = that.options[i];

            $('<input/>', {
                'type': 'radio',
                'name': that.field_name,
                'value': option.value
            }).appendTo(span);

            span.append(option.label);
        }

        span.append(' ');

        $('<span/>', {
            'name': 'undo',
            'class': 'ui-state-highlight ui-corner-all',
            'style': 'display: none;',
            'html': 'undo'
        }).appendTo(span);

        span.append('<br/>');

        for (var i=0; i<that.tables.length; i++) {
            var table = that.tables[i];

            var table_span = $('<span/>', { 'name': table.field_name }).appendTo(span);

            var field = that.get_field(table.field_name);
            field.create(table_span);
        }
    };

    return that;
}

function ipa_hbac_association_widget(spec) {

    spec = spec || {};

    var that = ipa_table_widget(spec);

    that.other_entity = spec.other_entity;
    that.category = spec.category;

    that.add_method = spec.add_method;
    that.delete_method = spec.delete_method;

    that.superior_init = that.superior('init');
    that.superior_create = that.superior('create');

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

        var buttons = $('span[name=buttons]', container);

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

        that.table_setup(container);

        var button = $('input[name=remove]', that.table);
        button.replaceWith(ipa_button({
            'label': button.val(),
            'icon': 'ui-icon-trash',
            'click': function() { that.remove(that.container); }
        }));

        button = $('input[name=add]', that.table);
        button.replaceWith(ipa_button({
            'label': button.val(),
            'icon': 'ui-icon-plus',
            'click': function() { that.add(that.container) }
        }));

        var entity = IPA.get_entity(that.entity_name);
        var association = entity.get_association(that.other_entity);

        if (association && association.associator == 'serial') {
            that.associator = serial_associator;
        } else {
            that.associator = bulk_associator;
        }
    };

    that.load = function(container, result) {

        that.values = result[that.name] || [];
        that.hide_undo(that.container);
        that.set_values(that.container, that.values);
    };

    that.set_values = function(container, values) {

        that.tbody.empty();
        for (var i=0; values && i<values.length; i++) {
            var record = {};
            record[that.name] = values[i];
            that.add_row(that.container, record);
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
            'other_entity': that.other_entity
        });

        dialog.add = function() {

            var values = dialog.get_selected_values();

            var batch = ipa_batch_command({
                'on_success': function() {
                    that.refresh(that.container);
                    dialog.close();
                },
                'on_error': function() {
                    that.refresh(that.container);
                    dialog.close();
                }
            });

            var command = ipa_command({
                'method': that.entity_name+'_mod',
                'args': [pkey],
                'options': {'all': true, 'rights': true},
                'on_success': function() {
                    that.category.load(container, ['']);
                }
            });
            command.set_option(that.category.name, '');
            batch.add_command(command);

            command = ipa_command({
                'method': that.entity_name+'_'+that.add_method,
                'args': [pkey]
            });
            command.set_option(that.other_entity, values.join(','));
            batch.add_command(command);

            batch.execute();
        };

        dialog.init();

        dialog.open(that.container);
    };

    that.remove = function(container) {

        var selected_values = that.get_selected_values();

        if (!selected_values.length) {
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
            'values': selected_values
        });

        dialog.remove = function() {

            var command = ipa_command({
                'method': that.entity_name+'_'+that.delete_method,
                'args': [pkey],
                'on_success': function() {
                    that.refresh(that.container);
                    dialog.close();
                },
                'on_error': function() {
                    that.refresh(that.container);
                    dialog.close();
                }
            });

            command.set_option(that.other_entity, selected_values.join(','));

            command.execute();
        };

        dialog.init();

        dialog.open(that.container);
    };

    that.refresh = function(container) {

        function on_success(data, text_status, xhr) {
            that.load(that.container, data.result.result);
        }

        function on_error(xhr, text_status, error_thrown) {
            var summary = $('span[name=summary]', that.tfoot).empty();
            summary.append('<p>Error: '+error_thrown.name+'</p>');
            summary.append('<p>'+error_thrown.title+'</p>');
            summary.append('<p>'+error_thrown.message+'</p>');
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        ipa_cmd('show', [pkey], {'rights': true}, on_success, on_error, that.entity_name);
    };

    return that;
}

function ipa_hbac_accesstime_widget(spec) {

    spec = spec || {};

    var that = ipa_widget(spec);

    that.text = spec.text;
    that.options = spec.options || [];

    that.superior_init = that.superior('init');
    that.superior_create = that.superior('create');
    that.superior_setup = that.superior('setup');

    that.init = function() {

        that.table = ipa_table_widget({
            'id': 'accesstime-table',
            'name': 'table', 'label': that.label
        });

        that.table.create_column({
            'name': that.name,
            'label': that.label,
            'primary_key': true
        });

        that.superior_init();
    };

    that.create = function(container) {

        that.superior_create(container);

        var span = $('<span/>', { 'name': 'text' }).appendTo(container);

        span.append(that.text);

        for (var i=0; i<that.options.length; i++) {
            var option = that.options[i];

            $('<input/>', {
                'type': 'radio',
                'name': that.name,
                'value': option.value
            }).appendTo(container);

            container.append(option.label);
        }

        container.append(' ');

        $('<span/>', {
            'name': 'undo',
            'class': 'ui-state-highlight ui-corner-all',
            'style': 'display: none;',
            'html': 'undo'
        }).appendTo(container);

        container.append('<br/>');

        span = $('<span/>', { 'name': 'table' }).appendTo(container);

        that.table.create(span);

        var buttons = $('span[name=buttons]', span);

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

        that.widget_setup(container);

        var span = $('span[name="table"]', that.container);
        that.table.setup(span);

        var button = $('input[name=remove]', span);
        button.replaceWith(ipa_button({
            'label': button.val(),
            'icon': 'ui-icon-trash',
            'click': function() { that.remove(that.container); }
        }));

        button = $('input[name=add]', span);
        button.replaceWith(ipa_button({
            'label': button.val(),
            'icon': 'ui-icon-plus',
            'click': function() { that.add(that.container) }
        }));

        var input = $('input[name="'+that.name+'"]', that.container);
        input.change(function() {
            that.show_undo(that.container);
        });

        var undo = that.get_undo(that.container);
        undo.click(function() {
            that.reset(that.container);
        });
    };

    that.save = function(container) {
        var value = $('input[name="'+that.name+'"]:checked', that.container).val();
        if (value == '') {
            return that.table.save(that.container);
        } else {
            return [];
        }
    };

    that.load = function(container, result) {

        that.values = result[that.name] || [];
        that.set_values(that.container, that.values);
        that.hide_undo(that.container);
    };

    that.set_values = function(container, values) {

        that.set_radio_value(that.container, values && values.length ? '' : 'all');

        that.table.tbody.empty();
        for (var i=0; values && i<values.length; i++) {
            var record = {};
            record[that.name] = values[i];
            that.table.add_row(that.container, record);
        }
    };

    that.set_radio_value = function(container, value) {
        $('input[name="'+that.name+'"][value="'+value+'"]', that.container).get(0).checked = true;
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

            var span = $('<span/>', { 'name': that.name }).appendTo(td);

            $('<input/>', {
                'type': 'text',
                'name': that.name,
                'size': 40
            }).appendTo(span);

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
                'method': that.entity_name+'_add_'+that.name,
                'args': [pkey],
                'on_success': function() {
                    that.refresh(that.container);
                    if (on_success) on_success();
                },
                'on_error': function() {
                    that.refresh(that.container);
                    if (on_error) on_error();
                }
            });

            command.set_option(that.name, value);

            command.execute();
        }

        dialog.add_button('Add', function() {
            add(
                function() { dialog.clear(dialog.container); }
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

        dialog.open(that.container);
    };

    that.remove = function(container) {

        var values = that.table.get_selected_values();

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

            var batch = ipa_batch_command({
                'on_success': function() {
                    that.refresh(that.container);
                    dialog.close();
                },
                'on_error': function() {
                    that.refresh(that.container);
                    dialog.close();
                }
            });

            for (var i=0; i<values.length; i++) {
                var command = ipa_command({
                    'method': that.entity_name+'_remove_'+that.name,
                    'args': [pkey]
                });

                command.set_option(that.name, values[i]);

                batch.add_command(command);
            }

            batch.execute();
        };

        dialog.init();

        dialog.open(that.container);
    };

    that.refresh = function(container) {

        function on_success(data, text_status, xhr) {
            that.load(that.container, data.result.result);
        }

        function on_error(xhr, text_status, error_thrown) {
            var summary = $('span[name=summary]', that.table.tfoot).empty();
            summary.append('<p>Error: '+error_thrown.name+'</p>');
            summary.append('<p>'+error_thrown.title+'</p>');
            summary.append('<p>'+error_thrown.message+'</p>');
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        ipa_cmd('show', [pkey], {'rights': true}, on_success, on_error, that.entity_name);
    };

    return that;
}
