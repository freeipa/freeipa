/*jsl:import ipa.js */

/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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


IPA.entity_factories.sudorule = function() {

    return IPA.entity_builder().
        entity('sudorule').
        search_facet({
            columns:['cn','description','cmdcategory']
        }).
        details_facet({
            factory: IPA.sudorule_details_facet
        }).
        adder_dialog({
            fields:['cn']
        }).
        build();
};

IPA.entity_factories.sudocmd = function() {

    return IPA.entity_builder().
        entity( 'sudocmd').
        search_facet({
            columns:['sudocmd','description']}).
        details_facet({sections:[
            {
                name: 'general',
                label: IPA.messages.details.general,
                fields:['sudocmd','description']
            },
            {
                name: 'groups',
                label: IPA.messages.objects.sudocmd.groups,
                factory: IPA.details_section,
                fields:[{
                    factory: IPA.sudocmd_member_sudocmdgroup_table_widget,
                    name: 'memberof_sudocmdgroup',
                    label: '',//IPA.messages.objects.sudocmd.groups,
                    other_entity: 'sudocmdgroup',
                    save_values: false,
                    columns:[
                        {
                            name: 'cn',
                            primary_key: true,
                            width: '150px',
                            link: true
                        },
                        {
                            name: 'description',
                            width: '150px'
                        }
                    ],
                    adder_columns:[
                        {
                            name: 'cn',
                            primary_key: true,
                            width: '100px'
                        },
                        {
                            name: 'description',
                            width: '100px'
                        }
                    ]
                }]
            }]}).
        adder_dialog({
            fields:['sudocmd','description']
        }).
        build();

};

IPA.entity_factories.sudocmdgroup = function() {
    return IPA.entity_builder().
        entity('sudocmdgroup').
        search_facet({
            columns:['cn','description']
        }).
        details_facet({sections:[
            {

                name: 'general',
                label: IPA.messages.dialogs.general,
                fields:['cn','description']
            },
            {
                name: 'commands',
                factory:  IPA.details_section,
                fields: [{
                    factory: IPA.association_table_widget,
                    name: 'member_sudocmd',
                    label: IPA.messages.objects.sudocmdgroup.commands,
                    other_entity: 'sudocmd',
                    save_values: false,
                    columns:[
                        {
                            name: 'sudocmd',
                            primary_key: true,
                            width: '150px',
                            link: true
                        },
                        {
                            name: 'description',
                            width: '150px'
                        }
                    ],
                    adder_columns: [
                        {
                            name: 'sudocmd',
                            primary_key: true,
                            width: '100px'
                        },
                        {
                            name: 'description',
                            width: '100px'
                        }
                    ]
                }]
            }]}).
        adder_dialog({
            fields:['cn','description']
        }).
        build();
};


/*
* TODO:  user the serial associator to perform back end operations.
*/
IPA.sudocmd_member_sudocmdgroup_table_widget = function(spec) {

    spec = spec || {};

    var that = IPA.association_table_widget(spec);

    that.get_records = function(on_success, on_error) {

        var length = that.values.length;
        if (!length) return;

        if (length > 100) {
            length = 100;
        }

        if (!that.values.length) return;

        var batch = IPA.batch_command({
            'name': that.entity_name+'_'+that.name+'_show',
            'on_success': on_success,
            'on_error': on_error
        });

        for (var i=0; i<length; i++) {
            var value = that.values[i];

            var command = IPA.command({
                entity: that.other_entity,
                method: 'show',
                args: [value],
                options: {
                    all: true,
                    rights: true
                }
            });

            batch.add_command(command);
        }

        batch.execute();
    };

    that.add = function(values, on_success, on_error) {

        if (!values.length) return;

        var batch = IPA.batch_command({
            'name': that.entity_name+'_'+that.name+'_add',
            'on_success': on_success,
            'on_error': on_error
        });

        var pkey = IPA.nav.get_state(that.entity_name+'-pkey');

        for (var i=0; i<values.length; i++) {
            var value = values[i];

            var command = IPA.command({
                entity: that.other_entity,
                method: 'add_member',
                args: [value]
            });

            command.set_option('sudocmd', pkey);

            batch.add_command(command);
        }

        batch.execute();
    };

    that.remove = function(values, on_success, on_error) {

        if (!values.length) return;

        var batch = IPA.batch_command({
            'name': that.entity_name+'_'+that.name+'_remove',
            'on_success': on_success,
            'on_error': on_error
        });

        var pkey = IPA.nav.get_state(that.entity_name+'-pkey');

        for (var i=0; i<values.length; i++) {
            var value = values[i];

            var command = IPA.command({
                entity: that.other_entity,
                method: 'remove_member',
                args: [value]
            });

            command.set_option('sudocmd', pkey);

            batch.add_command(command);
        }

        batch.execute();
    };

    return that;
};


IPA.sudo = {};


IPA.sudorule_details_facet = function(spec) {

    spec = spec || {};

    var that = IPA.details_facet(spec);

    var section;

    if (IPA.layout) {
        section = that.create_section({
            'name': 'general',
            'label': IPA.messages.dialogs.general,
            'template': 'sudorule-details-general.html #contents'
        });
    } else {
        section = IPA.sudo.rule_details_general_section({
            'name': 'general',
            'label': IPA.messages.dialogs.general
        });
        that.add_section(section);
    }

    section.text({name: 'cn', read_only: true});
    section.textarea({name: 'description'});
    section.radio({name: 'ipaenabledflag'});

    section = IPA.rule_details_section({
        'name': 'user',
        'label': IPA.messages.objects.sudorule.user,
        'field_name': 'usercategory',
        'options': [
            { 'value': 'all', 'label': IPA.messages.objects.sudorule.anyone },
            { 'value': '', 'label': IPA.messages.objects.sudorule.specified_users }
        ],
        'tables': [
            { 'field_name': 'memberuser_user' },
            { 'field_name': 'memberuser_group' }
        ]
    });
    that.add_section(section);

    var category = section.add_field(IPA.radio_widget({
        name: 'usercategory'
    }));
    section.add_field(IPA.sudorule_association_table_widget({
        'id': that.entity_name+'-memberuser_user',
        'name': 'memberuser_user', 'category': category,
        'other_entity': 'user', 'add_method': 'add_user', 'remove_method': 'remove_user',
        'external': 'externaluser'
    }));
    section.add_field(IPA.sudorule_association_table_widget({
        'id': that.entity_name+'-memberuser_group',
        'name': 'memberuser_group', 'category': category,
        'other_entity': 'group', 'add_method': 'add_user', 'remove_method': 'remove_user'
    }));

    section = IPA.rule_details_section({
        'name': 'host',
        'label': IPA.messages.objects.sudorule.host,
        'field_name': 'hostcategory',
        'options': [
            { 'value': 'all', 'label': IPA.messages.objects.sudorule.any_host },
            { 'value': '', 'label': IPA.messages.objects.sudorule.specified_hosts }
        ],
        'tables': [
            { 'field_name': 'memberhost_host' },
            { 'field_name': 'memberhost_hostgroup' }
        ]
    });
    that.add_section(section);

    category = section.add_field(IPA.radio_widget({
        name: 'hostcategory'
    }));
    section.add_field(IPA.sudorule_association_table_widget({
        'id': that.entity_name+'-memberhost_host',
        'name': 'memberhost_host', 'category': category,
        'other_entity': 'host', 'add_method': 'add_host', 'remove_method': 'remove_host',
        'external': 'externalhost'
    }));
    section.add_field(IPA.sudorule_association_table_widget({
        'id': that.entity_name+'-memberhost_hostgroup',
        'name': 'memberhost_hostgroup', 'category': category,
        'other_entity': 'hostgroup', 'add_method': 'add_host', 'remove_method': 'remove_host'
    }));

    section = IPA.sudo.rule_details_command_section({
        'name': 'command',
        'label': IPA.messages.objects.sudorule.command
    });
    that.add_section(section);

    section = IPA.sudo.rule_details_runas_section({
        'name': 'runas',
        'label': IPA.messages.objects.sudorule.runas
    });
    that.add_section(section);

    that.update = function(on_success, on_error) {

        var pkey = IPA.nav.get_state(that.entity_name+'-pkey');

        var modify_operation = {
            'execute': false,
            'command': IPA.command({
                entity: that.entity_name,
                method: 'mod',
                args: [pkey],
                options: {all: true, rights: true}
            })
        };

        var categories = {
            'usercategory': {
                'remove_values': false
            },
            'hostcategory': {
                'remove_values': false
            },
            'cmdcategory': {
                'remove_values': false
            },
            'ipasudorunasusercategory': {
                'remove_values': false
            },
            'ipasudorunasgroupcategory': {
                'remove_values': false
            }
        };

        var member_operations = {
            'memberuser': {
                'category': 'usercategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity_name,
                    method: 'remove_user',
                    args: [pkey],
                    options: {all: true, rights: true}
                })
            },
            'memberhost': {
                'category': 'hostcategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity_name,
                    method: 'remove_host',
                    args: [pkey],
                    options: {all: true, rights: true}
                })
            },
            'memberallowcmd': {
                'category': 'cmdcategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity_name,
                    method: 'remove_allow_command',
                    args: [pkey],
                    options: {all: true, rights: true}
                })
            },
            'ipasudorunas': {
                'category': 'ipasudorunasusercategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity_name,
                    method: 'remove_runasuser',
                    args: [pkey],
                    options: {all: true, rights: true}
                })
            },
            'ipasudorunasgroup': {
                'category': 'ipasudorunasgroupcategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity_name,
                    method: 'remove_runasgroup',
                    args: [pkey],
                    options: {all: true, rights: true}
                })
            }
        };

        var enable_operation = {
            'execute': false,
            'command': IPA.command({
                entity: that.entity_name,
                method: 'enable',
                args: [pkey],
                options: {all: true, rights: true}
            })
        };

        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];

            var section_fields = section.fields.values;
            for (var j=0; j<section_fields.length; j++) {
                var field = section_fields[j];
                if (!field.is_dirty()) continue;

                var values = field.save();
                if (!values) continue;

                var param_info = IPA.get_entity_param(that.entity_name, field.name);

                // skip primary key
                if (param_info && param_info['primary_key']) continue;

                var p = field.name.indexOf('_');
                if (p >= 0) {
                    // prepare command to remove members if needed
                    var attribute = field.name.substring(0, p);
                    var other_entity = field.name.substring(p+1);

                    if (member_operations[attribute] && values.length) {
                        member_operations[attribute].command.set_option(other_entity, values.join(','));
                        member_operations[attribute].has_values = true;
                    }
                    continue;
                }

                // skip unchanged field
                if (!field.is_dirty()) continue;

                // check enable/disable
                if (field.name == 'ipaenabledflag') {
                    if (values[0] == 'FALSE') enable_operation.command.method = 'disable';
                    enable_operation.execute = true;
                    continue;
                }


                if (categories[field.name] && values[0] == 'all') {
                    categories[field.name].remove_values = true;
                }

                if (param_info) {
                    if (values.length == 1) {
                        modify_operation.command.set_option(field.name, values[0]);
                    } else if (field.join) {
                        modify_operation.command.set_option(field.name, values.join(','));
                    } else {
                        modify_operation.command.set_option(field.name, values);
                    }

                } else {
                    if (values.length) {
                        modify_operation.command.set_option('setattr', field.name+'='+values[0]);
                    } else {
                        modify_operation.command.set_option('setattr', field.name+'=');
                    }
                    for (var k=1; k<values.length; k++) {
                        modify_operation.command.set_option('addattr', field.name+'='+values[k]);
                    }
                }

                modify_operation.execute = true;
            }
        }

        var batch = IPA.batch_command({
            'name': 'sudorule_details_update',
            'on_success': function(data, text_status, xhr) {
                that.refresh();
                if (on_success) on_success(data, text_status, xhr);
            },
            'on_error': function(xhr, text_status, error_thrown) {
                that.refresh();
                if (on_error) on_error(xhr, text_status, error_thrown);
            }
        });

        for (var member_attribute in member_operations) {
            var member_operation = member_operations[member_attribute];
            if (member_operation.has_values &&
                categories[member_operation.category].remove_values) {
                batch.add_command(member_operation.command);
            }
        }

        if (modify_operation.execute) batch.add_command(modify_operation.command);
        if (enable_operation.execute) batch.add_command(enable_operation.command);

        if (!batch.commands.length) {
            that.refresh();
            return;
        }


        batch.execute();
    };

    return that;
};


IPA.sudo.rule_details_general_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_section(spec);

    that.create = function(container) {

        var table = $('<table/>', {
            'style': 'width: 100%;'
        }).appendTo(container);

        var param_info = IPA.get_entity_param(that.entity_name, 'cn');

        var tr = $('<tr/>').appendTo(table);

        var td = $('<td/>', {
            style: 'width: 100px; text-align: right;',
            html: param_info.label+':',
            title: param_info ? param_info.doc : 'cn'
        }).appendTo(tr);

        td = $('<td/>').appendTo(tr);

        var field = that.get_field('cn');

        var span = $('<span/>', {
            name: 'cn',
            title: param_info ? param_info.doc : 'cn'
        }).appendTo(td);

        $('<label/>', {
            name: 'cn',
            style: 'display: none;'
        }).appendTo(span);

        $('<input/>', {
            'type': 'text',
            'name': 'cn',
            'size': 30
        }).appendTo(span);

        span.append(' ');

        field.create_undo(span);

        param_info = IPA.get_entity_param(that.entity_name, 'description');

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>', {
            style: 'text-align: right; vertical-align: top;',
            html: param_info.label+':',
            title: param_info ? param_info.doc : 'description'
        }).appendTo(tr);

        td = $('<td/>').appendTo(tr);

        field = that.get_field('description');

        span = $('<span/>', {
            name: 'description',
            title: param_info ? param_info.doc : 'description'
        }).appendTo(td);

        $('<textarea/>', {
            'name': 'description',
            'rows': 5,
            'style': 'width: 100%'
        }).appendTo(span);

        span.append(' ');

        field.create_undo(span);

        param_info = IPA.get_entity_param(that.entity_name, 'ipaenabledflag');
        var label = IPA.messages.objects.sudorule.ipaenabledflag;

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>', {
            style: 'text-align: right; vertical-align: top;',
            html: label+':',
            title: label
        }).appendTo(tr);

        td = $('<td/>').appendTo(tr);

        field = that.get_field('ipaenabledflag');

        span = $('<span/>', {
            name: 'ipaenabledflag',
            title: label
        }).appendTo(td);

        $('<input/>', {
            'type': 'radio',
            'name': 'ipaenabledflag',
            'value': 'TRUE'
        }).appendTo(span);

        span.append(' ');

        span.append(IPA.messages.objects.sudorule.active);

        span.append(' ');

        $('<input/>', {
            'type': 'radio',
            'name': 'ipaenabledflag',
            'value': 'FALSE'
        }).appendTo(span);

        span.append(' ');

        span.append(IPA.messages.objects.sudorule.inactive);

        span.append(' ');

        field.create_undo(span);
    };

    return that;
};


IPA.sudo.rule_details_command_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_section(spec);

    that.init = function() {

        var category = that.add_field(IPA.radio_widget({
            name: 'cmdcategory'
        }));

        that.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberallowcmd_sudocmd',
            'name': 'memberallowcmd_sudocmd', 'label': 'Command',
            'category': category,
            'other_entity': 'sudocmd', 'add_method': 'add_allow_command', 'remove_method': 'remove_allow_command'
        }));
        that.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberallowcmd_sudocmdgroup',
            'name': 'memberallowcmd_sudocmdgroup', 'label': 'Groups',
            'category': category,
            'other_entity': 'sudocmdgroup', 'add_method': 'add_allow_command', 'remove_method': 'remove_allow_command'
        }));

        that.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberdenycmd_sudocmd',
            'name': 'memberdenycmd_sudocmd', 'label': 'Command',
            'other_entity': 'sudocmd', 'add_method': 'add_deny_command', 'remove_method': 'remove_deny_command'
        }));
        that.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberdenycmd_sudocmdgroup',
            'name': 'memberdenycmd_sudocmdgroup', 'label': 'Groups',
            'other_entity': 'sudocmdgroup', 'add_method': 'add_deny_command', 'remove_method': 'remove_deny_command'
        }));

        that.section_init();
    };

    that.create = function(container) {

        if (that.template) return;

        var field = that.get_field('cmdcategory');
        var param_info = IPA.get_entity_param(that.entity_name, 'cmdcategory');

        var span = $('<span/>', {
            name: 'cmdcategory',
            title: param_info ? param_info.doc : 'cmdcategory'
        }).appendTo(container);

        $('<h3/>', {
            text: IPA.messages.objects.sudorule.allow,
            title: IPA.messages.objects.sudorule.allow
        }).appendTo(span);

        $('<input/>', {
            type: 'radio',
            name: 'cmdcategory',
            value: 'all'
        }).appendTo(span);

        span.append(' ');

        span.append(IPA.messages.objects.sudorule.any_command);

        span.append(' ');

        $('<input/>', {
            type: 'radio',
            name: 'cmdcategory',
            value: ''
        }).appendTo(span);

        span.append(' ');

        span.append(IPA.messages.objects.sudorule.specified_commands);

        span.append(' ');

        field.create_undo(span);

        param_info = IPA.get_entity_param(that.entity_name, 'memberallowcmd_sudocmd');

        var table_span = $('<span/>', {
            name: 'memberallowcmd_sudocmd',
            title: param_info ? param_info.doc : 'memberallowcmd_sudocmd'
        }).appendTo(span);

        field = that.get_field('memberallowcmd_sudocmd');
        field.create(table_span);

        param_info = IPA.get_entity_param(that.entity_name, 'memberallowcmd_sudocmdgroup');

        table_span = $('<span/>', {
            name: 'memberallowcmd_sudocmdgroup',
            title: param_info ? param_info.doc : 'memberallowcmd_sudocmdgroup'
        }).appendTo(span);

        field = that.get_field('memberallowcmd_sudocmdgroup');
        field.create(table_span);

        $('<h3/>', {
            text: IPA.messages.objects.sudorule.deny,
            title: IPA.messages.objects.sudorule.deny
        }).appendTo(span);

        param_info = IPA.get_entity_param(that.entity_name, 'memberdenycmd_sudocmd');

        table_span = $('<span/>', {
            name: 'memberdenycmd_sudocmd',
            title: param_info ? param_info.doc : 'memberdenycmd_sudocmd'
        }).appendTo(span);

        field = that.get_field('memberdenycmd_sudocmd');
        field.create(table_span);

        param_info = IPA.get_entity_param(that.entity_name, 'memberdenycmd_sudocmdgroup');

        table_span = $('<span/>', {
            name: 'memberdenycmd_sudocmdgroup',
            title: param_info ? param_info.doc : 'memberdenycmd_sudocmdgroup'
        }).appendTo(span);

        field = that.get_field('memberdenycmd_sudocmdgroup');
        field.create(table_span);
    };

    that.setup = function(container) {

        that.section_setup(container);

        function update_tables(value) {

            var enabled = ('' === value);

            var field = that.get_field('memberallowcmd_sudocmd');
            field.set_enabled(enabled);

            field = that.get_field('memberallowcmd_sudocmdgroup');
            field.set_enabled(enabled);
        }

        var cmdcategory = that.get_field('cmdcategory');
        cmdcategory.reset = function() {
            cmdcategory.widget_reset();
            var values = cmdcategory.save();
            if (values.length === 0) return;
            var value = values[0];
            update_tables(value);
        };

        var inputs = $('input[name=cmdcategory]', container);
        inputs.change(function() {
            var input = $(this);
            var value = input.val();
            update_tables(value);
        });
    };

    return that;
};


IPA.sudo.rule_details_runas_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_section(spec);

    that.init = function() {

        var category = that.add_field(IPA.radio_widget({
            name: 'ipasudorunasusercategory',
            label: 'Run as User category'
        }));

        that.add_field(IPA.sudorule_association_table_widget({
            'id': that.entity_name+'-runasruser_user',
            'name': 'ipasudorunas_user', 'label': 'Users', 'category': category,
            'other_entity': 'user', 'add_method': 'add_runasuser', 'remove_method': 'remove_runasuser'
        }));
        that.add_field(IPA.sudorule_association_table_widget({
            'id': that.entity_name+'-runasuser_group',
            'name': 'ipasudorunas_group', 'label': 'Groups', 'category': category,
            'other_entity': 'group', 'add_method': 'add_runasuser', 'remove_method': 'remove_runasuser'
        }));

        category = that.add_field(IPA.radio_widget({
            name: 'ipasudorunasgroupcategory',
            label: 'Run as Group category'
        }));

        that.add_field(IPA.sudorule_association_table_widget({
            'id': that.entity_name+'-runasgroup_group',
            'name': 'ipasudorunasgroup_group', 'label': 'Groups', 'category': category,
            'other_entity': 'group', 'add_method': 'add_runasgroup', 'remove_method': 'remove_runasgroup'
        }));

        that.section_init();
    };

    that.create = function(container) {

        if (that.template) return;

        var field = that.get_field('ipasudorunasusercategory');
        var param_info = IPA.get_entity_param(that.entity_name, 'ipasudorunasusercategory');

        var span = $('<span/>', {
            name: 'ipasudorunasusercategory',
            title: param_info ? param_info.doc : 'ipasudorunasusercategory'
        }).appendTo(container);

        $('<input/>', {
            'type': 'radio',
            'name': 'ipasudorunasusercategory',
            'value': 'all'
        }).appendTo(span);

        span.append(' ');

        span.append(IPA.messages.objects.sudorule.anyone);

        span.append(' ');

        $('<input/>', {
            'type': 'radio',
            'name': 'ipasudorunasusercategory',
            'value': ''
        }).appendTo(span);

        span.append(' ');

        span.append(IPA.messages.objects.sudorule.specified_users);

        span.append(' ');

        field.create_undo(span);

        span.append('<br/>');

        param_info = IPA.get_entity_param(that.entity_name, 'ipasudorunas_user');

        var table_span = $('<span/>', {
            name: 'ipasudorunas_user',
            title: param_info ? param_info.doc : 'ipasudorunas_user'
        }).appendTo(span);

        field = that.get_field('ipasudorunas_user');
        field.create(table_span);

        param_info = IPA.get_entity_param(that.entity_name, 'ipasudorunas_group');

        table_span = $('<span/>', {
            name: 'ipasudorunas_group',
            title: param_info ? param_info.doc : 'ipasudorunas_group'
        }).appendTo(span);

        field = that.get_field('ipasudorunas_group');
        field.create(table_span);

        field = that.get_field('ipasudorunasgroupcategory');
        param_info = IPA.get_entity_param(that.entity_name, 'ipasudorunasgroupcategory');

        span = $('<span/>', {
            name: 'ipasudorunasgroupcategory',
            title: param_info ? param_info.doc : 'ipasudorunasgroupcategory'
        }).appendTo(container);

        $('<input/>', {
            'type': 'radio',
            'name': 'ipasudorunasgroupcategory',
            'value': 'all'
        }).appendTo(span);

        span.append(' ');

        span.append(IPA.messages.objects.sudorule.any_group);

        span.append(' ');

        $('<input/>', {
            'type': 'radio',
            'name': 'ipasudorunasgroupcategory',
            'value': ''
        }).appendTo(span);

        span.append(' ');

        span.append(IPA.messages.objects.sudorule.specified_groups);

        span.append(' ');

        field.create_undo(span);

        span.append('<br/>');

        param_info = IPA.get_entity_param(that.entity_name, 'ipasudorunasgroup_group');

        table_span = $('<span/>', {
            name: 'ipasudorunasgroup_group',
            title: param_info ? param_info.doc : 'ipasudorunasgroup_group'
        }).appendTo(span);

        field = that.get_field('ipasudorunasgroup_group');
        field.create(table_span);
    };

    that.setup = function(container) {

        that.section_setup(container);

        function user_update_tables(value) {

            var enabled = ('' === value);

            var field = that.get_field('ipasudorunas_user');
            field.set_enabled(enabled);

            field = that.get_field('ipasudorunas_group');
            field.set_enabled(enabled);
        }

        var user_category = that.get_field('ipasudorunasusercategory');
        user_category.reset = function() {
            user_category.widget_reset();
            var values = user_category.save();
            if (values.length === 0) return;
            var value = values[0];
            user_update_tables(value);
        };

        var user_inputs = $('input[name=ipasudorunasusercategory]', container);
        user_inputs.change(function() {
            var input = $(this);
            var value = input.val();
            user_update_tables(value);
        });

        function group_update_tables(value) {

            var enabled = ('' === value);

            var field = that.get_field('ipasudorunasgroup_group');
            field.set_enabled(enabled);
        }

        var group_category = that.get_field('ipasudorunasgroupcategory');
        group_category.reset = function() {
            group_category.widget_reset();
            var values = group_category.save();
            if (values.length === 0) return;
            var value = values[0];
            group_update_tables(value);
        };

        var group_inputs = $('input[name=ipasudorunasgroupcategory]', container);
        group_inputs.change(function() {
            var input = $(this);
            var value = input.val();
            group_update_tables(value);
        });
    };

    return that;
};


IPA.sudorule_association_table_widget = function(spec) {

    spec = spec || {};

    var that = IPA.rule_association_table_widget(spec);

    that.external = spec.external;

    that.create_add_dialog = function() {
        var pkey = IPA.nav.get_state(that.entity_name+'-pkey');
        var label = IPA.metadata.objects[that.other_entity].label;
        var title = 'Add '+label+' to '+that.entity_name+' '+pkey;

        var template;
        if (IPA.layout) {
            template = 'sudorule-'+that.other_entity+'-dialog.html #contents';
        }

        return IPA.sudo.rule_association_adder_dialog({
            'title': title,
            'entity_name': that.entity_name,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'external': that.external,
            'template': template
        });
    };

    that.load = function(result) {
        that.values = result[that.name] || [];
        if (that.external) {
            var external_values = result[that.external] || [];
            $.merge(that.values, external_values);
        }
        that.reset();
    };

    return that;
};


IPA.sudo.rule_association_adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.association_adder_dialog(spec);

    that.external = spec.external;

    that.init = function() {

        if (!that.columns.length) {
            var pkey_name = IPA.metadata.objects[that.other_entity].primary_key;
            that.create_column({
                name: pkey_name,
                label: IPA.metadata.objects[that.other_entity].label,
                primary_key: true,
                width: '200px'
            });
        }

        that.available_table = IPA.table_widget({
            name: 'available'
        });

        var columns = that.columns.values;
        that.available_table.set_columns(columns);

        that.available_table.init();

        that.selected_table = IPA.table_widget({
            name: 'selected'
        });

        that.selected_table.set_columns(columns);

        that.selected_table.init();

        that.association_adder_dialog_init();
    };

    that.create = function() {

        // do not call that.dialog_create();

        var search_panel = $('<div/>', {
            'class': 'adder-dialog-filter'
        }).appendTo(that.container);

        $('<input/>', {
            type: 'text',
            name: 'filter',
            style: 'width: 244px'
        }).appendTo(search_panel);

        search_panel.append(' ');

        $('<input/>', {
            type: 'button',
            name: 'find',
            value: IPA.messages.buttons.find
        }).appendTo(search_panel);

        var results_panel = $('<div/>', {
            'class': 'adder-dialog-results'
        }).appendTo(that.container);

        var class_name = that.external ? 'adder-dialog-internal' : 'adder-dialog-available';

        var available_panel = $('<div/>', {
            name: 'available',
            'class': class_name
        }).appendTo(results_panel);

        $('<div/>', {
            html: IPA.messages.dialogs.available,
            'class': 'ui-widget-header'
        }).appendTo(available_panel);

        that.available_table.create(available_panel);

        var buttons_panel = $('<div/>', {
            name: 'buttons',
            'class': 'adder-dialog-buttons'
        }).appendTo(results_panel);

        var p = $('<p/>').appendTo(buttons_panel);
        $('<input />', {
            type: 'button',
            name: 'remove',
            value: '<<'
        }).appendTo(p);

        p = $('<p/>').appendTo(buttons_panel);
        $('<input />', {
            type: 'button',
            name: 'add',
            value: '>>'
        }).appendTo(p);

        var selected_panel = $('<div/>', {
            name: 'selected',
            'class': 'adder-dialog-selected'
        }).appendTo(results_panel);

        $('<div/>', {
            html: IPA.messages.dialogs.prospective,
            'class': 'ui-widget-header'
        }).appendTo(selected_panel);

        that.selected_table.create(selected_panel);

        if (that.external) {
            var external_panel = $('<div/>', {
                name: 'external',
                'class': 'adder-dialog-external'
            }).appendTo(results_panel);

            $('<div/>', {
                html: IPA.messages.objects.sudorule.external,
                'class': 'ui-widget-header'
            }).appendTo(external_panel);

            $('<input/>', {
                type: 'text',
                name: 'external',
                style: 'width: 244px'
            }).appendTo(external_panel);
        }
    };

    that.setup = function() {
        that.association_adder_dialog_setup();
        if (that.external) that.external_field = $('input[name=external]', that.container);
    };

    that.add = function() {
        var rows = that.available_table.remove_selected_rows();
        that.selected_table.add_rows(rows);

        if (that.external) {
            var pkey_name = IPA.metadata.objects[that.other_entity].primary_key;
            var value = that.external_field.val();
            if (!value) return;

            var record = {};
            record[pkey_name] = value;
            that.selected_table.add_record(record);
            that.external_field.val('');
        }
    };

    return that;
};
