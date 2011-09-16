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
            columns: [
                'cn',
                'ipaenabledflag',
                'description'
            ]
        }).
        details_facet({
            factory: IPA.sudorule_details_facet
        }).
        adder_dialog({
            fields: [ 'cn' ]
        }).
        build();
};

IPA.entity_factories.sudocmd = function() {

    return IPA.entity_builder().
        entity('sudocmd').
        search_facet({
            columns: [
                'sudocmd',
                'description'
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'general',
                    label: IPA.messages.details.general,
                    fields: [
                        'sudocmd',
                        {
                            factory: IPA.textarea_widget,
                            name: 'description'
                        }
                    ]
                }
            ]
        }).
        association_facet({
            name: 'memberof_sudocmdgroup',
            associator: IPA.serial_associator,
            columns:[
                {
                    name: 'cn',
                    primary_key: true,
                    link: true
                },
                { name: 'description' }
            ],
            adder_columns: [
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
        }).
        standard_association_facets().
        adder_dialog({
            fields: [
                'sudocmd',
                {
                    factory: IPA.textarea_widget,
                    name: 'description'
                }
            ]
        }).
        build();

};

IPA.entity_factories.sudocmdgroup = function() {
    return IPA.entity_builder().
        entity('sudocmdgroup').
        search_facet({
            columns: [
                'cn',
                'description'
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'general',
                    label: IPA.messages.details.general,
                    fields: [
                        'cn',
                        {
                            factory: IPA.textarea_widget,
                            name: 'description'
                        }
                    ]
                }
            ]
        }).
        association_facet({
            name: 'member_sudocmd',
            columns: [
                {
                    name: 'sudocmd',
                    primary_key: true,
                    link: true
                },
                { name: 'description' }
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
        }).
        standard_association_facets().
        adder_dialog({
            fields: [
                'cn',
                {
                    factory: IPA.textarea_widget,
                    name: 'description'
                }
            ]
        }).
        build();
};

IPA.sudo = {};

IPA.sudorule_details_facet = function(spec) {

    spec = spec || {};

    var that = IPA.details_facet(spec);

    function general_section(){
        var section = IPA.details_table_section({
            name: 'general',
            label: IPA.messages.details.general,
            entity: that.entity,
            facet: that
        });

        section.text({
            name: 'cn',
            read_only: true
        });
        section.textarea({
            name: 'description'
        });
        section.radio({
            name: 'ipaenabledflag',
            options: [
                { value: 'TRUE', label: IPA.get_message('true') },
                { value: 'FALSE', label: IPA.get_message('false') }
            ]
        });
        return section;
    }

    function options_section(){
        var section = IPA.sudo.options_section({
            name: 'options',
            label: IPA.messages.objects.sudorule.options,
            entity: that.entity,
            facet: that
        });
        return section;
    }


    function user_section(){
        var section = IPA.rule_details_section({
            name: 'user',
            label: IPA.messages.objects.sudorule.user,
            field_name: 'usercategory',
            entity: that.entity,
            options: [
                { value: 'all',
                  label: IPA.messages.objects.sudorule.anyone },
                { value: '',
                  label: IPA.messages.objects.sudorule.specified_users }
            ],
            tables: [
                { field_name: 'memberuser_user' },
                { field_name: 'memberuser_group' }
            ]
        });

        section.add_field(IPA.radio_widget({
            entity: that.entity,
            name: 'usercategory'
        }));
        section.add_field(IPA.sudorule_association_table_widget({
            id: that.entity.name+'-memberuser_user',
            entity: that.entity,
            name: 'memberuser_user',
            add_method: 'add_user',
            remove_method: 'remove_user',
            external: 'externaluser',
            add_title: IPA.messages.association.add.member,
            remove_title: IPA.messages.association.remove.member
        }));
        section.add_field(IPA.sudorule_association_table_widget({
            id: that.entity.name+'-memberuser_group',
            entity: that.entity,
            name: 'memberuser_group',
            add_method: 'add_user',
            remove_method: 'remove_user',
            add_title: IPA.messages.association.add.member,
            remove_title: IPA.messages.association.remove.member
        }));
        return section;
    }

    function host_section(){
        var section = IPA.rule_details_section({
            name: 'host',
            entity: that.entity,
            label: IPA.messages.objects.sudorule.host,
            field_name: 'hostcategory',
            options: [
                { 'value': 'all', 'label': IPA.messages.objects.sudorule.any_host },
                { 'value': '', 'label': IPA.messages.objects.sudorule.specified_hosts }
            ],
            tables: [
                { 'field_name': 'memberhost_host' },
                { 'field_name': 'memberhost_hostgroup' }
            ]
        });

        section.add_field(IPA.radio_widget({
            entity: that.entity,
            name: 'hostcategory'
        }));
        section.add_field(IPA.sudorule_association_table_widget({
            id: that.entity.name+'-memberhost_host',
            entity: that.entity,
            name: 'memberhost_host',
            add_method: 'add_host',
            remove_method: 'remove_host',
            external: 'externalhost',
            add_title: IPA.messages.association.add.member,
            remove_title: IPA.messages.association.remove.member
        }));
        section.add_field(IPA.sudorule_association_table_widget({
            id: that.entity.name+'-memberhost_hostgroup',
            entity: that.entity,
            name: 'memberhost_hostgroup',
            add_method: 'add_host',
            remove_method: 'remove_host',
            add_title: IPA.messages.association.add.member,
            remove_title: IPA.messages.association.remove.member
        }));
        return section;
    }


    that.update = function(on_success, on_error) {

        var args = that.get_primary_key();

        var modify_operation = {
            'execute': false,
            'command': IPA.command({
                entity: that.entity.name,
                method: 'mod',
                args: args,
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
                    entity: that.entity.name,
                    method: 'remove_user',
                    args: args,
                    options: {all: true, rights: true}
                })
            },
            'memberhost': {
                'category': 'hostcategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity.name,
                    method: 'remove_host',
                    args: args,
                    options: {all: true, rights: true}
                })
            },
            'memberallowcmd': {
                'category': 'cmdcategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity.name,
                    method: 'remove_allow_command',
                    args: args,
                    options: {all: true, rights: true}
                })
            },
            'ipasudorunas': {
                'category': 'ipasudorunasusercategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity.name,
                    method: 'remove_runasuser',
                    args: args,
                    options: {all: true, rights: true}
                })
            },
            'ipasudorunasgroup': {
                'category': 'ipasudorunasgroupcategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity.name,
                    method: 'remove_runasgroup',
                    args: args,
                    options: {all: true, rights: true}
                })
            }
        };

        var enable_operation = {
            'execute': false,
            'command': IPA.command({
                entity: that.entity.name,
                method: 'enable',
                args: args,
                options: {all: true, rights: true}
            })
        };

        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];

            var section_fields = section.fields.values;
            for (var j=0; j<section_fields.length; j++) {
                var field = section_fields[j];

                // association tables are never dirty, so call
                // is_dirty() after checking table values

                var values = field.save();
                if (!values) continue;

                var param_info = field.param_info;

                // skip primary key
                if (param_info && param_info.primary_key) continue;

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
                if (on_success) on_success.call(this, data, text_status, xhr);
            },
            'on_error': function(xhr, text_status, error_thrown) {
                that.refresh();
                if (on_error) on_error.call(this, xhr, text_status, error_thrown);
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

    /*initialization*/
    that.add_section(general_section());
    that.add_section(options_section());
    that.add_section(user_section());
    that.add_section(host_section());
    that.add_section(IPA.sudo.rule_details_command_section({
        name: 'command',
        entity: that.entity,
        label: IPA.messages.objects.sudorule.command
    }));
    that.add_section(IPA.sudo.rule_details_runas_section({
        name: 'runas',
        entity: that.entity,
        label: IPA.messages.objects.sudorule.runas
    }));


    return that;
};

IPA.sudo.options_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_section(spec);

    that.facet = spec.facet;


    function setup_table(){
        that.table = that.add_field(IPA.table_widget({
            name: 'ipasudoopt',
            show_buttons: true
        }));

        that.table.create_column({
            name: 'ipasudoopt',
            label: IPA.get_method_option('sudorule_add_option', 'ipasudoopt').label,
            entity_name:that.entity.name,
            primary_key: true
        });

        that.table.create = function(container) {

            that.table.table_create(container);

            var button = IPA.action_button({
                name: 'remove',
                label: IPA.messages.buttons.remove,
                icon: 'remove-icon',
                click: function() {
                    that.remove_handler();
                    return false;
                }
            }).appendTo(that.table.buttons);

            button = IPA.action_button({
                name: 'add',
                label: IPA.messages.buttons.add,
                icon: 'add-icon',
                click: function() {
                    that.add_handler();
                    return false;
                }
            }).appendTo(that.table.buttons);
        };
    }

    that.add_handler = function() {
        if (that.facet.is_dirty()) {
            var dialog = IPA.dirty_dialog({
                facet: that.facet
            });

            dialog.callback = function() {
                that.show_add_dialog();
            };
            dialog.open(that.container);

        } else {
            that.show_add_dialog();
        }
    };

    that.remove_handler = function() {
        if (that.facet.is_dirty()) {
            var dialog = IPA.dirty_dialog({
                facet: that.facet
            });

            dialog.callback = function() {
                that.show_remove_dialog();
            };
            dialog.open(that.container);

        } else {
            that.show_remove_dialog();
        }
    };

    that.show_add_dialog = function() {

        var label = IPA.get_method_option('sudorule_add_option', 'ipasudoopt').label;

        var title = IPA.messages.dialogs.add_title;
        title = title.replace('${entity}', label);

        var dialog = IPA.dialog({
            title: title
        });

        var ipasudoopt = dialog.add_field(IPA.text_widget({
            name: 'ipasudoopt',
            label: label
        }));

        dialog.add_button(IPA.messages.buttons.add, function() {
            var value = ipasudoopt.save()[0];

            var pkey = IPA.nav.get_state(that.entity.name+'-pkey');

            var command = IPA.command({
                entity: 'sudorule',
                method: 'add_option',
                args: [pkey],
                options: {
                    ipasudoopt: value
                },
                on_success: function(data) {
                    that.load(data.result.result);
                    dialog.close();
                },
                on_error: function(data) {
                    that.update();
                    dialog.close();
                }
            });

            command.execute();
        });

        dialog.add_button(IPA.messages.buttons.cancel, function() {
            dialog.close();
        });

        dialog.open(that.container);
    };

    that.show_remove_dialog = function() {

        var label = IPA.get_method_option('sudorule_add_option', 'ipasudoopt').label;
        var values = that.table.get_selected_values();

        if (!values.length) {
            var message = IPA.messages.dialogs.remove_empty;
            alert(message);
            return;
        }

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');

        var title = IPA.messages.dialogs.remove_title;
        title = title.replace('${entity}', label);

        var dialog = IPA.deleter_dialog({
            title: title,
            values: values
        });

        dialog.execute = function() {

            var batch = IPA.batch_command({
                on_success: function(data) {
                    //last successful result of batch results contains valid data
                    var result;
                    for(var i = data.result.results.length - 1; i > -1; i--) {
                        result = data.result.results[i].result;
                        if(result) break;
                    }

                    if(result) {
                        that.load(result);
                    } else {
                        that.update();
                    }

                    dialog.close();
                },
                on_error: function(data) {
                    that.update();
                    dialog.close();
                }
            });

            for (var i=0; i<values.length; i++) {
                var command = IPA.command({
                    entity: 'sudorule',
                    method: 'remove_option',
                    args: [pkey]
                });

                command.set_option('ipasudoopt', values[i]);

                batch.add_command(command);
            }

            batch.execute();
        };

        dialog.open(that.container);
    };

    that.update = function() {
        var command = IPA.command({
            entity: that.facet.entity.name,
            method: 'show',
            args: that.facet.get_primary_key(true),
            on_success: function(data) {
                that.load(data.result.result);
            }
        });

        command.execute();
    };

    /*initialization*/
    setup_table();

    return that;
};



IPA.sudo.rule_details_command_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_section(spec);

    function setup_fields(){
        that.category = that.add_field(
            IPA.radio_widget({
                name: 'cmdcategory',
                options:[
                    {
                        value:'all',
                        label:IPA.messages.objects.sudorule.any_command
                    },
                    {
                        value:'',
                        label:IPA.messages.objects.sudorule.specified_commands
                    }
                ]
            }));

        that.add_field(IPA.association_table_widget({
            id: that.entity.name+'-memberallowcmd_sudocmd',
            name: 'memberallowcmd_sudocmd',
            entity: that.entity,
            add_method: 'add_allow_command',
            remove_method: 'remove_allow_command',
            add_title: IPA.messages.association.add.memberallowcmd,
            remove_title: IPA.messages.association.remove.memberallowcmd
        }));
        that.add_field(IPA.association_table_widget({
            id: that.entity.name+'-memberallowcmd_sudocmdgroup',
            name: 'memberallowcmd_sudocmdgroup',
            entity: that.entity,
            add_method: 'add_allow_command',
            remove_method: 'remove_allow_command',
            add_title: IPA.messages.association.add.memberallowcmd,
            remove_title: IPA.messages.association.remove.memberallowcmd
        }));

        that.add_field(IPA.association_table_widget({
            id: that.entity.name+'-memberdenycmd_sudocmd',
            name: 'memberdenycmd_sudocmd',
            entity: that.entity,
            add_method: 'add_deny_command',
            remove_method: 'remove_deny_command',
            add_title: IPA.messages.association.add.memberdenycmd,
            remove_title: IPA.messages.association.remove.memberdenycmd
        }));
        that.add_field(IPA.association_table_widget({
            id: that.entity.name+'-memberdenycmd_sudocmdgroup',
            name: 'memberdenycmd_sudocmdgroup',
            entity: that.entity,
            add_method: 'add_deny_command',
            remove_method: 'remove_deny_command',
            add_title: IPA.messages.association.add.memberdenycmd,
            remove_title: IPA.messages.association.remove.memberdenycmd
        }));
    }

    that.create = function(container) {

        that.container = container;

        var field = that.get_field('cmdcategory');
        var param_info = IPA.get_entity_param(that.entity.name, 'cmdcategory');

        var span = $('<span/>', {
            name: 'cmdcategory',
            title: param_info.doc,
            'class': 'field'
        }).appendTo(container);

        $('<h3/>', {
            text: IPA.messages.objects.sudorule.allow,
            title: IPA.messages.objects.sudorule.allow
        }).appendTo(span);

        span.append(param_info.doc+": ");

        that.category.create(span);

        param_info = IPA.get_entity_param(
            that.entity.name, 'memberallowcmd_sudocmd');

        var table_span = $('<span/>', {
            name: 'memberallowcmd_sudocmd',
            title: param_info ? param_info.doc : 'memberallowcmd_sudocmd',
            'class': 'field'
        }).appendTo(span);

        field = that.get_field('memberallowcmd_sudocmd');
        field.create(table_span);

        param_info = IPA.get_entity_param(
            that.entity.name, 'memberallowcmd_sudocmdgroup');

        table_span = $('<span/>', {
            name: 'memberallowcmd_sudocmdgroup',
            title: param_info ? param_info.doc : 'memberallowcmd_sudocmdgroup',
            'class': 'field'
        }).appendTo(span);

        field = that.get_field('memberallowcmd_sudocmdgroup');
        field.create(table_span);

        $('<h3/>', {
            text: IPA.messages.objects.sudorule.deny,
            title: IPA.messages.objects.sudorule.deny
        }).appendTo(span);

        param_info = IPA.get_entity_param(
            that.entity.name, 'memberdenycmd_sudocmd');

        table_span = $('<span/>', {
            name: 'memberdenycmd_sudocmd',
            title: param_info ? param_info.doc : 'memberdenycmd_sudocmd',
            'class': 'field'
        }).appendTo(span);

        field = that.get_field('memberdenycmd_sudocmd');
        field.create(table_span);

        param_info = IPA.get_entity_param(
            that.entity.name, 'memberdenycmd_sudocmdgroup');

        table_span = $('<span/>', {
            name: 'memberdenycmd_sudocmdgroup',
            title: param_info ? param_info.doc : 'memberdenycmd_sudocmdgroup',
            'class': 'field'
        }).appendTo(span);

        field = that.get_field('memberdenycmd_sudocmdgroup');
        field.create(table_span);

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

    /*initialization*/
    setup_fields();

    return that;
};


IPA.sudo.rule_details_runas_section = function(spec) {

    spec = spec || {};

    var that = IPA.details_section(spec);

    function add_extra_fields(){
        that.add_field(
            IPA.radio_widget({
                name: 'ipasudorunasusercategory',
                options:[
                    {
                        value:'all',
                        label:IPA.messages.objects.sudorule.anyone},
                    {
                        value:'',
                        label:IPA.messages.objects.sudorule.specified_users
                    }
                ]
            }));

        that.add_field(IPA.sudorule_association_table_widget({
            id: that.entity.name+'-runasruser_user',
            name: 'ipasudorunas_user',
            entity: that.entity,
            add_method: 'add_runasuser',
            remove_method: 'remove_runasuser',
            add_title: IPA.messages.association.add.ipasudorunas,
            remove_title: IPA.messages.association.remove.ipasudorunas
        }));
        that.add_field(IPA.sudorule_association_table_widget({
            id: that.entity.name+'-runasuser_group',
            name: 'ipasudorunas_group',
            entity: that.entity,
            add_method: 'add_runasuser',
            remove_method: 'remove_runasuser',
            add_title: IPA.messages.association.add.ipasudorunas,
            remove_title: IPA.messages.association.remove.ipasudorunas
        }));

        that.add_field(
            IPA.radio_widget({
                name: 'ipasudorunasgroupcategory',
                options:[
                    {
                        value:'all',
                        label:IPA.messages.objects.sudorule.any_group
                    },
                    {
                        value:'',
                        label:IPA.messages.objects.sudorule.specified_groups
                    }
                ]
            }));

        that.add_field(IPA.sudorule_association_table_widget({
            id: that.entity.name+'-runasgroup_group',
            name: 'ipasudorunasgroup_group',
            entity: that.entity,
            add_method: 'add_runasgroup',
            remove_method: 'remove_runasgroup',
            add_title: IPA.messages.association.add.ipasudorunasgroup,
            remove_title: IPA.messages.association.remove.ipasudorunasgroup
        }));
    }

    that.create = function(container) {
        that.container = container;

        var field = that.get_field('ipasudorunasusercategory');
        var param_info = IPA.get_entity_param(
            that.entity.name, 'ipasudorunasusercategory');

        var span = $('<span/>', {
            name: 'ipasudorunasusercategory',
            title: param_info.doc,
            'class': 'field'
        }).appendTo(container);
        span.append(param_info.doc+": ");
        field.create(span);
        span.append('<br/>');

        param_info = IPA.get_entity_param(that.entity.name, 'ipasudorunas_user');

        var table_span = $('<span/>', {
            name: 'ipasudorunas_user',
            title: param_info ? param_info.doc : 'ipasudorunas_user',
            'class': 'field'
        }).appendTo(span);

        field = that.get_field('ipasudorunas_user');
        field.create(table_span);

        param_info = IPA.get_entity_param(that.entity.name, 'ipasudorunas_group');

        table_span = $('<span/>', {
            name: 'ipasudorunas_group',
            title: param_info ? param_info.doc : 'ipasudorunas_group',
            'class': 'field'
        }).appendTo(span);

        field = that.get_field('ipasudorunas_group');
        field.create(table_span);

        field = that.get_field('ipasudorunasgroupcategory');
        param_info = IPA.get_entity_param(
            that.entity.name, 'ipasudorunasgroupcategory');

        span = $('<span/>', {
            name: 'ipasudorunasgroupcategory',
            title: param_info.doc,
            'class': 'field'
        }).appendTo(container);

        span.append(param_info.doc+": ");
        field.create(span);
        span.append('<br/>');

        param_info = IPA.get_entity_param(
            that.entity.name, 'ipasudorunasgroup_group');

        table_span = $('<span/>', {
            name: 'ipasudorunasgroup_group',
            title: param_info ? param_info.doc : 'ipasudorunasgroup_group',
            'class': 'field'
        }).appendTo(span);

        field = that.get_field('ipasudorunasgroup_group');
        field.create(table_span);

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

    /*initialization*/
    add_extra_fields();

    return that;
};


IPA.sudorule_association_table_widget = function(spec) {

    spec = spec || {};

    var that = IPA.association_table_widget(spec);

    that.external = spec.external;

    that.create_add_dialog = function() {

        var entity_label = that.entity.metadata.label_singular;
        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        var other_entity_label = IPA.metadata.objects[that.other_entity].label;

        var title = that.add_title;
        title = title.replace('${entity}', entity_label);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', other_entity_label);

        return IPA.sudo.rule_association_adder_dialog({
            title: title,
            pkey: pkey,
            other_entity: that.other_entity,
            attribute_member: that.attribute_member,
            entity: that.entity,
            external: that.external,
            exclude: that.values
        });
    };

    that.load = function(result) {
        that.values = result[that.name] || [];
        if (that.external) {
            var external_values = result[that.external] || [];
            $.merge(that.values, external_values);
        }
        that.reset();
        that.unselect_all();
    };

    return that;
};


IPA.sudo.rule_association_adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.association_adder_dialog(spec);

    that.external = spec.external;

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
