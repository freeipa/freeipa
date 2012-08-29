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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.sudo = {
    //priority of commands in details facet
    remove_method_priority: IPA.config.default_priority - 1
};

IPA.sudo.rule_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.search_facet({
            row_enabled_attribute: 'ipaenabledflag',
            columns: [
                'cn',
                {
                    name: 'ipaenabledflag',
                    label: IPA.messages.status.label,
                    formatter: IPA.boolean_status_formatter()
                },
                'description'
            ],
            actions: [
                IPA.batch_disable_action,
                IPA.batch_enable_action
            ],
            control_buttons: [
                {
                    name: 'disable',
                    label: IPA.messages.buttons.disable,
                    icon: 'disabled-icon'
                },
                {
                    name: 'enable',
                    label: IPA.messages.buttons.enable,
                    icon: 'enabled-icon'
                }
            ]
        }).
        details_facet({
            factory: IPA.sudorule_details_facet,
            entity: that,
            command_mode: 'info',
            actions: [
                IPA.select_action,
                IPA.enable_action,
                IPA.disable_action,
                IPA.delete_action
            ],
            header_actions: ['select_action', 'enable', 'disable', 'delete'],
            state: {
                evaluators: [
                    {
                        factory: IPA.enable_state_evaluator,
                        field: 'ipaenabledflag'
                    }
                ],
                summary_conditions: [
                    IPA.enabled_summary_cond(),
                    IPA.disabled_summary_cond()
                ]
            }
        }).
        adder_dialog({
            fields: [ 'cn' ]
        });
    };

    return that;
};

IPA.sudo.command_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.search_facet({
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
                            type: 'textarea',
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
                'cn',
                'description'
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
                    type: 'textarea',
                    name: 'description'
                }
            ]
        });
    };

    return that;
};

IPA.sudo.command_group_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.search_facet({
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
                            type: 'textarea',
                            name: 'description'
                        }
                    ]
                }
            ]
        }).
        association_facet({
            name: 'member_sudocmd',
            columns: [
                'sudocmd',
                'description'
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
                    type: 'textarea',
                    name: 'description'
                }
            ]
        });
    };

    return that;
};

IPA.sudorule_details_facet = function(spec) {

    var entity_name = spec.entity.name;

    //
    // General
    //

    spec.fields = [
        {
            name: 'cn',
            read_only: true,
            widget: 'general.cn'
        },
        {
            type: 'textarea',
            name: 'description',
            widget: 'general.description'
        }
    ];

    spec.widgets = [
        {
            type: 'details_table_section',
            name: 'general',
            label: IPA.messages.details.general,
            widgets: [
                {
                    name: 'cn'
                },
                {
                    type: 'textarea',
                    name: 'description'
                }
            ]
        }
    ];

    //
    // Options
    //

    spec.fields.push(
        {
            name: 'ipasudoopt',
            widget: 'options.ipasudoopt'
        }
    );

    spec.widgets.push(
        {
            factory: IPA.sudo.options_section,
            name: 'options',
            label: IPA.messages.objects.sudorule.options,
            facet: that
        }
    );

    //
    // Users
    //

    spec.fields.push(
        {
            type: 'radio',
            name: 'usercategory',
            widget: 'user.rule.usercategory'
        },
        {
            type: 'rule_association_table',
            name: 'memberuser_user',
            widget: 'user.rule.memberuser_user',
            external: 'externaluser',
            priority: IPA.sudo.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'memberuser_group',
            widget: 'user.rule.memberuser_group',
            priority: IPA.sudo.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            factory: IPA.collapsible_section,
            name: 'user',
            label: IPA.messages.objects.sudorule.user,
            widgets: [
                {
                    factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'usercategory',
                    options: [
                        {
                            value: 'all',
                            label: IPA.messages.objects.sudorule.anyone
                        },
                        {
                            value: '',
                            label: IPA.messages.objects.sudorule.specified_users
                        }
                    ],
                    tables: [
                        { name: 'memberuser_user' },
                        { name: 'memberuser_group' }
                    ],
                    widgets: [
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_user',
                            name: 'memberuser_user',
                            add_method: 'add_user',
                            remove_method: 'remove_user',
                            external: 'externaluser',
                            add_title: IPA.messages.association.add.member,
                            remove_title: IPA.messages.association.remove.member
                        },
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_group',
                            name: 'memberuser_group',
                            add_method: 'add_user',
                            remove_method: 'remove_user',
                            add_title: IPA.messages.association.add.member,
                            remove_title: IPA.messages.association.remove.member
                        }
                    ]
                }
            ]
        }
    );

    //
    // Hosts
    //

    spec.fields.push(
        {
            type: 'radio',
            name: 'hostcategory',
            widget: 'host.rule.hostcategory'
        },
        {
            type: 'rule_association_table',
            name: 'memberhost_host',
            widget: 'host.rule.memberhost_host',
            external: 'externalhost',
            priority: IPA.sudo.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'memberhost_hostgroup',
            widget: 'host.rule.memberhost_hostgroup',
            priority: IPA.sudo.remove_method_priority
        }
    );

    spec.widgets.push(
    {
            factory: IPA.collapsible_section,
            name: 'host',
            label: IPA.messages.objects.sudorule.host,
            widgets: [
                {
                    factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'hostcategory',
                    options: [
                        {
                            'value': 'all',
                            'label': IPA.messages.objects.sudorule.any_host
                        },
                        {
                            'value': '',
                            'label': IPA.messages.objects.sudorule.specified_hosts
                        }
                    ],
                    tables: [
                        { 'name': 'memberhost_host' },
                        { 'name': 'memberhost_hostgroup' }
                    ],
                    widgets: [
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_user',
                            name: 'memberhost_host',
                            add_method: 'add_host',
                            remove_method: 'remove_host',
                            external: 'externalhost',
                            add_title: IPA.messages.association.add.member,
                            remove_title: IPA.messages.association.remove.member
                        },
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_group',
                            name: 'memberhost_hostgroup',
                            add_method: 'add_host',
                            remove_method: 'remove_host',
                            add_title: IPA.messages.association.add.member,
                            remove_title: IPA.messages.association.remove.member
                        }
                    ]
                }
            ]
        }
    );

    //
    // Run Commands
    //

    spec.fields.push(
        {
            type: 'radio',
            name: 'cmdcategory',
            widget: 'command.rule.cmdcategory'
        },
        {
            type: 'rule_association_table',
            name: 'memberallowcmd_sudocmd',
            widget: 'command.rule.memberallowcmd_sudocmd',
            priority: IPA.sudo.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'memberallowcmd_sudocmdgroup',
            widget: 'command.rule.memberallowcmd_sudocmdgroup',
            priority: IPA.sudo.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'memberdenycmd_sudocmd',
            widget: 'command.memberdenycmd_sudocmd',
            priority: IPA.sudo.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'memberdenycmd_sudocmdgroup',
            widget: 'command.memberdenycmd_sudocmdgroup',
            priority: IPA.sudo.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            factory: IPA.collapsible_section,
            name: 'command',
            label: IPA.messages.objects.sudorule.command,
            widgets: [
                {
                    factory: IPA.header_widget,
                    name: 'allow_header',
                    text: IPA.messages.objects.sudorule.allow,
                    description: IPA.messages.objects.sudorule.allow
                },
                {
                    factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'cmdcategory',
                    options: [
                        {
                            value: 'all',
                            label: IPA.messages.objects.sudorule.any_command
                        },
                        {
                            value: '',
                            label: IPA.messages.objects.sudorule.specified_commands
                        }
                    ],
                    tables: [
                        { name: 'memberallowcmd_sudocmd' },
                        { name: 'memberallowcmd_sudocmdgroup' }
                    ],
                    widgets: [
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberallowcmd_sudocmd',
                            name: 'memberallowcmd_sudocmd',
                            add_method: 'add_allow_command',
                            remove_method: 'remove_allow_command',
                            add_title: IPA.messages.association.add.memberallowcmd,
                            remove_title: IPA.messages.association.remove.memberallowcmd
                        },
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberallowcmd_sudocmdgroup',
                            name: 'memberallowcmd_sudocmdgroup',
                            add_method: 'add_allow_command',
                            remove_method: 'remove_allow_command',
                            add_title: IPA.messages.association.add.memberallowcmd,
                            remove_title: IPA.messages.association.remove.memberallowcmd
                        }
                    ]
                },
                {
                    factory: IPA.header_widget,
                    name: 'deny_header',
                    text: IPA.messages.objects.sudorule.deny,
                    description: IPA.messages.objects.sudorule.deny
                },
                {
                    type: 'rule_association_table',
                    id: entity_name+'-memberdenycmd_sudocmd',
                    name: 'memberdenycmd_sudocmd',
                    add_method: 'add_deny_command',
                    remove_method: 'remove_deny_command',
                    add_title: IPA.messages.association.add.memberdenycmd,
                    remove_title: IPA.messages.association.remove.memberdenycmd
                },
                {
                    type: 'rule_association_table',
                    id: entity_name+'-memberdenycmd_sudocmdgroup',
                    name: 'memberdenycmd_sudocmdgroup',
                    add_method: 'add_deny_command',
                    remove_method: 'remove_deny_command',
                    add_title: IPA.messages.association.add.memberdenycmd,
                    remove_title: IPA.messages.association.remove.memberdenycmd
                }
            ]
        }
    );

    //
    // As whom
    //

    spec.fields.push(
        {
            type: 'radio',
            name: 'ipasudorunasusercategory',
            widget: 'runas.runas_users.ipasudorunasusercategory'
        },
        {
            type: 'rule_association_table',
            name: 'ipasudorunas_user',
            widget: 'runas.runas_users.ipasudorunas_user',
            external: 'ipasudorunasextuser',
            priority: IPA.sudo.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'ipasudorunas_group',
            widget: 'runas.runas_users.ipasudorunas_group',
            priority: IPA.sudo.remove_method_priority
        },
        {
            type: 'radio',
            name: 'ipasudorunasgroupcategory',
            widget: 'runas.runas_groups.ipasudorunasgroupcategory'
        },
        {
            type: 'rule_association_table',
            name: 'ipasudorunasgroup_group',
            widget: 'runas.runas_groups.ipasudorunasgroup_group',
            external: 'ipasudorunasextgroup',
            priority: IPA.sudo.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            factory: IPA.collapsible_section,
            name: 'runas',
            label: IPA.messages.objects.sudorule.runas,
            widgets: [
                {
                    factory: IPA.rule_details_widget,
                    name: 'runas_users',
                    radio_name: 'ipasudorunasusercategory',
                    options: [
                        { value: 'all', label: IPA.messages.objects.sudorule.anyone },
                        { value: '', label: IPA.messages.objects.sudorule.specified_users }
                    ],
                    tables: [
                        { name: 'ipasudorunas_user' },
                        { name: 'ipasudorunas_group' }
                    ],
                    widgets: [
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-runasruser_user',
                            name: 'ipasudorunas_user',
                            external: 'ipasudorunasextuser',
                            add_method: 'add_runasuser',
                            remove_method: 'remove_runasuser',
                            add_title: IPA.messages.association.add.ipasudorunas,
                            remove_title: IPA.messages.association.remove.ipasudorunas
                        },
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-runasuser_group',
                            name: 'ipasudorunas_group',
                            add_method: 'add_runasuser',
                            remove_method: 'remove_runasuser',
                            add_title: IPA.messages.association.add.ipasudorunas,
                            remove_title: IPA.messages.association.remove.ipasudorunas
                        }
                    ]
                },
                {
                    factory: IPA.rule_details_widget,
                    name: 'runas_groups',
                    radio_name: 'ipasudorunasgroupcategory',
                    options: [
                        { value: 'all', label: IPA.messages.objects.sudorule.any_group },
                        { value: '', label: IPA.messages.objects.sudorule.specified_groups }
                    ],
                    tables: [
                        { name: 'ipasudorunasgroup_group' }
                    ],
                    widgets: [{
                        type: 'rule_association_table',
                        id: entity_name+'-runasgroup_group',
                        name: 'ipasudorunasgroup_group',
                        external: 'ipasudorunasextgroup',
                        add_method: 'add_runasgroup',
                        remove_method: 'remove_runasgroup',
                        add_title: IPA.messages.association.add.ipasudorunasgroup,
                        remove_title: IPA.messages.association.remove.ipasudorunasgroup
                    }]
                }
            ]
        }
    );

    var that = IPA.details_facet(spec);

    var init = function() {
        var options = that.widgets.get_widget('options');
        options.facet = that;
    };

    that.update_on_success = function(data, text_status, xhr) {
        that.refresh();
        that.on_update.notify();
        that.nofify_update_success();
    };

    that.update_on_error = function(xhr, text_status, error_thrown) {
        that.refresh();
    };

    init();

    return that;
};

IPA.sudo.options_section = function(spec) {

    spec = spec || {};

    var that = IPA.collapsible_section(spec);

    function setup_table(){
        that.table = IPA.table_widget({
            name: 'ipasudoopt',
            show_buttons: true
        });

        that.widgets.add_widget(that.table);

        that.table.create_column({
            name: 'ipasudoopt',
            label: IPA.get_command_option('sudorule_add_option', 'ipasudoopt').label,
            entity: that.entity,
            primary_key: true
        });

        that.table.create = function(container) {

            that.table.table_create(container);

            that.remove_button = IPA.action_button({
                name: 'remove',
                label: IPA.messages.buttons.remove,
                icon: 'remove-icon',
                'class': 'action-button-disabled',
                click: function() {
                    if (!that.remove_button.hasClass('action-button-disabled')) {
                        that.remove_handler();
                    }
                    return false;
                }
            }).appendTo(that.table.buttons);

            that.add_button = IPA.action_button({
                name: 'add',
                label: IPA.messages.buttons.add,
                icon: 'add-icon',
                click: function() {
                    if (!that.add_button.hasClass('action-button-disabled')) {
                        that.add_handler();
                    }
                    return false;
                }
            }).appendTo(that.table.buttons);
        };

        that.table.select_changed = function() {

            var values = that.table.get_selected_values();

            if (that.remove_button) {
                if (values.length === 0) {
                    that.remove_button.addClass('action-button-disabled');
                } else {
                    that.remove_button.removeClass('action-button-disabled');
                }
            }
        };

        that.table.update = function(values) {

            that.table.empty();

            for (var i=0; i<values.length; i++) {
                var value = values[i];
                if(!value || value === '') continue;

                var record = {
                    ipasudoopt: values[i]
                };
                that.table.add_record(record);
            }

            that.table.unselect_all();
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

        var label = IPA.get_command_option('sudorule_add_option', 'ipasudoopt').label;

        var title = IPA.messages.dialogs.add_title;
        title = title.replace('${entity}', label);

        var dialog = IPA.dialog({
            name: 'option-adder-dialog',
            title: title,
            sections: [
                {
                    fields: [
                        {
                            name: 'ipasudoopt',
                            label: label
                        }
                    ]
                }
            ]
        });

        dialog.create_button({
            name: 'add',
            label: IPA.messages.buttons.add,
            click: function() {
                var ipasudoopt = dialog.fields.get_field('ipasudoopt');
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
                        that.table.load(data.result.result);
                        dialog.close();
                        IPA.notify_success(IPA.messages.objects.sudorule.option_added);
                    },
                    on_error: function(data) {
                        that.reload();
                        dialog.close();
                    }
                });

                command.execute();
            }
        });

        dialog.create_button({
            name: 'cancel',
            label: IPA.messages.buttons.cancel,
            click: function() {
                dialog.close();
            }
        });

        dialog.open(that.container);
    };

    that.show_remove_dialog = function() {

        var label = IPA.get_command_option('sudorule_add_option', 'ipasudoopt').label;
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
                        that.table.load(result);
                    } else {
                        that.reload();
                    }

                    dialog.close();
                    IPA.notify_success(IPA.messages.objects.sudorule.option_removed);
                },
                on_error: function(data) {
                    that.reload();
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

    that.reload = function() {
        var command = IPA.command({
            entity: that.facet.entity.name,
            method: 'show',
            args: that.facet.get_primary_key(true),
            on_success: function(data) {
                that.table.load(data.result.result);
            }
        });

        command.execute();
    };

    /*initialization*/
    setup_table();

    return that;
};

IPA.register('sudorule', IPA.sudo.rule_entity);
IPA.register('sudocmd', IPA.sudo.command_entity);
IPA.register('sudocmdgroup', IPA.sudo.command_group_entity);
