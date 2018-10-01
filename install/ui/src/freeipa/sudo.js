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

define([
        './ipa',
        './jquery',
        './phases',
        './reg',
        './rpc',
        './text',
        './association',
        './entity',
        './details',
        './rule',
        './search'
       ],
            function(IPA, $, phases, reg, rpc, text) {

var exp = IPA.sudo = {
    //priority of commands in details facet
    remove_method_priority: IPA.config.default_priority - 1
};

var make_rule_spec = function() {
var spec = {
    name: 'sudorule',
    facets: [
        {
            $type: 'search',
            row_enabled_attribute: 'ipaenabledflag',
            columns: [
                'cn',
                {
                    name: 'ipaenabledflag',
                    label: '@i18n:status.label',
                    formatter: 'boolean_status'
                },
                'description'
            ],
            actions: [
                'batch_disable',
                'batch_enable'
            ],
            control_buttons: [
                {
                    name: 'disable',
                    label: '@i18n:buttons.disable',
                    icon: 'fa-minus'
                },
                {
                    name: 'enable',
                    label: '@i18n:buttons.enable',
                    icon: 'fa-check'
                }
            ]
        },
        {
            $type: 'details',
            $factory: IPA.sudorule_details_facet,
            command_mode: 'info',
            actions: [
                'select',
                'enable',
                'disable',
                'delete'
            ],
            header_actions: ['enable', 'disable', 'delete'],
            state: {
                evaluators: [
                    {
                        $factory: IPA.enable_state_evaluator,
                        field: 'ipaenabledflag'
                    }
                ],
                summary_conditions: [
                    IPA.enabled_summary_cond,
                    IPA.disabled_summary_cond
                ]
            }
        }
    ],
    adder_dialog: {
        title: '@i18n:objects.sudorule.add',
        fields: [ 'cn' ]
    },
    deleter_dialog: {
        title: '@i18n:objects.sudorule.remove'
    }
};

    add_sudorule_details_facet_widgets(spec.facets[1]);
    return spec;
};


var make_cmd_spec = function() {
return {
    name: 'sudocmd',
    facets: [
        {
            $type: 'search',
            columns: [
                'sudocmd',
                'description'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'general',
                    label: '@i18n:details.general',
                    fields: [
                        'sudocmd',
                        {
                            $type: 'textarea',
                            name: 'description'
                        }
                    ]
                }
            ]
        },
        {
            $type: 'association',
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
            ],
            remove_title: '@i18n:objects.sudocmd.remove_from_sudocmdgroups'
        }
    ],
    standard_association_facets: true,
    adder_dialog: {
        title: '@i18n:objects.sudocmd.add',
        fields: [
            'sudocmd',
            {
                $type: 'textarea',
                name: 'description'
            }
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.sudocmd.remove'
    }
};};


var make_cmd_group_spec = function() {
return {
    name: 'sudocmdgroup',
    facets: [
        {
            $type: 'search',
            columns: [
                'cn',
                'description'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'general',
                    label: '@i18n:details.general',
                    fields: [
                        'cn',
                        {
                            $type: 'textarea',
                            name: 'description'
                        }
                    ]
                }
            ]
        },
        {
            $type: 'association',
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
            ],
            remove_title: '@i18n:objects.sudocmdgroup.remove_sudocmds'
        }
    ],
    standard_association_facets: true,
    adder_dialog: {
        title: '@i18n:objects.sudocmdgroup.add',
        fields: [
            'cn',
            {
                $type: 'textarea',
                name: 'description'
            }
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.sudocmdgroup.remove'
    }
};};

/**
 * @ignore
 * @param {Object} facet spec
 */
var add_sudorule_details_facet_widgets = function (spec) {

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
            name: 'sudoorder',
            widget: 'general.sudoorder'
        },
        {
            $type: 'textarea',
            name: 'description',
            widget: 'general.description'
        }
    ];

    spec.widgets = [
        {
            $type: 'details_section',
            name: 'general',
            label: '@i18n:details.general',
            widgets: [
                {
                    name: 'cn'
                },
                'sudoorder',
                {
                    $type: 'textarea',
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
            $factory: IPA.sudo.options_section,
            name: 'options',
            label: '@i18n:objects.sudorule.options'
        }
    );

    //
    // Users
    //

    spec.fields.push(
        {
            $type: 'radio',
            name: 'usercategory',
            widget: 'user.rule.usercategory'
        },
        {
            $type: 'rule_association_table',
            name: 'memberuser_user',
            widget: 'user.rule.memberuser_user',
            external: 'externaluser',
            priority: IPA.sudo.remove_method_priority
        },
        {
            $type: 'rule_association_table',
            name: 'memberuser_group',
            widget: 'user.rule.memberuser_group',
            priority: IPA.sudo.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            $factory: IPA.section,
            name: 'user',
            label: '@i18n:objects.sudorule.user',
            widgets: [
                {
                    $factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'usercategory',
                    options: [
                        {
                            value: 'all',
                            label: '@i18n:objects.sudorule.anyone'
                        },
                        {
                            value: '',
                            label: '@i18n:objects.sudorule.specified_users'
                        }
                    ],
                    tables: [
                        { name: 'memberuser_user' },
                        { name: 'memberuser_group' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: 'sudorule-memberuser_user',
                            name: 'memberuser_user',
                            add_method: 'add_user',
                            remove_method: 'remove_user',
                            external: 'externaluser',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:objects.sudorule.remove_users'
                        },
                        {
                            $type: 'rule_association_table',
                            id: 'sudorule-memberuser_group',
                            name: 'memberuser_group',
                            add_method: 'add_user',
                            remove_method: 'remove_user',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:objects.sudorule.remove_groups'
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
            $type: 'radio',
            name: 'hostcategory',
            widget: 'host.rule.hostcategory'
        },
        {
            $type: 'rule_association_table',
            name: 'memberhost_host',
            widget: 'host.rule.memberhost_host',
            external: 'externalhost',
            priority: IPA.sudo.remove_method_priority
        },
        {
            $type: 'rule_association_table',
            name: 'memberhost_hostgroup',
            widget: 'host.rule.memberhost_hostgroup',
            priority: IPA.sudo.remove_method_priority
        }
    );

    spec.widgets.push(
    {
            $factory: IPA.section,
            name: 'host',
            label: '@i18n:objects.sudorule.host',
            widgets: [
                {
                    $factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'hostcategory',
                    options: [
                        {
                            'value': 'all',
                            label: '@i18n:objects.sudorule.any_host'
                        },
                        {
                            'value': '',
                            label: '@i18n:objects.sudorule.specified_hosts'
                        }
                    ],
                    tables: [
                        { 'name': 'memberhost_host' },
                        { 'name': 'memberhost_hostgroup' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: 'sudorule-memberuser_user',
                            name: 'memberhost_host',
                            add_method: 'add_host',
                            remove_method: 'remove_host',
                            external: 'externalhost',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:objects.sudorule.remove_hosts'
                        },
                        {
                            $type: 'rule_association_table',
                            id: 'sudorule-memberuser_group',
                            name: 'memberhost_hostgroup',
                            add_method: 'add_host',
                            remove_method: 'remove_host',
                            add_title: '@i18n:association.add.member',
                            remove_title: '@i18n:objects.sudorule.remove_hostgroups'
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
            $type: 'radio',
            name: 'cmdcategory',
            widget: 'command.rule.cmdcategory'
        },
        {
            $type: 'rule_association_table',
            name: 'memberallowcmd_sudocmd',
            widget: 'command.rule.memberallowcmd_sudocmd',
            priority: IPA.sudo.remove_method_priority
        },
        {
            $type: 'rule_association_table',
            name: 'memberallowcmd_sudocmdgroup',
            widget: 'command.rule.memberallowcmd_sudocmdgroup',
            priority: IPA.sudo.remove_method_priority
        },
        {
            $type: 'rule_association_table',
            name: 'memberdenycmd_sudocmd',
            widget: 'command.rule.memberdenycmd_sudocmd',
            priority: IPA.sudo.remove_method_priority
        },
        {
            $type: 'rule_association_table',
            name: 'memberdenycmd_sudocmdgroup',
            widget: 'command.rule.memberdenycmd_sudocmdgroup',
            priority: IPA.sudo.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            $factory: IPA.section,
            name: 'command',
            label: '@i18n:objects.sudorule.command',
            widgets: [
                {
                    $factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'cmdcategory',
                    options: [
                        {
                            value: 'all',
                            label: '@i18n:objects.sudorule.any_command'
                        },
                        {
                            value: '',
                            label: '@i18n:objects.sudorule.specified_commands'
                        }
                    ],
                    tables: [
                        { name: 'memberallowcmd_sudocmd' },
                        { name: 'memberallowcmd_sudocmdgroup' },
                        { name: 'memberdenycmd_sudocmd' },
                        { name: 'memberdenycmd_sudocmdgroup' }
                    ],
                    widgets: [
                        {
                            $factory: IPA.header_widget,
                            name: 'allow_header',
                            text: '@i18n:objects.sudorule.allow',
                            description: '@i18n:objects.sudorule.allow'
                        },
                        {
                            $type: 'rule_association_table',
                            id: 'sudorule-memberallowcmd_sudocmd',
                            name: 'memberallowcmd_sudocmd',
                            add_method: 'add_allow_command',
                            remove_method: 'remove_allow_command',
                            add_title: '@i18n:association.add.memberallowcmd',
                            remove_title: '@i18n:objects.sudorule.remove_allow_cmds'
                        },
                        {
                            $type: 'rule_association_table',
                            id: 'sudorule-memberallowcmd_sudocmdgroup',
                            name: 'memberallowcmd_sudocmdgroup',
                            add_method: 'add_allow_command',
                            remove_method: 'remove_allow_command',
                            add_title: '@i18n:association.add.memberallowcmd',
                            remove_title: '@i18n:objects.sudorule.remove_allow_cmdgroups'
                        },
                        {
                            $factory: IPA.header_widget,
                            name: 'deny_header',
                            text: '@i18n:objects.sudorule.deny',
                            description: '@i18n:objects.sudorule.deny'
                        },
                        {
                            $type: 'rule_association_table',
                            id: 'sudorule-memberdenycmd_sudocmd',
                            name: 'memberdenycmd_sudocmd',
                            add_method: 'add_deny_command',
                            remove_method: 'remove_deny_command',
                            add_title: '@i18n:association.add.memberdenycmd',
                            remove_title: '@i18n:objects.sudorule.remove_deny_cmds'
                        },
                        {
                            $type: 'rule_association_table',
                            id: 'sudorule-memberdenycmd_sudocmdgroup',
                            name: 'memberdenycmd_sudocmdgroup',
                            add_method: 'add_deny_command',
                            remove_method: 'remove_deny_command',
                            add_title: '@i18n:association.add.memberdenycmd',
                            remove_title: '@i18n:objects.sudorule.remove_deny_cmdgroups'
                        }
                    ]
                }
            ]
        }
    );

    //
    // As whom
    //

    spec.fields.push(
        {
            $type: 'radio',
            name: 'ipasudorunasusercategory',
            widget: 'runas.runas_users.ipasudorunasusercategory'
        },
        {
            $type: 'rule_association_table',
            name: 'ipasudorunas_user',
            widget: 'runas.runas_users.ipasudorunas_user',
            external: 'ipasudorunasextuser',
            priority: IPA.sudo.remove_method_priority
        },
        {
            $type: 'rule_association_table',
            name: 'ipasudorunas_group',
            widget: 'runas.runas_users.ipasudorunas_group',
            priority: IPA.sudo.remove_method_priority
        },
        {
            $type: 'radio',
            name: 'ipasudorunasgroupcategory',
            widget: 'runas.runas_groups.ipasudorunasgroupcategory'
        },
        {
            $type: 'rule_association_table',
            name: 'ipasudorunasgroup_group',
            widget: 'runas.runas_groups.ipasudorunasgroup_group',
            external: 'ipasudorunasextgroup',
            priority: IPA.sudo.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            $factory: IPA.section,
            name: 'runas',
            label: '@i18n:objects.sudorule.runas',
            widgets: [
                {
                    $factory: IPA.rule_details_widget,
                    name: 'runas_users',
                    radio_name: 'ipasudorunasusercategory',
                    options: [
                        { value: 'all', label: '@i18n:objects.sudorule.anyone' },
                        { value: '', label: '@i18n:objects.sudorule.specified_users' }
                    ],
                    tables: [
                        { name: 'ipasudorunas_user' },
                        { name: 'ipasudorunas_group' }
                    ],
                    widgets: [
                        {
                            $type: 'rule_association_table',
                            id: 'sudorule-runasruser_user',
                            name: 'ipasudorunas_user',
                            external: 'ipasudorunasextuser',
                            add_method: 'add_runasuser',
                            remove_method: 'remove_runasuser',
                            add_title: '@i18n:association.add.ipasudorunas',
                            remove_title: '@i18n:objects.sudorule.remove_runas_users'
                        },
                        {
                            $type: 'rule_association_table',
                            id: 'sudorule-runasuser_group',
                            name: 'ipasudorunas_group',
                            add_method: 'add_runasuser',
                            remove_method: 'remove_runasuser',
                            add_title: '@i18n:association.add.ipasudorunas',
                            remove_title: '@i18n:objects.sudorule.remove_runas_usergroups'
                        }
                    ]
                },
                {
                    $factory: IPA.rule_details_widget,
                    name: 'runas_groups',
                    radio_name: 'ipasudorunasgroupcategory',
                    options: [
                        { value: 'all', label: '@i18n:objects.sudorule.any_group' },
                        { value: '', label: '@i18n:objects.sudorule.specified_groups' }
                    ],
                    tables: [
                        { name: 'ipasudorunasgroup_group' }
                    ],
                    widgets: [{
                        $type: 'rule_association_table',
                        id: 'sudorule-runasgroup_group',
                        name: 'ipasudorunasgroup_group',
                        external: 'ipasudorunasextgroup',
                        add_method: 'add_runasgroup',
                        remove_method: 'remove_runasgroup',
                        add_title: '@i18n:association.add.ipasudorunasgroup',
                        remove_title: '@i18n:objects.sudorule.remove_runas_groups'
                    }]
                }
            ]
        }
    );
};

IPA.sudorule_details_facet = function(spec) {

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

    var that = IPA.section(spec);

    function setup_table(){
        that.table = IPA.table_widget({
            name: 'ipasudoopt',
            show_buttons: true
        });

        that.widgets.add_widget(that.table);

        that.table.create_column({
            name: 'ipasudoopt',
            label: '@mc-opt:sudorule_add_option:ipasudoopt:label',
            entity: that.entity,
            primary_key: true
        });

        that.table.create = function(container) {

            that.table.table_create(container);

            that.remove_button = IPA.button_widget({
                name: 'remove',
                label: '@i18n:buttons.remove',
                icon: 'fa-trash-o',
                enabled: false,
                button_class: 'btn btn-link',
                click: that.remove_handler
            });
            that.remove_button.create(that.table.buttons);

            that.add_button = IPA.button_widget({
                name: 'add',
                label: '@i18n:buttons.add',
                icon: 'fa-plus',
                button_class: 'btn btn-link',
                click: that.add_handler
            });
            that.add_button.create(that.table.buttons);
        };

        that.table.select_changed = function() {

            var values = that.table.get_selected_values();

            if (that.remove_button) {
                that.remove_button.set_enabled(values.length > 0);
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
            dialog.open();

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
            dialog.open();

        } else {
            that.show_remove_dialog();
        }
    };

    that.show_add_dialog = function() {

        var label = IPA.get_command_option('sudorule_add_option', 'ipasudoopt').label;

        var dialog = IPA.dialog({
            name: 'option-adder-dialog',
            title: text.get('@i18n:objects.sudorule.add_option'),
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
            label: '@i18n:buttons.add',
            click: function() {
                var ipasudoopt = dialog.fields.get_field('ipasudoopt');
                var value = ipasudoopt.save()[0];

                var pkey = that.facet.get_pkey();

                var command = rpc.command({
                    entity: 'sudorule',
                    method: 'add_option',
                    args: [pkey],
                    options: {
                        ipasudoopt: value
                    },
                    on_success: function(data) {
                        that.table.load(data.result.result);
                        dialog.close();
                        IPA.notify_success('@i18n:objects.sudorule.option_added');
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
            label: '@i18n:buttons.cancel',
            click: function() {
                dialog.close();
            }
        });

        dialog.open();
    };

    that.show_remove_dialog = function() {

        var values = that.table.get_selected_values();

        if (!values.length) {
            var message = text.get('@i18n:dialogs.remove_empty');
            window.alert(message);
            return;
        }

        var pkey = that.facet.get_pkey();

        var title = text.get('@i18n:objects.sudooptions.remove');

        var dialog = IPA.deleter_dialog({
            title: title,
            values: values
        });

        dialog.execute = function() {

            var batch = rpc.batch_command({
                on_success: function(data) {
                    //last successful result of batch results contains valid data
                    var result;
                    var succeeded = 0;

                    for (var i = data.result.results.length - 1; i > -1; i--) {
                        var error = data.result.results[i].error;
                        if (!result) result = data.result.results[i].result;
                        if (!error) succeeded++;
                    }

                    if (result) {
                        that.table.load(result);
                    } else {
                        that.reload();
                    }

                    var msg = text.get('@i18n:objects.sudorule.option_removed').replace('${count}', succeeded);
                    IPA.notify_success(msg);
                },
                on_error: function(data) {
                    that.reload();
                }
            });

            for (var i=0; i<values.length; i++) {
                var command = rpc.command({
                    entity: 'sudorule',
                    method: 'remove_option',
                    args: [pkey]
                });

                command.set_option('ipasudoopt', values[i]);

                batch.add_command(command);
            }

            batch.execute();
        };

        dialog.open();
    };

    that.reload = function() {
        var command = rpc.command({
            entity: that.facet.entity.name,
            method: 'show',
            args: that.facet.get_pkeys(),
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

exp.rule_spec = make_rule_spec();
exp.cmd_spec = make_cmd_spec();
exp.cmdgroup_spec = make_cmd_group_spec();
exp.register = function() {
    var e = reg.entity;

    e.register({type: 'sudorule', spec: exp.rule_spec});
    e.register({type: 'sudocmd', spec: exp.cmd_spec});
    e.register({type: 'sudocmdgroup', spec: exp.cmdgroup_spec});
};
phases.on('registration', exp.register);

return exp;
});
