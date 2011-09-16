/*jsl:import ipa.js */

/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.hbac = {
    //priority of commands in details facet
    remove_method_priority: IPA.config.default_priority - 1,
    enable_priority: IPA.config.default_priority + 1
};

IPA.hbac.rule_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.search_facet({
            search_all: true,
            columns: [
                'cn',
                'ipaenabledflag',
                'description'
            ]
        }).
        details_facet({
            factory: IPA.hbacrule_details_facet,
            entity: that,
            command_mode: 'info'
        }).
        adder_dialog({
            fields: [ 'cn' ]
        });
    };

    return that;
};

IPA.hbac.service_entity = function(spec) {

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
            name: 'memberof_hbacsvcgroup',
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

IPA.hbac.service_group_entity = function(spec) {

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
            name: 'member_hbacsvc',
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

IPA.hbacrule_details_facet = function(spec) {

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
        },
        {
            type: 'enable',
            name: 'ipaenabledflag',
            priority: IPA.sudo.enable_priority,
            widget: 'general.ipaenabledflag'
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
                },
                {
                    type: 'enable',
                    name: 'ipaenabledflag',
                    options: [
                        { value: 'TRUE', label: IPA.get_message('true') },
                        { value: 'FALSE', label: IPA.get_message('false') }
                    ]
                }
            ]
        }
    ];

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
            priority: IPA.hbac.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'memberuser_group',
            widget: 'user.rule.memberuser_group',
            priority: IPA.hbac.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            factory: IPA.collapsible_section,
            name: 'user',
            label: IPA.messages.objects.hbacrule.user,
            widgets: [
                {
                    factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'usercategory',
                    options: [
                        { value: 'all',
                        label: IPA.messages.objects.hbacrule.anyone },
                        { value: '',
                        label: IPA.messages.objects.hbacrule.specified_users }
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
            priority: IPA.hbac.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'memberhost_hostgroup',
            widget: 'host.rule.memberhost_hostgroup',
            priority: IPA.hbac.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            factory: IPA.collapsible_section,
            name: 'host',
            label: IPA.messages.objects.hbacrule.host,
            widgets: [
                {
                    factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'hostcategory',
                    options: [
                        {
                            'value': 'all',
                            'label': IPA.messages.objects.hbacrule.any_host
                        },
                        {
                            'value': '',
                            'label': IPA.messages.objects.hbacrule.specified_hosts
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
    // Service
    //

    spec.fields.push(
        {
            type: 'radio',
            name: 'servicecategory',
            widget: 'service.rule.servicecategory'
        },
        {
            type: 'rule_association_table',
            name: 'memberservice_hbacsvc',
            widget: 'service.rule.memberservice_hbacsvc',
            priority: IPA.hbac.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'memberservice_hbacsvcgroup',
            widget: 'service.rule.memberservice_hbacsvcgroup',
            priority: IPA.hbac.remove_method_priority
        }
    );

    spec.widgets.push(
    {
            factory: IPA.collapsible_section,
            name: 'service',
            label: IPA.messages.objects.hbacrule.service,
            widgets: [
                {
                    factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'servicecategory',
                    options: [
                        { 'value': 'all', 'label': IPA.messages.objects.hbacrule.any_host },
                        { 'value': '', 'label': IPA.messages.objects.hbacrule.specified_hosts }
                    ],
                    tables: [
                        { 'name': 'memberservice_hbacsvc' },
                        { 'name': 'memberservice_hbacsvcgroup' }
                    ],
                    widgets: [
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_user',
                            name: 'memberservice_hbacsvc',
                            add_method: 'add_service',
                            remove_method: 'remove_service',
                            add_title: IPA.messages.association.add.member,
                            remove_title: IPA.messages.association.remove.member
                        },
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_group',
                            name: 'memberservice_hbacsvcgroup',
                            add_method: 'add_service',
                            remove_method: 'remove_service',
                            add_title: IPA.messages.association.add.member,
                            remove_title: IPA.messages.association.remove.member
                        }
                    ]
                }
            ]
        }
    );

    //
    // Source host
    //

    spec.fields.push(
        {
            type: 'radio',
            name: 'sourcehostcategory',
            widget: 'sourcehost.rule.sourcehostcategory'
        },
        {
            type: 'rule_association_table',
            name: 'sourcehost_host',
            widget: 'sourcehost.rule.sourcehost_host',
            priority: IPA.hbac.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'sourcehost_hostgroup',
            widget: 'sourcehost.rule.sourcehost_hostgroup',
            priority: IPA.hbac.remove_method_priority
        }
    );

    spec.widgets.push(
    {
            factory: IPA.collapsible_section,
            name: 'sourcehost',
            label: IPA.messages.objects.hbacrule.sourcehost,
            widgets: [
                {
                    factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'sourcehostcategory',
                    options: [
                        { 'value': 'all', 'label': IPA.messages.objects.hbacrule.any_host },
                        { 'value': '', 'label': IPA.messages.objects.hbacrule.specified_hosts }
                    ],
                    tables: [
                        { 'name': 'sourcehost_host' },
                        { 'name': 'sourcehost_hostgroup' }
                    ],
                    widgets: [
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_user',
                            name: 'sourcehost_host',
                            add_method: 'add_sourcehost',
                            remove_method: 'remove_sourcehost',
                            add_title: IPA.messages.association.add.sourcehost,
                            remove_title: IPA.messages.association.remove.sourcehost
                        },
                        {
                            type: 'rule_association_table',
                            id: entity_name+'-memberuser_group',
                            name: 'sourcehost_hostgroup',
                            add_method: 'add_sourcehost',
                            remove_method: 'remove_sourcehost',
                            add_title: IPA.messages.association.add.sourcehost,
                            remove_title: IPA.messages.association.remove.sourcehost
                        }
                    ]
                }
            ]
        }
    );

    var that = IPA.details_facet(spec);

    that.on_update_success = function(data, text_status, xhr) {
        that.refresh();
    };

    that.on_update_error = function(xhr, text_status, error_thrown) {
        that.refresh();
    };

    return that;
};

IPA.hbac_deny_warning_dialog = function(container) {
    var dialog = IPA.dialog({
        'title': 'HBAC Deny Rules found'
    });

    var link_path = "config";
    if (IPA.use_static_files){
        link_path = "html";
    }

    dialog.create = function() {
        dialog.container.append(
            "HBAC rules with type deny have been found."+
                "  These rules have been deprecated." +
                "  Please remove them, and restructure the HBAC rules." );
        $('<p/>').append($('<a/>',{
            text: 'Click here for more information',
            href: '../' +link_path +'/hbac-deny-remove.html',
            target: "_blank",
            style: 'target: tab; color: blue; '
        })).appendTo(dialog.container);
    };

    dialog.create_button({
        name: 'edit',
        label: 'Edit HBAC Rules',
        click: function() {
            dialog.close();
            IPA.nav.show_page('hbacrule', 'search');
        }
    });

    dialog.create_button({
        name: 'ignore',
        label: 'Ignore for now',
        click: function() {
            dialog.close();
        }
    });

    dialog.open();
};

IPA.register('hbacrule', IPA.hbac.rule_entity);
IPA.register('hbacsvc', IPA.hbac.service_entity);
IPA.register('hbacsvcgroup', IPA.hbac.service_group_entity);
