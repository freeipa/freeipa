/*jsl:import ipa.js */

/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2012 Red Hat
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

IPA.selinux = {
    remove_method_priority: IPA.config.default_priority - 1,
    enable_priority: IPA.config.default_priority + 1
};

IPA.selinux.selinuxusermap_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.search_facet({
            row_enabled_attribute: 'ipaenabledflag',
            search_all_attributes: true,
            columns: [
                'cn',
                'ipaselinuxuser',
                {
                    name: 'ipaenabledflag',
                    label: IPA.messages.status.label,
                    formatter: IPA.boolean_status_formatter()
                },
                'description'
            ]
        }).
        details_facet({
            factory: IPA.selinux_details_facet,
            entity: that,
            command_mode: 'info'
        }).
        adder_dialog({
            fields: [
                'cn',
                'ipaselinuxuser'
            ]
        });
    };

    return that;
};

IPA.selinux_details_facet = function(spec) {

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
            name: 'ipaselinuxuser',
            widget: 'general.ipaselinuxuser'
        },
        {
            type: 'entity_select',
            name: 'seealso',
            widget: 'general.seealso'
        },
        {
            type: 'enable',
            name: 'ipaenabledflag',
            label: IPA.messages.status.label,
            priority: IPA.selinux.enable_priority,
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
                    name: 'ipaselinuxuser',
                    widget: 'general.ipaselinuxuser'
                },
                {
                    type: 'entity_select',
                    name: 'seealso',
                    other_entity: 'hbacrule',
                    other_field: 'cn'
                },
                {
                    type: 'enable',
                    name: 'ipaenabledflag',
                    options: [
                        { value: 'TRUE', label: IPA.messages.status.enabled },
                        { value: 'FALSE', label: IPA.messages.status.disabled }
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
            priority: IPA.selinux.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'memberuser_group',
            widget: 'user.rule.memberuser_group',
            priority: IPA.selinux.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            factory: IPA.collapsible_section,
            name: 'user',
            label: IPA.messages.objects.selinuxusermap.user,
            widgets: [
                {
                    factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'usercategory',
                    options: [
                        { value: 'all',
                        label: IPA.messages.objects.selinuxusermap.anyone },
                        { value: '',
                        label: IPA.messages.objects.selinuxusermap.specified_users }
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
            priority: IPA.selinux.remove_method_priority
        },
        {
            type: 'rule_association_table',
            name: 'memberhost_hostgroup',
            widget: 'host.rule.memberhost_hostgroup',
            priority: IPA.selinux.remove_method_priority
        }
    );

    spec.widgets.push(
        {
            factory: IPA.collapsible_section,
            name: 'host',
            label: IPA.messages.objects.selinuxusermap.host,
            widgets: [
                {
                    factory: IPA.rule_details_widget,
                    name: 'rule',
                    radio_name: 'hostcategory',
                    options: [
                        {
                            'value': 'all',
                            'label': IPA.messages.objects.selinuxusermap.any_host
                        },
                        {
                            'value': '',
                            'label': IPA.messages.objects.selinuxusermap.specified_hosts
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

    var that = IPA.details_facet(spec);

    that.update_on_success = function(data, text_status, xhr) {
        that.refresh();
        that.on_update.notify();
    };

    that.update_on_error = function(xhr, text_status, error_thrown) {
        that.refresh();
    };

    return that;
};

IPA.register('selinuxusermap', IPA.selinux.selinuxusermap_entity);