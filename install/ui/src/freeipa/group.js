/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Endi Dewata <edewata@redhat.com>
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

define([
        'dojo/on',
        './ipa',
        './jquery',
        './phases',
        './reg',
        './details',
        './search',
        './association',
        './entity'],
    function(on, IPA, $, phases, reg) {

var exp = IPA.group = {
    search_facet_group: {
        name: 'search',
        label: '@i18n:objects.group.group_categories',
        facets: {
            search_group: 'group_search',
            search_hostgroup: 'hostgroup_search',
            search_netgroup: 'netgroup_search'
        }
    }
};

var make_spec = function() {
return {
    name: 'group',
    facets: [
        {
            $type: 'search',
            tab_label: '@i18n:objects.group.user_groups',
            facet_groups: [IPA.group.search_facet_group],
            tabs_in_sidebar: true,
            disable_facet_tabs: false,
            columns: [
                'cn',
                'gidnumber',
                'description'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'details',
                    fields: [
                        'cn',
                        {
                            $type: 'textarea',
                            name: 'description'
                        },
                        {
                            $type: 'value_map',
                            name: 'external',
                            param: 'objectclass',
                            label: '@i18n:objects.group.type',
                            default_label: '@i18n:objects.group.nonposix',
                            value_map: {
                                ipaexternalgroup: '@i18n:objects.group.external',
                                posixgroup: '@i18n:objects.group.posix'
                            }
                        },
                        'gidnumber',
                        {
                            $type: 'link',
                            name: 'pwpolicy',
                            param: 'cn',
                            label: '@mo:pwpolicy.label_singular',
                            other_entity: 'pwpolicy',
                            require_link: true
                        }
                    ]
                }
            ],
            actions: [
                'select',
                'make_posix',
                'make_external',
                'delete'
            ],
            header_actions: ['make_posix', 'make_external', 'delete'],
            state: {
                evaluators: [
                    IPA.object_class_evaluator
                ]
            }
        },
        {
            $type: 'association',
            name: 'member_user',
            columns:[
                'uid',
                'uidnumber',
                'mail',
                'telephonenumber',
                'title'
            ],
            adder_columns:[
                {
                    name: 'uid',
                    primary_key: true
                }
            ],
            remove_title: '@i18n:objects.group.remove_users'
        },
        {
            $type: 'association',
            name: 'member_group',
            remove_title: '@i18n:objects.group.remove_groups'
        },
        {
            $type: 'association',
            name: 'member_service',
            remove_title: '@i18n:objects.group.remove_services'
        },
        {
            $type: 'attribute',
            name: 'member_external',
            attribute: 'ipaexternalmember',
            tab_label: 'External',
            facet_group: 'member',
            columns: [
                {
                    name: 'ipaexternalmember',
                    label: '@mc-opt:group_add_member:ipaexternalmember:label'
                }
            ]
        },
        {
            $type: 'association',
            name: 'memberof_group',
            associator: IPA.serial_associator,
            remove_title: '@i18n:objects.group.remove_from_groups'
        },
        {
            $type: 'association',
            name: 'memberof_netgroup',
            associator: IPA.serial_associator,
            remove_title: '@i18n:objects.group.remove_from_netgroups'
        },
        {
            $type: 'association',
            name: 'memberof_role',
            associator: IPA.serial_associator,
            remove_title: '@i18n:objects.group.remove_from_roles'
        },
        {
            $type: 'association',
            name: 'memberof_hbacrule',
            associator: IPA.serial_associator,
            add_method: 'add_user',
            remove_method: 'remove_user',
            remove_title: '@i18n:objects.group.remove_from_hbac'
        },
        {
            $type: 'association',
            name: 'memberof_sudorule',
            associator: IPA.serial_associator,
            add_method: 'add_user',
            remove_method: 'remove_user',
            remove_title: '@i18n:objects.group.remove_from_sudo'
        }
    ],
    standard_association_facets: true,
    adder_dialog: {
        $factory: IPA.group_adder_dialog,
        fields: [
            'cn',
            {
                $type: 'textarea',
                name: 'description'
            },
            {
                $type: 'radio',
                name: 'type',
                label: '@i18n:objects.group.type',
                flags: ['no_command'],
                default_value: 'posix',
                options: [
                    {
                        value: 'nonposix',
                        label: '@i18n:objects.group.nonposix'
                    },
                    {
                        value: 'external',
                        label: '@i18n:objects.group.external'
                    },
                    {
                        value: 'posix',
                        label: '@i18n:objects.group.posix'
                    }
                ]
            },
            'gidnumber'
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.group.remove'
    }
};};

IPA.group_adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.entity_adder_dialog(spec);

    var init = function() {

        var type_field = that.fields.get_field('type');
        on(type_field, 'value-change', that.on_type_change);
    };

    that.on_type_change = function() {

        var type_field = that.fields.get_field('type');
        var gid_field = that.fields.get_field('gidnumber');
        var posix = type_field.get_value()[0] === 'posix';

        if (!posix) {
            gid_field.reset();
        }

        gid_field.set_enabled(posix);
    };

    that.create_add_command = function(record) {

        var command = that.entity_adder_dialog_create_add_command(record);

        var type_field = that.fields.get_field('type');
        var type = type_field.save()[0];

        if (type === 'nonposix' || type === 'external') {
            command.set_option(type, true);
        }

        return command;
    };

    init();

    return that;
};

IPA.group.make_posix_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'make_posix';
    spec.method = spec.method || 'mod';
    spec.label = spec.label || '@i18n:objects.group.make_posix';
    spec.needs_confirm = spec.needs_confirm !== undefined ? spec.needs_confirm : true;
    spec.disable_cond = spec.disable_cond || ['oc_posixgroup', 'oc_ipaexternalgroup'];
    spec.options = spec.options || {
        posix: true
    };

    var that = IPA.object_action(spec);

    return that;
};

IPA.group.make_external_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'make_external';
    spec.method = spec.method || 'mod';
    spec.label = spec.label || '@i18n:objects.group.make_external';
    spec.needs_confirm = spec.needs_confirm !== undefined ? spec.needs_confirm : true;
    spec.disable_cond = spec.disable_cond || ['oc_posixgroup','oc_ipaexternalgroup'];
    spec.options = spec.options || {
        external: true
    };

    var that = IPA.object_action(spec);

    return that;
};

exp.entity_spec = make_spec();
exp.register = function() {
    var e = reg.entity;
    var a = reg.action;

    e.register({ type: 'group', spec: exp.entity_spec });

    a.register('make_posix', exp.make_posix_action);
    a.register('make_external', exp.make_external_action);
};

phases.on('registration', exp.register);

return exp;
});
