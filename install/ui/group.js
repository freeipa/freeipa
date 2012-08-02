/*jsl:import ipa.js */

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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.group = {};

IPA.group.entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.search_facet({
            columns: [
                'cn',
                'gidnumber',
                'description'
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'details',
                    fields: [
                        'cn',
                        {
                            type: 'textarea',
                            name: 'description'
                        },
                        {
                            type: 'value_map',
                            name: 'external',
                            param: 'objectclass',
                            label: IPA.messages.objects.group.type,
                            default_label: IPA.messages.objects.group.normal,
                            value_map: {
                                ipaexternalgroup: IPA.messages.objects.group.external,
                                posixgroup: IPA.messages.objects.group.posix
                            }
                        },
                        'gidnumber'
                    ]
                }
            ],
            actions: [
                IPA.select_action,
                IPA.group.make_posix_action,
                IPA.group.make_external_action,
                IPA.delete_action
            ],
            header_actions: ['select_action', 'make_posix', 'make_external', 'delete'],
            state: {
                evaluators: [
                    IPA.object_class_evaluator
                ]
            }
        }).
        association_facet({
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
                    name: 'cn',
                    width: '100px'
                },
                {
                    name: 'uid',
                    primary_key: true,
                    width: '100px'
                }
            ]
        }).
        association_facet({
            name: 'member_group'
        }).
        attribute_facet({
            name: 'member_external',
            attribute: 'ipaexternalmember',
            tab_label: 'External',
            facet_group: 'member',
            columns: [
                {
                    name: 'ipaexternalmember',
                    label: IPA.get_command_option('group_add_member', 'ipaexternalmember').label
                }
            ]

        }).
        association_facet({
            name: 'memberof_group',
            associator: IPA.serial_associator
        }).
        association_facet({
            name: 'memberof_netgroup',
            associator: IPA.serial_associator
        }).
        association_facet({
            name: 'memberof_role',
            associator: IPA.serial_associator
        }).
        association_facet({
            name: 'memberof_hbacrule',
            associator: IPA.serial_associator,
            add_method: 'add_user',
            remove_method: 'remove_user'
        }).
        association_facet({
            name: 'memberof_sudorule',
            associator: IPA.serial_associator,
            add_method: 'add_user',
            remove_method: 'remove_user'
        }).
        standard_association_facets().
        adder_dialog({
            factory: IPA.group_adder_dialog,
            fields: [
                'cn',
                {
                    type: 'textarea',
                    name: 'description'
                },
                {
                    type: 'radio',
                    name: 'type',
                    label: IPA.messages.objects.group.type,
                    flags: ['no_command'],
                    default_value: 'normal',
                    options: [
                        {
                            value: 'normal',
                            label: IPA.messages.objects.group.normal
                        },
                        {
                            value: 'external',
                            label: IPA.messages.objects.group.external
                        },
                        {
                            value: 'posix',
                            label: IPA.messages.objects.group.posix
                        }
                    ]
                },
                'gidnumber'
            ]
        });
    };

    return that;
};

IPA.group_adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.entity_adder_dialog(spec);

    var init = function() {

        var type_field = that.fields.get_field('type');
        type_field.widget.value_changed.attach(that.on_type_change);
    };

    that.on_type_change = function(value) {

        var gid_field = that.fields.get_field('gidnumber');
        var external_field = that.fields.get_field('external');

        var posix = value[0] === 'posix';

        if (!posix) {
            gid_field.reset();
        }

        gid_field.set_enabled(posix);
    };

    that.create_add_command = function(record) {

        var command = that.entity_adder_dialog_create_add_command(record);

        var type_field = that.fields.get_field('type');
        var type = type_field.save()[0];

        if (type === 'normal') {
            command.set_option('nonposix', true);
        } else if (type === 'external') {
            command.set_option('external', true);
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
    spec.label = spec.label || IPA.messages.objects.group.make_posix;
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
    spec.label = spec.label || IPA.messages.objects.group.make_external;
    spec.disable_cond = spec.disable_cond || ['oc_posixgroup','oc_ipaexternalgroup'];
    spec.options = spec.options || {
        external: true
    };

    var that = IPA.object_action(spec);

    return that;
};

IPA.register('group', IPA.group.entity);
