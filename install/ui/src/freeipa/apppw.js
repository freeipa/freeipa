/*  Authors:
 *    Richard Kalinec <rkalinec@gmail.com>
 *
 * Copyright (C) 2020 Red Hat
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
        './menu',
        './phases',
        './reg',
        './details',
        './facet',
        './text',
        './search',
        './entity'],
            function (IPA, phases, reg) {
/**
 * App passwords module
 * @class
 * @singleton
 */
var apppw = IPA.apppw = {
    app_link: 'https://github.com/freeipa/freeipa/blob/master/doc/designs/app-passwords.md',
    app_link_text: '@i18n:objects.apppw.app_link'
};

var make_spec = function () {
    return {
        name: 'apppw',
        enable_test: function () {
            return true;
        },
        facets: [
            {
                $type: 'search',
                $pre_ops: [
                    // redefining 'add' and 'remove' actions to be shown in
                    // self service
                    {
                        $replace: [['actions', [
                            [
                                'add',
                                {
                                    $type: 'add',
                                    name: 'add',
                                    hide_cond: []
                                }
                            ],
                            [
                                'batch_remove',
                                {
                                    $type: 'batch_remove',
                                    name: 'remove',
                                    hide_cond: []
                                }
                            ]
                        ]]]
                    }
                ],
                columns: [
                    'uid',
                    'description',
                    'ou'
                ]
            },
            {
                $type: 'details',
                actions: [
                    'select',
                    'delete'
                ],
                header_actions: ['delete'],
                sections: [
                    {
                        name: 'details',
                        label: '@i18n:objects.apppw.details',
                        fields: [
                            {
                                $type: 'textarea',
                                name: 'uid'
                            },
                            {
                                $type: 'textarea',
                                name: 'description'
                            },
                            {
                                $type: 'textarea',
                                name: 'ou'
                            }
                        ]
                    }
                ]
            }
        ],

        adder_dialog: {
            title: '@i18n:objects.apppw.add',
            $factory: apppw.adder_dialog,
            $pre_ops: [
                apppw.adder_dialog_preop
            ],
            fields: [
                'uid',
                'description',
                'ou'
            ],
            selfservice_fields: [
                'uid',
                'description',
                'ou'
            ]
        },
        deleter_dialog: {
            title: '@i18n:objects.apppw.remove'
        }
    };
};

/**
 * App password adder dialog pre-op.
 *
 * Switches fields to different set when in self-service.
 */
apppw.adder_dialog_preop = function (spec) {

    spec.self_service = IPA.is_selfservice;

    if (IPA.is_selfservice) {
        spec.fields = spec.selfservice_fields;
    }

    return spec;
};

/**
 * App password adder dialog
 *
 * @class
 * @extends IPA.entity_adder_dialog
 */
apppw.adder_dialog = function (spec) {

    var that = IPA.entity_adder_dialog(spec);

    /**
     * Dialog sends different command options when in self-service mode.
     */
    that.self_service = !!spec.self_service;

    /** @inheritDoc */
    that.create_add_command = function (record) {

        var command = that.entity_adder_dialog_create_add_command(record);
        return command;
    };

    return that;
};

/**
 * Entity specification object
 * @member apppw
 */
apppw.spec = make_spec();

/**
 * Register entity
 * @member apppw
 */
apppw.register = function () {
    var e = reg.entity;

    e.register({ type: 'apppw', spec: apppw.spec });
};

phases.on('registration', apppw.register);

return apppw;
});
