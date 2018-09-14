/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
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
        './menu',
        './phases',
        './reg',
        './details',
        './search',
        './entity',
        './dialogs/password'
       ],
            function(IPA, $, menu, phases, reg) {

/**
 * Radius module
 * @class
 * @singleton
 */
var radiusproxy = IPA.radiusproxy = {};

var make_spec = function() {
return {
    name: 'radiusproxy',
    enable_test: function() {
        return true;
    },
    facets: [
        {
            $type: 'search',
            columns: [
                'cn',
                'ipatokenradiusserver',
                'ipatokenusermapattribute',
                'description'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'details',
                    label: '@i18n:objects.radiusproxy.details',
                    fields: [
                        'cn',
                        {
                            $type: 'textarea',
                            name: 'description'
                        },
                        'ipatokenradiusserver', // TODO: add validation
                        'ipatokenusermapattribute', // TODO: add validation
                        'ipatokenradiustimeout',
                        'ipatokenradiusretries'
                    ]
                }
            ],
            actions: [
                {
                    $type: 'password',
                    dialog: {
                        password_name: 'ipatokenradiussecret'
                    }
                }
            ],
            header_actions: ['password']
        }
    ],
    adder_dialog: {
        fields: [
            'cn',
            'ipatokenradiusserver',
            {
                $type: 'password',
                name: 'ipatokenradiussecret'
            },
            {
                $type: 'password',
                name: 'secret_verify',
                label: '@i18n:password.verify_password',
                flags: ['no_command'],
                required: true,
                validators: [{
                    $type: 'same_password',
                    other_field: 'ipatokenradiussecret'
                }]
            },
            'ipatokenusermapattribute'
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.radiusproxy.remove',
    },
};};

/**
 * Radius specification object
 */
radiusproxy.spec = make_spec();

/**
 * Register radiusproxy entity
 */
radiusproxy.register = function() {
    var e = reg.entity;
    e.register({type: 'radiusproxy', spec: radiusproxy.spec});
};

phases.on('registration', radiusproxy.register);

return radiusproxy;
});
