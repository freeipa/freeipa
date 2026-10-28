// Copyright (C) 2022  FreeIPA Contributors see COPYING for license

define([
        'dojo/on',
        './ipa',
        './jquery',
        './menu',
        './phases',
        './reg',
        './text',
        './details',
        './search',
        './entity',
        './dialogs/password'
       ],
    function(on, IPA, $, menu, phases, reg, text) {

/**
 * IdP module
 * @class
 * @singleton
 */
var idp = IPA.idp = {};

// Templates are hardcoded in idp_add class
// and cannot be retrieved with an API call
// Structure below references template names
// and additional fields per template
idp.templates = [
    { value: 'keycloak',
      label: text.get('@i18n:objects.idp.template_keycloak'),
      fields: ['ipaidporg', 'ipaidpbaseurl']},
    { value: 'google',
      label: text.get('@i18n:objects.idp.template_google'),
      fields: []},
    { value: 'github',
      label: text.get('@i18n:objects.idp.template_github'),
      fields: []},
    { value: 'microsoft',
      label: text.get('@i18n:objects.idp.template_microsoft'),
      fields: ['ipaidporg']},
    { value: 'okta',
      label: text.get('@i18n:objects.idp.template_okta'),
      fields: ['ipaidpbaseurl']}
];


var make_spec = function() {
return {
    name: 'idp',
    enable_test: function() {
        return true;
    },
    facets: [
        {
            $type: 'search',
            columns: [
                'cn',
                'ipaidpclientid',
                'ipaidpscope',
                'description'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'idpclient',
                    label: '@i18n:objects.idp.label_idpclient',
                    fields: [
                        'cn',
                        'ipaidpclientid',
                        {
                            $type: 'password',
                            name: 'ipaidpclientsecret',
                            flags: ['w_if_no_aci']
                        },
                    ]
                },
                {
                    name: 'idp',
                    label: '@i18n:objects.idp.label_idp',
                    fields: [
                        'ipaidpscope',
                        'ipaidpsub',
                        'ipaidpauthendpoint',
                        'ipaidpdevauthendpoint',
                        'ipaidptokenendpoint',
                        'ipaidpuserinfoendpoint',
                        'ipaidpkeysendpoint',
                        'ipaidpissuerurl'
                    ]
                }
            ],
            actions: [
                {
                    $type: 'password',
                    dialog: {
                        password_name: 'ipaidpclientsecret'
                    }
                }
            ],
            header_actions: ['password']
        }
    ],
    adder_dialog: {
        title: '@i18n:objects.idp.add',
        policies: [
            IPA.add_idp_policy
        ],
        sections: [
            {
                name: 'idpclientsetup',
                label: '@i18n:objects.idp.label_idpclient',
                fields: [
                    'cn',
                    'ipaidpclientid',
                    {
                        $type: 'password',
                        name: 'ipaidpclientsecret'
                    },
                    {
                        $type: 'password',
                        name: 'ipaidpclientsecret_verify',
                        label: '@i18n:objects.idp.verify_secret',
                        flags: ['no_command'],
                        required: false,
                        validators: [{
                            $type: 'same_password',
                            other_field: 'ipaidpclientsecret'
                        }]
                    }
                ]
            },
            {
                name: 'idpsetup',
                label: '@i18n:objects.idp.label_idp',
                fields: [
                    {
                        name: 'type',
                        label: 'Provider type',
                        $type: 'radio',
                        flags: ['no_command'],
                        layout: 'vertical',
                        default_value: 'template',
                        options: [
                            {
                                value: 'template',
                                label: 'Pre-defined IdP template',
                            },
                            {
                                value: 'custom',
                                label: 'Custom IdP definition',
                            }
                        ]
                    },
                    {
                        label: '@i18n:idp.provider',
                        name: 'ipaidpprovider',
                        $type: 'select',
                        options: IPA.create_options(idp.templates)
                    },
                    {
                        name: 'ipaidporg',
                        label: '@i18n:objects.idp.ipaidporg',
                        metadata: '@mc-opt:idp_add:ipaidporg'
                    },
                    {
                        name: 'ipaidpbaseurl',
                        label: '@i18n:objects.idp.ipaidpbaseurl',
                        metadata: '@mc-opt:idp_add:ipaidpbaseurl'
                    },
                    'ipaidpscope',
                    'ipaidpsub',
                    'ipaidpauthendpoint',
                    'ipaidpdevauthendpoint',
                    'ipaidptokenendpoint',
                    'ipaidpuserinfoendpoint',
                    'ipaidpkeysendpoint'
                ]
            },
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.idp.remove'
    }
};};

IPA.add_idp_policy = function() {
    // Custom provider fields
    // need to be hidden for a chosen template
    // and show for the custom provider
    var custom_fields = [
        'ipaidpauthendpoint',
        'ipaidpdevauthendpoint',
        'ipaidptokenendpoint',
        'ipaidpuserinfoendpoint',
        'ipaidpkeysendpoint'
    ];

    // Template may require an additional field
    // Make it required and visible in that case
    var template_fields = [
        'ipaidporg',
        'ipaidpbaseurl'
    ];

    var that = IPA.facet_policy();

    that.init = function() {
        // Handle choice of either pre-defined or custom IdP
        var type_f = that.container.fields.get_field('type');
        on(type_f, 'value-change', that.on_type_change);

        // Handle choice of a pre-defined IdP to show/remove additional fields
        var prov_f = that.container.fields.get_field('ipaidpprovider');
        on(prov_f, 'value-change', that.on_prov_change);
    };

    that.on_type_change = function() {
        var type_f = that.container.fields.get_field('type');
        var mode = type_f.get_value()[0];
        var show_custom = true;

        if (mode === 'template') show_custom = false;

        // For custom template we show custom fields
        // and mark all of them required and passed to the RPC
        // If show_custom is false, the opposite happens
        custom_fields.forEach(fname => {
            widget_f = that.container.fields.get_field(fname);
            widget_f.set_required(show_custom);
            widget_f.set_enabled(show_custom);
            widget_f.widget.set_visible(show_custom);
        });

        // For template fields we show them if custom aren't shown
        template_fields.forEach(fname => {
            widget_f = that.container.fields.get_field(fname);
            widget_f.set_enabled(!show_custom);
            widget_f.widget.set_visible(!show_custom);
        });

        widget_f = that.container.fields.get_field('ipaidpprovider');
        widget_f.set_required(!show_custom);
        widget_f.set_enabled(!show_custom);
        widget_f.widget.set_visible(!show_custom);
};

    that.on_prov_change = function() {
        var prov_f = that.container.fields.get_field('ipaidpprovider');
        var value = prov_f.get_value()[0];

        // First, clear template fields from the previous provider choice
        template_fields.forEach(fname => {
            widget_f = that.container.fields.get_field(fname);
            widget_f.widget.set_visible(false);
            widget_f.set_required(false);
            widget_f.set_enabled(false);
        });

        // Second, enable and get required template-specific fields
        idp.templates.forEach(idp_v => {
            if (idp_v['value'] == value) {
                idp_v['fields'].forEach(fname => {
                    widget_f = that.container.fields.get_field(fname);
                    widget_f.set_required(true);
                    widget_f.set_enabled(true);
                    widget_f.widget.set_visible(true);
                });
            }
        }

        )
    };

    return that;
};

/**
 * IdP specification object
 */
idp.spec = make_spec();

/**
 * Register IdP entity
 */
idp.register = function() {
    var e = reg.entity;
    e.register({type: 'idp', spec: idp.spec});
};

phases.on('registration', idp.register);

return idp;
});
