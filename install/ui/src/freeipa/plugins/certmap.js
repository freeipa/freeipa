//
// Copyright (C) 2017  FreeIPA Contributors see COPYING for license
//


define([
        'dojo/_base/lang',
        'dojo/_base/declare',
        'dojo/Evented',
        'dojo/on',
        '../certificate',
        '../navigation',
        '../field',
        '../ipa',
        '../phases',
        '../reg',
        '../widget',
        '../text',
        '../util',
        // plain imports
        '../search',
        '../entity'],
            function(lang, declare, Evented, on, certificate, navigation,
                 mod_field, IPA, phases, reg, widget_mod, text, util) {
/**
 * Certificate map module
 * @class
 */
var certmap = IPA.certmap = {

    search_facet_group: {
        facets: {
            certmaprule_search: 'certmaprule_search',
            certmapconfig: 'certmapconfig_details',
            certmapmatch: 'certmapmatch_details'
        }
    }
};

var make_certmaprule_spec = function() {
return {
    name: 'certmaprule',
    facets: [
        {
            $type: 'search',
            always_request_members: true,
            details_facet: 'details',
            facet_groups: [certmap.search_facet_group],
            facet_group: 'search',
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
            disable_facet_tabs: true,
            facet_groups: [certmap.search_facet_group],
            facet_group: 'search',
            actions: [
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
                ]
            },
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
                            name: 'ipacertmapmaprule',
                            tooltip: {
                                title: '@mc-opt:certmaprule_add:ipacertmapmaprule:doc'
                            }
                        },
                        {
                            name: 'ipacertmapmatchrule',
                            tooltip: {
                                title: '@mc-opt:certmaprule_add:ipacertmapmatchrule:doc'
                            }
                        },
                        {
                            $type: 'multivalued',
                            name: 'associateddomain',
                            tooltip: {
                                title: '@mc-opt:certmaprule_add:associateddomain:doc'
                            }
                        },
                        {
                            name: 'ipacertmappriority',
                            tooltip: {
                                title: '@mc-opt:certmaprule_add:ipacertmappriority:doc'
                            }
                        }
                    ]
                }
            ]
        }
    ],
    adder_dialog: {
        fields: [
            'cn',
            {
                name: 'ipacertmapmaprule',
                tooltip: {
                    title: '@mc-opt:certmaprule_add:ipacertmapmaprule:doc'
                }
            },
            {
                name: 'ipacertmapmatchrule',
                tooltip: {
                    title: '@mc-opt:certmaprule_add:ipacertmapmatchrule:doc'
                }
            },
            {
                $type: 'multivalued',
                name: 'associateddomain',
                tooltip: {
                    title: '@mc-opt:certmaprule_add:associateddomain:doc'
                }
            },
            {
                name: 'ipacertmappriority',
                tooltip: {
                    title: '@mc-opt:certmaprule_add:ipacertmappriority:doc'
                }
            },
            {
                $type: 'textarea',
                name: 'description'
            }
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.certmap.remove'
    }
};};


var make_certmapconfig_spec = function() {
return {
    name: 'certmapconfig',
    defines_key: false,
    facets: [
        {
            $type: 'details',
            facet_groups: [certmap.search_facet_group],
            facet_group: 'search',
            sections: [
                {
                    name: 'details',
                    fields: [
                        {
                            $type: 'checkbox',
                            name: 'ipacertmappromptusername'
                        }
                    ]
                }
            ]
        }
    ]
};};


/**
 * Multivalued widget which is used for working with user's certmap.
 *
 * @class
 * @extends IPA.custom_command_multivalued_widget
 */
certmap.certmap_multivalued_widget = function (spec) {

    spec = spec || {};
    spec.adder_dialog_spec = spec.adder_dialog_spec || {
        name: 'custom-add-dialog',
        title: '@i18n:objects.certmap.adder_title',
        policies: [
            {
                $factory: IPA.multiple_choice_section_policy,
                widget: 'type'
            }
        ],
        fields: [
            {
                $type: 'multivalued',
                name: 'ipacertmapdata',
                label: '@i18n:objects.certmap.data_label',
                widget: 'type.ipacertmapdata'
            },
            {
                $type: 'multivalued',
                name: 'certificate',
                label: '@i18n:objects.certmap.certificate',
                widget: 'type.certificate',
                child_spec: {
                    $type: 'textarea'
                }
            },
            {
                name: 'issuer',
                label: '@i18n:objects.certmap.issuer',
                widget: 'type.issuer'
            },
            {
                name: 'subject',
                label: '@i18n:objects.certmap.subject',
                widget: 'type.subject'
            }
        ],
        widgets: [
            {
                $type: 'multiple_choice_section',
                name: 'type',
                choices: [
                    {
                        name: 'data',
                        label: '@i18n:objects.certmap.data_label',
                        fields: ['ipacertmapdata', 'certificate'],
                        required: [],
                        enabled: true
                    },
                    {
                        name: 'issuer_subj',
                        label: '@i18n:objects.certmap.issuer_subject',
                        fields: ['issuer', 'subject'],
                        required: ['issuer', 'subject']
                    }
                ],
                widgets: [
                    {
                        $type: 'multivalued',
                        name: 'ipacertmapdata'
                    },
                    {
                        $type: 'multivalued',
                        name: 'certificate',
                        child_spec: {
                            $type: 'textarea'
                        },
                        tooltip: {
                            title: '@mc-opt:user_add_certmapdata:certificate:doc'
                        }
                    },
                    {
                        name: 'issuer',
                        tooltip: {
                            title: '@mc-opt:user_add_certmapdata:issuer:doc'
                        }
                    },
                    {
                        name: 'subject',
                        tooltip: {
                            title: '@mc-opt:user_add_certmapdata:subject:doc'
                        }
                    }
                ]
            }
        ]
    };

    var that = IPA.custom_command_multivalued_widget(spec);

    that.create_remove_dialog_title = function(row) {
        return text.get('@i18n:objects.certmap.deleter_title');
    };

    that.create_remove_dialog_message = function(row) {
        var message = text.get('@i18n:objects.certmap.deleter_content');
        message = message.replace('${data}', row.widget.new_value);

        return message;
    };

    /**
     * Compose options for add command.
     * @return {Object} options
     */
    that.create_add_options = function() {
        var options = {};
        var widgets = that.adder_dialog.widgets.get_widgets();
        var widget = widgets[0];
        var inner_widgets = widget.widgets.get_widgets();

        var normalize_certs = function(certs) {
            for (var k = 0, l = certs.length; k<l; k++) {
                certs[k] = certificate.get_base64(certs[k]);
            }
        };

        for (var i = 0, l = inner_widgets.length; i<l; i++) {
            var w = inner_widgets[i];

            if (w.enabled) {
                var field = that.adder_dialog.fields.get_field(w.name);
                var value = field.save();

                if (field.name === 'issuer' || field.name === 'subject') {
                    value = value[0];
                } else if (field.name === 'certificate') {
                    normalize_certs(value);
                }

                if (!util.is_empty(value)) options[field.name] = value;
            }
        }

        return options;
    };


    /**
     * Compose options for remove command.
     *
     * @param {Object} row
     * @return {Object} options
     */
    that.create_remove_options = function(row) {
        var options = {};
        var data = row.widget.new_value;

        options['ipacertmapdata'] = data;

        return options;
    };

    return that;
};

/**
 * Certificat Mapping Rules entity specification object
 * @member certmap
 */
certmap.certmaprule_spec = make_certmaprule_spec();

/**
 * Certificate Mapping Configuration entity specification object
 * @member certmap
 */
certmap.certmapconfig_spec = make_certmapconfig_spec();


/**
 * Register entity
 * @member cermap
 */
certmap.register = function() {
    var e = reg.entity;
    var w = reg.widget;

    e.register({type: 'certmaprule', spec: certmap.certmaprule_spec});
    e.register({type: 'certmapconfig', spec: certmap.certmapconfig_spec});
    w.register('certmap_multivalued',
                certmap.certmap_multivalued_widget);
};

phases.on('registration', certmap.register);

return certmap;
});
