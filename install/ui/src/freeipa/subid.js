/*
 * Copyright (C) 2021  FreeIPA Contributors see COPYING for license
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

var exp = IPA.subid = {};

exp.search_facet_control_buttons_pre_op = function(spec, context) {
    spec.control_buttons = [
        {
            name: 'add',
            label: '@i18n:buttons.add',
            icon: 'fa-plus'
        },
        {
            name: 'refresh',
            label: '@i18n:buttons.refresh',
            icon: 'fa-refresh'
        }
    ];

    return spec;
};

var make_spec = function() {
return {
    name: 'subid',
    facets: [
        {
            $type: 'search',
            $pre_ops: [ exp.search_facet_control_buttons_pre_op ],
            columns: [
                'ipauniqueid',
                'ipaowner',
                'ipasubgidnumber',
                'ipasubuidnumber'
            ]
        },
        {
            $type: 'details',
            disable_facet_tabs: true,
            sections: [
                {
                    name: 'details',
                    fields: [
                        'ipauniqueid',
                        'description',
                        {
                            $type: 'link',
                            name: 'ipaowner',
                            label: '@i18n:objects.subid.ipaowner',
                            title: '@mo-param:subid:ipaowner:label',
                            other_entity: 'user'
                        },
                        {
                            name: 'ipasubgidnumber',
                            label: '@i18n:objects.subid.ipasubgidnumber',
                            title: '@mo-param:subid:ipasubgidnumber:label'
                        },
                        {
                            name: 'ipasubgidcount',
                            label: '@i18n:objects.subid.ipasubgidcount',
                            title: '@mo-param:subid:ipasubgidcount:label'
                        },
                        {
                            name: 'ipasubuidnumber',
                            label: '@i18n:objects.subid.ipasubuidnumber',
                            title: '@mo-param:subid:ipasubuidnumber:label'
                        },
                        {
                            name: 'ipasubuidcount',
                            label: '@i18n:objects.subid.ipasubuidcount',
                            title: '@mo-param:subid:ipasubuidcount:label'
                        }
                    ]
                }
            ]
        },
        {
            $type: 'details',
            name: 'stats',
            label: '@i18n:objects.subid.stats',
            refresh_command_name: 'stats',
            check_rights: false,
            no_update: true,
            disable_facet_tabs: true,
            disable_breadcrumb: true,
            require_pkey: false,
            fields: [
                {
                    name: 'assigned_subids',
                    label: '@i18n:objects.subid.assigned_subids',
                    read_only: true
                },
                {
                    name: 'baseid',
                    label: '@i18n:objects.subid.baseid',
                    read_only: true
                },
                {
                    name: 'dna_remaining',
                    label: '@i18n:objects.subid.dna_remaining',
                    read_only: true
                },
                {
                    name: 'rangesize',
                    label: '@i18n:objects.subid.rangesize',
                    read_only: true
                },
                {
                    name: 'remaining_subids',
                    label: '@i18n:objects.subid.remaining_subids',
                    read_only: true
                }
            ]
        }
    ],
    adder_dialog: {
        title: '@i18n:objects.subid.add',
        method: 'generate',
        fields: [
            {
                $type: 'entity_select',
                name: 'ipaowner',
                other_entity: 'user',
                other_field: 'uid'
            }
        ]
    }
};};

exp.entity_spec = make_spec();
exp.register = function() {
    var e = reg.entity;
    e.register({type: 'subid', spec: exp.entity_spec});
};
phases.on('registration', exp.register);

return {};
});
