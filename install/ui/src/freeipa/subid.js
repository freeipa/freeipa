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

var make_spec = function() {
return {
    name: 'subid',
    facets: [
        {
            $type: 'search',
            columns: [
                'ipauniqueid',
                'ipaowner',
                'ipasubgidnumber',
                'ipasubuidnumber'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'details',
                    fields: [
                        'ipauniqueid',
                        'description',
                        {
                            name: 'ipaowner',
                            label: '@i18n:objects.subid.ipaowner',
                            title: '@mo-param:subid:ipaowner:label'
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
