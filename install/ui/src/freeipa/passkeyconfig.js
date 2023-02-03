/*
 *  Copyright (C) 2022  FreeIPA Contributors see COPYING for license
 */

define([
        './ipa',
        './jquery',
        './phases',
        './reg',
        './details',
        './search',
        './association',
        './entity'],
            function(IPA, $, phases, reg) {

var exp = IPA.passkeyconfig = {};

var make_spec = function() {
return {
    name: 'passkeyconfig',
    defines_key: false,
    facets: [
        {
            $type: 'details',
            title: '@mo:config.label',
            sections: [
                {
                    name: 'options',
                    label: '@i18n:objects.passkeyconfig.options',
                    fields: [
                        {
                            $type: 'checkbox',
                            name: 'iparequireuserverification'
                        }
                    ]
                }
            ],
            needs_update: true
        }
    ]
};};

exp.entity_spec = make_spec();
exp.register = function() {
    var e = reg.entity;
    e.register({type: 'passkeyconfig', spec: exp.entity_spec});
};
phases.on('registration', exp.register);

return {};
});
