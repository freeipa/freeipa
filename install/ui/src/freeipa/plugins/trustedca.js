//
// Copyright (C) 2023  FreeIPA Contributors see COPYING for license
//

define([
    '../ipa',
    '../jquery',
    '../phases',
    '../reg',
    '../certificate'
],
function(IPA, $, phases, reg, cert) {
/**
 * trustedca module
 * @class plugins.trustedca
 * @singleton
 */
var trustedca = IPA.trustedca = {
};

var make_trustedca_spec = function() {
return {
    name: 'trustedca',
    facets: [
        {
            $type: 'search',
            disable_facet_tabs: false,
            tabs_in_sidebar: true,
            tab_label: '@mo:trustedca.label',
            facet_groups: [cert.facet_group],
            facet_group: 'certificates',
            no_update: true,
            columns: [
                'cn',
                'subject'
            ]
        },
        {
            $type: 'details',
            $factory: IPA.cert.details_facet,
            no_update: true,
            disable_facet_tabs: true,
            // TODO: add 'cacertificate' text field and download feature
            sections: [
                {
                    name: 'details',
                    label: '@i18n:objects.cert.certificate',
                    fields: [
                        'cn',
                        'serial_number',
                        'serial_number_hex',
                        'subject',
                        'issuer',
                        'valid_not_before',
                        'valid_not_after',
                        'sha1_fingerprint',
                        'sha256_fingerprint',
                        'ipakeytrust',
                        {
                            $type: 'multivalued',
                            name: 'ipakeyextusage'
                        }
                    ]
                }
            ]
        }
    ]
};};


/**
 * Certificate profile entity specification object
 * @member plugins.trustedca
 */
trustedca.trustedca_spec = make_trustedca_spec();


/**
 * Register entity
 * @member plugins.trustedca
 */
trustedca.register = function() {
    var e = reg.entity;
    e.register({type: 'trustedca', spec: trustedca.trustedca_spec});
};

phases.on('registration', trustedca.register);

return trustedca;
});
