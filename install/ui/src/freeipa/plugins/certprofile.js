//
// Copyright (C) 2015  FreeIPA Contributors see COPYING for license
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
 * certprofile module
 * @class plugins.certprofile
 * @singleton
 */
var certprofile = IPA.certprofile = {
};

var make_certprofile_spec = function() {
return {
    name: 'certprofile',
    facets: [
           {
            $type: 'search',
            $pre_ops: [
                { $del: [[ 'control_buttons', [{ name: 'add'}] ]] }
            ],
            disable_facet_tabs: false,
            tabs_in_sidebar: true,
            tab_label: '@mo:certprofile.label',
            facet_groups: [cert.facet_group],
            facet_group: 'certificates',
            columns: [
                'cn',
                'description',
                'ipacertprofilestoreissued'
            ]
        },
        {
            $type: 'details',
            disable_facet_tabs: true,
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
                            $type: 'checkbox',
                            name: 'ipacertprofilestoreissued'
                        }
                    ]
                }
            ]
        }
    ],
    deleter_dialog: {
        title: '@i18n:objects.caprofile.remove',
    },
};};


/**
 * Certificate profile entity specification object
 * @member plugins.certprofile
 */
certprofile.certprofile_spec = make_certprofile_spec();


/**
 * Register entity
 * @member plugins.certprofile
 */
certprofile.register = function() {
    var e = reg.entity;
    e.register({type: 'certprofile', spec: certprofile.certprofile_spec});
};

phases.on('registration', certprofile.register);

return certprofile;
});
