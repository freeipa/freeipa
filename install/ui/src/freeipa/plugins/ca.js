//
// Copyright (C) 2016  FreeIPA Contributors see COPYING for license
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
 * ca module
 * @class plugins.ca
 * @singleton
 */
 var ca = IPA.ca = {};

 var make_ca_spec = function() {
     var spec = {
         name: 'ca',
         facets: [
             {
                 $type: 'search',
                 disable_facet_tabs: false,
                 tabs_in_sidebar: true,
                 tab_label: '@mo:ca.label',
                 facet_groups: [cert.facet_group],
                 facet_group: 'certificates',
                 columns: [
                     'cn',
                     'ipacasubjectdn',
                     'description'
                 ]
             },
             {
                 $type: 'details',
                 disable_facet_tabs: true,
                 fields: [
                     'cn',
                     {
                         $type: 'textarea',
                         name: 'description'
                     },
                     'ipacaid',
                     'ipacaissuerdn',
                     'ipacasubjectdn'
                 ]
             }
         ],
         adder_dialog: {
             title: '@i18n:objects.ca.add',
             fields: [
                 {
                     $type: 'text',
                     name: 'cn',
                     required: true
                 },
                 'ipacasubjectdn',
                 {
                     $type: 'textarea',
                     name: 'description'
                 }
             ]
         },
         deleter_dialog: {
             title: '@i18n:objects.ca.remove'
         }
     };

     return spec;
 };

 /**
  * CA entity specification object
  * @member plugins.ca
  */
ca.ca_spec = make_ca_spec();

/**
 * Register entity
 * @member plugins.ca
 */
ca.register = function() {
    var e = reg.entity;

    e.register({type: 'ca', spec: ca.ca_spec});
};

phases.on('registration', ca.register);

return ca;
});
