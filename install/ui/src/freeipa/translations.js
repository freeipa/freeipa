//
// Copyright (C) 2018  FreeIPA Contributors see COPYING for license
//

define([
    './jquery',
    './config',
    './_base/i18n'
   ],
   function( $, config, i18n) {

 /**
  *
  * Retrieve translations from server
  *
  * @class translations
  * @singleton
  *
  */

var translations = {};

var retrieve  = function() {

    var result = false;

    var jsondata = {
        method: "i18n_messages",
        params: [ [], { "version": window.ipa_loader.api_version } ]
    };

    var json_url = config.i18n_messages_url;

    // test case: tests dir with crafted data stored in the local json file
    if (window.location.protocol === 'file:') {
        json_url = "data/" + jsondata.method + '.json';
    }

    var request = {
        method: 'POST',
        url: json_url,
        data: JSON.stringify(jsondata),
        dataType: "json",
        contentType: 'application/json',
        async: false,
        processData: false,
        success: success_handler,
        error: error_handler
    };

    function error_handler(xhr, text_status, error_thrown) {
        result = false;
    }

    function success_handler(data, text_status, xhr) {
        if (!data.error) {
            i18n.source = data.result.texts;
            result = true;
        }
    }

    $.ajax(request);
    return result;
};

if (!retrieve()) {
    throw new Error('Couldn\'t receive translations');
}

translations.update = retrieve;
return translations;
});
