//
// Copyright (C) 2018  FreeIPA Contributors see COPYING for license
//

define([
    'dojo/dom',
    './text',
    'dojo/domReady!'
], function(dom, text) {
    if (msg = text.get('@i18n:unauthorized-page')) {
        dom.byId('unauthorized-msg').innerHTML=msg;
    }
});
