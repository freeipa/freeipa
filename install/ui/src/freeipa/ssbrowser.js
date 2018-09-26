//
// Copyright (C) 2018  FreeIPA Contributors see COPYING for license
//

define([
    'dojo/dom',
    './text',
    'dojo/domReady!'
], function(dom, text) {
    return {
        init: function() {
            msg = "".concat(
                text.get('@i18n:ssbrowser-page.header'),
                text.get('@i18n:ssbrowser-page.firefox-header'),
                text.get('@i18n:ssbrowser-page.firefox-actions'),
                text.get('@i18n:ssbrowser-page.chrome-header'),
                text.get('@i18n:ssbrowser-page.chrome-certificate'),
                text.get('@i18n:ssbrowser-page.chrome-spnego'),
                text.get('@i18n:ssbrowser-page.ie-header'),
                text.get('@i18n:ssbrowser-page.ie-actions')
            );
            dom.byId('ssbrowser-msg').innerHTML=msg;
        }
    };
});
