var dojoConfig = {
    baseUrl: "../ui/js",
    has: {
        'dojo-firebug': false,
        'dojo-debug-messages': true
    },
    parseOnLoad: false,
    async: true,
    packages: [
        {
            name:'dojo',
            location:'dojo'
        },
        {
            name: 'freeipa',
            location: 'freeipa'
        }
    ]
};
(function() {
    var icons = [
        '../ui/favicon.ico'
    ];
    var styles = [
        '../ui/css/patternfly.css',
        '../ui/css/ipa.css'
    ];
    var scripts = [
        '../ui/js/libs/jquery.js',
        '../ui/js/libs/jquery.ordered-map.js',
        '../ui/js/dojo/dojo.js'
    ];
    ipa_loader.scripts(scripts, function() {
        require([
            'dojo/dom',
            'freeipa/core',
            'dojo/domReady!'
            ],
            function(dom) {
                var text = require('freeipa/text');
                var msg = "".concat(
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
            });
    });
    ipa_loader.styles(styles);
    ipa_loader.icons(icons);
})();
