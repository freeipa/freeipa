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
                var msg = text.get('@i18n:unauthorized-page');
                if (msg) {
                    dom.byId('unauthorized-msg').innerHTML=msg;
                }
            });
    });
    ipa_loader.styles(styles);
    ipa_loader.icons(icons);
})();
