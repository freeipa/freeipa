var dojoConfig = {
    baseUrl: "js",
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
    ],
    cacheBust: ipa_loader.num_version || ""
};

(function() {
    var ie = !!document.getElementById('ie-detector');
    var styles = ['css/patternfly.css', 'css/ipa.css', 'ipa.css'];
    if (ie) styles.push('ie.css');
    var icons = ['favicon.ico'];
    var scripts = [
        'js/libs/json2.js',
        'js/libs/jquery.js',
        'js/libs/bootstrap.js',
        'js/libs/jquery.ordered-map.js',
        'js/libs/browser.js',
        'js/dojo/dojo.js'
    ];
    ipa_loader.scripts(scripts, function() {
        require(['freeipa/core', 'dojo/domReady!'], function(app) {
            var sync = require('freeipa/plugins/sync_otp');
            sync.facet_spec.widgets[1].allow_cancel = false;
            app.run_simple('sync-otp');
        });
    });
    ipa_loader.styles(styles);
    ipa_loader.icons(icons);
})();
