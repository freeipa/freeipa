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
    var styles = [
        'css/patternfly.css',
        'css/ipa.css',
        'ipa.css'
    ];
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
            var reset_pass = require('freeipa/plugins/login');
            reset_pass.facet_spec.widgets[1].view = "reset";
            app.run_simple('login');
        });
    });
    ipa_loader.styles(styles);
    ipa_loader.icons(icons);
})();
