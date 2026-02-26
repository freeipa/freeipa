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
        'js/libs/jquery.js',
        'js/libs/jquery.ordered-map.js',
        'js/dojo/dojo.js'
    ];
    ipa_loader.scripts(scripts, function() {
        require([
            'freeipa/core',
            'dojo/domReady!'
            ], function(app) {
                app.run_simple('migrate');
            });
    });
    ipa_loader.styles(styles);
    ipa_loader.icons(icons);

})();
