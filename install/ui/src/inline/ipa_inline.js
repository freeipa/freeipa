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
            name: 'libs',
            location: 'libs'
        },
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
        'css/bootstrap-datepicker3.min.css',
        'css/ipa.css',
        'ipa.css'
    ];
    if (ie) styles.push('ie.css');
    var icons = ['favicon.ico'];
    var scripts = [
        'js/libs/json2.js',
        'js/libs/jquery.js',
        'js/libs/bootstrap.js',
        'js/libs/bootstrap-datepicker.js',
        'js/libs/patternfly.js',
        'js/libs/jquery.ordered-map.js',
        'js/libs/browser.js',
        'js/dojo/dojo.js',
        'js/libs/qrcode.js'
    ];
    ipa_loader.scripts(scripts, function() {
        require(['freeipa/app'], function(app){ app.run(); });
    });
    ipa_loader.styles(styles);
    ipa_loader.icons(icons);
})();
