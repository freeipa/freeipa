//
// Web UI application profile
//

var profile = (function(){
    return {
        basePath: ".",
        releaseDir: "../release",
        releaseName: "lib",
        action: "release",

        // Remove just comments. Don't use Shrinksave or Clusure, we don't
        // pack it, it would raise error.
        // Additional optimization can be done by uglify.js.
        layerOptimize: "comments",
        optimize: "comments",
        cssOptimize: "comments",
        mini: true,
        stripConsole: "warn",
        selectorEngine: "lite",

        defaultConfig: {
            hasCache:{
                "config-deferredInstrumentation": 0,
                "config-dojo-loader-catches": 0,
                "config-tlmSiblingOfDojo": 0,
                "dojo-amd-factory-scan": 0,
                "dojo-combo-api": 0,
                "dojo-config-api": 1,
                "dojo-config-require": 0,
                "dojo-debug-messages": 0,
                "dojo-dom-ready-api": 1,
                "dojo-firebug": 0,
                "dojo-guarantee-console": 1,
                "dojo-has-api": 1,
                "dojo-inject-api": 1,
                "dojo-loader": 1,
                "dojo-log-api": 0,
                "dojo-modulePaths": 0,
                "dojo-moduleUrl": 0,
                "dojo-publish-privates": 0,
                "dojo-requirejs-api": 0,
                "dojo-sniff": 0,
                "dojo-sync-loader": 0, //all modules should be AMD
                "dojo-test-sniff": 0,
                "dojo-timeout-api": 0,
                "dojo-trace-api": 0,
                "dojo-undef-api": 0,
                "dojo-v1x-i18n-Api": 1,
                "dom": 1,
                "host-browser": 1,
                "extend-dojo": 1
            },
            async: 1
        },

        // Dojo package and layer is not included to not pollute release dir.
        // It will raise some dependency errors. #TODO:update builder to be
        // able to specify dependencies to ignore

        packages:[
            {
                name: "freeipa",
                location: "freeipa"
            }
        ],

        layers: {
            "freeipa/app": {
                include: ["freeipa/app"]
            }
        }
    };
})();