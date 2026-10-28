//
// DOJO profile
//

var profile = (function(){
    return {
        basePath: ".",
        releaseDir: "../release",
        releaseName: "dojo",
        action: "release",

        layerOptimize: false,
        optimize: false,
        cssOptimize: false,
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
                "dojo-sync-loader": 0,
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


        packages:[
            {
                name: "dojo",
                location: "dojo"
            }
        ],

        layers: {
            "dojo/dojo": {
                // explicitly include all modules which we want in our build
                include: [
                    "dojo/dojo",
                    "dojo/domReady",
                    "dojo/_base/declare",
                    // ^ core is about 20KB
                    "dojo/_base/lang",
                    "dojo/_base/array",
                    "dojo/string",
                    // ^ adds 10KB
                    "dojo/dom",
                    "dojo/dom-construct",
                    "dojo/dom-class",
                    "dojo/dom-style",
                    "dojo/dom-prop",
                    // ^ adds 20KB, with router only 5KB
                    "dojo/Stateful",
                    "dojo/Evented",
                    "dojo/on",
                    "dojo/io-query",
                    //
                    "dojo/keys",
                    "dojo/router",
                    "dojo/hash", //used by router
                    "dojo/topic", //used by router
                    // ^ adds 20 KB, most of it is dojo/dom*
                    "dojo/store/Observable",
                    "dojo/store/Memory",
                    "dojo/query",
                    "dojo/NodeList-dom",
                    "dojo/promise/all"
                    // Total size: 75KB
                ],
                customBase: true,
                boot: true
            }
        }
    };
})();