//
// Web UI application profile
//

var profile = (function(){
    return {
        basePath: ".",
        releaseDir: "../release",
        releaseName: "lib",
        action: "release",

        // optimization done separately by uglify.js
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

        packages:[
            {
                name: "freeipa",
                location: "freeipa",
                providedMids: [
                    // all modules in our dojo build
                    // basically sorted layer content obtained from build report
                    'dojo/_base/array',
                    'dojo/_base/config',
                    'dojo/_base/connect',
                    'dojo/_base/declare',
                    'dojo/_base/Deferred',
                    'dojo/_base/event',
                    'dojo/_base/kernel',
                    'dojo/_base/lang',
                    'dojo/_base/sniff',
                    'dojo/_base/window',
                    'dojo/aspect',
                    'dojo/Deferred',
                    'dojo/dojo',
                    'dojo/dom',
                    'dojo/dom-attr',
                    'dojo/dom-class',
                    'dojo/dom-construct',
                    'dojo/dom-geometry',
                    'dojo/dom-prop',
                    'dojo/dom-style',
                    'dojo/domReady',
                    'dojo/errors/CancelError',
                    'dojo/errors/create',
                    'dojo/Evented',
                    'dojo/has',
                    'dojo/hash',
                    'dojo/io-query',
                    'dojo/keys',
                    'dojo/mouse',
                    'dojo/on',
                    'dojo/promise/instrumentation',
                    'dojo/promise/Promise',
                    'dojo/promise/tracer',
                    'dojo/ready',
                    'dojo/router',
                    'dojo/router/RouterBase',
                    'dojo/sniff',
                    'dojo/Stateful',
                    'dojo/store/Memory',
                    'dojo/store/Observable',
                    'dojo/store/util/QueryResults',
                    'dojo/store/util/SimpleQueryEngine',
                    'dojo/topic',
                    'dojo/when',
                    'dojo/domReady!', //added with '!' as a loader plugin
                    "dojo/query",
                    "dojo/string",
                    "dojo/NodeList-dom",
                    "dojo/promise/all",
                    "libs/d3"
                ]
            }
        ],

        layers: {
            "freeipa/core": {
                include: ["freeipa/core"]
            },
            "freeipa/app": {
                include: ["freeipa/app", "freeipa/extend"]
            }
        }
    };
})();