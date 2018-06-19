//
// BUILDER profile
//

var profile = (function(){
    return {
        basePath: ".",
        releaseDir: "../release",
        releaseName: "build",
        action: "release",

        layerOptimize: false,
        optimize: false,
        cssOptimize: false,
        mini: true,
        stripConsole: "warn",
        selectorEngine: "lite",

        staticHasFeatures: {
            "host-rhino":0,
            "host-browser":0,
            "host-node":1,
            "dom":0,
            "dojo-has-api":1,
            "dojo-xhr-factory":0,
            "dojo-inject-api":1,
            "dojo-timeout-api":0,
            "dojo-trace-api":1,
            "dojo-loader-catches":0,
            "dojo-dom-ready-api":0,
            "dojo-dom-ready-plugin":0,
            "dojo-ready-api":1,
            "dojo-error-api":1,
            "dojo-publish-privates":1,
            "dojo-gettext-api":1,
            "dojo-sniff":0,
            "dojo-loader":1,
            "dojo-test-xd":0,
            "dojo-test-sniff":0
        },

        packages:[{
            name: "dojo",
            location: "dojo"
        },{
            name: "build",
            location: "build"
        }],

        layers: {
            "build/build": {
                include: [
                    'dojo/dojo',
                    'build/buildControlBase',
                    'build/argv',
                    'build/build.profile',
                    'build/discover',
                    'build/messages',
                    'build/removeComments',
                    'build/fs',
                    'build/main',
                    'build/fileUtils',
                    'build/process',
                    'build/v1xProfiles',
                    'build/replace',
                    'build/fileHandleThrottle',
                    'build/buildControl',
                    'build/commandLineArgs',
                    'build/stringify',
                    'build/buildControlDefault',
                    'build/version',
                    'build/plugins/querySelector',
                    'build/plugins/domReady',
                    'build/plugins/has',
                    'build/plugins/text',
                    'build/plugins/loadInit',
                    'build/plugins/require',
                    'build/plugins/i18n',
                    'build/transforms/depsDump',
                    'build/transforms/copy',
                    'build/transforms/trace',
                    'build/transforms/read',
                    'build/transforms/writeAmd',
                    'build/transforms/dojoPragmas',
                    'build/transforms/report',
                    'build/transforms/hasFindAll',
                    'build/transforms/hasFixup',
                    'build/transforms/writeDojo',
                    'build/transforms/depsScan',
                    'build/transforms/write',
                    'build/transforms/dojoReport',
                    'build/transforms/writeOptimized',
                    'build/transforms/insertSymbols',
                    'build/transforms/hasReport',
                    'build/transforms/writeCss',
                    'build/transforms/depsDeclarative',
                    'build/transforms/optimizeCss',
                    'build/node/fs',
                    'build/node/process',
                    'build/rhino/fs',
                    'build/rhino/process'
                ],
                customBase: true,
                boot: true
            }
        }
    };
})();