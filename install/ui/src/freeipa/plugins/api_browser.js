//
// Copyright (C) 2015  FreeIPA Contributors see COPYING for license
//

define(['dojo/_base/declare',
        'dojo/on',
        '../facets/Facet',
        '../phases',
        '../reg',
        '../widget',
        '../widgets/APIBrowserWidget',
        '../builder'
       ],

    function(declare, on, Facet, phases, reg, widget,
        APIBrowserWidget, builder) {


var plugins = {}; // dummy namespace object

/**
 * API browser plugin
 *
 * @class
 * @singleton
 */
plugins.api_browser = {};

plugins.api_browser.facet_spec = {
    name: 'apibrowser',
    'class': 'apibrowser container-fluid',
    widgets: [
        {
            $type: 'activity',
            name: 'activity',
            text: 'Working',
            visible: false
        },
        {
            $type: 'apibrowser',
            name: 'apibrowser'
        }
    ]
};

/**
 * API browser facet
 * @class
 */
plugins.api_browser.APIBrowserFacet = declare([Facet], {

    init: function(spec) {
        this.inherited(arguments);
        var browser = this.get_widget('apibrowser');

        on(this, 'show', function(args) {

            var state = this.get_state();
            var t = state.type;
            var n = state.name;

            if (t && n) {
                browser.show_item(t, n);
                return;
            } else if (t) {
                if (t == 'command') {
                    browser.show_default_command();
                    return;
                } else {
                    browser.show_default_object();
                    return;
                }
            }
            browser.show_default();
            return;
        }.bind(this));

        // Reflect item change in facet state and therefore URL hash
        browser.watch('current', function(name, old, value) {
            var state = {};
            if (value.type && value.name) {
                state = { type: value.type, name: value.name };
            }
            this.set_state(state);
        }.bind(this));
    }
});

phases.on('registration', function() {

    var fa = reg.facet;
    var w = reg.widget;

    w.register('apibrowser', APIBrowserWidget);

    fa.register({
        type: 'apibrowser',
        factory: plugins.api_browser.APIBrowserFacet,
        spec: plugins.api_browser.facet_spec
    });
});

return plugins.api_browser;

});
