//
// Copyright (C) 2015  FreeIPA Contributors see COPYING for license
//

define(['dojo/_base/declare',
        '../builder',
        '../facet'
       ],
       function(declare, builder, mod_facet) {


/**
 * Header Mixin
 *
 * Extension of facet - actions
 *
 * @class facets.ActionMixin
 */
var ActionMixin = declare([], {

    /**
     * State object for actions
     * @property {facet.state}
     */
    action_state: null,

    /**
     * Collection of facet actions
     * @property {facet.action_holder}
     */
    actions: null,

    show: function() {
        this.inherited(arguments);
        this.actions.on_load();
    },

    /** Constructor */
    constructor: function(spec) {

        this.action_state = builder.build('', spec.state || {}, {}, { $factory: mod_facet.state });
        this.actions = builder.build('', { actions: spec.actions }, {}, { $factory: mod_facet.action_holder } );
        this.action_state.init(this);
        this.actions.init(this);
    }
});

return ActionMixin;
});