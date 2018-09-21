/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Endi Sukma Dewata <edewata@redhat.com>
 *    Adam Young <ayoung@redhat.com>
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2010-2011 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

define([
        'dojo/_base/lang',
        './metadata',
        './_base/Singleton_registry',
        './builder',
        './ipa',
        './jquery',
        './reg',
        './text',
        './facet'],
    function(lang, metadata_provider, Singleton_registry, builder,
             IPA, $, reg, text) {

/**
 * Entity module
 *
 * @class entity
 * @singleton
 */
var exp = {};

/**
 * Entity
 *
 * Represents a business logic object type, ie. user. Maintains
 * information related to that object.
 * @class entity.entity
 * @alternateClassName IPA.entity
 */
exp.entity = IPA.entity = function(spec) {

    spec = spec || {};

    spec.policies = spec.policies || [
        IPA.search_facet_update_policy,
        IPA.details_facet_update_policy
    ];

    var that = IPA.object();

    /**
     * Name
     * @property {string}
     */
    that.name = spec.name;

    /**
     * Label
     * @property {string}
     */
    that.label = text.get(spec.label);

    /**
     * Entity has primary key(s)
     * @property {boolean} defines_key=true
     */
    that.defines_key = spec.defines_key !== undefined ? spec.defines_key : true;

    /**
     * Metadata
     * @property {Object}
     */
    that.metadata = spec.metadata;

    /**
     * Dialogs
     * @protected
     * @property {ordered_map}
     */
    that.dialogs = $.ordered_map();

    /**
     * Dialog specifications
     * @property {Array.<Object>}
     */
    that.dialog_specs = spec.dialogs || [];

    /**
     * Dialogs defined in `dialog_specs` were created -> `dialogs` is populated.
     * @property {boolean}
     */
    that.dialogs_created = false;

    /**
     * Entity policies
     * @property {IPA.entity_policies}
     */
    that.policies = IPA.entity_policies({
        entity: that,
        policies: spec.policies
    });


    /**
     * Facets
     * @protected
     * @property {ordered_map}
     */
    that.facets = $.ordered_map();

    /**
     * Facet groups
     * @property {ordered_map}
     */
    that.facet_groups = $.ordered_map();

    /**
     * Facet group object specifications
     * @property {Array.<Object>}
     */
    that.facet_group_specs = spec.facet_groups;

    /**
     * Facet object specifications
     * @property {Array.<Object>}
     */
    that.facet_specs = spec.facets || [];

    /**
     * Facets and facet groups were created
     * @property {boolean}
     */
    that.facets_created = false;

    /**
     * Current facet
     * @property {IPA.facet}
     */
    that.facet = null;

    /**
     * Name of facet to which other facets should redirect in case of unexpected
     * event.
     * @property {string}
     */
    that.redirect_facet = spec.redirect_facet;

    /**
     * Containing entity in case if this is a nested entity
     * @property {entity.entity}
     */
    that.containing_entity = null;

    /**
     * Initialize entity.
     * Should be called by builder if used.
     */
    that.init = function() {
        if (!that.metadata) {
            that.metadata = that.get_default_metadata();
            if (!that.metadata) {
                throw {
                    expected: true,
                    message: "Entity " + that.name + " not supported by server."
                };
            }
        }
        that.label = text.get(that.label) || that.metadata.label || that.name;
    };

    /**
     * Initialize entity.
     * Should be called by builder if used.
     * @return Metadata
     */
    that.get_default_metadata = function() {
        return metadata_provider.get('@mo:'+that.name);
    };

    /**
     * Getter for `containing_entity`
     * @return {entity.entity}
     */
    that.get_containing_entity = function() {
        return that.containing_entity;
    };

    /**
     * Builder overrides for dialogs belonging to this entity
     *
     * It's purpose is to set valid context and add the dialogs.
     */
    that.dialog_build_overrides = {
        $pre_ops: [
            function (spec, context) {
                spec.entity = context.entity;
                return spec;
            }
        ],
        $post_opts: [
            function (obj, spec, context) {
                context.entity.add_dialog(obj);
                return obj;
            }
        ],
        $factory: IPA.dialog
    };

    /**
     * Get dialog with given name
     *
     * Uses lazy creation - creates dialogs from spec if not done yet.
     *
     * @param {string} name
     * @return Dialog
     */
    that.get_dialog = function(name) {

        //build all dialogs on the first time
        if(!that.dialogs_created) {
            that.add_dialog(that.dialog_specs);
            that.dialogs_created = true;
        }

        return that.dialogs.get(name);
    };

    /**
     * Add one or multiple dialog(s) to entity
     *
     * New dialogs are built if specs are supplied.
     * @param {IPA.dialog|Array.<IPA.dialog>} dialog - dialog(s) or spec(s) to add
     */
    that.add_dialog = function(dialog) {

        var add = function (dialog) {
            dialog.entity = that;
            that.dialogs.put(dialog.name, dialog);
        };

        var context = { entity: that };
        dialog = builder.build('', dialog, context, that.dialog_build_overrides);
        if (lang.isArray(dialog)) {
            for (var i=0; i<dialog.length; i++) {
                add(dialog[i]);
            }
        } else  {
            add(dialog);
        }

        return that;
    };

    /**
     * Add facet group
     * @deprecated
     */
    that.add_facet_group = function(facet_group) {
        that.facet_groups.put(facet_group.name, facet_group);
    };

    /**
     * Get facet group
     * @deprecated
     */
    that.get_facet_group = function(name) {
        return that.facet_groups.get(name);
    };

    /**
     * Remove facet group
     * @deprecated
     */
    that.remove_facet_groups = function() {
        that.facet_groups.empty();
    };

    /**
     * This method is used only in get_facet method and there is no sense to
     * use it alone. Will be removed.
     * @deprecated
     */
    that.add_redirect_info = function(facet_name) {
        if (!that.redirect_facet && facet_name){
             that.redirect_facet = facet_name;
        }
    };

    that.create_facet_type = function(facet_name) {

        // Keep names unique among all facets.
        // Facets added later should also follow this pattern but it's not
        // enforced.
        return that.name + '_' + facet_name;
    };

    /**
     * Get facet with given name.
     *
     * Uses lazy creation. All facets are created from facet specs upon first
     * get_facet call.
     *
     *  - returns current or first facet if name is *undefined*.
     *  - returns default facet if name == 'default' - first facet of non-empty
     *    facet group
     *
     * @param {string|undefined|"default"} name - facet name
     * @return {IPA.facet}
     *
     */
    that.get_facet = function(name) {

        var i, l, facets, facet;

        //build all facets on the first time
        if(!that.facets_created) {

            var facet_specs = that.facet_specs;
            for (i=0,l=facet_specs.length; i<l; i++) {
                var type_name = that.create_facet_type(facet_specs[i].name);
                facet = reg.facet.get(type_name);
                that.add_facet(facet);
                if (facet.name === 'search') {
                    that.add_redirect_info(facet.name);
                }
            }
            that.facets_created = true;
            that.policies.facets_created();
        }

        if (name === undefined) {
            // return the main facet
            return that.facets.values[0];

        } else if (name === 'default') {
            // return the first facet in the first facet group
            var facet_groups = that.facet_groups.values;
            for (i=0; i<facet_groups.length; i++) {
                var facet_group = facet_groups[i];
                facets = facet_group.facets.values;
                if (!facets.length) continue;
                return facets[0];
            }

            return that.facets.values[0];
        }


        facet = that.facets.get(name);
        // maybe the facet is in central facet registry
        if (!facet) {
            facet = reg.facet.get(that.create_facet_type(name));
        }

        return facet;
    };

    /**
     * Add facet to entity
     *
     * @param {IPA.facet} facet - facet to add
     * @param {string} facet.facet_group - facet group to add the facet
     */
    that.add_facet = function(facet) {

        that.facets.put(facet.name, facet);

        if (facet.facet_group) {
            var facet_group = that.get_facet_group(facet.facet_group);
            if (facet_group) {
                facet_group.add_facet(facet);
            }
        }

        return that;
    };

    /**
     * Helper function - evaluates if entity as any attribute members.
     * Useful for knowing when to add 'no_members' option to RPC call.
     * @return {boolean}
     */
    that.has_members = function() {
        var members = that.metadata.attribute_members;
        var has = false;
        if (members) {
            for (var member in members) {
                if (members.hasOwnProperty(member)) {
                    has = true;
                    break;
                }
            }
        }
        return has;
    };

    /**
     * Builder used for building this entity.
     */
    that.builder = spec.builder || IPA.entity_builder(that);

    that.entity_init = that.init;

    return that;
};

/**
 * Entity post builder
 *
 * - contains methods for entity post creation operations.
 * - has chained API.
 * - direct usage is not recommended. It's usable only when overriding standard
 *   behavior. By default, calls of most methods are registered as post operations
 *   for {@link _base.builder}.
 *
 * @class entity.entity_builder
 * @alternateClassName IPA.entity_builder
 */
exp.entity_builder = IPA.entity_builder = function(entity) {

    var that = IPA.object();

    var facet_group = null;
    var facet = null;
    var section = null;

    /** Default facet groups **/
    that.default_facet_groups = [
        'member',
        'settings',
        'memberof',
        'managedby'
    ];

    /**
     * Build and add facet group
     * @param {Object} spec - facet group specification
     */
    that.facet_group = function(spec) {

        if (typeof spec === 'string') {
            spec = { name: spec };
        }

        var preop = function(spec) {

            spec.entity = entity;
            spec.label = spec.label || '@i18n:facet_groups.'+spec.name;
            return spec;
        };

        var facet_group = builder.build('', spec, {}, {
            $factory: IPA.facet_group,
            $pre_ops: [preop]
        });

        entity.add_facet_group(facet_group);

        return that;
    };

    /**
     * Replace facet groups
     *
     * @param {Array.<Object>} specs - specifications of new facet groups
     */
    that.facet_groups = function(specs) {

        entity.remove_facet_groups();

        for (var i=0; i<specs.length; i++) {
            specs[i].entity = entity;
            that.facet_group(specs[i]);
        }

        return that;
    };

    /**
     * Add facet spec
     * @param {Object} spec
     */
    that.facet = function(spec) {

        entity.facet_specs.push(spec);

        return that;
    };

    /**
     * Add search facet
     * @deprecated
     * @param {Object} spec
     */
    that.search_facet = function(spec) {

        spec.$type = spec.$type || 'search';

        that.facet(spec);

        add_redirect_info(spec.name);

        return that;
    };

    /**
     * Add nested search facet
     * @deprecated
     * @param {Object} spec
     */
    that.nested_search_facet = function(spec) {

        spec.$type = spec.$type || 'nested_search';

        that.facet(spec);

        return that;
    };

    /**
     * Add details facet
     * @deprecated
     * @param {Object} spec
     */
    that.details_facet = function(spec) {

        spec.$type = spec.$type || 'details';

        that.facet(spec);

        return that;
    };

    /**
     * Add association facet
     * @deprecated
     * @param {Object} spec
     */
    that.association_facet = function(spec) {

        spec.$type = spec.$type || 'association';

        that.facet(spec);

        return that;
    };

    /**
     * Add attribute_facet facet
     * @deprecated
     * @param {Object} spec
     */
    that.attribute_facet = function(spec) {

        spec.$type = spec.$type || 'attribute';

        that.facet(spec);

        return that;
    };

    /**
     * Add missing association facets
     *
     * Facets are based on entity attribute_members. Doesn't add duplicates so
     * facet defined in entity spec are ignored and only the missing are added.
     *
     * Direct usage is deprecated. Use `standard_association_facets: true`
     * in entity spec instead.
     *
     * @deprecated
     * @param {Object} spec - object to be mixed-in in each new facet spec
     */
    that.standard_association_facets = function(spec) {

        spec = spec || {};
        spec.entity = entity;

        var direct_associations = [];
        var indirect_associations = [];

        for (var association in entity.metadata.attribute_members) {
            if (association == 'memberindirect' ||
                association == 'memberofindirect') {
                indirect_associations.push(association);
            } else {
                direct_associations.push(association);
            }
        }

        // make sure direct facets are created first
        var attribute_members = direct_associations.concat(indirect_associations);

        for (var i=0; i<attribute_members.length; i++) {
            var attribute_member = attribute_members[i];
            var other_entities = entity.metadata.attribute_members[attribute_member];

            for (var j=0; j<other_entities.length; j++) {

                var other_entity = other_entities[j];
                var association_name = attribute_member+'_'+other_entity;

                //already prepared facet
                var facet = get_spec_by_name(entity.facet_specs, association_name);
                //already prepared direct facet for indirect facet
                var direct_facet = get_direct_facet(entity.facet_specs,
                                                    attribute_member,
                                                    other_entity);
                if (facet || direct_facet) {
                    continue; //in both cases don't prepare new facet
                }

                var tmp_spec = $.extend({}, spec);
                tmp_spec.name = association_name;

                that.association_facet(tmp_spec);
            }
        }

        return that;
    };

    function get_spec_by_name(specs, name) {
        if(!specs || !specs.length) return null;

        for(var i=0; i<specs.length; i++) {
            if(specs[i].name === name) {
                return specs[i];
            }
        }

        return null;
    }

    /**
     * If it's an indirect attribute member, return its direct facets spec
     * if it exists.
     */
    function get_direct_facet(facets, attribute_member, other_entity) {

        var index = attribute_member.indexOf('indirect');
        if(index > -1) {
            var direct_attribute_member = attribute_member.substring(0, index);
            return get_spec_by_name(facets,
                                    direct_attribute_member+'_'+other_entity);
        }

        return null;
    }

    function add_redirect_info(facet_name){
        facet_name = facet_name || 'search';
        if (!entity.redirect_facet){
            entity.redirect_facet = facet_name;
        }
    }

    /**
     * Set containing(parent) entity
     *
     * Direct usage is deprecated. Set `containing_entity: 'entity_name'` in
     * entity spec instead.
     * @deprecated
     */
    that.containing_entity = function(entity_name) {
        add_redirect_info();
        entity.containing_entity = IPA.get_entity(entity_name);
        return that;
    };

    that.dialog = function(spec) {

        if (spec instanceof Object) {
            spec.$factory = spec.$factory || IPA.dialog;
            spec.entity = entity;

        } else {
            spec = {
                $factory: IPA.dialog,
                name: spec,
                entity: entity
            };
        }

        entity.dialog_specs.push(spec);
        return that;
    };

    /**
     * Add adder dialog spec
     *
     * Set `adder_dialog: { ... }` in entity instead.
     * @deprecated
     */
    that.adder_dialog = function(spec) {
        spec.$factory = spec.$factory || IPA.entity_adder_dialog;
        spec.name = spec.name || 'add';

        spec.title = spec.title || text.get('@i18n:dialogs.add_title_default');

        return that.dialog(spec);
    };

    /**
     * Add deleter_dialog spec
     *
     * Set `deleter_dialog: { ... }` in entity instead.
     * @deprecated
     */
    that.deleter_dialog = function(spec) {
        spec.$factory = spec.$factory || IPA.search_deleter_dialog;
        spec.name = spec.name || 'remove';

        return that.dialog(spec);
    };

    that.facet_groups(entity.facet_group_specs || that.default_facet_groups);

    return that;
};

/**
 * Entity post build operations
 *
 * they:
 *
 * - invokes `enable_test()`, `init()`
 * - sets containing entity
 * - creates standard association facets
 * - add adder dialog
 * - adds deleter dialog
 *
 * @member entity
 * @property {Object} entity_post_ops
 * @property  {Function} entity_post_ops.init
 * @property  {Function} entity_post_ops.containing_entity
 * @property  {Function} entity_post_ops.standard_association_facets
 * @property  {Function} entity_post_ops.adder_dialog
 * @property  {Function} entity_post_ops.deleter_dialog
 */
exp.entity_post_ops = {

    init: function(entity, spec, context) {

        if (typeof spec.enable_test === 'function') {
            if (!spec.enable_test()) throw {
                expected: true
            };
        }
        if (entity.init) {
            entity.init(spec, context);
        }
        return entity;
    },

    containing_entity: function(entity, spec, context) {
        if (spec.containing_entity) {
            entity.builder.containing_entity(spec.containing_entity);
        }
        return entity;
    },

    standard_association_facets: function(entity, spec, context) {
        var saf = spec.standard_association_facets;
        if (saf) {
            var facet_spec;
            if (typeof saf === 'object') facet_spec = saf;
            entity.builder.standard_association_facets(facet_spec);
        }
        return entity;
    },

    adder_dialog: function(entity, spec, context) {

        if (spec.adder_dialog) {
            entity.builder.adder_dialog(spec.adder_dialog);
        }
        return entity;
    },

    deleter_dialog: function(entity, spec, context) {

        if (spec.deleter_dialog) {
            entity.builder.deleter_dialog(spec.deleter_dialog);
        }
        return entity;
    },

    facets: function(entity, spec, context) {

        var facet_specs = entity.facet_specs;

        for (var i=0,l=facet_specs.length; i<l; i++) {
            var f_spec = facet_specs[i];

            if (!f_spec.entity) {
                f_spec.entity = entity;
            }

            reg.facet.register_from_spec(function(spec) {
                // replace the original spec with the merged one so there is
                // only one
                facet_specs[i] = spec;
                return entity.create_facet_type(spec.name);
            }, f_spec);
        }
        return entity;
    }
};

/**
 * Entity policy base class
 *
 * Policy is a mediator object. Usually it handles inter-facet communication.
 *
 * Specific policy should override `facet_created` method.
 *
 * @class entity.entity_policy
 * @alternateClassName IPA.entity_policy
 * @abstract
 */
exp.entity_policy = IPA.entity_policy = function(spec) {

    spec = spec || {};

    var that = IPA.object();

    /**
     * Entity this policy is associated with
     * @property {entity.entity}
     */
    that.entity = spec.entity;

    /**
     * Facet created
     *
     * Functional entry point. This method is called after facets are created.
     * It allows the policy to registered various event handlers to facets or
     * do other work.
     */
    that.facets_created = function() {
    };

    return that;
};

/**
 * Collection of entity policies.
 * @class entity.entity_policies
 * @alternateClassName IPA.entity_policies
 */
exp.entity_policies = IPA.entity_policies = function(spec) {

    var that = IPA.object();

    /**
     * Entity to be set to all policies
     */
    that.entity = spec.entity;

    /**
     * Policies
     */
    that.policies = [];

    /**
     * Add policy
     * @param {entity.entity_policy} policy
     */
    that.add_policy = function(policy) {

        policy.entity = that.entity;
        that.policies.push(policy);
    };

    /**
     * Add policies
     * @param {Array.<entity.entity_policy>} policies
     */
    that.add_policies = function(policies) {

        if (!policies) return;

        for (var i=0; i<policies.length; i++) {
            that.add_policy(policies[i]);
        }
    };

    /**
     * Call each policy's `facet_policy` method
     */
    that.facets_created = function() {

        for (var i=0; i<that.policies.length; i++) {
            that.policies[i].facets_created();
        }
    };

    var policies = builder.build('', spec.policies, {},
                                  { $factory: IPA.entity_policy }) || [];
    that.add_policies(policies);

    return that;
};

/**
 * Facet update policy
 *
 * This policy sets destination facet of destination entity as expired
 * when specific event of source facet of this entity is raised.
 *
 * @class entity.facet_update_policy
 * @extends entity.entity_policy
 * @alternateClassName IPA.facet_update_policy
 *
 * @param {Object} spec
 * @param {string} spec.event - event name
 * @param {string} spec.source_facet - source facet name
 * @param {string} spec.dest_facet - destination facet name
 * @param {string} spec.dest_entity_name - destination entity name
 *
 */
exp.facet_update_policy = IPA.facet_update_policy = function(spec) {

    spec = spec || {};

    var that = IPA.entity_policy();

    /**
     * Source event name
     * @property {string} event=on_update
     */
    that.event = spec.event || 'on_update';

    /**
     * Source facet name
     */
    that.source_facet_name = spec.source_facet;

    /**
     * Destination facet name
     */
    that.dest_facet_name = spec.dest_facet;

    /**
     * Destination entity name
     */
    that.dest_entity_name = spec.dest_entity;

    /**
     * @inheritDoc
     */
    that.facets_created = function() {

        that.source_facet = that.entity.get_facet(that.source_facet_name);
        var dest_entity = that.entity;
        if (that.dest_entity_name) {
            dest_entity = IPA.get_entity(that.dest_entity_name);
            if (!dest_entity) return;
        }
        that.dest_facet = dest_entity.get_facet(that.dest_facet_name);

        if (!that.source_facet || !that.dest_facet) return;

        var event = that.source_facet[that.event];
        if (!event && !event.attach) return;

        event.attach(that.set_expired_flag);
    };

    /**
     * Set facet as expired
     */
    that.set_expired_flag = function() {

        that.dest_facet.set_expired_flag();
    };

    return that;
};

/**
 * Adder facet update policy
 *
 * Update destination details facet when new object is added (adder dialog
 * 'added' event).
 *
 * @class entity.adder_facet_update_policy
 * @extends entity.entity_policy
 * @alternateClassName IPA.adder_facet_update_policy
 *
 */
exp.adder_facet_update_policy = IPA.adder_facet_update_policy = function(spec) {

    spec = spec || {};

    var that = IPA.entity_policy();

    /**
     * Source event name
     * @property {string} event='added'
     */
    that.event = spec.event || 'added';
    /** Adder dialog name */
    that.dialog_name = spec.dialog_name || 'add';
    /** Destination facet name */
    that.dest_facet_name = spec.dest_facet || 'details';
    /** Destination entity name */
    that.dest_entity_name = spec.dest_entity;

    /** @inheritDoc */
    that.facets_created = function() {

        that.dialog = that.entity.get_dialog(that.dialog_name);
        var dest_entity = that.entity;
        if (that.dest_entity_name) {
            dest_entity = IPA.get_entity(that.dest_entity_name);
            if (!dest_entity) return;
        }
        that.dest_facet = dest_entity.get_facet(that.dest_facet_name);

        if (!that.dialog || !that.dest_facet) return;

        var event = that.dialog[that.event];
        if (!event && !event.attach) return;

        event.attach(that.set_expired_flag);
    };

    /** Set facet as expired */
    that.set_expired_flag = function() {

        that.dest_facet.set_expired_flag();
    };

    return that;
};


/**
 * Search facet update policy
 *
 * Expires details facet when search facet is updated.
 *
 * @class entity.search_facet_update_policy
 * @extends entity.facet_update_policy
 * @alternateClassName IPA.search_facet_update_policy
 */
exp.search_facet_update_policy = IPA.search_facet_update_policy = function(spec) {

    spec = spec || {};
    spec.source_facet = 'search';
    spec.dest_facet = 'details';

    return IPA.facet_update_policy(spec);
};

/**
 * Details facet update policy
 *
 * Expires search facet when details facet is updated.
 *
 * @class entity.details_facet_update_policy
 * @extends entity.facet_update_policy
 * @alternateClassName IPA.details_facet_update_policy
 */
exp.details_facet_update_policy =IPA.details_facet_update_policy = function(spec) {

    spec = spec || {};
    spec.source_facet = 'details';
    spec.dest_facet = 'search';

    return IPA.facet_update_policy(spec);
};

// Entity builder and registry
var registry = new Singleton_registry();
reg.set('entity', registry);
builder.set('entity', registry.builder);
registry.builder.factory = exp.entity;
registry.builder.post_ops.push(
    exp.entity_post_ops.init,
    exp.entity_post_ops.containing_entity,
    exp.entity_post_ops.standard_association_facets,
    exp.entity_post_ops.adder_dialog,
    exp.entity_post_ops.deleter_dialog,
    exp.entity_post_ops.facets);

return exp;
});
