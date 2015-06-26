//
// Copyright (C) 2015  FreeIPA Contributors see COPYING for license
//

define([
        'dojo/_base/lang',
        'dojo/_base/declare',
        'dojo/on',
        './builder',
        './ipa',
        './jquery',
        './menu',
        './metadata',
        './phases',
        './reg',
        './rpc',
        './text',
        './details',
        './facet',
        './field',
        './search',
        './entity'],
            function(lang, declare, on, builder, IPA, $, menu, metadata_provider,
                phases, reg, rpc, text, mod_details, mod_facet, mod_field) {
/**
 * Topology module
 * @class
 * @singleton
 */
var topology = IPA.topology = {

    search_facet_group: {
        name: 'search',
        label: '@i18n:tabs.topology',
        facets: {
            suffix_search: 'topologysuffix_search',
            server_search: 'server_search',
            domainlevel: 'domainlevel_details'
        }
    }
};

var make_suffix_spec = function() {
return {
    name: 'topologysuffix',
    enable_test: function() {
        return true;
    },
    facet_groups: [ 'segments', 'settings' ],
    facets: [
        {
            $type: 'search',
            disable_facet_tabs: false,
            tabs_in_sidebar: true,
            no_update: true,
            tab_label: '@mo:topologysuffix.label',
            facet_groups: [topology.search_facet_group],
            facet_group: 'search',
            columns: [
                'cn',
                'iparepltopoconfroot'
            ]
        },
        {
            $type: 'nested_search',
            facet_group: 'segments',
            nested_entity: 'topologysegment',
            search_all_entries: true,
            label: '@mo:topologysegment.label',
            tab_label: '@mo:topologysegment.label',
            name: 'topologysegment',
            columns: [
                'cn',
                'iparepltoposegmentleftnode',
                'iparepltoposegmentrightnode',
                'iparepltoposegmentdirection'
            ]
        },
        {
            $type: 'details',
            no_update: true,
            sections: [
                {
                    name: 'details',
                    fields: [
                        'cn',
                        {
                            name: 'iparepltopoconfroot',
                            read_only: true
                        }
                    ]
                }
            ]
        }
    ]
};};


var make_segment_spec = function() {
return {
    name: 'topologysegment',
    containing_entity: 'topologysuffix',
    enable_test: function() {
        return true;
    },
    facets: [
        {
            $type: 'details',
            disable_breadcrumb: false,
            sections: [
                {
                    name: 'details',
                    label: '@i18n:objects.topology.segment_details',
                    fields: [
                        'cn',
                        {
                            $type: 'entity_select',
                            name: 'iparepltoposegmentleftnode',
                            other_entity: 'server',
                            other_field: 'cn',
                            z_index: 2
                        },
                        {
                            $type: 'entity_select',
                            name: 'iparepltoposegmentrightnode',
                            other_entity: 'server',
                            other_field: 'cn',
                            z_index: 1
                        },
                        'iparepltoposegmentdirection'
                    ]
                },
                {
                    name: 'replication_config',
                    label: '@i18n:objects.topology.replication_config',
                    fields: [
                        {
                            $type: 'radio',
                            name: 'nsds5replicaenabled',
                            options: ['on', 'off'],
                            default_value: 'on',
                            read_only: true
                        },
                        'nsds5replicatimeout',
                        'nsds5replicastripattrs',
                        'nsds5replicatedattributelist',
                        'nsds5replicatedattributelisttotal'
                    ]
                }
            ]
        }
    ],
    adder_dialog: {
        fields: [
            {
                name: 'cn',
                required: false
            },
            {
                $type: 'entity_select',
                name: 'iparepltoposegmentleftnode',
                other_entity: 'server',
                other_field: 'cn',
                z_index: 2
            },
            {
                $type: 'entity_select',
                name: 'iparepltoposegmentrightnode',
                other_entity: 'server',
                other_field: 'cn',
                z_index: 1
            }
        ]
    }
};};

var make_server_spec = function() {
return {
    name: 'server',
    facets: [
           {
            $type: 'search',
            no_update: true,
            disable_facet_tabs: false,
            tabs_in_sidebar: true,
            tab_label: '@mo:server.label',
            facet_groups: [topology.search_facet_group],
            facet_group: 'search',
            columns: [
                'cn',
                'ipamindomainlevel',
                'ipamaxdomainlevel',
                'iparepltopomanagedsuffix'
            ]
        },
        {
            $type: 'details',
            no_update: true,
            disable_facet_tabs: true,
            sections: [
                {
                    name: 'details',
                    fields: [
                        { name: 'cn', read_only: true },
                        { name: 'ipamindomainlevel', read_only: true },
                        { name: 'ipamaxdomainlevel', read_only: true },
                        { name: 'iparepltopomanagedsuffix', read_only: true }
                    ]
                }
            ]
        }
    ]
};};

var make_domainlevel_spec = function() {
return {
    name: 'domainlevel',
    facets: [
        {
            $type: 'details',
            get_all_attrs: false,
            check_rights: false,
            no_update: true,
            refresh_command_name: 'get',
            disable_facet_tabs: false,
            tabs_in_sidebar: true,
            tab_label: '@mo:domainlevel.label',
            facet_groups: [topology.search_facet_group],
            facet_group: 'search',
            sections: [
                {
                    name: 'details',
                    fields: [
                        {
                            name: 'ipadomainlevel',
                            read_only: true,
                            adapter: topology.domainlevel_adapter
                        }
                    ]
                }
            ],
            actions: ['domainlevel_set'],
            control_buttons: [{
                label: '@i18n:objects.domainlevel.set',
                name: 'domainlevel_set'
            }]
        }
    ]
};};

topology.domainlevel_adapter = declare([mod_field.Adapter], {
    load: function(data) {
        return [this.get_record(data)];
    }
});


topology.domainlevel_metadata = function(spec, context) {
    var metadata = metadata_provider.source;
    metadata.objects.domainlevel = {
        name: 'domainlevel',
        label: text.get('@i18n:objects.domainlevel.label'),
        label_singular: text.get('@i18n:objects.domainlevel.label_singular'),
        only_webui: true,
        takes_params: [
            {
                'class': "Int",
                doc: "",
                flags: [],
                label: text.get("@i18n:objects.domainlevel.ipadomainlevel"),
                maxvalue: 2147483647,
                minvalue: 0,
                name: "ipadomainlevel",
                type: "int"
            }
        ]
    };
    return spec;
};

/**
 * Set Domain Level Action
 *
 * @class topology.domainlevel_set_action
 * @extends {IPA.action}
 */
topology.domainlevel_set_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'domainlevel_set';
    spec.label = spec.label || '@i18n:objects.domainlevel.set';
    var that = IPA.action(spec);

    /**
     * Dialog spec
     * @property {Object}
     */
    that.dialog = spec.dialog || {
        $type: 'command',
        entity: 'domainlevel',
        method: 'set',
        title: '@i18n:objects.domainlevel.set',
        confirm_button_label: '@i18n:buttons.set',
        fields: [
            {
                name: 'ipadomainlevel',
                primary_key: true
            }
        ]
    };

    /**
     * Refresh facet after successful action
     * @property {boolean} refresh=true
     */
    that.refresh = spec.refresh !== undefined ? spec.refresh : true;

    /**
     * @inheritDoc
     */
    that.execute_action = function(facet) {

        var dialog = builder.build('dialog', that.dialog);
        dialog.succeeded.attach(function() {
            if (that.refresh) facet.refresh();
        });
        dialog.open();
    };
    return that;
};



/**
 * Topology suffix entity specification object
 * @member topology
 */
topology.suffix_spec = make_suffix_spec();

/**
 * Topology segment entity specification object
 * @member topology
 */
topology.segment_spec = make_segment_spec();

/**
 * IPA server entity specification object
 * @member topology
 */
topology.server_spec = make_server_spec();

/**
 * Domain Level entity specification object
 * @member topology
 */
topology.domainlevel_spec = make_domainlevel_spec();


/**
 * Register entity
 * @member topology
 */
topology.register = function() {
    var e = reg.entity;
    var a = reg.action;

    e.register({type: 'topologysuffix', spec: topology.suffix_spec});
    e.register({type: 'topologysegment', spec: topology.segment_spec});
    e.register({type: 'server', spec: topology.server_spec});
    e.register({type: 'domainlevel', spec: topology.domainlevel_spec});

    a.register('domainlevel_set', topology.domainlevel_set_action);
};

phases.on('registration', topology.register);
phases.on('post-metadata', topology.domainlevel_metadata);

return topology;
});
