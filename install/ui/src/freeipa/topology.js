//
// Copyright (C) 2015  FreeIPA Contributors see COPYING for license
//

define([
        'dojo/_base/lang',
        'dojo/_base/declare',
        'dojo/Evented',
        'dojo/Stateful',
        'dojo/Deferred',
        'dojo/on',
        'dojo/promise/all',
        'dojo/when',
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
        './facets/ActionMixin',
        './facets/HeaderMixin',
        './facets/Facet',
        './topology_graph',
        './navigation',
        // plain imports
        './search',
        './entity'],
            function(lang, declare, Evented, Stateful, Deferred, on, all, when,
                builder, IPA, $, menu, metadata_provider, phases, reg, rpc,
                text, mod_details, mod_facet, mod_field, ActionMixin,
                HeaderMixin, Facet, topology_graph, navigation) {
/**
 * Topology module
 * @class
 * @singleton
 */
var topology = IPA.topology = {

    required_domain_level: 1,

    search_facet_group: {
        name: 'search',
        label: '@i18n:tabs.topology',
        facets: {
            suffix_search: 'topologysuffix_search',
            server_search: 'server_search',
            domainlevel: 'domainlevel_details',
            topologygraph: 'topology-graph'
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
                'iparepltopomanagedsuffix_topologysuffix'
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
                        { $type: 'multivalued', name: 'iparepltopomanagedsuffix_topologysuffix', read_only: true }
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
        dialog.succeeded.attach(function(data) {
            IPA.domain_level = data.result.result;
            if (that.refresh) facet.refresh();
        });
        dialog.open();
    };
    return that;
};

/**
 * Sets 'managed-topology' state if topology is managed
 * @class
 * @extends facet.state_evaluator
 */
topology.managed_topology_evaluator = function(spec) {

    spec = spec || {};

    spec.event = spec.event || 'show';

    var that = IPA.state_evaluator(spec);
    that.name = spec.name || 'state_evaluator';

    that.on_event = function() {

        var old_state = that.state;
        that.state = [];

        if (IPA.domain_level >= topology.required_domain_level) {
            that.state.push('managed-topology');
        }

        that.notify_on_change(old_state);
    };

    return that;
};


topology.topology_graph_facet_spec = {
    name: 'topology-graph',
    'class': 'topology-graph container-fluid',
    label: 'Topology Graph',
    tab_label: 'Topology Graph',
    facet_groups: [topology.search_facet_group],
    facet_group: 'search',
    actions: ['refresh', 'segment_add', 'segment_del'],
    control_buttons: [
        {
            name: 'refresh',
            label: '@i18n:buttons.refresh',
            icon: 'fa-refresh'
        },
        {
            name: 'segment_add',
            label: '@i18n:buttons.add',
            icon: 'fa-plus'
        },
        {
            name: 'segment_del',
            label: '@i18n:buttons.remove',
            icon: 'fa-trash-o'
        }
    ],
    widgets: [
        {
            $type: 'activity',
            name: 'activity',
            text: 'Working',
            visible: false
        },
        {
            $type: 'topology-graph',
            name: 'topology-graph'
        }
    ],
    state: {
        evaluators: [
            topology.managed_topology_evaluator
        ]
    }
};

/**
 * Facet containing topology graph
 *
 * @class
 */
topology.TopologyGraphFacet = declare([Facet, ActionMixin, HeaderMixin], {

    init: function(spec) {
        this.inherited(arguments);
        var graph = this.get_widget('topology-graph');

        on(this, 'show', lang.hitch(this, function(args) {
            graph.update();
        }));

        on(graph, 'link-selected', lang.hitch(this, function(data) {
            this.set_selected_link(data.link);
        }));
    },

    set_selected_link: function(link) {
        this.selected_link = link;
        this.action_state.put('selected_link', link ? ['link_selected'] : []);
    },

    refresh: function() {
        var graph = this.get_widget('topology-graph');
        graph.update();
    }
});

/**
 * Shows topology segment adder dialog with suffix select
 *
 * @class topology.add_segment_action
 * @extends IPA.action
 */
topology.add_segment_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'segment_add';
    spec.method = spec.method || 'add';
    spec.enable_cond = spec.enable_cond || ['managed-topology'];

    var that = IPA.action(spec);

    that.execute_action = function(facet, on_success, on_error) {

        that.facet = facet;

        var entity = reg.entity.get('topologysegment');
        var title = text.get('@i18n:dialogs.add_title');
        var label = entity.metadata.label_singular;
        title = title.replace('${entity}', label);

        var dialog = IPA.entity_adder_dialog({
            entity: 'topologysegment',
            title: title,
            fields: [
                {
                    name: 'cn',
                    required: false
                },
                {
                    $type: 'entity_select',
                    name: 'suffix',
                    label: '@mo:topologysuffix.label_singular',
                    other_entity: 'topologysuffix',
                    other_field: 'cn',
                    z_index: 3,
                    required: true
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
        });
        dialog.added.attach(that.on_success);

        dialog.show_edit_page = function(entity, result) {
            var suffix = this.fields.get_field('suffix').save()[0];
            var cn = result.cn[0];
            navigation.show_entity(entity.name, 'default', [suffix, cn]);
        };

        dialog.create_add_command = function(record) {

            var args = [this.fields.get_field('suffix').save()[0]];
            var cn = this.fields.get_field('cn').save()[0];
            if (cn) args.push(cn);

            var options = {
                'iparepltoposegmentleftnode':
                    this.fields.get_field('iparepltoposegmentleftnode').save()[0],
                'iparepltoposegmentrightnode':
                    this.fields.get_field('iparepltoposegmentrightnode').save()[0]
            };

            var command = rpc.command({
                entity: this.entity.name,
                method: this.method,
                retry: this.retry,
                args: args,
                options: options
            });

            return command;
        };

        dialog.open();
    };

    that.on_success = function(data) {
        that.facet.refresh();
    };

    return that;
};

/**
 * Deletes selected segment
 *
 * Facet must have 'selected_link' option.
 *
 * Facet should reflect the selection in action state: "link_selected"
 *
 * @class topology.del_segment_action
 * @extends IPA.delete_action
 */
topology.del_segment_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'segment_del';
    spec.enable_cond = spec.enable_cond || ['link_selected'];

    var that = IPA.delete_action(spec);

    that.execute_action = function(facet, on_success, on_error) {

        that.facet = facet;

        var args = [
            facet.selected_link.suffix.cn[0],
            facet.selected_link.segment.cn[0]
        ];

        rpc.command({
            entity: 'topologysegment',
            method: that.method,
            args: args,
            options: that.options,
            on_success: that.get_on_success(facet, on_success),
            on_error: that.get_on_error(facet, on_error)
        }).execute();
    };

    that.get_confirm_message = function(facet) {
        var pkey = facet.selected_link.segment.cn[0];
        var msg = that.confirm_msg.replace('${object}', pkey);
        return msg;
    };

    that.on_success = function(facet, data, text_status, xhr) {

        IPA.notify_success(data.result.summary);
        that.facet.refresh();
        that.facet.set_selected_link(null);
    };

    that.on_error = function(facet, xhr, text_status, error_thrown) {
    };

    return that;
};

/**
 * Graph widget encapsulates and supply data to graph component
 *
 * Graph is show only with domain level 1.
 *
 * @class
 */
topology.TopologyGraphWidget = declare([Stateful, Evented], {

    graph: null,

    // nodes
    container_node: null,
    el: null,

    disabled_view_el: null,
    topology_view_el: null,
    current_view_el: null,
    visualization_cnt_el: null,

    _get_servers: function() {
        var deferred = new Deferred();
        var s_promise = rpc.command({
            entity: 'server',
            method: 'find',
            options: {
                sizelimit: 0
            }
        }).execute();
        when(s_promise, lang.hitch(this, function(results) {
            // suffixes load success
            var servers = results.data.result.result;
            deferred.resolve(servers);
        }), function(results) {
            deferred.reject({
                message: 'unable to load servers',
                results: results
            });
        });
        return deferred.promise;
    },

    _get_suffixes: function() {
        var deferred = new Deferred();

        function get_suffixes() {
            return rpc.command({
                entity: 'topologysuffix',
                method: 'find',
                options: {
                    sizelimit: 0
                }
            }).execute();
        }

        function get_segments(suffix_name) {
            return rpc.command({
                entity: 'topologysegment',
                method: 'find',
                args: [suffix_name],
                options: {
                    sizelimit: 0
                }
            }).execute();
        }

        var suff_promise = get_suffixes();

        when(suff_promise, lang.hitch(this, function(results) {
            // suffixes load success
            var suffixes = results.data.result.result;
            var segment_promises = [];
            for (var i=0,l=suffixes.length; i<l; i++) {
                var suffix = suffixes[i];
                var promise = get_segments(suffix['cn'][0]);
                segment_promises.push(promise);
            }
            all(segment_promises).then(lang.hitch(this, function(results) {
                // segments load success
                for (var j=0,l=results.length; j<l; j++) {
                    suffixes[j].segments = results[j].data.result.result;
                }
                deferred.resolve(suffixes);
            }), lang.hitch(this, function(results) {
                // segments load failed
                deferred.reject({
                    message: 'unable to load segments',
                    results: results
                });
            }));
        }), lang.hitch(this, function(results) {
            // suffix load failed
            deferred.reject({
                message: 'unable to load suffixes',
                results: results
            });
        }));

        return deferred.promise;
    },

    _transform_data: function(servers, suffixes) {

        var i,l;
        var nodes = [];
        var links = [];
        var node_map = {};

        function add_to_targets(source, target, link) {
            if (!source.targets[target.id]) {
                source.targets[target.id] = [];
            }
            source.targets[target.id].push(link);
            source.targets[target.id].sort(function(a, b) {
                return a.suffix.cn[0] > b.suffix.cn[0];
            });
        }

        for (i=0,l=servers.length; i<l; i++) {
            var server = servers[i];
            var name = server.cn[0];
            var node = {
                id: name,
                data: server,
                targets: {}
            };
            node_map[name] = i;
            nodes.push(node);
        }

        for (i=0,l=suffixes.length; i<l; i++) {
            var suffix = suffixes[i];

            for (var j=0,l2=suffix.segments.length; j<l2; j++) {
                var segment = suffix.segments[j];
                var direction = segment.iparepltoposegmentdirection[0];
                var source_cn = segment.iparepltoposegmentleftnode[0];
                var target_cn = segment.iparepltoposegmentrightnode[0];

                // check for invalid segments - can happen if there is
                // some issue with topo plugin
                if (node_map[source_cn] === undefined ||
                    node_map[target_cn] === undefined) {
                    window.console.log('dangling segment: ' + segment.cn[0]);
                    continue; // skip invalid segments
                }

                var link = {
                    source: node_map[source_cn],
                    target: node_map[target_cn],
                    left: true,
                    right: true,
                    suffix: suffix,
                    segment: segment
                };
                if (direction === 'left') {
                    link.right = false;
                } else if (direction === 'right') {
                    link.left = false;
                }

                links.push(link);
                var src_node = nodes[link.source];
                var target_node = nodes[link.target];
                add_to_targets(src_node, target_node, link);
                add_to_targets(target_node, src_node, link);
            }
        }

        var data = {
            nodes: nodes,
            links: links,
            suffixes: suffixes
        };

        return data;
    },

    _get_data: function() {

        var deferred = new Deferred();

        var segments = this._get_suffixes();
        var masters = this._get_servers();

        all([masters, segments]).then(lang.hitch(this, function(raw) {
            var data = this._transform_data(raw[0], raw[1]);
            deferred.resolve(data);
        }), function(error) {
            deferred.reject(error);
        });

        return deferred.promise;
    },

    update: function() {
        this._update_view();

        if (IPA.domain_level < topology.required_domain_level) return;

        when(this._get_data()).then(lang.hitch(this, function(data) {
            if (!this.graph) {
                this.graph = new topology_graph.TopoGraph({
                    nodes: data.nodes,
                    links: data.links,
                    suffixes: data.suffixes
                });
                this._bind_graph_events(this.graph);
                this.graph.initialize(this.visualization_cnt_el);

            } else {
                this.graph.update(data.nodes, data.links, data.suffixes);
            }
        }), function(error) {
            IPA.notify(error.message, 'error');
        });
    },

    _bind_graph_events: function(graph) {

        var self = this;
        function forward(event) {
            on(graph, event, function(data) {
                self.emit(event, data);
            });
        }

        forward('link-selected');
    },

    _update_view: function() {

        var view;

        if (IPA.domain_level < topology.required_domain_level) {
            if (!this.disabled_view_el) {
                view = this._render_disabled_view();
            } else {
                view = this.disabled_view_el;
            }
        } else {
            if (!this.topology_view_el) {
                view = this._render_topology_view();
            } else {
                view = this.topology_view_el;
            }
        }
        if (view !== this.current_view_el) {
            this.el.empty();
            view.appendTo(this.el);
        }
        this.current_view_el = view;
    },

    render: function() {
        this.el = $('<div/>', { 'class': this.css_class });
        this._update_view();
        if (this.container_node) {
            this.el.appendTo(this.container_node);
        }
        return this.el;
    },

    _render_disabled_view: function() {
        if (this.disabled_view_el) return this.disabled_view_el;

        this.disabled_view_el = $('<div/>', { 'class': 'disabled-view' });
        var msg = text.get('@i18n:objects.topology.insufficient_domain_level');
        msg = msg.replace('${domainlevel}', topology.required_domain_level);
        $('<div/>')
            .append(
                $('<p/>', {
                    text: msg
                })
            )
            .appendTo(this.disabled_view_el);

        return this.disabled_view_el;
    },

    _render_topology_view: function() {
        if (this.topology_view_el) return this.topology_view_el;

        this.topology_view_el = $('<div/>', { 'class': 'topology-view' });
        this.visualization_cnt_el = $('<div/>', { 'class': 'visualization' }).
            appendTo(this.topology_view_el);

        return this.topology_view_el;
    },

    _init_widgets: function() {
    },

    constructor: function(spec) {
        lang.mixin(this, spec);
        this._init_widgets();
    }
});

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
    var fa = reg.facet;
    var w = reg.widget;

    e.register({type: 'topologysuffix', spec: topology.suffix_spec});
    e.register({type: 'topologysegment', spec: topology.segment_spec});
    e.register({type: 'server', spec: topology.server_spec});
    e.register({type: 'domainlevel', spec: topology.domainlevel_spec});

    a.register('domainlevel_set', topology.domainlevel_set_action);
    a.register('segment_add', topology.add_segment_action);
    a.register('segment_del', topology.del_segment_action);

    w.register('topology-graph', topology.TopologyGraphWidget);
    fa.register({
        type: 'topology-graph',
        ctor: topology.TopologyGraphFacet,
        spec: topology.topology_graph_facet_spec
    });
};

phases.on('registration', topology.register);
phases.on('post-metadata', topology.domainlevel_metadata);

return topology;
});
