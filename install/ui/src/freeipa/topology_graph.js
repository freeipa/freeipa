//
// Copyright (C) 2015  FreeIPA Contributors see COPYING for license
//

'use strict';

define([
        'dojo/_base/lang',
        'dojo/_base/declare',
        'dojo/on',
        'dojo/Evented',
        './jquery',
        'libs/d3'
],
            function(lang, declare, on, Evented, $, d3) {
/**
 * Topology Graph module
 * @class
 * @singleton
 */
var topology_graph = {
};

/**
 * Topology graph visualization
 *
 * @class
 */
topology_graph.TopoGraph = declare([Evented], {
    width: 960,
    height: 500,
    _colors: d3.scale.category10(),
    _svg : null,
    _path: null,
    _circle: null,

    _selected_link: null,
    _mousedown_link: null,

    /**
     * Nodes - IPA servers
     *   id - int
     *
     * @property {Array}
     */
    nodes: [],

    /**
     * Links between nodes
     * @property {Array}
     */
    links: [],

    /**
     * List of suffices
     * @property {Array}
     */
    suffices: [],

    /**
     * Initializes the graph
     * @param  {HTMLElement} container container where to put the graph svg element
     */
    initialize: function(container) {
        this._create_svg(container);
        this.update(this.nodes, this.links, this.suffices);
        return;
    },

    /**
     * Update the graph
     * @param  {Array} nodes    array of node objects
     * @param  {Array} links    array of link objects
     * @param  {Array} suffices array of suffices
     */
    update: function(nodes, links, suffices) {
        // delete all from svg
        this._svg.selectAll("*").remove();
        this._svg.attr('width', this.width)
                 .attr('height', this.height);

        this.links = links;
        this.nodes = nodes;
        this.suffices = suffices;

        // load saved coordinates
        for (var i=0,l=nodes.length; i<l; i++) {
            var node = nodes[i];
            if (this._get_local_storage_attr(node.id, 'fixed') === 'true') {
                node.fixed = true;
                node.x = Number(this._get_local_storage_attr(node.id, 'x'));
                node.y = Number(this._get_local_storage_attr(node.id, 'y'));
            }
        }

        this._init_layout();
        this._define_shapes();

        // handles to link and node element groups
        this._path = this._svg.append('svg:g').selectAll('path');
        this._circle = this._svg.append('svg:g').selectAll('g');

        this._selected_link = null;
        this._mouseup_node = null;
        this._mousedown_link = null;
        this.restart();
    },

    _create_svg: function(container) {
        this._svg = d3.select(container[0]).
            append('svg').
            attr('width', this.width).
            attr('height', this.height);
    },

    _init_layout: function() {
        var l = this._layout = d3.layout.force();
        l.links(this.links);
        l.nodes(this.nodes);
        l.size([this.width, this.height]);
        l.linkDistance(150);
        l.charge(-1000);
        l.on('tick', lang.hitch(this, this._tick));
    },

    _get_local_storage_attr: function(id, attr) {
        return window.localStorage.getItem('topo_' + id + attr);
    },

    _set_local_storage_attr: function(id, attr, value) {
        window.localStorage.setItem('topo_' + id + attr, value);
    },

    _remove_local_storage_attr: function(id, attr) {
        window.localStorage.removeItem('topo_' + id + attr);
    },

    _save_node_info: function(d) {
        if (d.fixed) {
            this._set_local_storage_attr(d.id, 'fixed', 'true');
            this._set_local_storage_attr(d.id, 'x', d.x);
            this._set_local_storage_attr(d.id, 'y', d.y);
        } else {
            this._remove_local_storage_attr(d.id, 'fixed');
            this._remove_local_storage_attr(d.id, 'x');
            this._remove_local_storage_attr(d.id, 'y');
        }
    },

    /**
     * Simulation tick which
     *
     * - adjusts link path and position
     * - node position
     * - saves node position
     */
    _tick: function() {
        var self = this;
        // draw directed edges with proper padding from node centers
        this._path.attr('d', function(d) {
            var node_targets = d.source.targets[d.target.id];
            var target_count = node_targets.length;
            target_count = target_count ? target_count : 0;

            // ensure right direction of curve
            var link_i = node_targets.indexOf(d);
            link_i = link_i === -1 ? 0 : link_i;
            var dir = link_i % 2;
            if (d.source.id < d.target.id) {
                dir = dir ? 0 : 1;
            }

            var dx = d.target.x - d.source.x,
                dy = d.target.y - d.source.y;
            if (dx === 0) dx = 1;
            if (dy === 0) dy = 1;
            var dist = Math.sqrt(dx * dx + dy * dy),
                ux = dx / dist, // directional vector
                uy = dy / dist,
                nx = -uy, // normal vector
                ny = ux, // normal vector
                off = dir ? -1 : 1, // determines shift direction of curve
                ns = 5, // shift on normal vector
                s = target_count > 1 ? 1 : 0, // shift from center?
                spad = d.left ? 18 : 18, // source padding
                tpad = d.right ? 18 : 18, // target padding
                sourceX = d.source.x + (spad * ux) + off * nx * ns * s,
                sourceY = d.source.y + (spad * uy) + off * ny * ns * s,
                targetX = d.target.x - (tpad * ux) + off * nx * ns * s,
                targetY = d.target.y - (tpad * uy) + off * ny * ns * s,
                dr = s ? dist * Math.log10(dist) : 0;

            return 'M' + sourceX + ',' + sourceY +
                   'A' + dr + " " + dr + " 0 0 " + dir +" " +
                         targetX + " " + targetY;
        });

        this._circle.attr('transform', function(d) {
            self._save_node_info(d);
            return 'translate(' + d.x + ',' + d.y + ')';
        });
    },

    _get_marker_name: function(suffix, start) {

        var name = suffix ? suffix.cn[0] : 'drag';
        var arrow = start ? 'start-arrow' : 'end-arrow';
        return name + '-' + arrow;
    },

    /**
     * Markers on the end of links
     */
    _add_marker: function(name, color, refX) {
        this._svg.append('svg:defs')
            .append('svg:marker')
                .attr('id', name)
                .attr('viewBox', '0 -5 10 10')
                .attr('refX', 6)
                .attr('markerWidth', 3)
                .attr('markerHeight', 3)
                .attr('orient', 'auto')
            .append('svg:path')
                .attr('d', refX)
                .attr('fill', color);
    },

    /**
     * Suffix hint so user will know which links belong to which suffix
     */
    _append_suffix_hint: function(suffix, x, y) {
        var color = d3.rgb(this._colors(suffix.cn[0]));
        this._svg.append('svg:text')
            .attr('x', x)
            .attr('y', y)
            .attr('class', 'suffix')
            .attr('fill', color)
            .text(suffix.cn[0]);
    },

    /**
     * Defines link arrows and colors of suffices(links) and nodes
     */
    _define_shapes: function() {

        var name, color;

        var defs = this._svg.selectAll('defs');
        defs.remove();

        var x = 10;
        var y = 20;

        for (var i=0,l=this.suffices.length; i<l; i++) {

            var suffix = this.suffices[i];
            color = d3.rgb(this._colors(suffix.cn[0]));

            name = this._get_marker_name(suffix, false);
            this._add_marker(name, color, 'M0,-5L10,0L0,5');

            name = this._get_marker_name(suffix, true);
            this._add_marker(name, color, 'M10,-5L0,0L10,5');

            this._append_suffix_hint(suffix, x, y);
            y += 30;
        }

        this._circle_color = this._colors(1);
    },

    /**
     * Restart the simulation to reflect changes in data/state
     */
    restart: function() {
        var self = this;

        // set the graph in motion
        self._layout.start();

        // path (link) group
        this._path = this._path.data(self._layout.links());

        // update existing links
        this._path
            .classed('selected', function(d) {
                return d === self._selected_link;
            })
            .style('marker-start', function(d) {
                var name = self._get_marker_name(d.suffix, true);
                return d.left ? 'url(#'+name+')' : '';
            })
            .style('marker-end', function(d) {
                var name = self._get_marker_name(d.suffix, false);
                return d.right ? 'url(#'+name+')' : '';
            });


        // add new links
        this._path.enter().append('svg:path')
            .attr('class', 'link')
            .style('stroke', function(d) {
                var suffix = d.suffix ? d.suffix.cn[0] : '';
                return d3.rgb(self._colors(suffix)).toString();
            })
            .classed('selected', function(d) {
                return d === self._selected_link;
            })
            .style('marker-start', function(d) {
                var name = self._get_marker_name(d.suffix, true);
                return d.left ? 'url(#'+name+')' : '';
            })
            .style('marker-end', function(d) {
                var name = self._get_marker_name(d.suffix, false);
                return d.right ? 'url(#'+name+')' : '';
            })
            .on('mousedown', function(d) {
                if (d3.event.ctrlKey) return;

                // select link
                self._mousedown_link = d;
                if (self._mousedown_link === self._selected_link) {
                    self._selected_link = null;
                } else {
                    self._selected_link = self._mousedown_link;
                }
                self.emit('link-selected', { link: self._selected_link });
                self.restart();
            });

        // remove old links
        this._path.exit().remove();

        // circle (node) group
        this._circle = this._circle.data(
            self._layout.nodes(),
            function(d) {
                return d.id;
            }
        );

        // add new nodes
        var g = this._circle.enter()
            .append('svg:g')
            .on("dblclick", function(d) {
                d.fixed = !d.fixed;
            })
            .call(self._layout.drag);

        g.append('svg:circle')
            .attr('class', 'node')
            .attr('r', 12)
            .style('fill', function(d) {
                return self._colors(1);
            })
            .style('stroke', function(d) {
                return d3.rgb(self._colors(1)).darker().toString();
            });

        // show node IDs
        g.append('svg:text')
            .attr('dx', 0)
            .attr('dy', 30)
            .attr('class', 'id')
            .attr('fill', '#002235')
            .text(function(d) {
                return d.id.split('.')[0];
            });

        // remove old nodes
        self._circle.exit().remove();
    },

    constructor: function(spec) {
        lang.mixin(this, spec);
    }
});

return topology_graph;
});
