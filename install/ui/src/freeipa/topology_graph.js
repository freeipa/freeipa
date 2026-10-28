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
    _adder_anim_duration: 200,
    _adder_inner_radius: 15,
    _adder_outer_radius: 30,
    _colors: d3.scale.category10(),
    _svg : null,
    _path: null,
    _circle: null,

    _create_agreement: null,
    _selected_link: null,
    _mousedown_link: null,
    _source_node: null,
    _source_node_html: null,
    _target_node: null,
    _drag_line: null,

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
     * List of suffixes
     * @property {Array}
     */
    suffixes: [],

    /**
     * Initializes the graph
     * @param  {HTMLElement} container container where to put the graph svg element
     */
    initialize: function(container) {
        this._create_svg(container);
        this.update(this.nodes, this.links, this.suffixes);
        return;
    },

    /**
     * Update the graph
     * @param  {Array} nodes    array of node objects
     * @param  {Array} links    array of link objects
     * @param  {Array} suffixes array of suffixes
     */
    update: function(nodes, links, suffixes) {
        var curr_trasform = this._get_stored_transformation();

        var zoomed = function() {
            var translate = d3.event.translate;
            var scale = d3.event.scale;
            var transform = "translate(" + translate + ")scale(" + scale + ")";

            this._svg.selectAll('g.shapes')
                .attr("transform", transform);
            this._store_current_transformation();
        }.bind(this);

        // adds zoom behavior to the svg
        var zoom = d3.behavior.zoom()
            .translate(curr_trasform.translate)
            .scale(curr_trasform.scale)
            .scaleExtent([0.2, 1])
            .on("zoom", zoomed);

        // delete all from svg
        this._svg.selectAll("*").remove();
        this._svg.attr('width', this.width)
                 .attr('height', this.height)
                 .call(zoom);

        this.links = links;
        this.nodes = nodes;
        this.suffixes = suffixes;

        // load saved coordinates
        // node.fixed uses integer
        // this is useful when you need to store the original value and set
        // the node temporarily fixed
        for (var i=0,l=nodes.length; i<l; i++) {
            var node = nodes[i];
            node.fixed = 0;
            if (this._get_local_storage_attr(node.id, 'fixed')) {
                node.fixed = 1;
                node.x = Number(this._get_local_storage_attr(node.id, 'x'));
                node.y = Number(this._get_local_storage_attr(node.id, 'y'));
            }
            node.ca_adder = d3.svg.arc()
                .innerRadius(this._adder_inner_radius)
                .outerRadius(this._adder_inner_radius)
                .startAngle(2 * (Math.PI/180))
                .endAngle(178 * (Math.PI/180));

            node.domain_adder = d3.svg.arc()
                .innerRadius(this._adder_inner_radius)
                .outerRadius(this._adder_inner_radius)
                .startAngle(182 * (Math.PI/180))
                .endAngle(358 * (Math.PI/180));

            node.drag_mode = false;
        }

        this._init_layout();
        this._define_shapes();

        // handles to link and node element groups
        // the order of adding shapes is important because of order of showing
        // them
        this._path = this._svg.append('svg:g')
                              .classed('shapes', true)
                              .selectAll('path');

        this._drag_line = this._svg.append('svg:g')
            .classed('shapes', true)
            .append('path')
            .style('marker-end', 'url(#end-arrow)')
            .attr('class', 'link dragline hidden')
            .attr('d', 'M0,0L0,0')
            .on('click', function() {
                d3.event.preventDefault();
                d3.event.stopPropagation();

                this._create_agreement = false;
                this.reset_mouse_vars();

                this._drag_line
                    .classed('hidden', true)
                    .style('marker-end', '');

                this.restart();

            }.bind(this));

        this._circle = this._svg.append('svg:g')
                           .classed('shapes', true)
                           .selectAll('g');

        this._selected_link = null;
        this._mousedown_link = null;
        this._selected_node = null;
        this._source_node = null;
        this._target_node = null;
        this.restart();
    },
    _create_svg: function(container) {
        var self = this;

        this._svg = d3.select(container[0]).
            append('svg').
            attr('width', this.width).
            attr('height', this.height).
            on('mousemove', mousemove);

            function mousemove(d) {
                if (!self._source_node && !self._create_agreement) return;

                var translate = self._get_stored_transformation();
                var x = self._source_node.x;
                var y = self._source_node.y;

                var mouse_x = x + d3.mouse(self._source_node_html)[0];
                var mouse_y = y + d3.mouse(self._source_node_html)[1];

                // update drag line
                self._drag_line.attr('d', 'M' + x + ',' + y + 'L' + mouse_x + ',' + mouse_y);

                self.restart();
            }

    },

    _init_layout: function() {
        var l = this._layout = d3.layout.force();
        l.links(this.links);
        l.nodes(this.nodes);
        l.size([this.width, this.height]);
        l.linkDistance(150);
        l.charge(-1000);
        l.on('tick', this._tick.bind(this));

        var that = this;

        l.on('end', function () {
            var nodes = l.nodes();

            for (var i = 0; i < nodes.length; i++) {
                var curr_node = nodes[i];

                if (!curr_node.fixed) {
                    curr_node.fixed = 1;
                    that._save_node_info(curr_node);
                }
            }
        });
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
            this._set_local_storage_attr(d.id, 'fixed', d.fixed + '');
            this._set_local_storage_attr(d.id, 'x', d.x);
            this._set_local_storage_attr(d.id, 'y', d.y);
        } else {
            this._remove_local_storage_attr(d.id, 'fixed');
            this._remove_local_storage_attr(d.id, 'x');
            this._remove_local_storage_attr(d.id, 'y');
        }
    },

    _store_current_transformation: function(d) {
        var prefix = "graph_";
        var translate = d3.event.translate;
        var scale = d3.event.scale;

        this._set_local_storage_attr(prefix, "translate", translate);
        this._set_local_storage_attr(prefix, "scale", scale);
    },

    _get_stored_transformation: function(d) {
        var prefix = "graph_";
        var current_translate = this._get_local_storage_attr(prefix, "translate");
        var current_scale = this._get_local_storage_attr(prefix, "scale");

        if (current_translate) {
            var temp_translate = current_translate.split(",");
            temp_translate[0] = parseInt(temp_translate[0], 10);
            temp_translate[1] = parseInt(temp_translate[1], 10);
            current_translate = temp_translate;
        } else {
            current_translate = [0, 0];
        }

        if (!current_scale) {
            current_scale = 1;
        }

        return {
            translate: current_translate,
            scale: current_scale
        };
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
                spad = 18, // source padding
                tpad = 18, // target padding
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
     * Defines link arrows and colors of suffixes(links) and nodes
     */
    _define_shapes: function() {

        var name, color;

        var defs = this._svg.selectAll('defs');
        defs.remove();

        var x = 10;
        var y = 20;

        for (var i=0,l=this.suffixes.length; i<l; i++) {

            var suffix = this.suffixes[i];
            color = d3.rgb(this._colors(suffix.cn[0]));

            name = this._get_marker_name(suffix, false);
            this._add_marker(name, color, 'M0,-5L10,0L0,5');

            name = this._get_marker_name(suffix, true);
            this._add_marker(name, color, 'M10,-5L0,0L10,5');

            this._append_suffix_hint(suffix, x, y);
            y += 30;
        }
    },

    /**
     * Returns lenght of string with set class in pixels
     */
     _count_string_size: function(str, cls) {
         if (!str) return 0;

         cls = cls || '';

         var node = this._svg.append('text')
            .classed(cls, true)
            .text(str);

         var length = node.node().getComputedTextLength();

         node.remove();

         return length;
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

        var drag = d3.behavior.drag()
            .on("dragstart", dragstarted)
            .on("drag", dragged)
            .on("dragend", dragended);

        function dragstarted(d) {
            d.drag_mode = true;
            hide_semicircles.bind(this, d)();
            d3.event.sourceEvent.stopPropagation();
            // Store the original value of fixed and set the node fixed.
            d.fixed = d.fixed << 1;
            d.fixed |= 1;
        }

        function dragged(d) {
            d.px = d3.event.x;
            d.py = d3.event.y;
            var translate = "translate(" + d.x + "," + d.y + ")";
            d3.select(this).attr('transform', translate);
            self._layout.resume();
        }

        function dragended(d) {
            d.drag_mode = false;
            // Restore old value of fixed.
            d.fixed = d.fixed >> 1;
            self._layout.resume();
        }

        function add_labels(type, color, adder_group) {
            var label_radius = 3;
            var decimal_plus = parseInt('f067', 16); // Converts hexadecimal
            // code of plus icon to decimal.

            var plus = adder_group
                .append('text')
                .classed('plus', true)
                .classed(type + '_plus', true)
                .text(String.fromCharCode(decimal_plus));

            var label = adder_group.append('path')
                    .attr('id', type + '_label');

            if (type === 'ca') {
                plus.attr('dx', '18')
                    .attr('dy', '4');
                var adder_label = adder_group.append('text')
                    .append('textPath')
                        .classed('adder_label', true)
                        .style('fill', color)
                        .attr('xlink:href', '#' + type + '_label')
                        .text(type);

                var str_size = self._count_string_size(type, 'adder_label');
                var str_translate = str_size + self._adder_outer_radius + 3;
                label.attr('d', 'M 33 3 L ' + str_translate + ' 3');

                adder_group.insert('rect', 'text')
                    .attr('x', '33')
                    .attr('y', '-11')
                    .attr('rx', label_radius)
                    .attr('ry', label_radius)
                    .attr('width', str_size)
                    .attr('height', '18')
                    .style("fill", "white");
            }
            else {
                plus.attr('dx', '-26')
                    .attr('dy', '4');
                adder_label = adder_group.append('text')
                    .append('textPath')
                        .classed('adder_label', true)
                        .style('fill', color)
                        .attr('xlink:href', '#' + type + '_label')
                        .text(type);

                str_size = self._count_string_size(type, 'adder_label');
                str_translate = str_size + self._adder_outer_radius + 3;
                label.attr('d', 'M -' + str_translate + ' 3 L -33 3');

                adder_group.insert('rect', 'text')
                    .attr('x', '-'+str_translate)
                    .attr('y', '-11')
                    .attr('rx', label_radius)
                    .attr('ry', label_radius)
                    .attr('width', str_size)
                    .attr('height', '18')
                    .style('fill', 'white');
            }
        }

        function create_semicircle(d, type) {
            var color = d3.rgb(self._colors(type)).toString();
            var adder_group = d3.select(this).select('g');
            var scale = '1.05';

            adder_group.append("path")
                .classed(type+'_adder', true)
                .classed('adder', true)
                .attr("d", d[type + '_adder'])
                .attr("fill", color)
                .on('mouseover', function(d) {
                    window.clearTimeout(d._timeout_hide);

                    d3.select(this).attr('transform', 'scale('+scale+')');
                    adder_group.select('text.' + type + '_plus')
                        .attr('transform', 'scale('+scale+')');
                })
                .on('mouseout', function(d) {
                    d3.select(this).attr('transform', '');
                    adder_group.select('text.' + type + '_plus')
                        .attr('transform', '');
                })
                .on('click', function(d) {
                    d3.event.preventDefault();
                    d3.event.stopPropagation();
                    self.emit('link-selected', { link: null });

                    hide_semicircles.bind(this, d)();

                    // select node
                    if (!self._source_node) {
                        self._source_node = d;
                        self._source_node_html = d3.select(this)
                                                    .select('circle').node();
                        self._create_agreement = true;
                    }

                    self._selected_link = null;

                    var translate = self._get_stored_transformation();
                    var x = self._source_node.x;
                    var y = self._source_node.y;

                    // add position of node + translation of whole graph + relative
                    // position of the mouse
                    var mouse_x = d.x + d3.mouse(this)[0];
                    var mouse_y = d.y + d3.mouse(this)[1];

                    // reposition drag line
                    self._drag_line
                        .style('marker-end', 'url(#' + type + '-end-arrow)')
                        .style('stroke', color)
                        .classed('hidden', false)
                        .attr('suffix', type)
                        .attr('d', 'M' + x + ',' + y +
                                'L' + mouse_x + ',' + mouse_y);

                    self.restart();
                }.bind(this))
                .on('mousedown.drag', function() {
                    d3.event.preventDefault();
                    d3.event.stopPropagation();
                })
                .transition()
                    .duration(self._adder_anim_duration)
                    .attr("d", d[type + '_adder']
                        .outerRadius(self._adder_outer_radius))
                    .each('end', function() {
                        add_labels(type, color, adder_group);
                    });
        }

        function show_semicircles(d) {

            if(!d3.select(this).select('g path').empty()) return;

            if (!d.drag_mode && !self._create_agreement) {

                // append invisible circle which covers spaces between node
                // and adders it prevents hiding adders when mouse is on the space
                d3.select(this).append('g')
                    .append('circle')
                    .attr('r', self._adder_outer_radius)
                    .style('opacity', 0);
                create_semicircle.bind(this, d, 'ca')();

                create_semicircle.bind(this, d, 'domain')();

                //move the identification text
                d3.select(this).select('text')
                    .transition()
                        .duration(self._adder_anim_duration)
                        .attr('dy', '45');
            }
        }

        function hide_semicircles(d) {
            var curr_nod = d3.select(this);
            curr_nod.selectAll('.plus,.adder_label,rect')
                .transition()
                    .ease('exp')
                    .duration(100)
                    .style('font-size', '0px')
                    .remove();
            curr_nod.select('path.domain_adder')
                .transition()
                    .attr("d", d.domain_adder
                        .outerRadius(self._adder_inner_radius))
                    .duration(self._adder_anim_duration);
            curr_nod.select('path.ca_adder')
                .transition()
                    .attr("d", d.ca_adder
                        .outerRadius(self._adder_inner_radius))
                    .duration(self._adder_anim_duration);
            curr_nod.select('g')
                .transition()
                    .duration(self._adder_anim_duration)
                    .remove();
            curr_nod.select('text')
                .transition()
                    .attr('dy', '30')
                    .duration(self._adder_anim_duration);
        }

        function is_suffix_shown(suffix) {
            var links = self._source_node.targets[self._target_node.id];

            if (!links) return false;

            for (var i=0, l=links.length; i<l; i++) {
                var link = links[i];
                if (link.suffix.cn[0] === suffix) {
                    self._selected_link = link;
                    self.emit('link-selected', { link: link });
                    return true;
                }
            }

            return false;
        }

        // add new nodes
        var g = this._circle.enter()
            .append('svg:g')
            .on("dblclick", function(d) {
                // Stops propagation dblclick event to the zoom behavior.
                d3.event.preventDefault();
                d3.event.stopPropagation();
                //xor operation switch value of fixed from 1 to 0 and vice versa
                d.fixed = d.fixed ^ 1;
                self._layout.resume();
            })
            .on('mouseover', function(d) {
                window.clearTimeout(d._timeout_hide);
                show_semicircles.bind(this, d)();
                d3.select('circle.cover').classed('cover', true);
            })
            .on('mouseout', function(d) {
                d._timeout_hide = window.setTimeout(hide_semicircles
                                                        .bind(this, d), 50);
            })
            .on('click', function(d) {
                if (!self._create_agreement) return;

                d3.event.preventDefault();
                d3.event.stopPropagation();

                if (self._source_node !== d) {
                    self._target_node = d;
                    var source = self._source_node;
                    var target = self._target_node;
                    var suffix = self._drag_line.attr('suffix');
                    var direction = 'left';
                    var link = {
                        source: source,
                        target: target,
                        suffix: suffix,
                        left: false,
                        right: false
                    };

                    if (!is_suffix_shown(suffix)) {
                        link[direction] = true;
                        self.emit('add-agreement', link);
                    }
                }

                self._drag_line
                    .classed('hidden', true)
                    .attr('suffix', '')
                    .style('marker-end', '');

                self.restart();
                self.reset_mouse_vars();
            })
            .call(drag);

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
                return d.caption;
            });

        // remove old nodes
        self._circle.exit().remove();

        // get previously set position and scale of the graph and move current
        // graph to the proper position
        var curr_transform = this._get_stored_transformation();
        var transform = "translate(" + curr_transform.translate +
                        ")scale(" + curr_transform.scale + ")";

        this._svg.selectAll('g.shapes')
            .attr("transform", transform);
    },

    reset_mouse_vars: function() {
        this._source_node = null;
        this._source_node_html = null;
        this._target_node = null;
        this._mousedown_link = null;
        this._create_agreement = null;

    },

    resize: function(height, width) {
        if (!(isNaN(height) || isNaN(width))) {
            this.height = height < 0 ? 0 : height;
            this.width = width < 0 ? 0 : width;

            if (this._svg) {
                this._svg
                    .attr('width', this.width)
                    .attr('height', this.height);
            }
        }
    },

    constructor: function(spec) {
        lang.mixin(this, spec);
    }
});

return topology_graph;
});
