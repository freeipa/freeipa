/**
 * Copyright (C) 2019  FreeIPA Contributors see COPYING for license
 */

define([
        'freeipa/ipa',
        'freeipa/topology',
        'freeipa/jquery'],
    function(IPA, topology, $) {
        return function() {

var widget;

function inject_data(widget, data) {
    widget._get_data = function() {
        return data;
    };
}

QUnit.module('topology', {
    beforeEach: function(assert) {
        widget = new topology.TopologyGraphWidget(
            topology.topology_graph_facet_spec
        );
        widget.render();
    }
});

QUnit.test('Testing TopoGraph nodes', function(assert) {
    var nodes = [
        { id: 'master.ipa.test' },
        { id: 'replica.ipa.test' }
    ];

    var suffixes = [
        { cn: ['ca'] },
        { cn: ['domain'] }
    ];

    inject_data(widget, { nodes: nodes, links: [], suffixes: suffixes });

    widget.update();

    assert.ok($('circle.node', widget.el).length === nodes.length,
        'Checking rendered nodes count');

    assert.ok($('text.id:eq(0)', widget.el).text() === 'master',
        'Checking "master" node label');
    assert.ok($('text.id:eq(1)', widget.el).text() === 'replica',
        'Checking "replica" node label');

    assert.ok($('text.suffix:eq(0)', widget.el).text() === 'ca',
        'Checking "ca" suffix');
    assert.ok($('text.suffix:eq(1)', widget.el).text() === 'domain',
        'Checking "domain" suffix');
});

QUnit.test('Testing TopoGraph links', function(assert) {
    var nodes = [
        { id: 'master.ipa.test', targets: { 'replica.ipa.test': [] } },
        { id: 'replica.ipa.test' }
    ];

    var suffixes = [
        { cn: ['ca'] },
        { cn: ['domain'] }
    ];

    var links = [{
        source: 0,
        target: 1,
        left: false,
        right: true,
        suffix: suffixes[0]
    }];

    inject_data(widget, { nodes: nodes, links: links, suffixes: suffixes });
    widget.update();

    assert.ok($('circle.node', widget.el).length === nodes.length,
        'Checking rendered nodes count');

    var rendered_links = $('path.link', widget.el).not('.dragline');
    assert.ok(rendered_links.length === 1,
        'Checking right direction link is rendered');

    var marker = rendered_links.first().css('marker-end');
    assert.ok(marker && marker !== 'none',
        'Checking right direction link has proper marker');

    links.push({
        source: 0,
        target: 1,
        left: true,
        right: false,
        suffix: suffixes[1]
    })

    inject_data(widget, {
        nodes: nodes,
        links: links,
        suffixes: suffixes
    });
    widget.update();

    rendered_links = $('path.link', widget.el).not('.dragline')
    assert.ok(rendered_links.length === 2,
        'Checking left direction link is rendered');

    marker = rendered_links.last().css('marker-start');
    assert.ok(marker && marker !== 'none',
        'Checking left direction link has proper marker');
});

QUnit.test('Testing TopoGraph for multiple DNS zones', function(assert) {
    var nodes = [
        { id: 'master.ipa.zone1' },
        { id: 'replica.ipa.zone1' },
        { id: 'master.ipa.zone2' },
        { id: 'master.ipa.zone1.common' },
        { id: 'replica.ipa.zone2.common' },
    ];

    var suffixes = [
        { cn: ['ca'] },
        { cn: ['domain'] }
    ];

    inject_data(widget, { nodes: nodes, links: [], suffixes: suffixes });
    widget.update();

    $('text.id', widget.el).each(function(i) {
        assert.ok($(this).text() === nodes[i].id,
            'Checking node label "' + $(this).text() + '" is FQDN');
    });

    nodes = nodes.filter(function(node) { return /\.common$/.test(node.id) });

    inject_data(widget, { nodes: nodes, links: [], suffixes: suffixes });
    widget.update();

    $('text.id', widget.el).each(function(i) {
        assert.ok($(this).text().indexOf('common') < 0,
            'Checking node label "' + $(this).text() + '" is relative');
    });
});

QUnit.test('Testing TopoGraph with one node', function(assert) {
    var node = { id: 'master.ipa.test' };

    inject_data(widget, { nodes: [node], links: [], suffixes: [] });
    widget.update();

    assert.ok($('text.id:eq(0)', widget.el).text() === node.id,
        'Checking node label is FQDN');
});

};});
