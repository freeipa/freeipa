/*  Authors:
 *    Adam Young <ayoung@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */


var target_container;
var target_widget;
var target_facet;
var entity = IPA.entity({ name: 'bogus', redirect_facet: 'details' });
var group_entity = IPA.entity({ name: 'group' });

module('aci', {
        setup: function() {
            IPA.ajax_options.async = false;
            IPA.init({
                url: 'data',
                on_error: function(xhr, text_status, error_thrown) {
                    ok(false, "ipa_init() failed: "+error_thrown);
                }
            });

           target_facet = IPA.details_facet({
                entity: entity,
                fields: [
                    {
                        type: 'select',
                        name: 'target',
                        widget: 'target.target',
                        enabled: false
                    },
                    {
                        name: 'filter',
                        widget: 'target.filter',
                        enabled: false
                    },
                    {
                        type: 'entity_select',
                        name: 'memberof',
                        widget: 'target.memberof',
                        enabled: false
                    },
                    {
                        name: 'subtree',
                        widget: 'target.subtree',
                        enabled: false
                    },
                    {
                        type: 'entity_select',
                        name: 'targetgroup',
                        widget: 'target.targetgroup',
                        enabled: false
                    },
                    {
                        type: 'select',
                        name: 'type',
                        widget: 'target.type',
                        enabled: false
                    },
                    {
                        name: 'attrs',
                        widget: 'target.attrs',
                        enabled: false
                    },
                    {
                        name: 'attrs_multi',
                        param: 'attrs',
                        type: 'multivalued',
                        widget: 'target.attrs_multi',
                        enabled: false
                    }
                ],
                widgets: [
                    {
                        type: 'permission_target',
                        container_factory: IPA.details_table_section,
                        group_entity: group_entity,
                        name: 'target',
                        label: 'Target',
                        show_target: false
                    }
                ],
                policies: [
                    IPA.permission_target_policy('target')
                ]
            });
           entity.add_facet('details', target_facet);

            target_container = $('<div id="target"/>').appendTo(document.body);
            target_facet.create(target_container);
            target_widget = target_facet.widgets.get_widget('target');
        },
        teardown: function() {
                target_container.remove();
        }}
);


test("IPA.attributes_widget.", function() {

    var aciattrs = IPA.metadata.objects['user'].aciattrs;

    var container = $('<span/>', {
        name: 'attrs'
    });

    var widget = IPA.attributes_widget({
        name: 'attrs',
        object_type: 'user',
        entity:entity
    });

    widget.create(container);

    var table = $('table', container);

    ok(
        table,
        'Widget contains table');

    var tr = $('tbody tr', table);

    same(
        tr.length, aciattrs.length,
        'Widget contains all user ACI attributes');

    var record = {
        'attrs': [
            "unmatched",
            "cn",
            "description"
        ]
    };

    same(
        widget.save(), [],
        'Widget has no initial values');

    widget.update(record.attrs);

    tr = $('tbody tr', table);

    same(
        tr.length, aciattrs.length+1,
        'Widget contains all user ACI attributes plus 1 unmatched attribute');

    same(
        widget.save(), record.attrs.sort(),
        'All loaded values are saved and sorted');
});

test("IPA.rights_widget.", function() {

    var container = $('<span/>', {
        name: 'permissions'
    });

    var widget = IPA.rights_widget({
        name: 'permissions',
        entity:entity
    });

    widget.create(container);

    var inputs = $('input', container);

    same(
        inputs.length, widget.rights.length,
        'Widget displays all permissions');
});

var get_visible_rows = function(section) {
    var keys = section.rows.keys;

    var visible = [];

    for (var i=0; i<keys.length; i++) {
        var key = keys[i];
        var row = section.rows.get(key);
        var row_visible = row.css('display') !== 'none';
        if(row_visible) {
            visible.push(key);
        }
    }

    return visible;
};

test("Testing aci grouptarget.", function() {
    var data = {};
    data.result = {};
    data.result.result = {
        targetgroup: 'ipausers'
    };

    target_facet.load(data);

    same(target_widget.target, 'targetgroup' , 'group control selected');


    same(get_visible_rows(target_widget), ['targetgroup', 'attrs'],
        'group select row visible');

    ok ($('option', target_widget.group_select.container).length > 2,
        'group select populated');

});

test("Testing type target.", function() {
    var data = {};
    data.result = {};
    data.result.result = {
        type: 'hostgroup'
    };

    target_facet.load(data);

    same(target_widget.target, 'type', 'type selected');

    $("input[type=checkbox]").attr("checked",true);
    var record = {};
    target_facet.save(record);

    same(record.type[0], data.result.result.type,
         "saved type matches sample data");

    same(get_visible_rows(target_widget), ['memberof', 'type', 'attrs'],
        'type and attrs rows visible');

    ok((record.attrs.length > 10),
       "response length shows some attrs set");
});


test("Testing filter target.", function() {

    var data = {};
    data.result = {};
    data.result.result = {
        filter: 'somevalue'
    };

    target_facet.load(data);

    var record = {};
    target_facet.save(record);

    same(target_widget.target, 'filter', 'filter selected');

    same(get_visible_rows(target_widget), ['filter', 'attrs_multi'], 'filter row visible');

    ok(record.filter[0], data.result.result.filter, 'filter set correctly');
});



test("Testing subtree target.", function() {

    var data = {};
    data.result = {};
    data.result.result = {
        subtree: 'ldap:///cn=*,cn=roles,cn=accounts,dc=example,dc=co'
    };

    target_facet.load(data);
    var record = {};
    target_facet.save(record);

    same(record.subtree[0], data.result.result.subtree, 'subtree set correctly');

    same(get_visible_rows(target_widget), ['memberof', 'subtree', 'attrs_multi'], 'subtree row visible');
});



