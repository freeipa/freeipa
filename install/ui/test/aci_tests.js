/*  Authors:
 *    Adam Young <ayoung@redhat.com>
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
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
        'freeipa/metadata',
        'freeipa/aci',
        'freeipa/details',
        'freeipa/facet',
        'freeipa/field',
        'freeipa/ipa',
        'freeipa/jquery',
        'freeipa/reg',
        'freeipa/widget'
       ],
        function(md, aci, mod_details, mod_facet, fields, IPA, $, reg, widgets) {
    return function() {

var target_container;
var target_widget;
var target_facet;
var entity = IPA.entity({ name: 'bogus', redirect_facet: 'details' });
var group_entity = IPA.entity({ name: 'group' });

module('aci', {
        setup: function() {

            fields.register();
            widgets.register();
            aci.register();
            mod_facet.register();
            mod_details.register();

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
                        $type: 'radio',
                        name: 'target',
                        widget: 'target.target',
                        enabled: false
                    },
                    {
                        $type: 'multivalued',
                        name: 'extratargetfilter',
                        widget: 'target.extratargetfilter',
                        acl_param: 'ipapermtargetfilter',
                        enabled: false
                    },
                    {
                        $type: 'multivalued',
                        name: 'memberof',
                        widget: 'target.memberof',
                        enabled: false
                    },
                    {
                        name: 'ipapermlocation',
                        widget: 'target.ipapermlocation',
                        enabled: false
                    },
                    {
                        name: 'ipapermtarget',
                        widget: 'target.ipapermtarget',
                        enabled: false
                    },
                    {
                        $type: 'select',
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
                        $type: 'multivalued',
                        widget: 'target.attrs_multi',
                        enabled: false
                    }
                ],
                widgets: [
                    {
                        $type: 'permission_target',
                        container_factory: IPA.details_section,
                        group_entity: group_entity,
                        name: 'target',
                        label: 'Target',
                        show_target: false
                    }
                ],
                policies: [
                    {
                        $factory: aci.permission_target_policy,
                        widget_name: 'target'
                    }
                ]
            });
            entity.add_facet('details', target_facet);
            target_container = $('<div id="content"/>').appendTo(document.body);
            target_facet.container_node = target_container[0];
            target_facet.create();
            target_widget = target_facet.widgets.get_widget('target');
        },
        teardown: function() {
            target_container.remove();
        }}
);


test("aci.attributes_widget", function() {

    var aciattrs = md.source.objects.user.aciattrs;

    var container = $('<span/>', {
        name: 'attrs'
    });

    var widget = aci.attributes_widget({
        name: 'attrs',
        object_type: 'user',
        entity:entity
    });

    widget.create(container);

    var table = $('table', container);

    ok(
        table,
        'Widget contains table');

    widget.update({});
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

test("aci.rights_widget.", function() {

    var container = $('<span/>', {
        name: 'permissions'
    });

    var widget = aci.rights_widget({
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


test("Testing type target.", function() {
    var data = {
        id: null,
        error: null,
        result: { result: { type: 'hostgroup'} }
    };

    target_facet.load(data);

    same(target_widget.target, 'type', 'type selected');

    var attrs_w = target_widget.widgets.get_widget('attrs');
    var options = attrs_w.options;
    ok(options.length > 0, "Attrs has some options");
    // check them all
    var values = [];
    for (var i=0,l=options.length; i<l; i++) {
        values.push(options[i].value);
    }
    attrs_w.update(values);
    attrs_w.emit('value-change', { source: attrs_w });

    var record = {};
    target_facet.save(record);

    same(record.type[0], data.result.result.type,
         "saved type matches sample data");

    same(get_visible_rows(target_widget), ['type', 'extratargetfilter',
        'ipapermtarget', 'memberof', 'attrs'],
        'type and attrs rows visible');

    same(record.attrs.length, options.length, "response contains all checked attrs");
});


test("Testing general target.", function() {

    var data = {
        id: null,
        error: null,
        result: { result: { extratargetfilter: 'hostgroup'} }
    };

    target_facet.load(data);

    var record = {};
    target_facet.save(record);

    same(target_widget.target, 'general', 'general selected');

    same(get_visible_rows(target_widget), ['type', 'ipapermlocation',
        'extratargetfilter', 'ipapermtarget', 'memberof',
        'attrs_multi'], 'general target fields visible');

    same(record.extratargetfilter[0], data.result.result.extratargetfilter, 'filter set correctly');
});

};});
