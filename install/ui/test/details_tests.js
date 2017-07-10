/*  Authors:
 *    Adam Young <ayoung@redhat.com>
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
    'freeipa/ipa',
    'freeipa/jquery',
    'freeipa/details',
    'freeipa/facet',
    'freeipa/field',
    'freeipa/reg',
    'freeipa/rpc',
    'freeipa/entity',
    'freeipa/widget'],
        function(md, IPA, $, mod_details, mod_facet, mod_field, reg, rpc) {
    return function() {

var details_container;


module('details', {
    setup: function() {
        IPA.ajax_options.async = false;

        mod_facet.register();
        mod_details.register();
        mod_field.register();

        IPA.init({
            url: 'data',
            on_error: function(xhr, text_status, error_thrown) {
                ok(false, "ipa_init() failed: "+error_thrown);
            }
        });

        details_container = $('<div id="details"/>').appendTo(document.body);

        IPA.register('user', function(spec) {

            return IPA.entity({
                name: 'user',
                metadata: md.source.objects.user
            });
        });
    },
    teardown: function() {
        details_container.remove();
        reg.facet.remove('details');
    }
});


test("Testing IPA.details_section.create().", function() {

    var facet = IPA.details_facet({
        entity: IPA.get_entity('user'),
        sections: [
            {
                name:'IDIDID',
                label:'NAMENAMENAME',
                fields: [
                    'cn', 'uid', 'mail'
                ]
            }
        ]
    });

    var section = facet.widgets.get_widget('IDIDID');

    ok(section !== null, 'Verifying section existence.');

    var fields = section.widgets.get_widgets();
    var container = $("<div/>");
    section.create(container);

    var section_el = $('.details-section-content', container);

    same(
        section_el.length, 1,
        'Verifying section element');

    var controls = $('.form-group', section_el);
    same(
        controls.length, fields.length,
        'Verifying number of controls');

    for (var i=0; i<fields.length; i++) {
        var field = fields[i];

        var field_label = $('.control-label label[name='+field.name+']', container);
        same(
            field_label.text(), field.label,
            'Verifying label for field '+field.name);

        var field_container = $('.controls div[name='+field.name+']', container);

        ok(
            field_container.length,
            'Verifying container for field '+field.name);

        ok(
            field_container.hasClass('widget'),
            'Verifying field '+field.name+' was created');
    }
});



test("Testing details lifecycle: create, load.", function(){

    var data = {};
    data.result = {};
    data.result.result = {};

    rpc.command({
        entity: 'user',
        method: 'show',
        args: ['kfrog'],
        on_success: function(data, text_status, xhr) {
            ok(true, "rpc.command() succeeded.");
        },
        on_error: function(xhr, text_status, error_thrown) {
            ok(false, "rpc.command() failed: "+error_thrown);
        }
    }).execute();

    var save_called = false;
    var load_called = false;

    var load_success_called = false;
    var load_failure_called = false;
    var update_success_called = false;
    var update_failure_called = false;

    function test_field(spec) {
        var that = IPA.field(spec);

        that.load = function(record) {
            load_called = true;
            that.field_load(record);
        };

        return that;
    }

    function test_widget(spec) {
        var that = IPA.input_widget(spec);

        that.widget_save = that.save;

        that.save = function() {
            save_called = true;
            return that.widget_save();
        };

        return that;
    }

    reg.field.register('test', test_field);
    reg.widget.register('test', test_widget);

    IPA.register('user', function(spec) {

        var that = IPA.entity(spec);

        that.init = function() {
            that.entity_init();

            that.builder.details_facet({
                sections: [
                    {
                        name: 'identity',
                        label: IPA.messages.details.identity,
                        fields: [ 'title', 'givenname', 'sn', 'cn', 'displayname', 'initials' ]
                    },
                    {
                        name: 'contact',
                        label: 'contact',
                        fields: [
                            {
                                $type: 'test',
                                name:'test'
                            },
                            {
                                $type: 'multivalued',
                                name:'mail'
                            },
                            {
                                $type: 'multivalued',
                                name:'telephonenumber'
                            },
                            {
                                $type: 'multivalued',
                                name:'pager'
                            },
                            {
                                $type: 'multivalued',
                                name:'mobile'
                            },
                            {
                                $type: 'multivalued',
                                name:'facsimiletelephonenumber'
                            }
                        ]
                    }
                ]
            });
        };

        return that;
    });

    var entity = IPA.get_entity('user');
    var container = $('<div/>', {}).appendTo(details_container);
    var facet = entity.get_facet('details');
    facet.container_node = container[0];
    facet.create();

    facet.load(data);

    var contact = $('.details-section[name=contact]', facet.dom_node);

    ok(
        contact.length,
        'Verifying section for contact is created');

    var identity = $('.details-section[name=identity]', facet.dom_node);

    ok(
        identity.length,
        'Verifying section for identity is created');

    var rows = $('.form-group', identity);

    same(
        rows.length, 6,
        'Verifying rows for identity');

    ok (load_called, 'load manager called');

    var field = facet.fields.get_field('test');
    field.set_value("foo");
    var widget = facet.widgets.get_widget('contact.test');
    // simulate user change
    widget.emit('value-change', { source: widget, value: "foo" });

    facet.update(
        function(){update_success_called = true;},
        function(){update_failure_called = true;});

    ok (update_success_called,'update success called');
    ok (!update_failure_called,'update failure not called');
    ok (save_called, 'save called');

});


test("Testing IPA.details_section_create again()",function() {

    var facet = IPA.details_facet({
        entity: IPA.get_entity('user'),
        disable_breadcrumb: true,
        disable_facet_tabs: true,
        sections: [
            {
                name:'IDIDID',
                label:'NAMENAMENAME',
                fields: [
                    {
                        name: 'cn',
                        label: 'Entity Name'
                    },
                    {
                        name: 'description',
                        label: 'Description'
                    },
                    {
                        name: 'number',
                        label: 'Entity ID'
                    }
                ]
            }
        ]
    });

    var section = facet.widgets.get_widget('IDIDID');
    ok(section !== null, 'Verifying section existence.');
    var fields = section.widgets.get_widgets();

    var container = $("<div title='entity'/>");
    var details = $("<div/>");
    container.append(details);

    var data = {};
    data.result = {};
    data.result.result = {};

    section.create(container);
    facet.load(data);

   var section_el = $('.details-section-content', container);

    same(
        section_el.length, 1,
        'Verifying section element');

    var controls = $('.form-group', section_el);
    same(
        controls.length, fields.length,
        'Verifying number of controls');

    for (var i=0; i<fields.length; i++) {
        var field = fields[i];

        var field_label = $('.control-label label[name='+field.name+']', container);
        same(
            field_label.text(), field.label,
            'Verifying label for field '+field.name);

        var field_container = $('.controls div[name='+field.name+']', container);

        ok(
            field_container.length,
            'Verifying container for field '+field.name);

        ok(
            field_container.hasClass('widget'),
            'Verifying field '+field.name+' was created');
    }
});

};});
