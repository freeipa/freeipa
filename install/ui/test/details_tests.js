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

var details_container;


module('details', {
    setup: function() {
        IPA.ajax_options.async = false;

        IPA.init({
            url: 'data',
            on_error: function(xhr, text_status, error_thrown) {
                ok(false, "ipa_init() failed: "+error_thrown);
            }
        });

        IPA.nav = {};

        IPA.nav.get_state = function(key){
            return $.bbq.getState(key);
        };

        details_container = $('<div id="details"/>').appendTo(document.body);

        IPA.register('user', function(spec) {

            return IPA.entity({
                name: 'user',
                metadata: IPA.metadata.objects.user
            });
        });
    },
    teardown: function() {
        details_container.remove();
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

    var table = $('table', container);

    same(
        table.length, 1,
        'Verifying table');

    var rows = $('tr', table);
    same(
        rows.length, fields.length,
        'Verifying table rows');

    for (var i=0; i<fields.length; i++) {
        var field = fields[i];

        var field_label = $('.field-label[name='+field.name+']', container);
        same(
            field_label.text(), field.label+':',
            'Verifying label for field '+field.name);

        var field_container = $('.field[name='+field.name+']', container);

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

    IPA.command({
        entity: 'user',
        method: 'show',
        args: ['kfrog'],
        on_success: function(data, text_status, xhr) {
            ok(true, "IPA.command() succeeded.");
        },
        on_error: function(xhr, text_status, error_thrown) {
            ok(false, "IPA.command() failed: "+error_thrown);
        }
    }).execute();

    var save_called = false;
    var load_called = false;

    var load_success_called = false;
    var load_failure_called = false;
    var update_success_called = false;
    var update_failure_called = false;


    function save_password(){
        save_called = true;
        return [];
    }

    function load_manager(){
        load_called = true;
    }

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

    IPA.field_factories['test'] = test_field;
    IPA.widget_factories['test'] = test_widget;

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
                                type: 'test',
                                name:'test'
                            },
                            {
                                type: 'multivalued',
                                name:'mail'
                            },
                            {
                                type: 'multivalued',
                                name:'telephonenumber'
                            },
                            {
                                type: 'multivalued',
                                name:'pager'
                            },
                            {
                                type: 'multivalued',
                                name:'mobile'
                            },
                            {
                                type: 'multivalued',
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

    var entity_container = $('<div/>', {
        name: 'user',
        title: 'User',
        'class': 'entity'
    }).appendTo(details_container);

    entity.create(entity_container);

    var facet = entity.get_facet('details');

    var facet_container = $('<div/>', {
        name: facet.name,
        'class': 'facet'
    });

    facet.create(facet_container);

    facet.load(data);

    var contact = $('.details-section[name=contact]', facet_container);

    ok(
        contact.length,
        'Verifying section for contact is created');

    var identity = $('.details-section[name=identity]', facet_container);

    ok(
        identity.length,
        'Verifying section for identity is created');

    var rows = $('tr', identity);

    same(
        rows.length, 6,
        'Verifying rows for identity');

    facet_container.attr('id','user');

    ok (load_called, 'load manager called');

    var field = facet.fields.get_field('test');
    field.set_dirty(true);

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

    var table = $('table', container);

    same(
        table.length, 1,
        'Verifying table');

    var rows = $('tr', table);
    same(
        rows.length, fields.length,
        'Verifying table rows');

    for (var i=0; i<fields.length; i++) {
        var field = fields[i];

        var field_label = $('.field-label[name='+field.name+']', container);
        same(
            field_label.text(), field.label+':',
            'Verifying label for field '+field.name);

        var field_container = $('.field[name='+field.name+']', container);

        ok(
            field_container.length,
            'Verifying container for field '+field.name);

        ok(
            field_container.hasClass('widget'),
            'Verifying field '+field.name+' was created');
    }
});
