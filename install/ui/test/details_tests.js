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

        IPA.init(
            "data",
            true,
            function(data, text_status, xhr) {
            },
            function(xhr, text_status, error_thrown) {
                ok(false, "ipa_init() failed: "+error_thrown);
            }
        );

        details_container = $('<div id="details"/>').appendTo(document.body);

        var obj_name = 'user';
        IPA.entity_factories.user=
            function(){
                return IPA.entity({name:obj_name});
            };
        IPA.start_entities();
    },
    teardown: function() {
        details_container.remove();
    }
});


test("Testing IPA.details_section.create().", function() {

    var section = IPA.details_list_section({
        name:'IDIDID', label:'NAMENAMENAME'}).
        text({name:'cn'}).
        text({name:'uid'}).
        text({name:'mail'});

    section.entity_name = 'user';
    section.init();

    var fields = section.fields;
    var container = $("<div/>");
    section.create(container);

    var dl = $('dl', container);

    same(
        dl.length, 1,
        'Checking dl tag'
    );

    same(
        dl.attr('id'), section.name,
        'Checking section name'
    );

    var dts = $('dt', dl);
    same(
        dts.length, fields.length, // each field generates dt & dd
        'Checking number of children'
    );

    for (var i=0; i<fields.length; i++) {
        var field = fields[i];

        var dt = dts.get(i);
        same(
            dt.innerHTML, field.label+':',
            'Checking field '+field.name+'\'s label'
        );

        var span = $('span[name='+field.name+']', dl);

        ok(
            span.length,
            'Checking span tag for field '+field.name
        );

        var dd = $('dd', span);

        ok(
            dd.length == 0,
            'Checking dd tag for field '+field.name
        );
    }
});



test("Testing details lifecycle: create, setup, load.", function(){

    var result = {};

    IPA.command({
        entity: 'user',
        method: 'show',
        args: ['kfrog'],
        on_success: function(data, text_status, xhr) {
            result = data.result.result;
            ok(true, "IPA.command() succeeded.");
        },
        on_error: function(xhr, text_status, error_thrown) {
            ok(false, "IPA.command() failed: "+error_thrown);
        }
    }).execute();

    var setup_called = false;
    var save_called= false;
    var load_called = false;

    var load_success_called = false;
    var load_failure_called = false;
    var update_success_called = false;
    var update_failure_called = false;

    function setup_status(){
        setup_called = true;
    }

    function save_password(){
        save_called = true;
        return [];
    }

    function load_manager(){
        load_called = true;
    }

    var container = details_container;

    var obj_name = 'user';

    function test_widget(){
        var widget = IPA.widget({name: 'cn'});

        widget.setup = function(container) {
            setup_called = true;
            widget.widget_setup(container);
        };
        
        widget.load = function(record) {
            load_called = true;
            widget.widget_load(record);
        };
        
        widget.save = function() {
            save_called = true;
            widget.widget_save();
        };
        return widget;
    }

    var entity =   IPA.
        entity_builder().
        entity('user').
        details_facet({sections:[
            {
                name: 'identity',
                label: IPA.messages.details.identity,
                fields:['title','givenname','sn','cn','displayname', 'initials']
            },
            {
                name: 'contact',
                label:'contact',
                fields:
                [  {factory: test_widget,name:'test'},
                   {factory: IPA.multivalued_text_widget, name:'mail'},
                   {factory: IPA.multivalued_text_widget,
                    name:'telephonenumber'},
                   {factory: IPA.multivalued_text_widget, name:'pager'},
                   {factory: IPA.multivalued_text_widget, name:'mobile'},
                   {factory: IPA.multivalued_text_widget,
                    name:'facsimiletelephonenumber'}]
            },
        ]}).build();
    entity.init();

    var facet = entity.get_facet('details');
    facet.init();

    var content = $('<div/>', {
        'class': 'content'
    }).appendTo(container);

    facet.create_content(content);

    facet.setup(container);
    facet.load(result);

    var contact = container.find('dl#contact.entryattrs');

    ok(
        contact,
        'dl tag for contact is created'
    );

    var identity = container.find('dl#identity.entryattrs');

    ok(
        identity,
        'dl tag for identity is created'
    );

    var dts = identity.find('dt');

    same(
        dts.length, 6,
        'Checking dt tags for identity'
    );

    container.attr('id','user');

    ok (
        setup_called,
        'Setup status called'
    );

    ok (load_called, 'load manager called');

    facet.update(
        function(){update_success_called = true},
        function(){update_failure_called = true}
    );

    ok (update_success_called,'update success called');
    ok (!update_failure_called,'update failure not called');
    ok (save_called, 'save called');

});


test("Testing IPA.details_section_setup again()",function(){

    var section = IPA.details_list_section({
        name: 'IDIDID', label: 'NAMENAMENAME'}).
        text({name:'cn', label:'Entity Name'}).
        text({name:'description', label:'Description'}).
        text({name:'number', label:'Entity ID'});
    var fields = section.fields;
    var container = $("<div title='entity'/>");
    var details = $("<div/>");
    container.append(details);

    var result = {};

    section.create(container);
    section.setup(container);
    section.load(result);

    //var h2= container.find('h2');
    //ok(h2);
    //ok(h2[0].innerHTML.indexOf(section.label) > 1,"find name in html");

    var dl = $('dl', container);
    ok(
        dl.length,
        'dl is created'
    );

    same(
        dl[0].id, section.name,
        'checking section name'
    );

    var dt = $('dt', dl);
    same(
        dt.length, 3,
        '3 dt'
    );

    same(
        dt[0].innerHTML, fields[0].label+":",
        'inner HTML matches label'
    );

    var dd = $('dd', dl);
    same(
        dd.length, 3,
        '3 dd'
    );

    var span = $('span[name="cn"]', dd[0]);
    same(
        span.length, 1,
        '1 span'
    );
});
