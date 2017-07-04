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
    'dojo/on',
    'freeipa/ipa',
    'freeipa/jquery',
    'freeipa/group',
    'freeipa/field',
    'freeipa/widget',
    'freeipa/entity'
], function(on, IPA, $, group) {  return function() {

var widget_container;
var widget;
var factory;
var spec;


module('widget',{
       setup: function() {
           IPA.ajax_options.async = false;
           IPA.init({
               url: 'data',
               on_error: function(xhr, text_status, error_thrown) {
                   ok(false, "ipa_init() failed: "+error_thrown);
               }
           });
           widget_container = $('<div id="widget"/>').appendTo(document.body);

           widget = null;
           factory = null;
           spec = null;

           group.register();

       },
       teardown: function() {
           widget_container.remove();
       }}
);


function base_widget_test(value){
    spec.entity = {
        name:'user'
    };

    widget = factory(spec);

    var field_name = widget.name;
    ok(widget, "Created Widget");

    //init reads param info for an entity.  We'll use the user entity
    widget.name = field_name;

//    ok(widget.label,'widget with entity and name has label');
//    ok(widget.tooltip,'widget with entity and name has tooltip');


    ok(!widget.container,'widget has no container before create');
    widget.create(widget_container);
    ok(widget.container,'widget has container after create');

}


function widget_string_test() {
    var value = 'test_title';
    var mock_record = {'title': value};

    widget.update(mock_record.title);

    ok(widget.save() instanceof Array,'save returns array');


    mock_record = {'title':[value]};
    widget.update(mock_record.title);

    ok(widget.save() instanceof Array,'save returns array');

}



function text_tests(widget,input){

    var value_changed = false;
    var undo_clicked = false;

    widget.value_changed.attach(function() {
        value_changed = true;
    });

    widget.undo_clicked.attach(function() {
        undo_clicked = true;
    });

    input.val('changed');
    input.keyup();
    same(widget.save(),['changed'], "Setting Value");
    same(value_changed, true, "Click triggers value_changed");

    var undo = widget.get_undo();
    undo.click();
    same(undo_clicked, true, "Click on 'undo' triggers undo_clicked");
}

function multivalued_text_tests(widget) {

    var values = ['val1', 'val2', 'val3'];
    var changed = false;
    function on_change (event) {
        changed = true;
    }
    on(widget, 'value-change', on_change);

    widget.update(values);

    same(widget.save(), values, "All values loaded");

    values = ['val1', 'val2', 'val3', 'val4'];
    widget.add_row(['val4']);
    same(widget.save(), values, "Value added");
    ok(changed, "Value changed");
    changed = false;

    values = ['val1', 'val3', 'val4'];
    widget.remove_row(widget.rows[1]);

    same(widget.save(), values, "Value removed");
    ok(changed, "Value changed");
    changed = false;
}

test("IPA.table_widget" ,function(){
    factory = IPA.table_widget;
    spec = {
        undo:true,
        name:'users',
        entity: {
            name:'user'
        }
    };
    widget = factory(spec);
    widget.add_column(IPA.column({
        entity: spec.entity,
        name:'uid',
        label:'User ID',
        primary_key:'uid',
        width:'20em'
    }));
    widget.add_column(IPA.column({
        entity: spec.entity,
        name:'title',
        lable:'Title',
        primary_key:'uid',
        width:'20em'
    }));

    ok(!widget.container,'widget has no container before create');
    widget.create(widget_container);
    ok(widget.container,'widget has container after create');


    var mock_results = {
        users:[{ uid: 'kfrog', title:'reporter' },
               { uid: 'grover',title:'waiter' }]
    };

    widget.load(mock_results);

    same ($('tr' ,widget_container).length, 4, 'four rows after load');


});


test("Testing base widget.", function() {
    var update_called = false;
    spec = {
        name:'title'
    };

    factory = IPA.input_widget;
    base_widget_test('test_value');
    widget_string_test();
});



test("IPA.textarea_widget" ,function(){
    spec = {undo:true,name:'title'};
    factory = IPA.textarea_widget;
    base_widget_test('test_value');
    widget_string_test();
    text_tests(widget, $('textarea',widget_container));

});


test("Testing text widget.", function() {
    factory = IPA.text_widget;
    spec = {undo:true,name:'title'};
    base_widget_test('test_value');
    widget_string_test();
    text_tests(widget, $('input[type=text]',widget_container));

});

test("Testing multi-valued text widget.", function() {
    factory  = IPA.multivalued_widget;
    spec = {undo:true,name:'title'};
    base_widget_test('test_value');
    widget_string_test();
    multivalued_text_tests(widget);
});

test("Testing checkbox widget.", function() {
    factory  = IPA.checkbox_widget;
    spec = {name:'title'};
    base_widget_test('test_value');

    //Changing mock record from 'TRUE' to true. Value normalization is field's
    //job. Checkbox should work with booleans values.
     var mock_record = { 'title': [true] };

    widget.update(mock_record.title);
    same(widget.save(),[true], "Checkbox is set");

    mock_record = {'title':null};

    widget.update(mock_record.title);
    same(widget.save(), [false], "Checkbox is not set");

    var input = $('input[type=checkbox]',widget_container);

    same(input.length,1,'One control in the container');

    var value_changed = false;
    widget.value_changed.attach(function() {
        value_changed = true;
    });

    input.click();

    same(widget.save(),[true], "Click  sets checkbox");
    same(value_changed, true, "Click triggers value_changed");


});


test("IPA.checkboxes_widget" ,function(){
    factory  = IPA.checkboxes_widget;
    spec = {undo:true, name:'title' };
    base_widget_test('test_value');

});
test("IPA.select_widget" ,function(){

    factory  = IPA.select_widget;
    spec = {undo:true,name:'title'};
    base_widget_test('test_value');

});


test("IPA.entity_select_widget" ,function() {
    var user = IPA.entity({ name: 'user' });
    factory = IPA.entity_select_widget;
    spec = {
        name: 'uid',
        other_entity: user,
        other_field: 'uid'
    };

    base_widget_test('test_value');
    var mock_record = { uid: ['kfrog']};
    widget.update(mock_record.uid);
    ok($('option', widget.list).length > 1,"options come from AJAX");

    var value = widget.save();
    same(value, ['kfrog'],'select set from values');
});


test("IPA.entity_link_widget" ,function(){
    factory  = IPA.link_widget;
    spec = {
        name: 'gidnumber',
        other_entity:'group',
        other_pkeys: function() {
            return ['kfrog'];
        }
    };
    base_widget_test(widget,'user','test_value');

    var mock_entity = {
        get_primary_key: function(){
            return "";
        }
    };

    widget.entity = mock_entity;

    var nonlink = widget_container.find('label');
    var link = widget_container.find('a');

    ok(nonlink.length === 1, "Only one <label> element exists");
    ok(link.length === 1, "Only one <a> element exists");

    var mock_record = { gidnumber: ['123456']};
    widget.update(mock_record.gidnumber);

    link = widget_container.find('a:contains("123456")');

    same(link.length, 1,'link is populated');
    same(link.css('display'), 'inline','link is displayed');
    same(widget.nonlink.css('display'), 'none','text is not displayed');

});


test("IPA.radio_widget" ,function(){
    var options = [{label:"Engineer",value:"engineer"},
                   {label:"Manager", value:"manager"},
                   {label:"Director",value:"director"},
                   {label:"Vice President",value:"VP"}];
    factory = IPA.radio_widget;
    spec = {undo:true, name: 'title',options:options};
    base_widget_test('test_value');
    var mock_record = {'title':["director"]};
    widget.update(mock_record.title);
    var values = widget.save();
    same(values[0],'director','Options set correctly');

    mock_record = { title: ["VP"]};
    widget.update(mock_record.title);
    values = widget.save();
    same(values[0],'VP','Options set correctly');

    var i =0;
    $('label', widget_container).each( function(){
        same( $(this).text(),options[i].label, 'labels match');
        i += 1;
    });

});

};});
