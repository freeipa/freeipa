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


var widget_container;
var widget;
var factory
var spec;


module('widget',{
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
           widget_container = $('<div id="widget"/>').appendTo(document.body);

           widget = null;
           factory = null;
           spec = null;


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

    var entity_name = 'user';
    var field_name = widget.name;
    ok (widget, "Created Widget");

    //init reads param info for an entity.  We'll use the user entity
    widget.name = field_name;

    ok(widget.label,'widget with entity and name has label');
    ok(widget.tooltip,'widget with entity and name has tooltip');


    ok(!widget.container,'widget has no container before create');
    widget.create(widget_container);
    ok(widget.container,'widget has container after create');

}


function widget_string_test() {
    var value = 'test_title';
    var mock_record = {'title': value};

    widget.load(mock_record);

    ok(widget.save() instanceof Array,'save returns array');


    mock_record = {'title':[value]};
    widget.load(mock_record);

    ok(widget.save() instanceof Array,'save returns array');

}



function text_tests(widget,input){

    input.val('changed');
    input.keyup();
    same(widget.save(),['changed'], "Setting Value");
    same(widget.is_dirty(),true, "Click  sets is_dirty");

    var undo = widget.get_undo();
    undo.click();
    same(widget.is_dirty(),false, "Undo Clears is_dirty");


    var old_pattern =  widget.param_info.pattern;

    widget.param_info.pattern ='abc';
    input.val('not right');
    input.keyup();
    same(widget.valid,false, 'Field is not valid');
    var error_field = widget.get_error_link();

    same(error_field.css('display'),'block','error field is visible');


    input.val('abc');
    input.keyup();
    same(widget.valid,true, 'Field is valid');
    same(error_field.css('display'),'none','error field not visible');

    widget.param_info.pattern = old_pattern;

}

function multivalued_text_tests(widget) {

    var values = ['val1', 'val2', 'val3'];

    var record = {};
    record[widget.name] = values;

    widget.load(record);

    same(widget.save(), values, "All values loaded");
    same(widget.is_dirty(), false, "Field initially clean");

    values = ['val1', 'val2', 'val3', 'val4'];
    widget.add_row('val4');

    same(widget.save(), values, "Value added");
    same(widget.is_dirty(), true, "Field is dirty");

    values = ['val1', 'val3', 'val4'];
    widget.remove_row(1);

    same(widget.save(), values, "Value removed");
    same(widget.is_dirty(), true, "Field is dirty");
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
        width:'20em',
        entity_name:'user'
    }));
    widget.add_column(IPA.column({
        entity: spec.entity,
        name:'title',
        lable:'Title',
        primary_key:'uid',
        width:'20em',
        entity_name:'user'
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

    factory = IPA.widget;
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
    factory  = IPA.multivalued_text_widget;
    spec = {undo:true,name:'title'};
    base_widget_test('test_value');
    widget_string_test();
    multivalued_text_tests(widget);
});

test("Testing checkbox widget.", function() {
    factory  = IPA.checkbox_widget;
    spec = {name:'title'};
    base_widget_test('test_value');

    mock_record = {'title':'something'};

    widget.load(mock_record);
    same(widget.save(),[true], "Checkbox is set");

    mock_record = {'title':null};

    widget.load(mock_record);
    same(widget.save(), [false], "Checkbox is not set");

    var input = $('input[type=checkbox]',widget_container);

    same(input.length,1,'One control in the container');

    input.click();

    same(widget.save(),[true], "Click  sets checkbox");
    same(widget.is_dirty(),true, "Click  sets is_dirty");


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


test("IPA.entity_select_widget" ,function(){
    factory =  IPA.entity_select_widget;
    spec = {
        name: 'uid',
        other_entity:'user',
        field_name:'uid',
        other_field: 'uid' };

    base_widget_test('test_value');
    mock_record = {'uid':'kfrog'};
    widget.load(mock_record);
    ok( $('option',widget.list ).length > 1,"options come from AJAX");
    same(widget.values[0],'kfrog','select set from values');
});


test("IPA.entity_link_widget" ,function(){
    factory  = IPA.entity_link_widget;
    spec = {
        name: 'gidnumber',
        other_entity:'group'
    };
    base_widget_test(widget,'user','test_value');

    var mock_entity = {
        get_primary_key: function(){
            return "";
        }
    };

    mock_record = {'uid':'kfrog','gidnumber':'123456'};

    widget.entity = mock_entity;
    widget.create(widget_container);

    var nonlink = widget_container.find('label');
    var link = widget_container.find('a');

    ok(nonlink.length > 1);
    ok(link.length > 1);

    widget.load(mock_record);

    link = widget_container.find('a[text=123456]');

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
    widget.load(mock_record);
    var values = widget.save();
    same(values[0],'director','Options set correctly');

    mock_record = {'title':"VP"};
    widget.load(mock_record);
    values = widget.save();
    same(values[0],'VP','Options set correctly');

    var i =0;
    $('label', widget_container).each( function(){
        same( $(this).text(),options[i].label, 'labels match');
        i += 1;
    });

});









