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
       },
       teardown: function() {
           widget_container.remove();
       }}
);

function base_widget_test(widget,entity_name, value){
    var field_name = widget.name;
    ok (widget, "Created Widget");
    widget.init();
    ok(!widget.label,'widget with no entity has no label');
    ok(!widget.tooltip,'widget with entity and name has no tooltip');

    //init reads param info for an entity.  We'll use the user entity
    widget.entity_name = entity_name;
    widget.name = field_name;

    widget.init();
    ok(widget.label,'widget with entity and name has label');
    ok(widget.tooltip,'widget with entity and name has tooltip');


    ok(!widget.container,'widget has no container before setup');
    widget.create(widget_container);
    widget.setup(widget_container);

    ok(widget.container,'widget has container after setup');


}


function widget_string_test(widget) {
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
    var widget = IPA.table_widget({undo:true,name:'users'});

    widget.add_column(IPA.column({
        name:'uid',
        label:'User ID',
        primary_key:'uid',
        width:'20em',
        entity_name:'user'
    }));
    widget.add_column(IPA.column({
        name:'title',
        lable:'Title',
        primary_key:'uid',
        width:'20em',
        entity_name:'user'
    }));

    widget.init();
 
    ok(!widget.container,'widget has no container before setup');
    widget.create(widget_container);
    widget.setup(widget_container);

    ok(widget.container,'widget has container after setup');


    var mock_results = {
        users:[{ uid: 'kfrog', title:'reporter' },
               { uid: 'grover',title:'waiter' }]
    };

    widget.load(mock_results);

    same ($('tr' ,widget_container).length, 4, 'four rows after load');


});


test("Testing base widget.", function() {
    var update_called = false;
    var spec = {
        name:'title'
    };

    var widget = IPA.widget(spec);
    widget.update = function() {
        update_called = true;
    };

    base_widget_test(widget,'user','test_value');
    widget_string_test(widget);
    ok (update_called, 'Update called');

});


test("IPA.textarea_widget" ,function(){
    var widget = IPA.textarea_widget({undo:true,name:'title'});
    base_widget_test(widget,'user','test_value');
    widget_string_test(widget);
    text_tests(widget, $('textarea',widget_container));

});


test("Testing text widget.", function() {
    var widget = IPA.text_widget({undo:true,name:'title'});
    base_widget_test(widget,'user','test_value');
    widget_string_test(widget);
    text_tests(widget, $('input[type=text]',widget_container));

});

test("Testing multi-valued text widget.", function() {
    var widget = IPA.multivalued_text_widget({undo:true,name:'title'});
    base_widget_test(widget,'user','test_value');
    widget_string_test(widget);
    multivalued_text_tests(widget);
});

test("Testing checkbox widget.", function() {
    var widget = IPA.checkbox_widget({name:'title'});
    base_widget_test(widget,'user','test_value');

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
    var widget = IPA.checkboxes_widget({undo:true, name:'title' });
    base_widget_test(widget,'user','test_value');

});
test("IPA.select_widget" ,function(){

    var widget = IPA.select_widget({undo:true,name:'title'});
    base_widget_test(widget,'user','test_value');

});


test("IPA.entity_select_widget" ,function(){
    var widget = IPA.entity_select_widget({
        name: 'uid', entity:'user',field_name:'uid'});
    base_widget_test(widget,'user','test_value');
    ok( $('#uid-entity-select option').length > 1,"options populatedfrom AJAX");
    mock_record = {'uid':'kfrog'};
    widget.load(mock_record);
    same(widget.values[0],'kfrog','select set from values');
});




test("IPA.radio_widget" ,function(){
    var options = [{label:"Engineer",value:"engineer"},
                   {label:"Manager", value:"manager"},
                   {label:"Director",value:"director"},
                   {label:"Vice President",value:"VP"}];
    var widget = IPA.radio_widget({undo:true, name: 'title',options:options});
    base_widget_test(widget,'user','test_value');
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









