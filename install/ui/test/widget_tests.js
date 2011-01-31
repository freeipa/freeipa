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
                   ok(true, "ipa_init() succeeded.");
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



function base_widget_test(widget,entity_name, field_name,value){
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


function widget_string_test(widget, value){
   var value = 'test_title';
    var mock_record = {'title': value};

    widget.load(mock_record);

    ok(widget.save() instanceof Array,'save returns array');


    mock_record = {'title':[value]};
    widget.load(mock_record);

    ok(widget.save() instanceof Array,'save returns array');

}

test("Testing base widget.", function() {
    var update_called = false;
    var spec = {
        update:function(){
            update_called = true;
        }
    };

    var widget = IPA.widget(spec);
    base_widget_test(widget,'user','title','test_value');
    widget_string_test(widget);
    ok (update_called, 'Update called');

});


test("Testing text widget.", function() {
    var widget = IPA.text_widget({undo:true});
    base_widget_test(widget,'user','title','test_value');
    widget_string_test(widget);


    var input = $('input[type=text]',widget_container);
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

});

test("Testing checkbox widget.", function() {
    var widget = IPA.checkbox_widget();
    base_widget_test(widget,'user','title','test_value');

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

