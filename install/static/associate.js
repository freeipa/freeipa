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

/* REQUIRES: ipa.js */
/* CURRENTLY ALSO REQUIRES search.js, because it reuses it's code to create
 * the AssociationList elements; IT NEEDS IT'S OWN CODE! */

function ipa_associator(spec) {

    spec = spec || {};

    var that = {};

    that.entity_name = spec.entity_name;
    that.pkey = spec.pkey;

    that.other_entity = spec.other_entity;
    that.values = spec.values;

    that.method = spec.method;

    that.on_success = spec.on_success;
    that.on_error = spec.on_error;

    that.execute = function() {
    };

    return that;
}

/**
*This associator is built for the case where each association requires a separate rpc
*/
function serial_associator(spec) {

    spec = spec || {};

    var that = ipa_associator(spec);

    that.execute = function() {

        if (!that.values || !that.values.length) {
            that.on_success();
            return;
        }

        var value = that.values.shift();
        if (!value) {
            that.on_success();
            return;
        }

        var args = [value];
        var options = {};
        options[that.entity_name] = that.pkey;

        ipa_cmd(
            that.method,
            args,
            options,
            that.execute,
            that.on_error,
            that.other_entity
        );
    };

    return that;
}

/**
*This associator is for the common case where all the asociations can be sent
in a single rpc
*/
function bulk_associator(spec) {

    spec = spec || {};

    var that = ipa_associator(spec);

    that.execute = function() {

        if (!that.values || !that.values.length) {
            that.on_success();
            return;
        }

        var value = that.values.shift();
        if (!value) {
            that.on_success();
            return;
        }

        while (that.values.length > 0) {
            value += ',' + that.values.shift();
        }

        var args = [that.pkey];
        var options = { 'all': true };
        options[that.other_entity] = value;

        ipa_cmd(
            that.method,
            args,
            options,
            that.on_success,
            that.on_error,
            that.entity_name
        );
    };

    return that;
}

/**
 *  Create a form for a one to many association.
 *
 */
function ipa_adder_dialog(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.title = spec.title;
    that.entity_name = spec.entity_name;

    that.pkey = spec.pkey;
    that.other_entity = spec.other_entity;

    that.setup = spec.setup || ipa_adder_dialog_setup;
    that.execute = spec.execute || execute;
    that.on_success = spec.on_success;
    that.on_error = spec.on_error;

    that.associator = spec.associator;
    that.method = spec.method || 'add_member';

    that.dialog = $('<div/>', {
        'title': that.title
    });

    that.open = function() {

        that.setup();

        var availableList = $('#availableList', that.dialog);
        availableList.html('');

        var enrollments = $('#enrollments', that.dialog);
        enrollments.html('');

        $('#addToList', that.dialog).click(function(){
            $('#availableList :selected', that.dialog).each(function(i, selected){
                enrollments.append(selected);
            });
            $('#availableList :selected', that.dialog).remove();
        });
        $('#removeFromList', that.dialog).click(function(){
            $('#enrollments :selected', that.dialog).each(function(i, selected){
                availableList.append(selected);
            });
            $('#enrollments :selected', that.dialog).remove();
        });

        $('#find', that.dialog).click(function(){
            that.search();
        });

        that.dialog.dialog({
            modal: true,
            width: 600,
            buttons: {
                'Enroll': function() {
                    var values = [];
                    $('#enrollments', that.dialog).children().each(function (i, selected) {
                        values.push(selected.value);
                    });
                    that.execute(values);
                },
                'Cancel': that.close
            }
        });
    };

    that.close = function() {
        that.dialog.dialog('close');
    };

    that.search = function() {

        function search_on_win(data, text_status, xhr) {
            var results = data.result;
            var list = $('#availableList', that.dialog);
            list.html('');

            var searchColumn = IPA.metadata[that.other_entity].primary_key;

            for (var i =0; i != results.count; i++){
                var result = results.result[i];
                $('<option></option>',{
                    value: result[searchColumn][0],
                    html: result[searchColumn][0]
                }).appendTo(list);
            }
        }

        function search_on_fail(xhr, text_status, errow_thrown) {
            alert('associationSearchFailure');
        }

        var queryFilter = $('#associateFilter', that.dialog).val();
        ipa_cmd('find', [queryFilter], {}, search_on_win, null, that.other_entity);
    };

    that.get_values = function() {
        var values = [];
        $('#enrollments', that.dialog).children().each(function (i, selected) {
            values.push(selected.value);
        });
        return values;
    };

    function execute(values) {

        var associator = that.associator({
            'entity_name': that.entity_name,
            'pkey': that.pkey,
            'other_entity': that.other_entity,
            'values': that.get_values(),
            'method': that.method,
            'on_success': that.on_success,
            'on_error': that.on_error
        });

        associator.execute();
    }

    return that;
}

function ipa_deleter_dialog(spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.title = spec.title || IPA.messages.button.deletes;
    that.entity_name = spec.entity_name;

    that.pkey = spec.pkey;
    that.other_entity = spec.other_entity;

    that.setup = spec.setup || ipa_deleter_dialog_setup;
    that.execute = spec.execute || execute;
    that.on_success = spec.on_success;
    that.on_error = spec.on_error;

    that.associator = spec.associator;
    that.method = spec.method || 'remove_member';

    that.values = spec.values || [];

    that.dialog = $('<div/>', {
        'title': that.title,
        'class': 'search-dialog-delete'
    });

    that.add_value = function(value) {
        that.values.push(value);
    };

    that.set_values = function(values) {
        that.values = that.values.concat(values);
    };

    that.get_values = function() {
        return that.values;
    };

    that.open = function() {

        that.setup();

        that.dialog.dialog({
            modal: true,
            width: 400,
            buttons: {
                'Delete': that.execute,
                'Cancel': that.close
            }
        });
    };

    function execute() {

        var associator = that.associator({
            'entity_name': that.entity_name,
            'pkey': that.pkey,
            'other_entity': that.other_entity,
            'values': that.values,
            'method': that.method,
            'on_success': that.on_success,
            'on_error': that.on_error
        });

        associator.execute();
    }

    that.close = function() {
        that.dialog.dialog('close');
    };

    return that;
}

function ipa_association_config(spec) {
    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.associator = spec.associator;
    that.add_method = spec.add_method;
    that.delete_method = spec.delete_method;

    return that;
}

function ipa_association_widget(spec) {

    spec = spec || {};

    spec.add = spec.add || add;
    spec.remove = spec.remove || remove;

    var that = ipa_table_widget(spec);

    that.other_entity = spec.other_entity;

    that.super_create = that.super('create');
    that.super_setup = that.super('setup');

    that.create = function(container) {

        that.member_attribute = ipa_get_member_attribute(that.entity_name, that.other_entity);

        that.create_column({
            'name': that.member_attribute + '_' + that.other_entity,
            'label': IPA.metadata[that.other_entity].label,
            'primary_key': true
        });

        that.super_create(container);

        var div = $('#'+that.id, container);
        var buttons = $('span[name=buttons]', div);

        $('<input/>', {
            'type': 'button',
            'name': 'remove',
            'value': IPA.messages.button.delete
        }).appendTo(buttons);

        $('<input/>', {
            'type': 'button',
            'name': 'add',
            'value': IPA.messages.button.enroll
        }).appendTo(buttons);
    }

    that.setup = function(container) {

        that.super_setup(container);

        var entity = IPA.get_entity(that.entity_name);
        var association = entity.get_association(that.other_entity);

        if (association && association.associator == 'serial') {
            that.associator = serial_associator;
        } else {
            that.associator = bulk_associator;
        }

        that.add_method = association ? association.add_method : null;
        that.delete_method = association ? association.delete_method : null;
    };

    function add(container) {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var label = IPA.metadata[that.other_entity].label;
        var title = 'Enroll '+that.entity_name+' '+pkey+' in '+label;

        var dialog = ipa_adder_dialog({
            'name': 'adder_dialog',
            'title': title,
            'entity_name': that.entity_name,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'associator': that.associator,
            'method': that.add_method,
            'on_success': function() {
                that.refresh(container);
                dialog.close();
            },
            'on_error': function() {
                that.refresh(container);
                dialog.close();
            }
        });

        dialog.open();
    }

    function remove(container) {

        var values = that.get_selected_values();

        if (!values.length) {
            alert('Select '+that.label+' to be removed.');
            return;
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var label = IPA.metadata[that.other_entity].label;
        var title = 'Remove '+label+' from '+that.entity_name+' '+pkey;

        var dialog = ipa_deleter_dialog({
            'name': 'deleter_dialog',
            'title': title,
            'entity_name': that.entity_name,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'values': values,
            'associator': that.associator,
            'method': that.delete_method,
            'on_success': function() {
                that.refresh(container);
                dialog.close();
            },
            'on_error': function() {
                that.refresh(container);
                dialog.close();
            }
        });

        dialog.open();
    }

    return that;
}

function ipa_association_facet(spec) {

    spec = spec || {};

    var that = ipa_facet(spec);

    that.other_entity = null;

    that.is_dirty = function() {
        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var other_entity = $.bbq.getState(that.entity_name + '-enroll', true) || '';
        return pkey != that.pkey || other_entity != that.other_entity;
    };

    that.setup = function(container, unspecified) {

        that.pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        that.other_entity = $.bbq.getState(that.entity_name + '-enroll', true) || '';

        that.setup_views(container);

        //TODO I18N
        var header_message = that.other_entity + '(s) enrolled in '  +
            that.entity_name + ' ' + that.pkey;
        container.append( $('<h2/>',{ html:  header_message }) );

        $('<div/>', {
            'id': that.entity_name+'-'+that.other_entity
        }).appendTo(container);

        var table = ipa_association_widget({
            'id': that.entity_name+'-'+that.other_entity,
            'name': that.other_entity, 'label': IPA.metadata[that.other_entity].label,
            'entity_name': that.entity_name, 'other_entity': that.other_entity
        });

        table.create(container);
        table.setup(container);
        table.refresh(container);
    };

    return that;
}


function ipa_adder_dialog_setup() {

    var that = this;

    var div = $('<div id="associations"></div>');

    var form = $('<form></form>');
    var form_div = $('<div></div>');
    form_div.css('border-width', '1px');
    var sub_div = $('<div></div>');
    sub_div.append($('<input />', {
        id: 'associateFilter',
        type: 'text'
    }));
    sub_div.append($('<input />', {
        id: 'find',
        type: 'button',
        value: 'Find'
    }));

    form_div.append(sub_div);
    form.append(form_div);
    var form_div = $('<div id="results"></div>');
    form_div.css('border', '2px solid rgb(0, 0, 0)');
    form_div.css('position', 'relative');
    form_div.css('height', '200px');
    var sub_div = $('<div></div>');
    sub_div.css('float', 'left');
    sub_div.append($('<div></div>', {
        text: 'Available'
    }));
    sub_div.append($('<select></select>', {
        id: 'availableList',
        width: '150px',
        size: '10',
        multiple: 'true'
    }));
    form_div.append(sub_div);
    var sub_div = $('<div></div>');
    sub_div.css('float', 'left');
    var p = $('<p></p>');
    p.append($('<input />', {
        id: 'removeFromList',
        type: 'button',
        value: '<<'
    }));
    sub_div.append(p);
    var p = $('<p></p>');
    p.append($('<input />', {
        id: 'addToList',
        type: 'button',
        value: '>>'
    }));
    sub_div.append(p);
    form_div.append(sub_div);
    var sub_div = $('<div></div>');
    sub_div.css('float', 'left');
    sub_div.append($('<div></div>', {
        text: 'Prospective'
    }));
    sub_div.append($('<select></select>', {
        id: 'enrollments',
        width: '150px',
        size: '10',
        multiple: 'true'
    }));
    form_div.append(sub_div);
    form.append(form_div);
    div.append(form);
    that.dialog.append(div);
}

function association_list_create(obj_name, jobj)
{
    search_create(obj_name, [], jobj);
}

function ipa_deleter_dialog_setup() {

    var that = this;

    var ul = $('<ul/>');
    ul.appendTo(that.dialog);

    for (var i=0; i<that.values.length; i++) {
        $('<li/>',{
            'text': that.values[i]
        }).appendTo(ul);
    }

    $('<p/>', {
        'text': IPA.messages.search.delete_confirm
    }).appendTo(that.dialog);
}