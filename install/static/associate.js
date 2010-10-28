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

/**
*This associator is built for the case where each association requires a separate rpc
*/
function SerialAssociator(form, manyObjPkeys, on_success)
{
    var associator = this;
    this.form = form;
    this.manyObjPkeys =  manyObjPkeys;
    this.on_success = on_success;

    this.associateNext = function(){
        var form = this.form;
        //TODO assert pre-conditions
        var  manyObjPkey =  manyObjPkeys.shift();
        if (manyObjPkey){
            var options = {};
            options[form.oneObj] = form.pkey;
            var args = [manyObjPkey];

            ipa_cmd( form.method,args, options ,
                     function(data, text_status, xhr) {
                         if (data.error){
                             alert('error adding member: '+data.error.message);
                         }else{
                             associator.associateNext();
                         }
                     },
                     function(xhr, text_status, error_thrown) {
                         alert('associateFailure');
                     },
                     form.manyObj );
        }else{
            associator.on_success();
        }
    }
}

/**
*This associator is for the common case where all the asociations can be sent
in a single rpc
*/
function BulkAssociator(form, manyObjPkeys, on_success)
{
    var associator = this;
    this.form = form;
    this.manyObjPkeys = manyObjPkeys;
    this.on_success = on_success;

    this.associateNext = function() {
        var form = this.form;
        var option = manyObjPkeys.shift();
        while(manyObjPkeys.length > 0) {
            option += ',' + manyObjPkeys.shift();
        }

        var options = {
          'all':true
        };
        options[form.manyObj] = option;

        var args = [form.pkey];

        ipa_cmd( form.method,args, options ,
                 function(data, text_status, xhr) {
                     if (data.error){
                         alert('error adding member: '+data.error.message);
                     }else{
                         associator.on_success();
                     }
                 },
                 function(xhr, text_status, error_thrown) {
                     alert('associateFailure');
                 },
                 form.oneObj );
    }
}

/**
 *  Create a form for a one to many association.
 *
 */
function AssociationForm(oneObj, pkey, manyObj, on_success, associatorConstructor, method)
{
    var form = this;

    this.oneObj = oneObj;
    this.pkey = pkey;
    this.manyObj = manyObj;
    this.on_success = on_success;

    this.dialog = $('<div></div>');

    //An optional parameter to determine what ipa method to call to create
    //the association
    if (method)
        this.method = method;
    else
        this.method = 'add_member';

    if (associatorConstructor)
        this.associatorConstructor = associatorConstructor;
    else
        this.associatorConstructor = BulkAssociator;

    this.setup = function() {
        var label = IPA.metadata[form.manyObj].label;

        form.dialog.attr('title', 'Enroll '+form.oneObj+' '+form.pkey+' in '+label);

        association_form_create(form.dialog);

        var availableList = $('#availableList', form.dialog);
        availableList.html('');

        var enrollments = $('#enrollments', form.dialog);
        enrollments.html('');

        $('#addToList', form.dialog).click(function(){
            $('#availableList :selected', form.dialog).each(function(i, selected){
                enrollments.append(selected);
            });
            $('#availableList :selected', form.dialog).remove();
        });
        $('#removeFromList', form.dialog).click(function(){
            $('#enrollments :selected', form.dialog).each(function(i, selected){
                availableList.append(selected);
            });
            $('#enrollments :selected', form.dialog).remove();
        });

        $('#find', form.dialog).click(function(){
            form.search();
        });

        form.dialog.dialog({
            modal: true,
            width: 600,
            buttons: {
                'Enroll': function(evt) {
                    form.associate(form.on_success);
                },
                'Cancel': form.close
            }
        });
    };

    this.close = function() {
        form.dialog.dialog('close');
    };

    this.search = function() {

        function search_on_win(data, text_status, xhr) {
            var results = data.result;
            var list = $('#availableList', form.dialog);
            list.html('');

            var searchColumn = IPA.metadata[form.manyObj].primary_key;

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

        var queryFilter = $('#associateFilter', form.dialog).val();
        ipa_cmd('find', [queryFilter], {}, search_on_win, null, form.manyObj);
    };

    this.associate = function (on_success) {
        var manyObjPkeys = [];
        $('#enrollments', form.dialog).children().each(function (i, selected) {
            manyObjPkeys.push(selected.value);
        });
        var associator =
            new this.associatorConstructor(form, manyObjPkeys, on_success);
        associator.associateNext();
    };
}

function ipa_association_config(spec) {
    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.associator = spec.associator;
    that.method = spec.method;

    return that;
}

function ipa_association_facet(spec) {

    spec = spec || {};

    var that = ipa_facet(spec);

    that.configs = [];
    that.configs_by_name = {};

    that.other_entity = null;

    that.get_configs = function() {
        return that.configs;
    };

    that.get_config = function(name) {
        return that.configs_by_name[name];
    };

    that.add_config = function(config) {
        that.configs.push(config);
        that.configs_by_name[config.name] = config;
    };

    that.create_config = function(spec) {
        var config = ipa_association_config(spec);
        that.add_config(config);
        return config;
    };

    that.is_dirty = function() {
        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var other_entity = $.bbq.getState(that.entity_name + '-enroll', true) || '';
        return pkey != that.pkey || other_entity != that.other_entity;
    };

    that.setup = function(container, unspecified) {

        that.pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        that.other_entity = $.bbq.getState(that.entity_name + '-enroll', true) || '';

        that.member_attrribute = ipa_get_member_attribute(that.entity_name, that.other_entity);
        that.columns = [
            {
                'title': IPA.metadata[that.other_entity].label,
                'column': that.member_attrribute + '_' + that.other_entity
            }
        ];

        var config = that.get_config(that.other_entity);
        that.associator = config ? config.associator : null;
        that.method = config ? config.method : null;

        that.setup_views(container);

        //TODO I18N
        var header_message = that.other_entity + '(s) enrolled in '  +
            that.entity_name + ' ' + that.pkey;
        container.append($('<h2/>',{html:  header_message }) );
        association_list_create(that.entity_name, container);
        container.find('.search-filter').css('display', 'none');
        container.find('.search-buttons').html('');

        $('<input/>', {
            type:  'button',
            value: 'enroll',
            click: function() {
                that.show_enrollment_dialog();
            }
        }).appendTo(container.find('.search-buttons'));

        var header = $('<tr></tr>').appendTo(container.find('.search-table thead:last'));
        for (var i =0 ; i != that.columns.length ;i++){
            $('<th></th>',{
                html: that.columns[i].title
            }).appendTo(header);
        }
        that.refresh(container);
    };

    that.refresh = function(container) {

        function refresh_on_success(data, text_status, xhr) {
            var tbody = container.find('.search-table tbody');
            tbody.empty();
            var associationList = data.result.result[that.columns[0].column];
            for (var j = 0; j < associationList.length; j++){
                var row  = $('<tr/>').appendTo(tbody);
                for (var k = 0; k < that.columns.length ;k++){
                    var column = that.columns[k].column;
                    $('<td></td>',{
                        html: data.result.result[column][j]
                    }).appendTo(row);
                }
            }
        }

        function refresh_on_error(xhr, text_status, error_thrown) {
            var search_results = $('.search-results', container).empty();
            search_results.append('<p>Error: '+error_thrown.name+'</p>');
            search_results.append('<p>URL: '+this.url+'</p>');
            search_results.append('<p>'+error_thrown.message+'</p>');
        }

        ipa_cmd('show', [that.pkey], {}, refresh_on_success, refresh_on_error, that.entity_name);
    };

    that.show_enrollment_dialog = function() {

        var enrollment_dialog = new AssociationForm(
            that.entity_name,
            that.pkey,
            that.other_entity,
            function() {
                that.refresh();
                enrollment_dialog.close();
            },
            that.associator,
            that.method
        );
        enrollment_dialog.setup();
    };

    return that;
}


function association_form_create(jobj)
{
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
    form.append($('<hr />'));
    form.append($('<div></div>', {
        text: 'Message Area'
    }));
    form.append($('<hr />'));
    var form_div = $('<div></div>');
    var span = $('<span></span>');
    span.css('float', 'left');
    span.append($('<p></p>', {
        text: '*Enter Group Names and Press Groups'
    }));
    span.append($('<p></p>', {
        text: '*More stuff'
    }));
    span.append($('<p></p>', {
        text: '*More stuff'
    }));
    form_div.append(span);
    form.append(form_div);
    div.append(form);
    jobj.append(div);
}

function association_list_create(obj_name, jobj)
{
    search_create(obj_name, [], jobj);
}

