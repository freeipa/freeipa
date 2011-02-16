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


var target_container;
var target_section;

module('aci',{
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

           target_container = $('<div id="target"/>').appendTo(document.body);
           target_section = IPA.target_section({name: 'target', label: 'Target'});
           target_section.init();
           target_section.create(target_container);
       },
       teardown: function() {
           target_container.remove();
       }}
);


test("IPA.attributes_widget.", function() {

    var aciattrs = IPA.metadata.objects['user'].aciattrs;

    var container = $('<span/>', {
        name: 'attrs'
    });

    var widget = IPA.attributes_widget({
        name: 'attrs',
        object_type: 'user'
    });

    widget.init();
    widget.create(container);
    widget.setup(container);

    var table = $('table', container);

    ok(
        table,
        'Widget contains table'
    );

    var tr = $('tbody tr', table);

    same(
        tr.length, aciattrs.length,
        'Widget contains all user ACI attributes'
    );

    var record = {
        'attrs': [
            "unmatched",
            "cn",
            "description"
        ]
    };

    same(
        widget.save(), [],
        'Widget has no initial values'
    );

    widget.load(record);

    tr = $('tbody tr', table);

    same(
        tr.length, aciattrs.length+1,
        'Widget contains all user ACI attributes plus 1 unmatched attribute'
    );

    same(
        widget.save(), record.attrs.sort(),
        'All loaded values are saved and sorted'
    );
});

test("IPA.rights_widget.", function() {

    var container = $('<span/>', {
        name: 'permissions'
    });

    var widget = IPA.rights_widget({
        name: 'permissions'
    });

    widget.init();
    widget.create(container);
    widget.setup(container);

    var inputs = $('input', container);

    same(
        inputs.length, widget.rights.length,
        'Widget displays all permissions'
    );
});

test("Testing aci grouptarget.", function() {
    var sample_data_filter_only = {"targetgroup":"ipausers"};
    target_section.load(sample_data_filter_only);

    var selected = $(target_section.type_select+":selected");

    same(selected.val(), 'targetgroup' , 'group control selected');
    ok ($('#targetgroup-entity-select option').length > 2,
        'group select populated');

});

test("Testing type target.", function() {
    var sample_data_filter_only = {"type":"hostgroup"};

    target_section.load(sample_data_filter_only);
    var selected = $(target_section.type_select+":selected");
    same(selected.val(), 'type', 'type selected');

    $("input[type=checkbox]").attr("checked",true);
    var response_record = {};
    target_section.save(response_record);
    same(response_record.type, sample_data_filter_only.type,
         "saved type matches sample data");
    ok((response_record.attrs.length > 10),
       "response length shows some attrs set");

});


test("Testing filter target.", function() {

    var sample_data_filter_only = {"filter":"somevalue"};

    target_section.load(sample_data_filter_only);

    var selected = $(target_section.type_select+":selected");
    same(selected.val(), 'filter', 'filter selected');
});



test("Testing subtree target.", function() {

    var sample_data = {
        subtree:"ldap:///cn=*,cn=roles,cn=accounts,dc=example,dc=co"};

    target_section.load(sample_data);
    var record = {};
    target_section.save(record);
    same(record.subtree, sample_data.subtree, 'subtree set correctly');
});



