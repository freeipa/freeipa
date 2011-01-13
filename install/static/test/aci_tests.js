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


var target_section;
var aci_container;

module('aci',{
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
           aci_container = $('<div id="aci"/>').appendTo(document.body);
           target_section = IPA.target_section();
           target_section.create(aci_container);
       },
       teardown: function() {
           aci_container.remove();
       }}
);


test("Testing aci grouptarget.", function() {
    var sample_data_filter_only = {"targetgroup":"ipausers"};
    target_section.load(sample_data_filter_only);
    ok($('#aci_by_group')[0].checked, 'aci_by_group control selected');
    ok ($('#aci_target_group_select option').length > 2,'group select populated');

});



test("Testing aci object type.", function() {
    var sample_data_filter_only = {"type":"hostgroup"};
    target_section.load(sample_data_filter_only);
    ok($('.aci-attribute', aci_container).length > 4);
    ok($('#aci_by_type')[0].checked, 'aci_by_type control selected');

});


test("Testing aci filter only.", function() {

    var sample_data_filter_only = {"filter":"somevalue"};

    target_section.load(sample_data_filter_only);

    var filter_radio = $('#aci_by_filter');

    ok(filter_radio.length,'find "filter_only_radio" control');
    ok(filter_radio[0].checked,'filter_only_radio control is checked');

});



