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


test("Testing ipa_details_section.create().", function() {

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

    var section = ipa_details_section({name:'IDIDID', label:'NAMENAMENAME'}).
        input({name:'cn', label:'Entity Name'}).
        input({name:'description', label:'Description'}).
        input({name:'number', label:'Entity ID'});


    var fields = section.fields;
    var container = $("<div/>");
    section.create(container);

    var dl = container.find('dl');

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
        var dt = dts.get(i);
        same(
            dt.title, fields[i].name,
            'Checking field '+i+'\'s title'
        );

        same(
            dt.innerHTML, fields[i].label+':',
            'Checking field '+i+'\'s label'
        );
    }
});



test("Testing details lifecycle: create, setup, load.", function(){

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

    var result = {};

    ipa_cmd(
        'user_show',
        ['kfrog'],
        {},
        function(data, text_status, xhr) {
            result = data.result.result;
            ok(true, "ipa_cmd() succeeded.");
        },
        function(xhr, text_status, error_thrown) {
            ok(false, "ipa_cmd() failed: "+error_thrown);
        }
    );

    var setup_status_called = false;
    var save_password_called= false;
    var load_manager_called = false;
    var load_success_called = false;
    var load_failure_called = false;
    var update_success_called = false;
    var update_failure_called = false;

    function setup_status(){
        setup_status_called = true;
    }

    function save_password(){
        save_password_called = true;
        return [];
    }

    function load_manager(){
        load_manager_called = true;
    }

    function setup_st(){
    }

    var container = $("<div/>");
    var obj_name = 'user';
    ipa_entity_set_details_definition(obj_name, [
        ipa_stanza({name:'identity', label:'Identity Details'}).
            input({name:'title', label: 'Title'}).
            input({name:'givenname', label:'First Name'}).
            input({name:'sn', label:'Last Name'}).
            input({name:'cn', label:'Full Name'}).
            input({name:'displayname', label:'Dispaly Name'}).
            input({name:'initials', label:'Initials'}),
        ipa_stanza({name:'account', label:'Account Details'}).
            input({name:'status', label:'Account Status', setup: setup_status}).
            input({name:'uid', label:'Login'}).
            input({name:'userpassword', label:'Password', save: save_password}).
            input({name:'uidnumber', label:'UID'}).
            input({name:'gidnumber', label:'GID'}).
            input({name:'homedirectory', label:'homedirectory'}),
        ipa_stanza({name:'contact', label:'Contact Details'}).
            input({name:'mail', label:'E-mail Address'}).
            input({name:'telephonenumber', label:'Numbers'}),
        ipa_stanza({name:'address', label:'Mailing Address'}).
            input({name:'street', label:'Address'}).
            input({name:'location', label:'City'}).
            input({name:'state', label:'State', setup: setup_st}).
            input({name:'postalcode', label:'ZIP'}),
        ipa_stanza({name:'employee', label:'Employee Information'}).
            input({name:'ou', label:'Org. Unit'}).
            input({name:'manager', label:'Manager', load: load_manager}),
        ipa_stanza({name:'misc', label:'Misc. Information'}).
            input({name:'carlicense', label:'Car License'})
    ]);

    var entity = ipa_get_entity(obj_name);
    var facet = entity.get_facet('details');
    facet.create(container);
    facet.setup(container);
    facet.load(container, result);

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

    var dts= identity.find('dt');

    same(
        dts.length, 6,
        'Checking dt tags for identity'
    );

    same(
        dts[5].title, facet.sections[0].fields[5].name,
        'Checking dt title'
    );

    container.attr('id','user');

    ok (
        setup_status_called,
        'Setup status called'
    );

    ok (load_manager_called, 'load manager called');

    facet.update(container,
                     'kfrog',
                     function(){update_success_called = true},
                     function(){update_failure_called = true});

    ok (update_success_called,'update success called');
    ok (!update_failure_called,'update failure not called');
    ok (save_password_called, 'save password called');

});


test("Testing  _ipa_create_text_input().", function(){

    var name = "name";
    var value="value";
    var rights = 'rscwo'
    var input = _ipa_create_text_input(name, value, null,rights);
    ok(input,"input not null");

    var text = input.find('input');
    ok(text);

    same(text[0].name,name );
    same(text[0].value,value );
    same(text[0].type,"text" );
});

test("Testing  _ipa_create_text_input() read only .", function(){

    var name = "name";
    var value="value";
    var rights = 'rsc'
    var input = _ipa_create_text_input(name, value, null,rights);
    ok(input,"input not null");

    var text = input.find('input');
    ok(text);

    same(text[0].name,name );
    same(text[0].value,value );
    same(text[0].type,"text" );
    ok(text[0].disabled);

});




test("Testing ipa_details_section_setup again()",function(){

    var section = ipa_details_section({name: 'IDIDID', label: 'NAMENAMENAME'}).
        input({name:'cn', label:'Entity Name'}).
        input({name:'description', label:'Description'}).
        input({name:'number', label:'Entity ID'});
    var fields = section.fields;
    var container = $("<div title='entity'/>");
    var details = $("<div/>");
    container.append(details);

    var result = {};

    section.create(container);
    section.setup(container);
    section.load(container, result);

    ok(container.find('hr'),'hr');

    //var h2= container.find('h2');
    //ok(h2);
    //ok(h2[0].innerHTML.indexOf(section.label) > 1,"find name in html");

    var dl = container.find('dl');
    ok(dl,'dl');
    same(dl[0].children.length,6,'6 children');
    same(dl[0].id, section.name);
    same(dl[0].children[0].title, fields[0].name,'title matches name');
    same(dl[0].children[0].innerHTML, fields[0].label+":",
         'inner HTML matches label');
    same(dl[0].children[5].title, fields[2].name,
         'title matches fields[2] name');


});
