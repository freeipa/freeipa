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


test("Testing ipa_details_create().", function() {

    var name = 'NAMENAMENAME';
    var identity = 'IDIDID';

    var section = ipa_stanza({name:identity, label:name}).
        input({name:'cn', label:'Entity Name'}).
        input({name:'description', label:'Description'}).
        input({name:'number', label:'Entity ID'});


    var details = section.fields;
    var parent = $("<div/>");
    var container  = $("<div title='entity'/>");
    parent.append(container);
    ipa_details_section_setup(parent,container,  section);

    ok(parent.find('hr').length);

    var h2= parent.find('h2');
    ok(h2.length);
    ok(h2[0].innerHTML.indexOf(name) > 1,"find name in html");

    var dl = parent.find('dl');
    ok(dl.length);
    same(dl[0].children.length,3,"children tag count");
    same(dl[0].id, identity,"identity");
    same(details[0].name,  dl[0].children[0].title,"name");
    var d = dl[0].children[0].innerHTML;
    same(details[0].label+":",d);
    same(details[2].name,dl[0].children[2].title);
    d = dl[0].children[2].innerHTML;
    same(details[2].label+":" ,d);

});



test("Testing details lifecycle:setup, load, save ().", function(){

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
    var sections = facet.get_sections();
    ipa_details_create(container, sections);

    var contact = container.find('dl#contact.entryattrs');
    ok(contact);
    var identity = container.find('dl#identity.entryattrs');
    ok(identity);
    var dts= identity.find('dt');
    ok(dts);
    same(6, dts.length);
    same('initials',dts[5].title);

    //TODO extract into Fixture
    IPA.ajax_options.async = false;
    $.ajaxSetup(IPA.ajax_options);
    IPA.json_url = './data';
    IPA.use_static_files = true;

    container.attr('id','user');

    ok (setup_status_called , 'setup status called');


    ipa_details_load(container,
                     'kfrog',
                     function(){load_success_called = true},
                     function(){load_failure_called = true});

    ok (load_success_called,'load success called');
    ok (!load_failure_called,'load failure not called');


    ok (load_manager_called, 'load manager called');


    ipa_details_load(container,
                     'kfrog',
                     function(){load_success_called = true},
                     function(){load_failure_called = true});


    ipa_details_update(container,
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
    var input = _ipa_create_text_input(name, value);
    ok(input,"input not null");

    var text = input.find('input');
    ok(text);

    same(text[0].name,name );
    same(text[0].value,value );
    same(text[0].type,"text" );
});


test("Testing ipa_details_section_setup()",function(){

    var section = ipa_stanza({name: 'IDIDID', label: 'NAMENAMENAME'}).
        input({name:'cn', label:'Entity Name'}).
        input({name:'description', label:'Description'}).
        input({name:'number', label:'Entity ID'});
    var fields = section.fields;
    var container = $("<div title='entity'/>");
    var details = $("<div/>");
    container.append(details);

    ipa_details_section_setup(container, details, section);

    ok(container.find('hr'));

    var h2= container.find('h2');
    ok(h2);
    ok(h2[0].innerHTML.indexOf(section.label) > 1,"find name in html");

    var dl = container.find('dl');
    ok(dl);
    same(dl[0].children.length,3);
    same(dl[0].id, section.name);
    same(dl[0].children[0].title, fields[0].name);
    same(dl[0].children[0].innerHTML, fields[0].label+":");
    same(dl[0].children[2].title, fields[2].name);
    same(dl[0].children[2].innerHTML, fields[2].label+":");

});
