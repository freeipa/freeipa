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

    var fields = [
        {name:'cn', label:'Entity Name'},
        {name:'description', label:'Description'},
        {name:'number', label:'Entity ID'}
    ];

    var sections = [
        {name:'identity', label:'Entity Details', fields:fields}
    ];

    var identity = sections[0];
    var key = 'entity';

    var container = $("<div/>",{id: key});
    ipa_details_create(container, sections);

    same(
        container[0].title, key,
        "Checking container name"
    );
    
    var dl = container.find('dl#identity');
    ok(
        dl,
        "Checking section"
    );

    same(
        dl[0].children.length, fields.length,
        "Checking fields"
    );

});


test("Testing  _ipa_create_text_input().", function(){

    var name = "name";
    var value="value";
    var input = _ipa_create_text_input(name, value);
    ok(input,"input not null");

    same(input[0].name,name );
    same(input[0].value,value );
    same(input[0].type,"text" );
});



test("Testing ipa_details_section_setup()",function(){

    var fields = [
        {name:'cn', label:'Entity Name'},
        {name:'description', label:'Description'},
        {name:'number', label:'Entity ID'}
    ];

    var section = {
        name: 'IDIDID',
        label: 'NAMENAMENAME',
        fields: fields
    };

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