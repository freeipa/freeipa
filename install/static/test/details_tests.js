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

    var details = [
        ['identity', 'Entity Details', [
            ['cn', 'Entity Name'],
            ['description', 'Description'],
            ['number', 'Entity ID']
        ]]
    ];

    var identity = details[0];
    var attrs=identity[2];
    var key = 'entity';

    var container = $("<div/>",{id: "container"});
    ipa_details_create(key, details, container)

    same(container[0].title,key);
    var dl = container.find('dl#identity');
    ok(dl );

    same(dl[0].children.length, attrs.length);

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



test("Testing ipa_generate_dl()",function(){

    var details = [
        ['cn', 'Entity Name'],
        ['description', 'Description'],
        ['number', 'Entity ID']
    ];
    var name = 'NAMENAMENAME';
    var identity = 'IDIDID';
    var parent = $("<div/>");
    var jobj = $("<div title='entity'/>");
    parent.append(jobj);
    ipa_generate_dl(jobj, identity,name, details);

    ok(parent.find('hr'));

    var h2= parent.find('h2');
    ok(h2);
    ok(h2[0].innerHTML.indexOf(name) > 1,"find name in html");

    var dl = parent.find('dl');
    ok(dl);
    same(dl[0].children.length,3);
    same(dl[0].id, identity);
    same(dl[0].children[0].title,details[0][0]);
    same(dl[0].children[0].innerHTML,details[0][1]+":");
    same(dl[0].children[2].title,details[2][0]);
    same(dl[0].children[2].innerHTML,details[2][1]+":");

});