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

/* IPA Object Add  - creating new instances of entities */

/* REQUIRES: ipa.js */

/*
 * An associatev array between entity names and their builders
 */
var builders = {} ;


function add_fail(desc){
    alert(desc);
}


//Process for managing the 'add' functionality
function EntityBuilder(obj,addProperties,addOptionsFunction ){
    this.obj = obj;
    this.addProperties = addProperties;
    if (addOptionsFunction){
        this.addOptionsFunction = addOptionsFunction;
    }else{
        this.addOptionsFunction = function(){
            var options = { };
            return options;
        }
    }

    this.add = function(on_success){
        var options = this.addOptionsFunction();
        var params = [$("#pkey").val()];
        ipa_cmd( 'add', params, options, on_success, add_fail, this.obj );
    }

    this.setup = function(){
        showContent();
        $("<h1/>" ,{ html : "Add new " + this.obj } ).appendTo("#content");
        $("<div id='addForm'> </div>")
            .appendTo("#content");
        var label =$("<span>Add and </span>").appendTo("#addForm")
        $("<input \>",
          {id:'addEdit',
           type:'button',
           value:'Edit',
           click: function(){
               var params = ipa_parse_qs();
               builders[params["tab"]].add (addEdit)
           }
          }).appendTo(label);
        $("<input\>", {
            id:'addAnother',
            type:'button',
            value:'Add Another',
            click: function(){
               var params = ipa_parse_qs();
                builders[params["tab"]].add (addAnother)
            }
        }).appendTo(label);
        $("<dl id='addProperties' />").appendTo("#addForm");

        for (index = 0; index < this.addProperties.length; index++){
            var prop = this.addProperties[index];
            var title = $("<dt/>",{html:prop.title});
            var definition =    $("<dd></dd>");
            $("<input/>",{
                id:prop.id,
                type:prop.type
            }).appendTo(definition);
            definition.appendTo(title);
            title.appendTo("#addProperties");
        }
    }
    //register the new object with the associatev array of builders.
    builders[obj] = this;
}


function addAnother(response){
    var params = ipa_parse_qs();
    builders[params["tab"]].setup();
}

function addEdit(response){
    var params = ipa_parse_qs();
    var hash= "tab="
        + params["tab"]
        +"&facet=details&pkey="
        +$("#pkey").val();
    window.location.hash = hash;
}