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


//Process for managing the 'add' functionality
function EntityBuilder(obj,addProperties){

    var builder = this;

    this.obj = obj;
    this.addProperties = addProperties;

    this.getPKey = function(){
        return $("#pkey").val();
    }

    this.getOptions = function(){
        return {};
    }

    this.add_fail = function(desc){
        alert(desc);
    }

    this.add = function(pkey, on_success){
        var params = [pkey];
        var options = this.getOptions();
        ipa_cmd( 'add', params, options, on_success, this.add_fail, this.obj );
    }

    this.setup = function(){
        showContent();
        $("<h1/>" ,{ html : "Add new " + this.obj } ).appendTo("#content");
        $("<div id='addForm'> </div>")
            .appendTo("#content");
        var label =$("<span>Add and </span>").appendTo("#addForm")

        $("<input \>", {
            id:'addEdit',
            type:'button',
            value:'Edit',
            click: function(){
                var params = ipa_parse_qs();
                var pkey = builder.getPKey();
                builder.add(pkey, function(response){
                    if (response.error){
                        if (response.error.message) {
                            alert(response.error.message);
                        } else {
                            alert("error adding entry");
                        }
                        return;
                    }
                    var hash= "tab="
                        +params["tab"]
                        +"&facet=details&pkey="
                        +pkey;
                    window.location.hash = hash;
                });
            }
        }).appendTo(label);

        $("<input\>", {
            id:'addAnother',
            type:'button',
            value:'Add Another',
            click: function(){
                var params = ipa_parse_qs();
                var pkey = builder.getPKey();
                builder.add(pkey, function(response){
                    if (response.error){
                        if (response.error.message) {
                            alert(response.error.message);
                        } else {
                            alert("error adding entry");
                        }
                        return;
                    }
                    builder.setup();
                });
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
}



