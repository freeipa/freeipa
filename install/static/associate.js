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

function keyForFacet(tab, facet){
    qs = ipa_parse_qs();
    var key = qs['tab'] +'-'+ qs['facet'];
    return key;
}

/**
*This associator is built for the case where each association requires a separate rpc
*/
function SerialAssociator(form, oneObjPkey, manyObjPkeys){
    this.form = form;
    this.manyObjPkeys =  manyObjPkeys;
    this.oneObjPkey = oneObjPkey;

    this.associateNext = function(){
        var form = this.form;
        //TODO assert pre-conditions
        var  manyObjPkey =  manyObjPkeys.shift();
        if (manyObjPkey){
            var options = {};
            options[form.oneObj] = oneObjPkey;
            var args = [manyObjPkey];
            var associator = this;

            ipa_cmd( form.method,args, options ,
                     function(){
                         associator.associateNext();
                     },
                     function(response){
                         alert("associateFailure");
                     },
                     form.manyObj );
        }else{
            location.hash="tab="+form.oneObj
                +"&facet=details&pkey="+this.oneObjPkey;
        }
    }

}

/**
*This associator is for the common case where all the asociations can be sent
in a single rpc
*/
function BulkAssociator(form, pkey, manyObjPkeys){

 this.form = form;
    this.pkey =pkey;
    this.manyObjPkeys =  manyObjPkeys;

    this.associateNext = function(){
        var form = this.form;
        var option = manyObjPkeys.shift();
        while(manyObjPkeys.length > 0){
            option += "," + manyObjPkeys.shift();
        }

        var options = {
          "all":true
        };
        options[form.manyObj] = option;

        var args = [this.pkey];
        var associator = this;
        ipa_cmd( form.method,args, options ,
                 function(response){
                     var qs = ipa_parse_qs();
                     if (response.error){
                         alert("error adding memeber");
                     }else{
                         location.hash="tab=" +form.oneObj
                             +"&facet=details&pkey="+associator.pkey;
                     }
                 },
                 function(response){
                     alert("associateFailure");
                 },
                 form.oneObj );
    }
}

/**
 *  Create a form for a one to many association.
 *
 */
function AssociationForm(oneObj, manyObj,facet,facets, searchColumn, headerText , associatorConstructor, method){
    this.oneObj = oneObj;
    this.manyObj = manyObj;
    this.facet = facet;
    this.facets = facets;
    this.headerText = headerText;
    this.searchColumn = searchColumn;
    //An optional parameter to determine what ipa method to call to create
    //the association
    if (method){
        this.method = method;
    }else{
        this.method = 'add_member';
    }

    if (associatorConstructor){
        this.associatorConstructor = associatorConstructor;
    }else{
        this.associatorConstructor = SerialAssociator;
    }

    this.setup = function(pkey){
        showAssociations();
        qs = ipa_parse_qs();
        $("#availableList").html("");
        $("#enrollments").html("");

        setupFacetNavigation(this.oneObj,qs['pkey'],qs['facet'],this.facets);

        this.currentUserToEnroll = qs['pkey'];
        this.manyObjPkeys = [];
        var form = this;

        $('h1').text(this.headerText());


        $("#enroll").click(function(){
            form.associate();
        });
        $("#addToList").click(function(){
            $('#availableList :selected').each(function(i, selected){
                $("#enrollments").append(selected);
            });
            $('#availableList :selected').remove();
        });
        $("#removeFromList").click(function(){
            $('#enrollments :selected').each(function(i, selected){
                $("#availableList").append(selected);
            });
            $('#enrollments :selected').remove();
        });
        $("#find").click(function(){
            form.search();
        });
    }
    this.search = function(){

        var queryFilter = $("#associateFilter").val();

        var form = this;
        ipa_cmd( 'find', [queryFilter], {},
                 function(searchResults){
                        form.populateSearch(searchResults);
                 },
                 function(){
                     alert("associationSearchFailure");
                 },
                 this.manyObj);
    }

    this.associate = function(){
        var manyObjPkeys =  [];
        $('#enrollments').children().each(function(i, selected){
            manyObjPkeys.push(selected.value);
        });
        var pkey = qs['pkey'];
        var associator =
            new this.associatorConstructor (this, pkey, manyObjPkeys);
        associator.associateNext();
    }
    this.populateSearch = function(searchResults){
        var results = searchResults.result;
        $("#availableList").html("");
        for (var i =0; i != results.count; i++){
            var result = results.result[i];
            $("<option/>",{
                value: result[this.searchColumn][0],
                html:  result[this.searchColumn][0]
            }).appendTo( $("#availableList"));
        }
    }
}


/**
    A modfied version of search. It shows the  associations for an object.
*/
function AssociationList(obj,facet,assignFacet,associationColumns,facets) {
    this.obj = obj;
    this.facet = facet;
    this.assignFacet = assignFacet;
    this.associationColumns = associationColumns;
    this.facets = facets;


    this.populate = function(userData){
        var associationList = userData.result.result[this.associationColumns[0].column];
        for (var j = 0; j < associationList.length; j++){
            var row  = $("<tr/>").appendTo($('#searchResultsTable thead:last'));
            for (var k = 0; k < associationColumns.length ;k++){
                var column = this.associationColumns[k].column;
                $("<td/>",{
                    html: userData.result.result[column][j]
                }).appendTo(row);
            }
        }
    }
    this.setup=function(){
        qs = ipa_parse_qs();
        showSearch();
        buildFacetNavigation(facets);
        $("#filter").css("display","none");
        $("#searchButtons").html("");
        $("<input/>",{
            type:  'button',
            value: 'enroll',
            click: function(){
                location.hash="tab="+obj+"&facet="+assignFacet+"&pkey="+qs['pkey'];
            }
        }).appendTo("#searchButtons");
        var header = $("<tr/>").appendTo($('#searchResultsTable thead:last'));
        for (var i =0 ; i != associationColumns.length ;i++){
            $("<th/>",{
                html: associationColumns[i].title
            }).appendTo(header);
        }
        var form = this;
        ipa_cmd( 'show', [qs['pkey']], {},
                 function(result){
                     form.populate(result);
                 },
                 function(){
                     alert("associationListFailure");
                 },
                 this.obj);
    }
}
