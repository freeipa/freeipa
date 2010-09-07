
//Columns is an array of items in the form
// {title, column,  render}
//title: the the value that goes at the head of the column
//filed: the column in the response used for populating the value
//render: the function used to generate  cell.innerHtml
//       it is in the form:
//       render(current, cell)
//        current is the row in response
//        cell is the td in the table


//These are helper functions, either assigned to the rneder method
//Or called from a thin wrapper render method
function  renderSimpleColumn(current,cell){
    cell.innerHTML = current[this.column];
}


function  renderUnknownColumn(current,cell){
    cell.innerHTML = "Unknown";
}


function renderPkeyColumn2(obj,pkeyCol,current,cell){
    $("<a/>",{
    href:"#tab="+obj+"&facet=details&pkey="+current[pkeyCol],
    html:  "" + current[pkeyCol],
    }).appendTo(cell);
}

function renderPkeyColumn(form,current,cell){
    renderPkeyColumn2(form.obj, form.pkeyCol,current, cell);
}




function renderDetailColumn(current,cell,pkey,obj){
    $("<a/>",{
    href:"#tab="+obj+"&facet=details&pkey="+pkey,
    html:  ""+ current[this.column],
    }).appendTo(cell);
}



function SearchForm(obj, method, cols){

    this.buildColumnHeaders =  function (){
    var columnHeaders  = document.createElement("tr");
    for (var i =0 ; i != this.columns.length ;i++){
        var th = document.createElement("th");
        th.innerHTML = this.columns[i].title;
        columnHeaders.appendChild(th);
    }
    $('#searchResultsTable thead:last').append(columnHeaders);
    }


    this.renderResultRow = function(current){
    var row = document.createElement("tr");
    var cell;
    var link;
    for(var index = 0 ; index < this.columns.length; index++){
        this.columns[index].render(current, row.insertCell(-1));
    }
    return row;
    }

    this.searchSuccess = function (json){
        if (json.result.truncated){
            $("#searchResultsTable tfoot").html("More than "+sizelimit+" results returned.  First "+ sizelimit+" results shown." );
        }else{
            $("#searchResultsTable tfoot").html(json.result.summary);
        }
        $("#searchResultsTable tbody").find("tr").remove();
        for (var index = 0; index !=  json.result.result.length; index++){
            var current = json.result.result[index];
            $('#searchResultsTable tbody:last').append(this.renderResultRow(current));
        }
    }

    this.searchWithFilter = function(queryFilter){
        var form = this;

        $('#searchResultsTable tbody').html("");
        $('#searchResultsTable tbody').html("");
        $('#searchResultsTable tfoot').html("");

        ipa_cmd(this.method,
                [queryFilter],
                {"all":"true"},
                function(json){
                    form.searchSuccess(json);
                },
                function(json){
                    alert("Search Failed");
                },
                form.obj);
    }

    this.setup = function(){
        showSearch();

        $('#searchResultsTable thead').html("");
        $('#searchResultsTable tbody').html("");
        $('#searchResultsTable tfoot').html("");
        $("#new").click(function(){
            location.hash="tab="+obj+"&facet=add";
        });
        $("#query").click(executeSearch);
        this.buildColumnHeaders();
        var params = ipa_parse_qs();
        qs = location.hash.substring(1);
        //TODO fix this hack.  since parse returns an object, I don't know how to see if that object has a"critia" property if criteria is null.
        if (qs.indexOf("criteria") > 0)
        {
            this.searchWithFilter(params["criteria"]);
        }
    }

    this.obj = obj;
    this.method = method;
    this.columns = cols;
    this.setup();
}
executeSearch = function(){
    var queryFilter = $("#queryFilter").val();
    var qp = ipa_parse_qs();
    var tab = qp.tab;
    if (!tab){
        tab = 'user';
    }
    window.location.hash="#tab="
      +tab
    +"&facet=search&criteria="
    +queryFilter;
}
