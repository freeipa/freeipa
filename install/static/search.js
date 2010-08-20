//useSampleData is defined in index.xhtml.  Work around for development
var sampleData;


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

function renderDetailColumn(current,cell,pkey,obj){
    $("<a/>",{
	href:"#tab=user&facet=details&pkey="+pkey,
	html:  ""+ current[this.column],
	click: function(){ setupUserDetails(current.uid)},
    }).appendTo(cell);
}



function SearchForm(obj, method, cols, searchSampleData){

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
	window.location.hash="#tab="
	+this.obj
	    +"&facet=search&criteria="
	    +queryFilter;

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
		},form.obj, form.searchSampleData);

    }

    this.obj = obj;
    this.method = method;
    this.columns = cols;
    this.searchSampleData = searchSampleData;

    showSearch();

    $('#searchResultsTable thead').html("");
    $('#searchResultsTable tbody').html("");
    $('#searchResultsTable tfoot').html("");

    $("#new").click(function(){
	location.href="#tab="+obj+"&facet=add";
    });
    this.buildColumnHeaders();

    var params = ipa_parse_qs();

    if (params["criteria"]){
	this.searchWithFilter(params["criteria"]);
    }
}


executeSearch = function(searchForm){
    var queryFilter = $("#queryFilter").val();
    searchForm.searchWithFilter(queryFilter);
}

