//useSampleData is defined in index.xhtml.  Work around for development
var sampleData;


function clearOld(){
    $('#searchResultsTable thead').html("");
    $('#searchResultsTable tfoot').html("");
    $('#searchResultsTable tbody').find("tr").remove();
    $('#content').html("");
}

function showSearch(){
    clearOld();
    $('#search').css("visibility","visible");
    $('#content').css("visibility","hidden");
    $('#search').css("display","block");
    $('#content').css("display","none");
    $("#filter").css("display","block");
    $("#searchButtons").html("");
    

}

function showContent(){
    clearOld();
    $('#search').css("visibility","hidden");
    $('#content').css("visibility","visible");
    $('#search').css("display","none");
    $('#content').css("display","block");
}

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
    link = document.createElement("a");
    link.href= "?tab=" +obj+"&facet=details&pkey="+pkey;
    link.innerHTML = pkey;
    cell.appendChild(link);
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

    this.obj = obj;
    this.method = method;
    this.columns = cols;

    showSearch();

    $('#searchResultsTable thead').html("");
    $('#searchResultsTable tbody').html("");
    $("#new").click(function(){
	location.href="?tab="+obj+"&facet=add";
    });
    this.buildColumnHeaders();
}


executeSearch = function(searchForm){
    var queryFilter = $("#queryFilter").val();

    $('#searchResultsTable tbody').html("");

    ipa_cmd(searchForm.method,
	    [queryFilter],
	    {"all":"true"},
	    function(json){
		searchForm.searchSuccess(json);
	    },
	    function(json){
		alert("Search Failed");
	    },searchForm.obj);

}

