function setupHost(facet){
    if (facet == "details"){
	setupHostDetails();
    }else{
	setupHostSearch();
    }
}

function setupHostDetails(){
    var detailsForm = new DetailsForm();
}

function setupHostSearch(){

    sampleData = "sampledata/hostlist.json";
    var columns = [
	{title:"Host",column:"fqdn",render: function(current,cell){
	    renderDetailColumn(current,cell,current[this.column],"group");
	}},
	{title:"Comment",   column: "description", render: renderSimpleColumn},
	{title:"Enrolled?",  render: renderUnknownColumn},
	{title:"Manages?",   render: renderUnknownColumn}
    ];

    var hostSearchForm = new SearchForm("host", "find", columns);

    $("#query").unbind();
    $("#query").click(function(){
	sampleData = "sampledata/hostlist.json";
	executeSearch(hostSearchForm);
    });

    $("#new").unbind();
    $("#new").click( function() {
	alert("New Host...");
    });

}
