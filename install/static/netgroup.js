function setupNetgroup(facet){
    if (facet == "details"){
	setupNetgroupDetails();
    }else{
	setupNetgroupSearch();
    }
}




function setupNetgroupDetails(){
    var detailsForm = new DetailsForm();
}


function setupNetgroupSearch(){


    var columns = [
	{title:"Netgroup",column:"cn",render:  function(current,cell){
	    renderDetailColumn(current,cell,current[this.column],"netgroup");
	}},
	{title:"Description", column:"description",render: renderSimpleColumn}];

    var netgroupSearchForm = new SearchForm("netgroup", "find", columns);

    $("#query").unbind();
    $("#query").click(function(){
	sampleData = "sampledata/netgrouplist.json";
	executeSearch(netgroupSearchForm);
    });
    $("#new").unbind();
    $("#new").click( function() {
	alert("New Netgroup...");
    });


}
