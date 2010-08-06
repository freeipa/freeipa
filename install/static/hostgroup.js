function setupHostgroup(facet){
    if (facet == "details"){
	setupHostgroupDetails();
    }else{
	setupHostgroupSearch();
    }
}

function setupHostgroupDetails(){
    var detailsForm = new DetailsForm();
}


function setupHostgroupSearch(){

    var columns = [
	{title:"Hostgroup",column:"cn",render:  function(current,cell){
	     renderDetailColumn(current,cell,current[this.column],"hostgroup");
	 }},
	{title:"Description", column:"description",render: renderSimpleColumn}];

    var hostgroupSearchForm = new SearchForm("hostgroup", "find", columns);

    $("#query").unbind();

    $("#query").click(function(){
	sampleData = "sampledata/hostgrouplist.json";
	executeSearch(hostgroupSearchForm);
    });
    $("#new").unbind();
    $("#new").click( function() {
	alert("New Hostgroup...");
    });

}
