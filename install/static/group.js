function setupGroup(facet){
    if (facet == "details"){
	setupGroupDetails();
    }else{
	setupGroupSearch();
    }
}

function setupGroupDetails(){

    $('#search').css("visibility","hidden");
    $('#content').css("visibility","visible");
    $('#content').load("group-details.inc");

    sampleData = "sampledata/groupshow.json";
}

function setupGroupSearch(){

    var columns = [
	{title:"Group Name",  column:"cn",render: function(current,cell){
	    renderDetailColumn(current,cell,current[this.column],"group");
	}},
	{title:"GID",  column:"gidnumber",render: renderSimpleColumn},
	{title:"Description",  column:"description",render: renderSimpleColumn}
    ];

    var groupSearchForm = new SearchForm("group", "find", columns);

    $("#query").unbind();
    $("#query").click(function(){
	sampleData = "sampledata/grouplist.json";
	executeSearch(groupSearchForm);
    });
    $("#new").unbind();
    $("#new").click( function() {
	alert("New Group...");
    });


}
