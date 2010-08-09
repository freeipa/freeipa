function setupGroup(facet){
    if (facet == "details"){
	setupGroupDetails();
    }else  if (facet == "add"){
        setupAddGroup();
    }else{
	setupGroupSearch();
    }
}


function addGroupFail(desc){
    alert(desc);
}

function addGroup(on_success){
    
    var options = {  
	posix: $('#isposix').is(':checked') ? 1 : 0  ,
	description:  $("#groupdescription").val()};


    var gid = 	 $("#groupidnumber").val();
    if (gid.length > 0){
	options.gidnumber = gid;
    }

    var params = [$("#groupname").val()];

    ipa_cmd( 'add', params, options, on_success, addGroupFail, 'group' );

}

function addEditGroup(){
    addGroup(function (response){
	location.href="index.xhtml?tab=group&facet=details&pkey="+$("#groupname").val();
    });
}

function addAnotherGroup(){
    addGroup(setupAddGroup);
}


function setupAddGroup(){
    showContent();
    $("<h1>Add new Group</h1>").appendTo("#content");

    $("<form id='addGroupForm'> </form>")
	.appendTo("#content");
    
    $("<label>Add and </label><input id='addEdit' type='button' value='Edit'/><input id='addAnother' type='button' value='Add Another'/>").appendTo("#addGroupForm");
    $("<dl id='groupProperties' />").appendTo("#addGroupForm");
      
    $("<dt>Name</dt><dd><input id='groupname' type='text'/></dd>")
	.appendTo("#groupProperties");
    $("<dt>Description</dt><dd><input id='groupdescription' type='text'/></dd>")
	.appendTo("#groupProperties");

    $("<dt>Is this a posix Group</dt><dd><input id='isposix' type='checkbox'/></dd>")
	.appendTo("#groupProperties");
    $("<dt>GID</dt><dd><input id='groupidnumber' type='text'/></dd>")
	.appendTo("#groupProperties");


    $("#addEdit").click(addEditGroup);
    $("#addAnother").click(addAnotherGroup);

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
    $("#new").click( setupAddGroup );


}
