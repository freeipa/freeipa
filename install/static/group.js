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

var group_details_list =
    [['identity', 'Group Details', [
        ['cn', 'Group Name'],
        ['description', 'Description'],
	['gidnumber', 'Group ID']]]];

function setupGroupDetails(group){

    window.location.hash="#tab=user&facet=details&pkey="+group;

    //re initialize global parse of parameters
    qs = ipa_parse_qs();

    //TODO make this work for more than just user details
    user_details_lists;

    showDetails();

    ipa_details_init('group');
    ipa_details_create(group_details_list, $('#details'));
    ipa_details_load(qs['pkey'], on_win, null, "sampledata/groupshow.json");
    $('h1').text('Managing group: ' + group);
}



function renderGroupDetails(group)
{

}


function renderGroupDetailColumn(current,cell){

    $("<a/>",{
	href:"#tab=group&facet=details&pkey="+current.cn,
	html:  ""+ current[this.column],
	click: function(){ setupGroupDetails(current.cn)},
    }).appendTo(cell);
}


function setupGroupSearch(){

    var columns = [
	{title:"Group Name",  column:"cn",render: renderGroupDetailColumn},
	{title:"GID",  column:"gidnumber",render: renderSimpleColumn},
	{title:"Description",  column:"description",render: renderSimpleColumn}
    ];

    var groupSearchForm = new SearchForm("group", "find", columns,"sampledata/grouplist.json");

    $("#query").unbind();
    $("#query").click(function(){
	executeSearch(groupSearchForm);
    });
    $("#new").unbind();
    $("#new").click( setupAddGroup );


}
