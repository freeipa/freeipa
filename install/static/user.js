function setupUser(facet){
    if (facet == "details"){
	setupUserDetails()
    }else  if (facet == "add"){
	setupAddUser();
    }else  if (facet == "group"){
	setupUserGroupEnrollmentSearch();
    }else  if (facet == "groupmembership"){
	setupUserGroupMembership();
    }else{

	setupUserSearch();
    }
}

function add_user_fail(reason){
     alert("Add User Failed:"+JSON.stringify(reason));
}

function addUser(on_success){

    var options = {  givenname:  $("#firstname").val(),
		     sn:  $("#lastname").val(),
		    uid :        $("#login").val()};

    ipa_cmd( 'add', [], options, on_success, add_user_fail, 'user' );
}

function addAnotherUser(){

    addUser(setupAddUser);
}

function addEditUser(){
    addUser(function (response){
	location.href="index.xhtml?tab=user&facet=details&pkey="+$("#login").val();
    });
}

function setupAddUser(){

    showContent();

    $('#content').load("user-add.inc");
}


function setupUserDetails(){
    showContent();
    $('#content').load("user-details.inc");
    sampleData = "sampledata/usershow.json";
}

function  renderSimpleColumn(current,cell){
	cell.innerHTML = current[this.column];
}

function renderUserLinks(current, cell){
	link = document.createElement("a");
	cell.appendChild(link);

    $("<a/>",{
	href:"?tab=user&facet=details&pkey="+current.uid,
	html:  "[D]",
	click:setupUserDetails,
    }).appendTo(cell);

    $("<a/>",{
	href: "#tab=user&facet=details&pkey="+current.uid,
	click:setupUserGroupMembership,
	html: "[G]"
    }).appendTo(cell);

    $("<a/>",{
	href:"?tab=user&facet=netgroup&pkey="+current.uid,
	html: "[N]"
    }).appendTo(cell);

    $("<a/>",{
	href:"?tab=user&facet=role&pkey="+current.uid,
	html:"[R]"
    }).appendTo(cell);
}



function renderUserDetailColumn(current,cell){
    renderDetailColumn(current,cell,current[this.column],"user");
}


var columns  = [
    {title:"Name",     column:"cn",             render: renderSimpleColumn},
    {title:"Login",    column:"uid",            render: renderUserDetailColumn},
    {title:"UID",      column:"uidnumber",      render: renderSimpleColumn},
    {title:"EMAIL",    column:"mail",           render: renderSimpleColumn},
    {title:"Phone",    column:"telephonenumber",render: renderSimpleColumn},
    {title:"Job Title",column:"title",          render: renderSimpleColumn},
    {title:"Actions",  column:"none",           render: renderUserLinks}
];

function setupUserSearch(){
    var userSearchForm = new SearchForm("user", "find", columns);

    $("#query").unbind();
    $("#query").click(function(){
	sampleData = "sampledata/userlist.json";
	executeSearch(userSearchForm);
    });
    $("#new").unbind();
    $("#new").click(setupAddUser);

}

/*Usr group enrollement:
  given a user, manage the groups in which they are enrolled */
function populateUserGroupFailure(){
    alert("Can't find user");
}



function setupUserGroupEnrollmentSearch(pkey){
    sampleData = "sampledata/usershow.json";
    showContent();
    $("#content").load("user-groups.inc");
}


function populateUserGroupSearch(searchResults){
    results = searchResults.result;
 	$("#grouplist").html("");
	for (var i =0; i != searchResults.result.count; i++){
	    var li = document.createElement("option");
	    li.value = searchResults.result.result[i].cn;
	    li.innerHTML = searchResults.result.result[i].cn;
	    $("#grouplist").append(li);
	}
}

var currentUserToEnroll;
var groupsToEnroll;

function enrollUserInGroupSuccess(response){
    enrollUserInNextGroup();
}

function enrollUserInGroupFailure(response){
    alert("enrollUserInGroupFailure");
}

function enrollUserInNextGroup(){
   var  currentGroupToEnroll = 	groupsToEnroll.shift();

    if (currentGroupToEnroll){
	var options = {"user":currentUserToEnroll};
	var args = [currentGroupToEnroll];

	ipa_cmd( 'add_member',args, options ,
		 enrollUserInGroupSuccess,
		 enrollUserInGroupFailure, 'group' );
    }else{
	setupUserGroupMembership();
    }
}

function initializeUserGroupEnrollments(){

    $('h1').text('Enroll user ' + qs['pkey'] + ' in groups');

    $("#enrollGroups").click(function(){
	groupsToEnroll =  [];
	$('#enrollments').children().each(function(i, selected){
	    groupsToEnroll.push(selected.value);
	});

	currentUserToEnroll = qs['pkey'];
	enrollUserInNextGroup();
    });

    $("#addToList").click(function(){
	$('#grouplist :selected').each(function(i, selected){
	    $("#enrollments").append(selected);
	});
	$('#grouplist :selected').remove();
    });

    $("#removeFromList").click(function(){
	$('#enrollments :selected').each(function(i, selected){
	    $("#grouplist").append(selected);
	});
	$('#enrollments :selected').remove();
    });

    $("#query").click(function(){
	 sampleData="sampledata/grouplist.json";
	 ipa_cmd( 'find', [], {}, populateUserGroupSearch, populateUserGroupFailure, 'group' );

    });

}


function renderUserGroupColumn(){
}

/*Group Membership&*/

function  renderUserGroupColumn(current,cell){
	cell.innerHTML = "Nothing to see here";
}

var groupMembershipColumns  = [
    {title:"Group",       column:"cn",        render: renderUserGroupColumn},
    {title:"GID",         column:"gid",       render: renderUserGroupColumn},
    {title:"Description", column:"uidnumber", render: renderUserGroupColumn},

];


function populateUserEnrollments(userData){

    var memberof_group = userData.result.result.memberof_group
    for (var j = 0; j < memberof_group.length; j++){
	var row  = document.createElement("tr");

	var td = document.createElement("td");
	td.innerHTML = memberof_group[j];
	row.appendChild(td);

	td = document.createElement("td");
	td.innerHTML = "TBD";
	row.appendChild(td);

	var td = document.createElement("td");
	td.innerHTML = "TBD";
	row.appendChild(td);

	$('#searchResultsTable thead:last').append(row);
    }
}


function setupUserGroupMembership(){

    $("#searchButtons").html("");

    $("<input/>",{
	type:  'button',
	value: 'enroll',
	click: setupUserGroupEnrollmentSearch
    }).appendTo("#searchButtons");


    showSearch();
    var columnHeaders  = document.createElement("tr");
    for (var i =0 ; i != groupMembershipColumns.length ;i++){
	var th = document.createElement("th");
	th.innerHTML = groupMembershipColumns[i].title;
	columnHeaders.appendChild(th);
    }
    $('#searchResultsTable thead:last').append(columnHeaders);

    sampleData="sampledata/usershow.json";
    ipa_cmd( 'show', [qs['pkey']], {}, populateUserEnrollments, populateUserGroupFailure, 'user' );


}