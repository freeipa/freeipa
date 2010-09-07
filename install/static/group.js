function setupGroup(facet){

    if (groupForms[facet]){
        groupForms[facet].setup();
    }else if (facet == "details"){
        setupGroupDetails();
    }else if (facet == "add"){
        setupAddGroup();
    }else{
        groupForms.search.setup();
    }
}


function addGroupFail(desc){
    alert(desc);
}

function addGroup(on_success){

    var options = {
    posix: $('#isposix').is(':checked') ? 1 : 0  ,
    description:  $("#groupdescription").val()};


    var gid =      $("#groupidnumber").val();
    if (gid.length > 0){
    options.gidnumber = gid;
    }

    var params = [$("#groupname").val()];

    ipa_cmd( 'add', params, options, on_success, addGroupFail, 'group' );

}

function addEditGroup(){
    addGroup(function (response){
    location.hash="tab=group&facet=details&pkey="+$("#groupname").val();
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

var groupFacets=['details','users'];

function setupGroupDetails(group){

    //re initialize global parse of parameters
    qs = ipa_parse_qs();

    showDetails();
    setupFacetNavigation('group',qs['pkey'],qs['facet'],groupFacets);
    ipa_details_init('group');
    ipa_details_create(group_details_list, $('#details'));
    ipa_details_load(qs['pkey'], on_win, null);
    $('h1').text('Managing group: ' + group);
}

function renderGroupDetailColumn(current,cell){

    $("<a/>",{
        href:"#tab=group&facet=details&pkey="+current.cn,
        html:  ""+ current[this.column],
    }).appendTo(cell);
}



var groupSearchColumns = [
    {title:"Group Name",  column:"cn",render: renderGroupDetailColumn},
    {title:"GID",  column:"gidnumber",render: renderSimpleColumn},
    {title:"Description",  column:"description",render: renderSimpleColumn}
];

var groupForms = new GroupForms();

function GroupForms(){

    this.userListColumns = [ {title:"user",column:"member_user" }];
    this.obj="group";
    this.users = new AssociationList(
        this.obj,
        "users",
        "assignusers",
        this.userListColumns, groupFacets );

    this.assignusers = new AssociationForm(
        this.obj,
        "user",
        "assignusers",
        groupFacets,
        "uid",
        function(){
            return 'Add Users to group : '  + qs['pkey'] ;
        },
        BulkAssociator);


    this.search =  new SearchForm("group", "find", groupSearchColumns );


}

