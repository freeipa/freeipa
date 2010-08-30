var user_details_lists = [
    ['identity', 'Identity Details', [
        ['title', 'Title'],
        ['givenname', 'First Name'],
        ['sn', 'Last Name'],
        ['cn', 'Full Name'],
        ['displayname', 'Dispaly Name'],
        ['initials', 'Initials']
    ]
    ],
    ['account', 'Account Details', [
        ['call_a_status', 'Account Status'],
        ['uid', 'Login'],
        ['call_a_password', 'Password'],
        ['uidnumber', 'UID'],
        ['gidnumber', 'GID'],
        ['homedirectory', 'homedirectory']
    ]
    ],
    ['contact', 'Contact Details', [
        ['mail', 'E-mail Address'],
        ['call_a_numbers', 'Numbers']
    ]
    ],
    ['address', 'Mailing Address', [
        ['street', 'Address'],
        ['location', 'City'],
        ['call_a_st', 'State'],
        ['postalcode', 'ZIP']
    ]
    ],
    ['employee', 'Employee Information', [
        ['ou', 'Org. Unit'],
        ['call_a_manager', 'Manager']
    ]
    ],
    ['misc', 'Misc. Information', [
        ['carlicense', 'Car License']
    ]
    ]
];


function setupUser(facet){
    if (facet == "details"){
        setupUserDetails();
    }else  if (facet == "add"){
        userBuilder.setup();
    }else  if (facet == "group"){
        setupUserGroupList();
    }else  if (facet == "groupmembership"){
        setupUserGroupMembership();
    }else{
        userSearchForm.setup();
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
        setupUserDetails($("#login").val());
    });
}

var userAddProperties = [
    {title: 'login',      id: 'pkey',      type: 'text'},
    {title: 'First Name', id: 'firstname', type:'text'},
    {title: 'Last Name', id: 'lastname', type:'text'}
];
var userBuilder =
    new EntityBuilder(
        "user",
        userAddProperties,
        function(){
            var options = {  givenname:  $("#firstname").val(),
                             sn:  $("#lastname").val()};
            return options;
        });


function setupFacetNavigation(pkey,facet){
    $("#viewtype").html("");
    var facets = ["details","group", "groupmembership"];

    for (var i =0; i < facets.length; i++){
        var li = $('<li>').appendTo($("#viewtype"));
        if (facets[i] == facet){
            $('<img src="but-selected.png" alt="" />');
            li.html(facets[i]);
        }else{
            $('<img src="but-unselected.png" alt="" />').appendTo(li);
            $('<a/>',{
                href: "#tab=user&facet="+facets[i]+"&pkey="+pkey,
                html: facets[i]
            }).appendTo(li);
        }
    }
}

function setupUserDetails(user){
    qs = ipa_parse_qs();
    setupFacetNavigation(qs.pkey,qs.facet);
    showDetails();
    renderUserDetails();
}

function renderUserDetails()
{
    ipa_details_init('user');
    ipa_details_create(user_details_lists, $('#details'));

    if (qs['principal']) {
        ipa_cmd(
            'find', [], {'krbprincipalname': qs['principal']},
            on_win_find, null, 'user', "sampledata/usershow.json");

        return;
    }

    if (!qs['pkey'])
        return;

    ipa_details_load(qs['pkey'], on_win, null, "sampledata/usershow.json");
    $('h1').text('Managing user: ' + qs['pkey']);
}

function  renderSimpleColumn(current,cell){
    cell.innerHTML = current[this.column];
}

function renderUserLinks(current, cell){
    link = document.createElement("a");
    cell.appendChild(link);

    $("<a/>",{
        href:"#tab=user&facet=details&pkey="+current.uid,
        html:  "[D]",
    }).appendTo(cell);

    $("<a/>",{
        href: "#tab=user&facet=group&pkey="+current.uid,
        html: "[G]"
    }).appendTo(cell);

    $("<a/>",{
        href:"#tab=user&facet=netgroup&pkey="+current.uid,
        html: "[N]"
    }).appendTo(cell);

    $("<a/>",{
        href:"#tab=user&facet=role&pkey="+current.uid,
        html:"[R]"
    }).appendTo(cell);
}

function renderUserDetailColumn(current,cell){

    $("<a/>",{
        href:"#tab=user&facet=details&pkey="+current.uid,
        html:  ""+ current[this.column],
        click: function(){ setupUserDetails(current.uid)},
    }).appendTo(cell);
}

var userSearchColumns  = [
    {title:"Name",     column:"cn",             render: renderSimpleColumn},
    {title:"Login",    column:"uid",            render: renderUserDetailColumn},
    {title:"UID",      column:"uidnumber",      render: renderSimpleColumn},
    {title:"EMAIL",    column:"mail",           render: renderSimpleColumn},
    {title:"Phone",    column:"telephonenumber",render: renderSimpleColumn},
    {title:"Job Title",column:"title",          render: renderSimpleColumn},
    {title:"Actions",  column:"none",           render: renderUserLinks}
];

var userSearchForm = new SearchForm("user", "find", userSearchColumns,  "sampledata/userlist.json");

/*Usr group enrollement:
  given a user, manage the groups in which they are enrolled */
function populateUserGroupFailure(){
    alert("Can't find user");
}

function setupUserGroupMembership(pkey){
    sampleData = "sampledata/usershow.json";
    showAssociations();
    qs = ipa_parse_qs();
    setupFacetNavigation(qs['pkey'],qs['facet']);

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

    $("#find").click(function(){
        ipa_cmd( 'find', [], {}, populateUserGroupSearch, populateUserGroupFailure, 'group', "sampledata/grouplist.json" );

    });
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
    var  currentGroupToEnroll =     groupsToEnroll.shift();

    if (currentGroupToEnroll){
        var options = {"user":currentUserToEnroll};
        var args = [currentGroupToEnroll];

        ipa_cmd( 'add_member',args, options ,
                 enrollUserInGroupSuccess,
                 enrollUserInGroupFailure,'group' );
    }else{
        location.hash="tab=user&facet=group&pkey="+qs.pkey;
    }
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


function setupUserGroupList(){
    qs = ipa_parse_qs();
    setupFacetNavigation(qs['pkey'],qs['facet']);
    showSearch();

    $("#filter").css("display","none");

    $("#searchButtons").html("");
    $("<input/>",{
        type:  'button',
        value: 'enroll',
        click: function(){
            location.hash="tab=user&facet=groupmembership&pkey="+qs['pkey'];
        }
    }).appendTo("#searchButtons");
    var columnHeaders  = document.createElement("tr");
    for (var i =0 ; i != groupMembershipColumns.length ;i++){
        var th = document.createElement("th");
        th.innerHTML = groupMembershipColumns[i].title;
        columnHeaders.appendChild(th);
    }
    $('#searchResultsTable thead:last').append(columnHeaders);

    ipa_cmd( 'show', [qs['pkey']], {}, populateUserEnrollments, populateUserGroupFailure, 'user',"sampledata/usershow.json" );
}


function on_win(data, textStatus, xhr)
{
    if (data['error'])
        alert(data['error']['message']);
}

function on_win_find(data, textStatus, xhr)
{
    if (data['error']) {
        alert(data['error']['message']);
        return;
    }

    var result = data.result.result;
    if (result.length == 1) {
        var entry_attrs = result[0];
        qs['pkey'] = entry_attrs['uid'][0];

        ipa_details_load(qs['pkey'], on_win);
        $('h1').text('Managing user: ' + qs['pkey']);
    }
}

function reset_on_click()
{
    ipa_details_reset();
    return (false);
}

function update_on_click()
{
    ipa_details_update(qs['pkey'], on_win);
    return (false);
}

/* Account status Toggle button */

function toggle_on_click(obj)
{
    var jobj = $(obj);
    var val = jobj.attr('title');
    if (val == 'Active') {
        ipa_cmd(
            'lock', [qs['pkey']], {}, on_lock_win, on_fail,
            ipa_objs['user']['name']
        );
    } else {
        ipa_cmd(
            'unlock', [qs['pkey']], {}, on_lock_win, on_fail,
            ipa_objs['user']['name']
        );
    }
    return (false);
}

function on_lock_win(data, textStatus, xhr)
{
    if (data['error']) {
        alert(data['error']['message']);
        return;
    }

    var jobj = $('a[title=Active]');
    if (jobj.length) {
        if (ipa_details_cache) {
            var memberof = ipa_details_cache['memberof'];
            if (memberof) {
                memberof.push(
                    'cn=inactivated,cn=account inactivation'
                );
            } else {
                memberof = ['cn=inactivated,cn=account inactivation'];
            }
            ipa_details_cache['memberof'] = memberof;
            a_status(jobj.parent().prev(), ipa_details_cache);
            jobj.parent().remove()
        }
        return;
    }

    var jobj = $('a[title=Inactive]');
    if (jobj.length) {
        if (ipa_details_cache) {
            var memberof = ipa_details_cache['memberof'];
            if (memberof) {
                for (var i = 0; i < memberof.length; ++i) {
                    if (memberof[i].indexOf('cn=inactivated,cn=account inactivation') != -1) {
                        memberof.splice(i, 1);
                        break;
                    }
                }
            } else {
                memberof = [];
            }
            ipa_details_cache['memberof'] = memberof;
            a_status(jobj.parent().prev(), ipa_details_cache);
            jobj.parent().remove();
        }
        return;
    }
}

/* ATTRIBUTE CALLBACKS */

var toggle_temp = 'S <a href="jslink" onclick="return (toggle_on_click(this))" title="S">Toggle</a>';
function a_status(jobj, result, mode)
{
    if (mode != IPA_DETAILS_POPULATE)
        return;

    var memberof = result['memberof'];
    if (memberof) {
        for (var i = 0; i < memberof.length; ++i) {
            if (memberof[i].indexOf('cn=inactivated,cn=account inactivation') != -1) {
                var t = toggle_temp.replace(/S/g, 'Inactive');
                ipa_insert_first_dd(jobj, t);
                return;
            }
        }
    }
    ipa_insert_first_dd(jobj, toggle_temp.replace(/S/g, 'Inactive'));
}

var pwd_temp = '<a href="jslink" onclick="return (resetpwd_on_click(this))" title="A">Reset Password</a>';
function a_password(jobj, result, mode)
{
    if (mode == IPA_DETAILS_POPULATE)
        ipa_insert_first_dd(jobj, pwd_temp.replace('A', 'userpassword'));
}

var select_temp = '<select title="st"></select>';
var option_temp = '<option value="V">V</option>';
var states = [
    'AL', 'AK', 'AS', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'DC', 'FM',
    'FL', 'GA', 'GU', 'HI', 'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA',
    'ME', 'MH', 'MD', 'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV',
    'NH', 'NJ', 'NM', 'NY', 'NC', 'ND', 'MP', 'OH', 'OK', 'OR', 'PW',
    'PA', 'PR', 'RI', 'SC', 'SD', 'TN', 'TX', 'UT', 'VT', 'VI', 'VA',
    'WA', 'WV', 'WI', 'WY', '',
];
function a_st(jobj, result, mode)
{
    if (mode != IPA_DETAILS_POPULATE)
        return;

    var next = jobj.next();
    next.css('clear', 'none');
    next.css('width', '70px');

    ipa_insert_first_dd(jobj, select_temp);

    var sel = jobj.next().children().first();
    for (var i = 0; i < states.length; ++i)
        sel.append(option_temp.replace(/V/g, states[i]));

    var st = result['st'];
    if (st)
        sel.val(st);
    else
        sel.val('');
}
