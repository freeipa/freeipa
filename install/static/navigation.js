function setLoggedInText(principal){
    $("#loggedinas").html( "Logged in as  " + principal);
}

function whoamiSuccess(response){

    $.cookie("whoami", response.result.summary);
    setLoggedInText(response.result.summary);
}

function unimplemented(facet){

    showContent();
    $('#content').append("<div>Not yet implemented.</div>");

}

var parentTabs;
function getParentTabs(){
    if (!parentTabs){
    parentTabs  = {
        user     : "identity",
        group    : "identity",
        host     : "identity",
        hostgroup: "identity",
        netgroup : "identity",
        policy   : "policy",
        config   : "config"
    };
    }
    return parentTabs;
}

function buildNavigation(){
    params= ipa_parse_qs();
    var tab = params["tab"];

    if (!tab){
    tab=$.cookie("lastpage");
    }
    if  ( !tab ) {
    tab="user";
    }

    var facet = params["facet"];


    var siteMap = [{name:"IDENTITY",
            tab:"identity", //Default subtab
            children : [
            {name:"Users",tab:"user",  setup: setupUser},
            {name:"Groups",tab:"group",setup: setupGroup},
            {name:"Hosts",tab:"host",  setup:  setupHost},
            {name:"Hostgroups",
             tab:"hostgroup",
             setup:  setupHostgroup},
            {name:"Netgroups",tab:"netgroup", setup:setupNetgroup}
            ]},
           {name:"POLICY",  tab:"policy", setup: unimplemented},
           {name:"CONFIG",  tab:"config", setup: unimplemented }];

    //TODO autogen this from the site map

    var separator = $("<span class='main-separator' />");

    var currentMain =  siteMap[0];
    for (var i = 0 ; i < siteMap.length; i++){
    current = siteMap[i];
    if (i > 0){
        $('#main-nav').append(separator.clone());
    }
    var tabClass =  "main-nav-off";
    if  (tab == current.tab){
        currentMain =  current;
        tabClass = "main-nav-on";
    }

    var span = $("<span/>", {
        "class": tabClass,
        id: "span-tab-"+current.tab,
    });

    $("<a/>",{
        "id": "tab-"+current.tab,
        href:  "#tab="+current.tab,
        text: current.name,
    }).appendTo(span);

    span.appendTo("#main-nav")
    }

    if (currentMain.children){
    var selectedSub;
    for (var i =0; i < currentMain.children.length; i++){
        var currentSub = currentMain.children[i];

        var tabClass =  "sub-nav-off";
        if  (tab == currentSub.tab){
        tabClass = "sub-nav-on";
        selectedSub = currentSub;
        }

        var span =  $("<span/>", {
        "class": tabClass,
        id: "span-subtab-"+currentSub.tab
        });

        $("<a/>",{
        "id": "subtab-"+currentSub.tab,
        href:  "#tab="+currentSub.tab,
        text: currentSub.name,
        //click: setActiveSubtab,
        }).appendTo(span);

        span.appendTo("#sub-nav");
    }

    if (selectedSub  && selectedSub.setup){
        selectedSub.setup(facet);
    }
    }else if (currentMain && currentMain.setup){
        currentMain.setup(facet);
    }

    var whoami = $.cookie("whoami");
    if (whoami == null){
        ipa_cmd( 'whoami', [], {}, whoamiSuccess, null,null);
    }else{
        setLoggedInText(whoami);
    }
}

var setupFunctions;
function getSetupFunctions(){
    if (!setupFunctions){
    setupFunctions = {
        user:     setupUser,
        group:    setupGroup,
        host:     setupHost,
        hostgroup:setupHostgroup,
        netgroup:setupNetgroup,
    };
    }
    return setupFunctions;
}
$(window).bind( 'hashchange', function(e) {

    var queryParams = ipa_parse_qs();
    var tab=queryParams.tab;
    if (!tab){
        tab = 'user';
    }
    $(".sub-nav-on").removeClass('sub-nav-on').addClass("sub-nav-off")
    var active = "#span-subtab-"+tab;
    $(active).removeClass('sub-nav-off').addClass("sub-nav-on")

    setActiveTab(getParentTabs()[tab]);

    getSetupFunctions()[tab](queryParams.facet );
});



function setActiveTab(tabName){

    $(".main-nav-on").removeClass('main-nav-on').addClass("main-nav-off")
    var activeTab = "#span-tab-"+tabName;
    $(activeTab).removeClass('main-nav-off').addClass("main-nav-on")
}


function buildFacetNavigation(facets){
        setupFacetNavigation(qs['tab'], qs['pkey'],qs['facet'], facets);
}

function setupFacetNavigation(tab, pkey,facet,facets){
    $('#viewtype').css("display","block");
    $("#viewtype").html("");

    for (var i =0; i < facets.length; i++){
        var li = $('<li>').appendTo($("#viewtype"));
        if (facets[i] == facet){
            $('<img src="but-selected.png" alt="" />');
            li.html(facets[i]);
        }else{
            $('<img src="but-unselected.png" alt="" />').appendTo(li);
            $('<a/>',{
                href: "#tab="+tab+"&facet="+facets[i]+"&pkey="+pkey,
                html: facets[i]
            }).appendTo(li);
        }
    }
}

function clearOld(){

    $('h1').html("");
    $('#viewtype').css("display","none");

    $('#search').css("display","none");
    $('#details').css("display","none");
    $('#content').css("display","none");
    $('#associations').css("display","none");


    $('#searchResultsTable thead').html("");
    $('#searchResultsTable tfoot').html("");
    $('#searchResultsTable tbody').find("tr").remove();
    $("#searchButtons").html("");

    $('#content').html("");

    //remove old details
    $('.entryattrs dd').remove();
    $('#detail-lists').html("<hr/>");
}

function showSearch(){
    clearOld();
    $('#search').css("display","block");
    $("#filter").css("display","block");
}

function showContent(){
    clearOld();
    $('#viewtype').css("display","block");
    $('#content').css("display","block");
}

function showDetails(){
    clearOld();
    $('#viewtype').css("display","block");
    $('#details').css("display","block");
}

function showAssociations(){
    clearOld();
    $('#associations').css("display","block");
}