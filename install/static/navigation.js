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

function buildNavigation(){
    params= getPageParams();
    var tab = params["tab"];

    if (!tab){
	tab=$.cookie("lastpage");
    }
    if  ( !tab ) {
	tab="user";
    }

    var facet = params["facet"];


    var siteMap = [{name:"IDENTITY",
		    tab:"user",
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
	    href:  "#?tab="+current.tab,
	    text: current.name,
	    click: setActiveTab
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
		href:  "#?tab="+currentSub.tab,
		text: currentSub.name,
		click: setActiveSubtab,
	    }).appendTo(span);

	    span.appendTo("#sub-nav");
	}

	if (selectedSub  && selectedSub.setup){
	    selectedSub.setup(facet);
	}
    }else if (currentMain && currentMain.setup){
	currentMain.setup(facet);
    }

    sampleData = "sampledata/whoami.json";
    var whoami = $.cookie("whoami");
    if (whoami == null){
	ipa_cmd( 'whoami', [], {}, whoamiSuccess);
    }else{
	setLoggedInText(whoami);
    }
}


function setActiveTab(){

    var setupFunctions = {
	user:     setupUser,
	policy:   unimplemented,
	config:   unimplemented};



   var tabName = this.id.substring("tab-".length);
    $(".main-nav-on").removeClass('main-nav-on').addClass("main-nav-off")
    var activeTab = "#span-tab-"+tabName;
    $(activeTab).removeClass('main-nav-off').addClass("main-nav-on")

    setupFunctions[tabName]();

}

function setActiveSubtab(){

    var setupFunctions = {
	user:     setupUser,
	group:    setupGroup,
	host:     setupHost,
	hostgroup:setupHostgroup,
	netgroup:setupNetgroup,
};




    var subtabName = this.id.substring("subtab-".length);
    $(".sub-nav-on").removeClass('sub-nav-on').addClass("sub-nav-off")
    var active = "#span-subtab-"+subtabName;
    $(active).removeClass('sub-nav-off').addClass("sub-nav-on")

    setupFunctions[subtabName]();

}
