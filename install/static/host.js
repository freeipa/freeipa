function setupHost(facet){
    if (facet == "details"){
	setupHostDetails();
    }else{
	setupHostSearch();
    }
}

function setupHostDetails(host){
    hostDetailsForm.setup(host);    
}


var host_details_list =
    [['identity', 'Host Details', [
        ['fqdn', 'Fully Qualified Domain Name'],
        ['"krbprincipalname', 'Kerberos Principal'],
	['serverhostname', 'Host Name']]]];


function DetailsForm(obj, details_list, pkeyCol, sampleData   ){

    this.obj = obj;
    this.details_list = details_list;
    this.sampleData = sampleData;
    this.pkeyCol = pkeyCol;

    this.setup= function(key){
	window.location.hash="#tab="+this.obj+"user&facet=details&pkey="+key;
	
	//re initialize global parse of parameters
	qs = ipa_parse_qs();
	
	showDetails();
	$('h1').text(":RESET:key");
	
	ipa_details_init(this.obj);
	ipa_details_create(this.details_list, $('#details'));
	ipa_details_load(key, on_win, null, this.sampleData);
    }

}

var hostDetailsForm = new DetailsForm("host",host_details_list,"fqdn","sampledata/hostgroup.json") ;

function renderDetailColumn(form,current,cell){
    $("<a/>",{
	href:"#tab="+this.obj+"&facet=details&pkey="+current.fqdn,
	html:  "" +current[form.pkeyCol],
	click: function(){ form.setup(current[form.pkeyCol])},
    }).appendTo(cell);
}

function setupHostSearch(){
    var columns = [
	{title:"Host",column:"fqdn",render: function(current,cell){
	    renderDetailColumn(hostDetailsForm, current,cell);
	}},
	{title:"Comment",   column: "description", render: renderSimpleColumn},
	{title:"Enrolled?",  render: renderUnknownColumn},
	{title:"Manages?",   render: renderUnknownColumn}
    ];

    var hostSearchForm = new SearchForm("host", "find", columns, "sampledata/hostlist.json");

    $("#query").unbind();
    $("#query").click(function(){
	executeSearch(hostSearchForm);
    });

    $("#new").unbind();
    $("#new").click( function() {
	alert("New Host...");
    });
}
