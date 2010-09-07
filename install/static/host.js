function setupHost(facet){
    if (facet == "details"){
        hostDetailsForm.setup();
    }else if (facet == "add"){
        hostBuilder.setup();
    }else{
        hostSearchForm.setup();
    }
}

var hostAddProperties = [{title: 'Domain Name', id: 'pkey', type: 'text'}];
var hostBuilder = new EntityBuilder("host",hostAddProperties);


var host_details_list =  [['host', 'Host Details', [
    ['fqdn', 'Fully Qualified Domain Name'],
    ['krbprincipalname', 'Kerberos Principal'],
    ['serverhostname', 'Server Host Name']
]]];

var hostFacets = ["details","hostgroup", "hostgroupmembership"];

var hostDetailsForm = new DetailsForm("host",host_details_list,"fqdn",
                                      hostFacets ) ;

var hostSearchColumns = [
    {title:"Host",column:"fqdn",render: function(current,cell){
    renderPkeyColumn(hostDetailsForm,current,cell);
    }},
    {title:"Comment",   column: "description", render: renderSimpleColumn},
    {title:"Enrolled?",  render: renderUnknownColumn},
    {title:"Manages?",   render: renderUnknownColumn}
];
var hostSearchForm = new SearchForm("host", "find", hostSearchColumns);
