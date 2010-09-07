function setupNetgroup(facet){
    if (facet == "details"){
        netgroupDetailsForm.setup();
    }else  if(facet == "add"){
        netgroupBuilder.setup();
    }else{
        netgroupSearchForm.setup();
    }
}


var netgroup_details_list =
    [['identity', 'Netgroup Details', [
        ['cn', 'Netgroup Name'],
        ['description', 'Description'],
        ['nisdomainname', 'NIS Domain']]]];


var netgroupDetailsForm = new DetailsForm("netgroup",netgroup_details_list,"cn", ["details","hosts","groups","users"]) ;


var netgroupAddProperties =
    [{title: 'Netgroup Name', id: 'pkey', type: 'text'},
     {title: 'Description', id: 'description', type: 'text'}];


function netgroupAddOptionsFunction (){
    var options = {
        name: $('#pkey').val(),
        description: $('#description').val()
    };
    return options;
}

var netgroupBuilder = new EntityBuilder("netgroup",netgroupAddProperties,netgroupAddOptionsFunction);


var netgroupSearchColumns = [
    {title:"Netgroup",column:"cn",render:  function(current,cell){
        renderPkeyColumn(netgroupDetailsForm, current,cell);
    }},
    {title:"Description", column:"description",render: renderSimpleColumn}];

var netgroupSearchForm =
    new SearchForm("netgroup", "find", netgroupSearchColumns);
