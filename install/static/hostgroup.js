function setupHostgroup(facet){
    if (facet == "details"){
        hostgroupDetailsForm.setup();
    }else if (facet == "add"){
        hostgroupBuilder.setup();
    }else{
        hostgroupSearchForm.setup();
    }
}

var hostgroup_details_list =
    [['identity', 'Hostgroup Details', [
        ['cn', 'Hostgroup Name'],
        ['description', 'Description']]]];


var hostgroupDetailsForm = new DetailsForm("hostgroup",hostgroup_details_list,"cn","sampledata/hostgroupshow.json") ;



function hostgroupAddOptionsFunction (){
    var options = {
        name: $('#pkey').val(),
        description: $('#description').val()
    };
    return options;
}

var hostgroupAddProperties =
    [{title: 'Hostgroup Name', id: 'pkey', type: 'text'},
     {title: 'Description', id: 'description', type: 'text'}];

var hostgroupBuilder = new EntityBuilder("hostgroup",hostgroupAddProperties,hostgroupAddOptionsFunction);


var hostgroupSearchColumns = [
    {
        title:"Hostgroup", 
        column:"cn", 
        render:  function(current,cell){
            renderPkeyColumn(hostgroupDetailsForm, current,cell);
        }
    },
    {title:"Description", column:"description",render: renderSimpleColumn}];

var hostgroupSearchForm = 
    new SearchForm("hostgroup", "find", hostgroupSearchColumns,
                   "sampledata/hostgrouplist.json");
