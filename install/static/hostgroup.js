
function setupHostgroup(facet){
        hostgroupForms.setup(facet);
}

var hostgroup_details_list =
    [['identity', 'Hostgroup Details', [
        ['cn', 'Hostgroup Name'],
        ['description', 'Description']]]];

var hostgroupFacets = ["details","hosts","assignhosts"];



function hostgroupAddOptionsFunction (){
    var options = {
        name: $('#pkey').val(),
        description: $('#description').val()
    };
    return options;
}

var hostgroupForms = new HostgroupsForms();

function HostgroupsForms(){

    this.setup = function(facet){
        if (this[facet]){
            this[facet].setup();
        }else{
            this.unspecified.setup();
        }
    }


/**
*  used to initialize the search
*/
    this.hostgroupSearchColumns = [
        {
            title:"Hostgroup",
            column:"cn",
            render:  function(current,cell){
                renderPkeyColumn2('hostgroup', 'cn', current,cell);
            }
        },
        {title:"Description", column:"description",render: renderSimpleColumn}];

    this.hostgroupAddProperties =
    [{title: 'Hostgroup Name', id: 'pkey', type: 'text'},
     {title: 'Description', id: 'description', type: 'text'}];


    /**
       Facets
    */
    this.hostListColumns = [ {title:"Host",column:"member_host" }];
    this.obj="hostgroup";
    this.hosts = new AssociationList(
        this.obj,
        "hosts",
        "assignhosts",
        this.hostListColumns, hostgroupFacets );

    this.assignhosts = new AssociationForm(
        this.obj,
        "host",
        "assignhosts",
        hostgroupFacets,
        "fqdn",
        function(){
            return 'Add Hosts to to  hostgroup : '  + qs['pkey'] ;
        },
        BulkAssociator);

    this.details = new DetailsForm("hostgroup",hostgroup_details_list,"cn",hostgroupFacets) ;

    this.add = new EntityBuilder("hostgroup",this.hostgroupAddProperties,hostgroupAddOptionsFunction);

    this.search = new SearchForm("hostgroup", "find", this.hostgroupSearchColumns);
    this.unspecified = this.search;
}
