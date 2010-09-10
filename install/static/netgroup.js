function setupNetgroup(facet){
    netgroupForms.setup(facet);
}

var netgroupForms = new NetgroupForms();

function NetgroupForms(){
    this.obj='netgroup';
    this.pkeycol = 'cn';
    this.facets = ["details","users","assignusers","groups","assigngroups","hosts","assignhosts","hostgroups","assignhostgroups"];

    this.netgroupSearchColumns = [
        {title:"Netgroup",column:"cn",render:  function(current,cell){
            renderPkeyColumn2('netgroup', 'cn', current,cell);
        }},
        {title:"Description", column:"description",render: renderSimpleColumn}];


    this.details_list =
        [['identity', 'Netgroup Details', [
            ['cn', 'Netgroup Name'],
            ['description', 'Description'],
            ['nisdomainname', 'NIS Domain']]]];

    this.details = new DetailsForm(this.obj,this.details_list,this.pkeycol,
                              this.facets) ;



    this.add_properties =
        [{title: 'Netgroup Name', id: 'pkey', type: 'text'},
         {title: 'Description', id: 'description', type: 'text'}];

    this.add = new EntityBuilder("netgroup",this.add_properties);

    this.add.getOptions = function() {
        var options = {
            name: $('#pkey').val(),
            description: $('#description').val()
        };
        return options;
    }

    this.search =  new SearchForm("netgroup", "find", this.netgroupSearchColumns);

    this.userListColumns = [ {title:"user",column:"memberuser_user", }];
    this.users = new AssociationList(
        this.obj, "users", "assignusers", this.userListColumns, this.facets );

    this.assignusers = new AssociationForm(
        this.obj, "user", "assignuser", this.facets, "uid",
        function(){
            return 'Add Hosts to to  netgroup : '  + qs['pkey'] ;
        },
        BulkAssociator);


    this.groupListColumns = [ {title:"group",column:"memberuser_group", }];
    this.groups = new AssociationList(
        this.obj, "groups", "assigngroups", this.groupListColumns, this.facets );

    this.assigngroups = new AssociationForm(
        this.obj, "group", "assigngroup", this.facets, "cn",
        function(){
            return 'Add Hosts to to  netgroup : '  + qs['pkey'] ;
        },
        BulkAssociator);



    this.hostListColumns = [ {title:"host",column:"memberhost_host", }];

    this.hosts = new AssociationList(
        this.obj, "hosts", "assignhosts", this.hostListColumns, this.facets );

    this.assignhosts = new AssociationForm(
        this.obj, "host", "assignhosts", this.facets, "fqdn",
        function(){
            return 'Add Hosts to to  netgroup : '  + qs['pkey'] ;
        },
        BulkAssociator);


    this.hostgroupListColumns = [ {title:"hostgroup",column:"memberhost_hostgroup", }];

    this.hostgroups = new AssociationList(
        this.obj, "hostgroups", "assignhostgroups", this.hostgroupListColumns, this.facets );

    this.assignhostgroups = new AssociationForm(
        this.obj, "hostgroup", "assignhostgroups", this.facets, "cn",
        function(){
            return 'Add Hostgroups to to  netgroup : '  + qs['pkey'] ;
        },
        BulkAssociator);



    this.unspecified = this.search;
    this.setup = function(facet){
        if (this[facet]){
            this[facet].setup();
        }else{
            this.unspecified.setup();
        }
    }

}
