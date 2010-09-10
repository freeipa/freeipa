function setupService(facet) {
    serviceForms.setup(facet);
}

var serviceForms = new ServiceForms();

function ServiceForms() {

    this.obj = "service";

    this.facets = ['details', 'hosts', 'assignhosts'];

    this.setup = function(facet) {
        if (this[facet]) {
            this[facet].setup();
        } else {
            this.unspecified.setup();
        }
    };

    this.hostListColumns = [ {title:"host",column:"managedby_host"} ];

    this.hosts = new AssociationList(
        this.obj,
        "hosts",
        "assignhosts",
        this.hostListColumns,
        this.facets
    );

    this.assignhosts = new AssociationForm(
        this.obj,
        "host",
        "assignhosts",
        this.facets,
        "fqdn",
        function() {
            return 'Add Hosts to service : ' + qs['pkey'];
        },
        BulkAssociator,
        "add_host"
    );

    this.detailsList = [
        ['identity', 'Service Details', [
            ['krbprincipalname', 'Kerberos Principal']
        ]]
    ];

    this.details = new DetailsForm(
        "service",
        this.detailsList,
        "krbprincipalname",
        this.facets
    );

    this.addProperties = [
        {title: 'Service', id: 'service', type: 'text'},
        {title: 'Host Name', id: 'host', type: 'text'}
    ];

    this.add = new EntityBuilder(
        "service",
        this.addProperties
    );

    this.add.getPKey = function() {
        return $("#service").val()+"/"+$("#host").val();
    }

    this.searchColumns = [
        {
            title: "Service",
            column: "krbprincipalname",
            render: function (current, cell) {
                renderPkeyColumn2('service', 'krbprincipalname', current, cell);
            }
        },
        {
            title: "Has Keytab",
            column: "has_keytab",
            render: renderSimpleColumn
        }
    ];

    this.search = new SearchForm(
        "service",
        "find",
        this.searchColumns
    );

    this.unspecified = this.search;
}
