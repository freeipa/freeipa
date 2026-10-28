IPA.netgroup = {};

IPA.netgroup.entity = function(spec) {
    var that = IPA.entity(spec);
    that.init = function(params) {
        params.builder.search_facet({
            columns: [
                'cn',
                'description'
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'identity',
                    fields: [
                        'cn',
                        {
                            factory: IPA.textarea_widget,
                            name: 'description'
                        },
                        'nisdomainname'
                    ]
                }
            ]
        }).
        association_facet({
            name: 'memberhost_host',
            facet_group: 'member'
        }).
        association_facet({
            name: 'memberhost_hostgroup',
            facet_group: 'member'
        }).
        association_facet({
            name: 'memberuser_user',
            facet_group: 'member'
        }).
        association_facet({
            name: 'memberuser_group',
            facet_group: 'member'
        }).
        association_facet({
            name: 'memberof_netgroup',
            associator: IPA.serial_associator
        }).
        standard_association_facets().
        adder_dialog({
            fields: [
                'cn',
                {
                    factory: IPA.textarea_widget,
                    name: 'description'
                }
            ]
        });
    };

    return that;
};

IPA.register('netgroup', IPA.netgroup.entity);
