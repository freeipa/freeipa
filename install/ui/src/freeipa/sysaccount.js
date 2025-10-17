/*
 */

define([
    "dojo/on",
    "./ipa",
    "./builder",
    "./jquery",
    "./menu",
    "./phases",
    "./reg",
    "./rpc",
    "./text",
    "./details",
    "./facet",
    "./search",
    "./entity",
], function (
    on,
    IPA,
    builder,
    $,
    menu,
    phases,
    reg,
    rpc,
    text,
    mod_details,
    mod_facet,
) {
    /**
     * System accounts module
     * @class
     * @singleton
     */
    var exp = (IPA.sysaccount = {});

    var make_spec = function () {
        return {
            name: "sysaccount",
            policies: [
                IPA.search_facet_update_policy,
                IPA.details_facet_update_policy,
            ],
            facets: [
                {
                    $type: "search",
                    columns: ["uid"],
                },
                {
                    $type: "details",
                    header: sysaccount.sysaccount_facet_header,
                    actions: ["delete"],
                    header_actions: ["delete"],
                    state: {},
                    sections: [
                        {
                            name: "details",
                            fields: ["uid"],
                        },
                    ],
                },
            ],

            adder_dialog: {
                title: "@i18n:objects.sysaccount.add",
                fields: ["uid"],
            },
            deleter_dialog: {
                title: "@i18n:objects.sysaccount.remove",
            },
        };
    };

    /**
     * System accounts entity specification object
     * @member sysaccount
     */
    sysaccount.spec = make_spec();

    /**
     * Register entity
     * @member sysaccount
     */
    sysaccount.register = function () {
        var e = reg.entity;
        var f = reg.facet;
        var a = reg.action;
        var w = reg.widget;
        var ad = reg.association_adder_dialog;

        e.register({ type: "sysaccount", spec: sysaccount.spec });
    };

    phases.on("registration", sysaccount.register);

    return sysaccount;
});
