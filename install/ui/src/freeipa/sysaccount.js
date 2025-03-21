/*
 * System accounts support
 */

define([
    "dojo/on",
    "./ipa",
    "./builder",
    "./jquery",
    "./phases",
    "./reg",
    "./text",
], function (on, IPA, builder, $, phases, reg, text) {
    /**
     * System accounts module
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
                    row_disabled_attribute: "nsaccountlock",
                    columns: [
                        "uid",
                        "description",
                        {
                            $type: "checkbox",
                            name: "privileged",
                            label: "@i18n:objects.sysaccount.privileged",
                            formatter: {
                                $type: "boolean_status",
                                invert_value: false,
                            },
                        },
                        {
                            name: "nsaccountlock",
                            label: "@i18n:status.label",
                            formatter: {
                                $type: "boolean_status",
                                invert_value: true,
                            },
                        },
                    ],
                },
                {
                    $type: "details",
                    actions: [
                        "add",
                        "delete",
                        "enable",
                        "disable",
                        { $type: "reset_sysaccount_password" },
                    ],
                    header_actions: [
                        "reset_sysaccount_password",
                        "delete",
                        "enable",
                        "disable",
                    ],
                    state: {
                        evaluators: [
                            {
                                $factory: IPA.enable_state_evaluator,
                                field: "nsaccountlock",
                                adapter: { $type: "batch", result_index: 0 },
                                invert_value: true,
                            },
                            {
                                $factory: IPA.acl_state_evaluator,
                                name: "reset_password_acl_evaluator",
                                adapter: { $type: "batch", result_index: 0 },
                                attribute: "userpassword",
                            },
                        ],
                    },
                    sections: [
                        {
                            name: "details",
                            fields: [
                                "uid",
                                "description",

                                {
                                    $type: "checkbox",
                                    name: "privileged",
                                    label: "@i18n:objects.sysaccount.privileged",
                                    metadata:
                                        "@mc-opt:sysaccount_policy:privileged",
                                    needs_confirm: true,
                                    confirm_msg:
                                        "@i18n.objects.sysaccount.privileged_confirm",
                                    acl_param: "uid",
                                },
                            ],
                        },
                    ],
                },
                {
                    $type: "association",
                    name: "memberof_role",
                    associator: IPA.serial_associator,
                    add_title: "@i18n:objects.sysaccount.add_into_roles",
                    remove_title: "@i18n:objects.sysaccount.remove_from_roles",
                },
            ],
            standard_association_facets: true,
            adder_dialog: {
                title: "@i18n:objects.sysaccount.add",
                $factory: IPA.sysaccount.adder_dialog,
                sections: [
                    {
                        fields: [
                            {
                                name: "uid",
                                required: true,
                            },
                            {
                                name: "description",
                                required: false,
                            },
                            {
                                $type: "checkbox",
                                name: "privileged",
                                label: "@i18n:objects.sysaccount.privileged",
                                metadata: "@mc-opt:sysaccount_add:privileged",
                            },
                        ],
                    },
                    {
                        fields: [
                            {
                                name: "userpassword",
                                label: "@i18n:password.new_password",
                                $type: "password",
                                required: true,
                            },
                            {
                                name: "userpassword2",
                                label: "@i18n:password.verify_password",
                                $type: "password",
                                required: true,
                                flags: ["no_command"],
                            },
                        ],
                    },
                ],
            },
            deleter_dialog: {
                title: "@i18n:objects.sysaccount.remove",
            },
        };
    };

    IPA.sysaccount.adder_dialog = function (spec) {
        var that = IPA.entity_adder_dialog(spec);

        that.validate = function () {
            var valid = that.dialog_validate();

            var field1 = that.fields.get_field("userpassword");
            var field2 = that.fields.get_field("userpassword2");

            var password1 = field1.save()[0];
            var password2 = field2.save()[0];

            if (password1 !== password2) {
                field2.set_valid({
                    valid: false,
                    message: text.get("@i18n:password.password_must_match"),
                });
                valid = false;
            }

            return valid;
        };

        return that;
    };

    IPA.sysaccount.password_dialog_pre_op0 = function (spec) {
        spec.password_name = spec.password_name || "userpassword";
        return spec;
    };

    IPA.sysaccount.password_dialog_pre_op = function (spec) {
        spec.method = spec.method || "sysaccount_mod";
        return spec;
    };

    IPA.sysaccount.reset_password_action = function (spec) {
        spec = spec || {};
        spec.name = spec.name || "reset_sysaccount_password";
        spec.label = spec.label || "@i18n:password.reset_password";
        spec.enable_cond = spec.enable_cond || ["userpassword_w"];

        var that = IPA.action(spec);

        that.execute_action = function (facet) {
            var dialog = builder.build("dialog", {
                $type: "sysaccount_password",
                args: [facet.get_pkey()],
            });

            dialog.open();
        };

        that.save = function (record) {
            that.dialog_save(record);
            delete record.userpassword2;
        };

        return that;
    };

    /**
     * System accounts entity specification object
     * @member sysaccount
     */
    exp.entity_spec = make_spec();

    /**
     * Register entity
     * @member sysaccount
     */
    exp.register = function () {
        var e = reg.entity;
        var a = reg.action;
        var d = reg.dialog;
        e.register({ type: "sysaccount", spec: exp.entity_spec });
        a.register(
            "reset_sysaccount_password",
            IPA.sysaccount.reset_password_action,
        );
        d.copy("password", "sysaccount_password", {
            factory: IPA.sysaccount.password_dialog,
            pre_ops: [IPA.sysaccount.password_dialog_pre_op],
        });
        d.register_pre_op(
            "sysaccount_password",
            IPA.sysaccount.password_dialog_pre_op0,
            true,
        );
    };

    phases.on("registration", exp.register);

    return exp;
});
