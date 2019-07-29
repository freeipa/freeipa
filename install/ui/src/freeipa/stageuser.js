//
// Copyright (C) 2015  FreeIPA Contributors see COPYING for license
//

define([
        'dojo/on',
        './ipa',
        './jquery',
        './menu',
        './phases',
        './reg',
        './rpc',
        './text',
        './details',
        './facet',
        './user',
        './search',
        './entity'],
            function(
    on, IPA, $, menu, phases, reg, rpc, text, mod_details, mod_facet, mod_user) {
/**
 * Stage user module
 * @class
 * @singleton
 */
var stageuser = IPA.stageuser = {

    search_facet_group: {
        name: 'search',
        label: '@i18n:objects.stageuser.user_categories',
        facets: {
            search_normal: 'user_search',
            search: 'stageuser_search',
            search_preserved: 'user_search_preserved'
        }
    }
};

var make_stageuser_spec = function() {
return {
    name: 'stageuser',
    facet_groups: ['settings'],
    policies: [
        IPA.search_facet_update_policy,
        IPA.details_facet_update_policy,
        {
            $factory: IPA.facet_update_policy,
            source_facet: 'search',
            dest_entity: 'user',
            dest_facet: 'search'
        },
        {
            $factory: IPA.facet_update_policy,
            source_facet: 'details',
            dest_entity: 'user',
            dest_facet: 'search'
        }
    ],
    facets: [
        {
            $type: 'search',
            disable_facet_tabs: false,
            tabs_in_sidebar: true,
            tab_label: '@i18n:objects.stageuser.label',
            facet_groups: [stageuser.search_facet_group],
            facet_group: 'search',
            columns: [
                'uid',
                'givenname',
                'sn',
                'uidnumber',
                'mail',
                'telephonenumber',
                'title'
            ],
            actions: [
                {
                    $type: 'batch_activate'
                }
            ],
            control_buttons: [
                {
                    name: 'activate',
                    label: '@i18n:buttons.activate',
                    icon: 'fa-check'
                }
            ],
            policies: [
                mod_user.stageuser_sidebar_policy
            ],
            deleter_dialog: {
                title: '@i18n:objects.stageuser.remove',
                $factory: IPA.search_deleter_dialog
            }
        },
        {
            $type: 'details',
            disable_facet_tabs: true,
            sections: [
                {
                    name: 'identity',
                    label: '@i18n:details.identity',
                    fields: [
                        'title',
                        'givenname',
                        'sn',
                        'cn',
                        'displayname',
                        'initials',
                        'gecos',
                        {
                            name: 'userclass',
                            flags: ['w_if_no_aci']
                        }
                    ]
                },
                {
                    name: 'account',
                    label: '@i18n:objects.user.account',
                    fields: [
                        'uid',
                        {
                            $factory: mod_user.password_widget,
                            name: 'has_password',
                            metadata: '@mo-param:user:userpassword'
                        },
                        {
                            $type: 'datetime',
                            name: 'krbpasswordexpiration',
                            label: '@i18n:objects.user.krbpasswordexpiration',
                            read_only: true
                        },
                        {
                            name: 'uidnumber',
                            minvalue: -1
                        },
                        {
                            name: 'gidnumber',
                            minvalue: -1
                        },
                        'krbprincipalname',
                        {
                            $type: 'datetime',
                            name: 'krbprincipalexpiration'
                        },
                        'loginshell',
                        'homedirectory',
                        {
                            $type: 'sshkeys',
                            name: 'ipasshpubkey',
                            label: '@i18n:objects.sshkeystore.keys'
                        },
                        {
                            $type: 'certmap_multivalued',
                            name: 'ipacertmapdata',
                            item_name: 'certmapdata',
                            child_spec: {
                                $type: 'non_editable_row',
                                data_name: 'certmap'
                            },
                            tooltip: {
                                title: '@mc:stageuser_add_certmapdata.doc'
                            }
                        },
                        {
                            $type: 'checkboxes',
                            name: 'ipauserauthtype',
                            flags: ['w_if_no_aci'],
                            options: [
                                { label: '@i18n:authtype.type_password', value: 'password' },
                                { label: '@i18n:authtype.type_radius', value: 'radius' },
                                { label: '@i18n:authtype.type_otp', value: 'otp' },
                                { label: '@i18n:authtype.type_pkinit', value: 'pkinit' },
                                { label: '@i18n:authtype.type_hardened', value: 'hardened' }
                            ],
                            tooltip: '@i18n:authtype.user_tooltip'
                        },
                        {
                            $type: 'entity_select',
                            name: 'ipatokenradiusconfiglink',
                            flags: ['w_if_no_aci'],
                            other_entity: 'radiusproxy',
                            other_field: 'cn'
                        },
                        {
                            name: 'ipatokenradiususername',
                            flags: ['w_if_no_aci']
                        }
                    ]
                },
                {
                    name: 'contact',
                    label: '@i18n:objects.user.contact',
                    fields: [
                        { $type: 'multivalued', name: 'mail' },
                        { $type: 'multivalued', name: 'telephonenumber' },
                        { $type: 'multivalued', name: 'pager' },
                        { $type: 'multivalued', name: 'mobile' },
                        { $type: 'multivalued', name: 'facsimiletelephonenumber' }
                    ]
                },
                {
                    name: 'mailing',
                    label: '@i18n:objects.user.mailing',
                    fields: ['street', 'l', 'st', 'postalcode']
                },
                {
                    name: 'employee',
                    label: '@i18n:objects.user.employee',
                    fields: [
                        'ou',
                        {
                            $type: 'entity_select',
                            name: 'manager',
                            other_entity: 'user',
                            other_field: 'uid'
                        },
                        { $type: 'multivalued', name: 'departmentnumber' },
                        'employeenumber',
                        'employeetype',
                        'preferredlanguage'
                    ]
                },
                {
                    name: 'misc',
                    label: '@i18n:objects.user.misc',
                    fields: [
                        { $type: 'multivalued', name: 'carlicense' }
                    ]
                }
            ],
            actions: [
                'activate',
                'delete'
            ],
            header_actions: ['activate', 'delete'],
            state: {
                evaluators: [
                    {
                        $factory: mod_facet.noop_state_evaluator,
                        state: ['staging']
                    }
                ],
                summary_conditions: [
                    {
                        pos: ['staging'],
                        state: ['staging'],
                        description: 'Staging user'
                    }
                ]
            }
        }
    ],
    adder_dialog: {
        title: '@i18n:objects.stageuser.add',
        sections: [
            {
                fields: [
                    {
                        name: 'uid',
                        required: false
                    },
                    'givenname',
                    'sn',
                    'userclass'
                ]
            },
            {
                fields: [
                    {
                        name: 'userpassword',
                        label: '@i18n:password.new_password',
                        $type: 'password'
                    },
                    {
                        name: 'userpassword2',
                        label: '@i18n:password.verify_password',
                        $type: 'password',
                        flags: ['no_command'],
                        validators: [{
                            $type: 'same_password',
                            other_field: 'userpassword'
                        }]
                    }
                ]
            }
        ]
    }
};};

stageuser.search_preserved_facet_spec = {
    $type: 'search',
    $pre_ops: [
        { $del: [[ 'control_buttons', [{ name: 'add'}, { name: 'delete'}] ]] }
    ],
    disable_facet_tabs: false,
    tabs_in_sidebar: true,
    entity: 'user',
    managed_entity: 'user',
    name: 'search_preserved',
    label: '@i18n:objects.stageuser.preserved_label',
    tab_label: '@i18n:objects.stageuser.preserved_label',
    facet_groups: [stageuser.search_facet_group],
    facet_group: 'search',
    command_options: {
        'preserved': true
    },
    columns: [
        'uid',
        'givenname',
        'sn',
        'uidnumber',
        'mail',
        'telephonenumber',
        'title'
    ],
    actions: [
        {
            $type: 'batch_undel'
        },
        {
            $type: 'batch_stage'
        }
    ],
    control_buttons: [
        {
            name: 'undel',
            label: '@i18n:buttons.restore',
            icon: 'fa-heart'
        },
        {
            name: 'batch_stage',
            label: '@i18n:buttons.stage',
            icon: 'fa-user'
        }
    ],
    policies: [
        mod_user.stageuser_sidebar_policy
    ],
    deleter_dialog: {
        title: '@i18n:objects.stageuser.preserved_remove',
        $factory: IPA.search_deleter_dialog
    }
};

mod_user.entity_spec.policies = mod_user.entity_spec.policies || {};
mod_user.entity_spec.policies.push(
    {
        $factory: IPA.facet_update_policy,
        source_facet: 'search',
        dest_entity: 'stageuser',
        dest_facet: 'search'
    },
    {
        $factory: IPA.facet_update_policy,
        source_facet: 'search_preserved',
        dest_entity: 'stageuser',
        dest_facet: 'search'
    },
    {
        $factory: IPA.facet_update_policy,
        source_facet: 'search_preserved',
        dest_entity: 'user',
        dest_facet: 'search'
    },
    {
        $factory: IPA.facet_update_policy,
        source_facet: 'search',
        dest_entity: 'user',
        dest_facet: 'search_preserved'
    }
);


stageuser.batch_activate_action = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'activate';
    spec.method = spec.method || 'activate';
    spec.needs_confirm = spec.needs_confirm === undefined ? true : spec.needs_confirm;
    spec.enabled = spec.enabled === undefined ? false : spec.enabled;
    spec.enable_cond = spec.enable_cond || ['item-selected'];
    spec.success_msg = spec.success_msg || '@i18n:objects.stageuser.activate_success';
    spec.confirm_msg = spec.confirm_msg || '@i18n:objects.stageuser.activate_confirm';

    return IPA.batch_items_action(spec);
};

stageuser.activate_action = function(spec) {
    spec = spec || {};
    spec.name = spec.name || 'activate';
    spec.method = spec.method || 'activate';
    spec.needs_confirm = spec.needs_confirm !== undefined ? spec.needs_confirm : true;
    spec.confirm_msg = spec.confirm_msg || '@i18n:objects.stageuser.activate_one_confirm';
    spec.label = spec.label || '@i18n:buttons.activate';

    var that = IPA.object_action(spec);

    that.on_success = function(facet, data, text_status, xhr) {

        IPA.notify_success(data.result.summary);
        facet.on_update.notify();
        facet.redirect();
    };

    return that;
};

stageuser.batch_undel_action = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'undel';
    spec.method = spec.method || 'undel';
    spec.needs_confirm = spec.needs_confirm === undefined ? true : spec.needs_confirm;
    spec.enabled = spec.enabled === undefined ? false : spec.enabled;
    spec.enable_cond = spec.enable_cond || ['item-selected'];
    spec.success_msg = spec.success_msg || '@i18n:objects.stageuser.undel_success';
    spec.confirm_msg = spec.confirm_msg || '@i18n:objects.stageuser.undel_confirm';

    return IPA.batch_items_action(spec);
};

stageuser.undel_action = function(spec) {
    spec = spec || {};

    spec.name = spec.name || 'undel';
    spec.method = spec.method || 'undel';
    spec.needs_confirm = spec.needs_confirm === undefined ? true : spec.needs_confirm;
    spec.confirm_msg = spec.confirm_msg || '@i18n:objects.stageuser.undel_one_confirm';
    spec.label = spec.label || '@i18n:buttons.restore';

    var that = IPA.object_action(spec);

    that.on_success = function(facet, data, text_status, xhr) {
        IPA.notify_success(data.result.summary);
        facet.on_update.notify();
        facet.redirect();
    };

    return that;
};

stageuser.batch_stage_action = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'batch_stage';
    spec.method = spec.method || 'stage';
    spec.needs_confirm = spec.needs_confirm === undefined ? true : spec.needs_confirm;
    spec.enable_cond = spec.enable_cond || ['item-selected'];
    spec.success_msg = spec.success_msg || '@i18n:objects.stageuser.stage_success';
    spec.confirm_msg = spec.confirm_msg || '@i18n:objects.stageuser.stage_confirm';

    return IPA.batch_items_action(spec);
};

stageuser.stage_action = function(spec) {

    spec = spec || {};

    spec.name = spec.name || 'stage';
    spec.method = spec.method || 'stage';
    spec.show_cond = spec.show_cond || ['preserved_user'];
    spec.needs_confirm = spec.needs_confirm !== undefined ? spec.needs_confirm : true;
    spec.confirm_msg = spec.confirm_msg || '@i18n:objects.stageuser.stage_one_confirm';
    spec.label = spec.label || '@i18n:buttons.stage';

    var that = IPA.object_action(spec);

    that.on_success = function(facet, data, text_status, xhr) {

        IPA.notify_success(data.result.summary);
        facet.on_update.notify();
        facet.redirect();
    };

    return that;
};

/**
 * Stage user entity specification object
 * @member stageuser
 */
stageuser.stageuser_spec = make_stageuser_spec();

/**
 * Register entity
 * @member stageuser
 */
stageuser.register = function() {
    var a = reg.action;
    var e = reg.entity;
    var f = reg.facet;
    a.register('batch_activate', stageuser.batch_activate_action);
    a.register('activate', stageuser.activate_action);
    a.register('batch_undel', stageuser.batch_undel_action);
    a.register('undel', stageuser.undel_action);
    a.register('batch_stage', stageuser.batch_stage_action);
    a.register('stage', stageuser.stage_action);
    e.register({type: 'stageuser', spec: stageuser.stageuser_spec});
    f.register_from_spec('user_search_preserved', stageuser.search_preserved_facet_spec);
};

phases.on('registration', stageuser.register);

return stageuser;
});
