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
            ]
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
                            $type: 'checkboxes',
                            name: 'ipauserauthtype',
                            flags: ['w_if_no_aci'],
                            options: [
                                { label: '@i18n:authtype.type_password', value: 'password' },
                                { label: '@i18n:authtype.type_radius', value: 'radius' },
                                { label: '@i18n:authtype.type_otp', value: 'otp' }
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
                'delete'
            ],
            header_actions: ['delete'],
            state: {
                evaluators: [
                    {
                        $factory: IPA.enable_state_evaluator,
                        field: 'nsaccountlock',
                        adapter: { $type: 'batch', result_index: 0 },
                        invert_value: true
                    },
                    {
                        $factory: IPA.acl_state_evaluator,
                        name: 'reset_password_acl_evaluator',
                        adapter: { $type: 'batch', result_index: 0 },
                        attribute: 'userpassword'
                    },
                    IPA.user.self_service_other_user_evaluator
                ],
                summary_conditions: [
                    IPA.enabled_summary_cond,
                    IPA.disabled_summary_cond
                ]
            }
        }
    ],
    adder_dialog: {
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
        }
    ],
    control_buttons: [
        {
            name: 'undel',
            label: '@i18n:buttons.restore',
            icon: 'fa-heart'
        }
    ]
};

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
    a.register('batch_undel', stageuser.batch_undel_action);
    e.register({type: 'stageuser', spec: stageuser.stageuser_spec});
    f.register_from_spec('user_search_preserved', stageuser.search_preserved_facet_spec);
};

phases.on('registration', stageuser.register);

return stageuser;
});
