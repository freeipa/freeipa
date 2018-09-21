//
// Copyright (C) 2017 FreeIPA Contributors see COPYING for license
//

define([
        'dojo/on',
        './ipa',
        './jquery',
        './phases',
        './menu',
        './rpc',
        './reg',
        './text',
        './widget'],
            function(on, IPA, $, phases, menu, rpc, reg, text, widget) {

/**
 * Vault module
 * @class vault
 * @alternateClassName IPA.vault
 * @singleton
 */
var vault = IPA.vault = {

    search_facet_group: {
        name: 'vaults',
        facets: {
            vault_search: 'vault_search',
            user_search: 'vault_user_search',
            service_search: 'vault_service_search',
            shared_search: 'vault_shared_search',
            vaultconfig_details: 'vaultconfig_details'
        }
    }
};


/**
 * Create general specification of "* Vaults" details facets.
 */
var make_vaults_details_page_spec = function() {
    return {
        $type: 'details',
        $factory: vault.custom_details_facet,
        update_command_name: 'mod_internal',
        disable_facet_tabs: true,
        sections: [
            {
                name: 'global_info',
                layout_ccs_class: 'col-sm-12',
                fields: [
                    'cn',
                    'description',
                    {
                        name: 'ipavaulttype',
                        read_only: true
                    },
                    {
                        $type: 'text',
                        name: 'ipavaultsalt',
                        visible: false
                    },
                    {
                        $type: 'pub_key',
                        name: 'ipavaultpublickey',
                        visible: false
                    }
                ]
            },
            {
                $factory: IPA.section,
                name: 'divider',
                layout_css_class: 'col-sm-12',
                fields: []
            },
            {
                $factory: IPA.section,
                name: 'members',
                label: '@i18n:objects.vault.members',
                fields: [
                    {
                        $type: 'association_table',
                        id: 'member_user_cn',
                        name: 'member_user',
                        acl_param: 'member',
                        columns: [
                            {
                                name: 'member_user',
                                label: '@i18n:objects.vault.user'
                            }
                        ],
                        remove_title: '@i18n:objects.vault.remove_member_users'
                    },
                    {
                        $type: 'association_table',
                        id: 'member_group_cn',
                        name: 'member_group',
                        other_entity: 'group',
                        acl_param: 'member',
                        columns: [
                            {
                                name: 'member_group',
                                label: '@i18n:objects.vault.group'
                            }
                        ],
                        remove_title: '@i18n:objects.vault.remove_member_groups'
                    },
                    {
                        $type: 'association_table',
                        id: 'member_service_cn',
                        name: 'member_service',
                        other_entity: 'service',
                        other_option_name: 'services',
                        acl_param: 'member',
                        columns: [
                            {
                                name: 'member_service',
                                label: '@i18n:objects.vault.service'
                            }
                        ],
                        remove_title: '@i18n:objects.vault.remove_member_services'
                    }
                ]
            },
            {
                $factory: IPA.section,
                name: 'owners',
                label: '@i18n:objects.vault.owners',
                fields: [
                    {
                        $type: 'association_table',
                        id: 'owner_user_cn',
                        name: 'owner_user',
                        add_method: 'add_owner',
                        remove_method: 'remove_owner',
                        other_entity: 'user',
                        acl_param: 'owner',
                        columns: [
                            {
                                name: 'owner_user',
                                label: '@i18n:objects.vault.user'
                            }
                        ],
                        remove_title: '@i18n:objects.vault.remove_owner_users'
                    },
                    {
                        $type: 'association_table',
                        id: 'owner_group_cn',
                        name: 'owner_group',
                        add_method: 'add_owner',
                        remove_method: 'remove_owner',
                        other_entity: 'group',
                        acl_param: 'owner',
                        columns: [
                            {
                                name: 'owner_group',
                                label: '@i18n:objects.vault.group'
                            }
                        ],
                        remove_title: '@i18n:objects.vault.remove_owner_groups'
                    },
                    {
                        $type: 'association_table',
                        id: 'owner_service_cn',
                        name: 'owner_service',
                        add_method: 'add_owner',
                        remove_method: 'remove_owner',
                        other_entity: 'service',
                        other_option_name: 'services',
                        acl_param: 'owner',
                        columns: [
                            {
                                name: 'owner_service',
                                label: '@i18n:objects.vault.service'
                            }
                        ],
                        remove_title: '@i18n:objects.vault.remove_owner_services'
                    }
                ]
            }
        ]
    };
};


/**
 * Create entity spec for whole vaults and also spec for search facet, adder
 * and deleter dialog.
 */
var make_my_vault_spec = function() {
    var entity = {
        name: 'vault',
        facets: [
            {
                $type: 'search',
                tab_label: '@i18n:objects.vault.my_vaults_title',
                facet_groups: [vault.search_facet_group],
                facet_group: 'vaults',
                disable_facet_tabs: false,
                search_all_entries: true,
                tabs_in_sidebar: true,
                custom_actions: [
                    {
                        $type: 'add',
                        hide_cond: []
                    },
                    {
                        $type: 'batch_remove',
                        hide_cond: []
                    }
                ],
                columns: [
                    'cn',
                    'ipavaulttype'
                ],
                policies: [
                    vault.config_sidebar_policy
                ]
            }
        ],
        adder_dialog: {
            title: '@i18n:objects.vault.add',
            $factory: vault.custom_adder_dialog,
            name: 'add',
            method: 'add_internal',
            policies: [
                { $factory: vault.adder_policy }
            ]
        },
        deleter_dialog: {
            // Each parametr is present only in one facet. It could cause errors
            // in case that table on each facet gather more columns with these names.
            // I.e. facet with user vaults get column with name 'service', then
            // the value of 'service' column will be also added to command options.
            additional_table_attrs: ['username', 'service', 'shared'],
            title: '@i18n:objects.vault.remove'
        }
    };

    /**
     * This function extends general details facet - so the same declaration
     * of facet (which would differ only in several lines)
     * should not be present six times.
     */
    var update_facet_spec = function(facet, facet_type) {
        facet.sections[0].fields.push(facet_type);
        facet.refresh_attribute = facet_type;
        facet.update_attribute = facet_type;
        var user_members = facet.sections[2].fields[0];
        var group_members = facet.sections[2].fields[1];
        var service_members = facet.sections[2].fields[2];
        var user_owners = facet.sections[3].fields[0];
        var group_owners = facet.sections[3].fields[1];
        var service_owners = facet.sections[3].fields[2];

        var attributes = {
            refresh_attribute: facet_type,
            additional_add_del_field: facet_type
        };

        $.extend(user_members, attributes);
        $.extend(user_owners, attributes);
        $.extend(group_members, attributes);
        $.extend(group_owners, attributes);
        $.extend(service_members, attributes);
        $.extend(service_owners, attributes);
    };

    // Create details page for my vauls:
    var details_spec = make_vaults_details_page_spec();
    entity.facets.push(details_spec);

    // Create details page for user vaults and modify it
    details_spec = make_vaults_details_page_spec();

    details_spec.name = 'vault_user';
    update_facet_spec(details_spec, 'username');
    details_spec.redirect_info = {
        facet: 'user_search'
    };

    entity.facets.push(details_spec);

    // Create details page for service vaults and modify it
    details_spec = make_vaults_details_page_spec();

    details_spec.name = 'vault_service';
    update_facet_spec(details_spec, 'service');
    details_spec.redirect_info = {
        facet: 'service_search'
    };

    entity.facets.push(details_spec);

    // Create details page for shared vaults and modify it
    details_spec = make_vaults_details_page_spec();

    details_spec.name = 'vault_shared';
    update_facet_spec(details_spec, 'shared');
    details_spec.redirect_info = {
        facet: 'shared_search'
    };

    entity.facets.push(details_spec);

    return entity;
};


vault.custom_details_facet = function(spec) {
    spec = spec || {};

    var that = IPA.details_facet(spec);

    that.load = function(data) {
        that.details_facet_load(data);

        // show fields according to the type of vault

        var type_f = that.fields.get_field('ipavaulttype');
        var type = type_f.value[0];
        var salt_w = that.fields.get_field('ipavaultsalt').widget;
        var pub_key_w = that.fields.get_field('ipavaultpublickey').widget;

        if (type === 'symmetric') {
            pub_key_w.set_visible(false);
            salt_w.set_visible(true);
        } else if (type === 'asymmetric') {
            pub_key_w.set_visible(true);
            salt_w.set_visible(false);
        } else {
            pub_key_w.set_visible(false);
            salt_w.set_visible(false);
        }
    };

    return that;
};


vault.public_key_widget = function(spec) {
    spec = spec || {};

    var that = IPA.sshkey_widget(spec);

    that.set_user_value = function(value) {

        var previous = that.key;
        that.key = value;
        that.update_link();

        if (value !== previous) {
            that.value_changed.notify([], that);
            that.emit('value-change', { source: that });
        }
    };

    that.update = function(value) {
        var key = value[0];

        if (key) that.key = key;

        if (that.key && that.key !== '') {
            that.originally_set = true;
            that.original_key = that.key;
        }
        that.update_link();
        that.on_value_changed(value);
    };

    that.get_status = function() {

        var status = '';
        var value = that.key;

        if (that.original_key) {

            if (value !== that.original_key) {
                if (value === '') {
                    status = text.get('@i18n:objects.publickey.status_mod_ns');
                } else {
                    status = text.get('@i18n:objects.publickey.status_mod_s');
                }
            } else {
                // f00c is code of check icon
                var decimal_check_i = parseInt('f00c', 16);
                status = String.fromCharCode(decimal_check_i);
            }
        } else {
            status = text.get('@i18n:objects.publickey.status_new_ns');
        }

        return status;
    };

    that.create_edit_dialog = function() {

        var writable = that.is_writable();

        var dialog = IPA.dialog({
            name: 'pubkey-edit-dialog',
            title: '@i18n:objects.publickey.set_dialog_title',
            width: 500,
            height: 380
        });

        dialog.message = text.get('@i18n:objects.publickey.set_dialog_help');

        dialog.create_button({
            name: 'update',
            label: '@i18n:buttons.set',
            click: function() {
                var value = dialog.textarea.val();
                that.set_user_value(value);
                dialog.close();
            }
        });

        dialog.create_button({
            name: 'cancel',
            label: '@i18n:buttons.cancel',
            click: function() {
                dialog.close();
            }
        });

        dialog.create_content = function() {

            dialog.container.append(dialog.message);

            dialog.textarea = $('<textarea/>', {
                'class': 'certificate',
                disabled: !that.enabled
            }).appendTo(dialog.container);

            var key = that.key || '';
            dialog.textarea.val(key);
        };

        return dialog;
    };

    return that;
};


/**
 * Adder policy handles realtime showing and hiding fields when user switch
 * between User/Service/Shared vault in adder dialog.
 *
 * @extends IPA.facet_policy
 */
vault.adder_policy = function(spec) {

    var that = IPA.facet_policy(spec);

    that.init = function() {
        var type_f = that.container.fields.get_field('type');
        on(type_f, 'value-change', that.on_type_change);
    };

    that.on_type_change = function() {
        var type_f = that.container.fields.get_field('type');
        var user_f = that.container.fields.get_field('username');
        var service_f = that.container.fields.get_field('service');
        var mode = type_f.get_value()[0];
        var user = true;
        var service = true;

        if (mode === 'user') service = false;
        else if (mode === 'service') user = false;
        else if (mode === 'shared') user = service = false;

        user_f.set_enabled(user);
        user_f.widget.set_visible(user);
        service_f.set_enabled(service);
        service_f.widget.set_visible(service);
    };

    return that;
};


/**
 * Custom adder dialog.
 *
 * @extends IPA.entity_adder_dialog
 */
vault.custom_adder_dialog = function(spec) {
    spec = spec || {};

    spec.sections = spec.sections || [];

    var section_warn_arch_ret= {
        show_header: false,
        name: 'warning_ar',
        fields: [
            {
                field: false,
                $type: 'html',
                name: 'warn_arch_ret'
            }
        ],
        layout: {
            $factory: widget.fluid_layout,
            widget_cls: "col-sm-12 controls",
            label_cls: "hide"
        }
    };

    var section_f = {
        show_header: false,
        fields: [
            {
                $type: 'radio',
                name: 'type',
                flags: ['no_command'],
                label: '@i18n:objects.vault.type',
                options: [
                    {
                        value: 'user',
                        label: '@i18n:objects.vault.user'
                    },
                    {
                        value: 'service',
                        label: '@i18n:objects.vault.service'
                    },
                    {
                        value: 'shared',
                        label: '@i18n:objects.vault.shared'
                    }
                ]
            },
            {
                $type: 'entity_select',
                name: 'username',
                other_entity: 'user',
                other_field: 'uid'
            },
            {
                $type: 'entity_select',
                name: 'service',
                other_entity: 'service',
                other_field: 'krbprincipalname'
            },
            'cn',
            'description',
            {
                $type: 'radio',
                name: 'ipavaulttype',
                default_value: 'standard',
                read_only: true,
                options: [
                    {
                        value: 'standard',
                        label: '@i18n:objects.vault.standard_type'
                    },
                    {
                        label: '@i18n:objects.vault.symmetric_type'
                    },
                    {
                        label: '@i18n:objects.vault.asymmetric_type'
                    }
                ],
                tooltip: "@i18n:objects.vault.type_tooltip"
            }
        ]
    };

    var section_warn_standard = {
        name: 'warning_st',
        fields: [
            {
                field: false,
                $type: 'html',
                name: 'warn_standard'
            }
        ],
        layout: {
            $factory: widget.fluid_layout,
            widget_cls: "col-sm-12 controls",
            label_cls: "hide"
        }
    };

    spec.sections.push(section_warn_arch_ret);
    spec.sections.push(section_f);
    spec.sections.push(section_warn_standard);

    var that = IPA.entity_adder_dialog(spec);

    that.create_add_command = function(record) {
        var command = that.entity_adder_dialog_create_add_command(record);

        var type_f = that.fields.get_field('type');
        var type = type_f.save()[0];

        if (type === 'shared') command.set_option(type, true);

        return command;
    };

    that.create_content = function() {
        var warn_arch_ret_w = that.widgets.get_widget('warning_ar.warn_arch_ret');
        var warn_st_w = that.widgets.get_widget('warning_st.warn_standard');

        var warn_arch_text = text.get('@i18n:objects.vault.add_warn_arch_ret');
        var warn_st_text = text.get('@i18n:objects.vault.add_warn_standard');

        var warn_arch_ret = IPA.alert_helper.create_alert('arch', warn_arch_text);
        var warn_standard = IPA.alert_helper.create_alert('standard',
                                        warn_st_text);

        warn_st_w.html = IPA.alert_helper.render_alert(warn_standard);
        warn_arch_ret_w.html = IPA.alert_helper.render_alert(warn_arch_ret);

        that.entity_adder_dialog_create_content();

        var facet_name = that.entity.facet.name;
        facet_name = facet_name.substr(0, facet_name.indexOf('_'));
        if (facet_name === "") facet_name = 'user';

        var type_f = that.fields.get_field('type');
        type_f.set_pristine_value([facet_name]);

        if (IPA.is_selfservice) type_f.set_writable(false);
    };

    that.on_success = function(data) {
        var result = data.result.result;
        var my_vaults = that.entity.get_facet('search');

        function update_facet(name) {
            var fa = that.entity.get_facet(name);
            fa.set_expired_flag();
        }

        if (result.service) {
            update_facet('service_search');
        } else if (result.shared) {
            update_facet('shared_search');
        } else {
            update_facet('user_search');
            my_vaults.set_expired_flag();
        }
    };

    that.added.attach(that.on_success);

    return that;
};


/**
 * Creates specification of search facet for User Vaults
 */
var make_user_vault_search_spec = function() {
    return {
        $type: 'search',
        entity: 'vault',
        managed_entity: 'vault',
        name: 'user_search',
        tab_label: '@i18n:objects.vault.user_vaults_title',
        label: '@i18n:objects.vault.user_vaults_title',
        facet_groups: [vault.search_facet_group],
        facet_group: 'vaults',
        custom_actions: [
            {
                $type: 'add',
                hide_cond: []
            },
            {
                $type: 'batch_remove',
                hide_cond: []
            }
        ],
        additional_navigation_arguments: ['username'],
        show_values_with_dup_key: true,
        details_facet: 'vault_user',
        show_command_additional_attr: 'username',
        disable_facet_tabs: false,
        tabs_in_sidebar: true,
        command_options: {
            'users': true
        },
        columns: [
            'cn',
            'username',
            'ipavaulttype'
        ],
        policies: [
            vault.config_sidebar_policy
        ]
    };
};


var make_service_vault_spec = function() {
    return {
        $type: 'search',
        entity: 'vault',
        managed_entity: 'vault',
        name: 'service_search',
        tab_label: '@i18n:objects.vault.service_vaults_title',
        label: '@i18n:objects.vault.service_vaults_title',
        facet_groups: [vault.search_facet_group],
        facet_group: 'vaults',
        additional_navigation_arguments: ['service'],
        show_values_with_dup_key: true,
        details_facet: 'vault_service',
        show_command_additional_attr: 'service',
        disable_facet_tabs: false,
        tabs_in_sidebar: true,
        command_options: {
            'services': true
        },
        columns: [
            'cn',
            'service',
            'ipavaulttype'
        ],
        policies: [
            vault.config_sidebar_policy
        ]
    };
};


var make_shared_vault_spec = function() {
    return {
        $type: 'search',
        entity: 'vault',
        managed_entity: 'vault',
        tab_label: '@i18n:objects.vault.shared_vaults_title',
        name: 'shared_search',
        label: '@i18n:objects.vault.shared_vaults_title',
        facet_groups: [vault.search_facet_group],
        facet_group: 'vaults',
        additional_navigation_arguments: ['shared'],
        show_values_with_dup_key: true,
        show_command_additional_attr: 'shared',
        details_facet: 'vault_shared',
        disable_facet_tabs: false,
        tabs_in_sidebar: true,
        command_options: {
            'shared': true
        },
        columns: [
            'cn',
            'shared',
            'ipavaulttype'
        ],
        policies: [
            vault.config_sidebar_policy
        ]
    };
};


var make_vaultconfig_spec = function() {
    return {
        name: 'vaultconfig',
        facets: [
            {
                $type: 'details',
                label: '@i18n:objects.vault.config_title',
                tab_label: '@i18n:objects.vault.config_title',
                facet_groups: [vault.search_facet_group],
                facet_group: 'vaults',
                disable_facet_tabs: false,
                tabs_in_sidebar: true,
                check_rights: false,
                no_update: true,
                fields: [
                    {
                        $type: "multivalued",
                        name: 'kra_server_server'
                    },
                    {
                        $type: 'textarea',
                        name: 'transport_cert',
                        read_only: true,
                        style: {
                            width: '550px',
                            height: '350px'
                        }
                    }
                ],
                policies: [
                    vault.config_sidebar_policy
                ]
            }
        ]
    };
};


vault.config_sidebar_policy = function(spec) {

    var that = IPA.facet_policy(spec);

    that.post_create = function(data) {
        if (IPA.is_selfservice && that.container &&
            that.container.tabs_in_sidebar) {
            var header = that.container.header;

            if (header) header.tabs_widget.hide_tab('vaultconfig_details');
        }
    };

    return that;
};


vault.remove_vault_menu_item = function() {
    if (IPA.vault_enabled) return;

    var menu_location = IPA.is_selfservice ? 'vault' : 'network_services/vault';

    menu.remove_item(menu_location);
};

vault.my_vault_spec = make_my_vault_spec();

vault.user_vault_search_spec = make_user_vault_search_spec();

vault.service_vault_spec = make_service_vault_spec();

vault.shared_vault_spec = make_shared_vault_spec();

vault.vaultconfig_spec = make_vaultconfig_spec();

vault.register = function() {
    var e = reg.entity;
    var fa = reg.facet;
    var w = reg.widget;

    w.register('pub_key', vault.public_key_widget);
    e.register({type: 'vault', spec: vault.my_vault_spec});
    e.register({type: 'vaultconfig', spec: vault.vaultconfig_spec});
    fa.register_from_spec('vault_user_search', vault.user_vault_search_spec);
    fa.register_from_spec('vault_service_search', vault.service_vault_spec);
    fa.register_from_spec('vault_shared_search', vault.shared_vault_spec);
};

phases.on('registration', vault.register);
phases.on('profile', vault.remove_vault_menu_item, 20);

return vault;
});
