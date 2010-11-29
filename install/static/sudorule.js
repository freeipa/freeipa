/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */

function ipa_sudorule() {

    var that = ipa_entity({
        'name': 'sudorule'
    });

    that.init = function() {

        var dialog = ipa_sudorule_add_dialog({
            'name': 'add',
            'title': 'Add New Rule'
        });
        that.add_dialog(dialog);
        dialog.init();

        var facet = ipa_sudorule_search_facet({
            'name': 'search',
            'label': 'Search'
        });
        that.add_facet(facet);

        facet = ipa_sudorule_details_facet({
            'name': 'details',
            'label': 'Details'
        });
        that.add_facet(facet);

        that.entity_init();
    };

    return that;
}

IPA.add_entity(ipa_sudorule());

function ipa_sudorule_add_dialog(spec) {

    spec = spec || {};

    var that = ipa_add_dialog(spec);

    that.init = function() {

        that.add_dialog_init();

        that.add_field(ipa_text_widget({
            'name': 'cn',
            'label': 'Rule Name',
            'undo': false
        }));
    };

    return that;
}

function ipa_sudorule_search_facet(spec) {

    spec = spec || {};

    var that = ipa_search_facet(spec);

    that.init = function() {

        that.create_column({name:'cn', label:'Rule Name'});
        that.create_column({name:'description', label:'Description'});
        that.create_column({name:'cmdcategory', label:'Command category'});

        that.search_facet_init();
    };

    that.create = function(container) {
        that.search_facet_create(container);

        container.children().last().prepend(
            $('<h2/>', { 'html': IPA.metadata.sudorule.label }));
        container.children().last().prepend('<br/><br/>');

    };

    that.setup = function(container) {
        that.search_facet_setup(container);
    };

    return that;
}

function ipa_sudorule_details_facet(spec) {

    spec = spec || {};

    var that = ipa_details_facet(spec);

    that.init = function() {

        var section = ipa_details_list_section({
            'name': 'general',
            'label': 'General'
        });
        that.add_section(section);

        section.create_field({ 'name': 'cn', 'label': 'Name', 'read_only': true });
        section.create_field({ 'name': 'description', 'label': 'Description' });
        section.create_field({ 'name': 'cmdcategory', 'label': 'Command Category' });

        section = ipa_rule_details_section({
            'name': 'user',
            'label': 'Who',
            'field_name': 'memberuser',
            'tables': [
                { 'field_name': 'memberuser_user' },
                { 'field_name': 'memberuser_group' }
            ]
        });
        that.add_section(section);

        section.add_field(ipa_sudorule_association_widget({
            'id': that.entity_name+'-memberuser_user',
            'name': 'memberuser_user', 'label': 'Users',
            'other_entity': 'user', 'add_method': 'add_user', 'remove_method': 'remove_user'
        }));
        section.add_field(ipa_sudorule_association_widget({
            'id': that.entity_name+'-memberuser_group',
            'name': 'memberuser_group', 'label': 'Groups',
            'other_entity': 'group', 'add_method': 'add_user', 'remove_method': 'remove_user'
        }));

        section = ipa_rule_details_section({
            'name': 'host',
            'label': 'Where',
            'field_name': 'memberhost',
            'tables': [
                { 'field_name': 'memberhost_host' },
                { 'field_name': 'memberhost_hostgroup' }
            ]
        });
        that.add_section(section);

        section.add_field(ipa_sudorule_association_widget({
            'id': that.entity_name+'-memberhost_host',
            'name': 'memberhost_host', 'label': 'Host',
            'other_entity': 'host', 'add_method': 'add_host', 'remove_method': 'remove_host'
        }));
        section.add_field(ipa_sudorule_association_widget({
            'id': that.entity_name+'-memberhost_hostgroup',
            'name': 'memberhost_hostgroup', 'label': 'Groups',
            'other_entity': 'hostgroup', 'add_method': 'add_host', 'remove_method': 'remove_host'
        }));

        section = ipa_rule_details_section({
            'name': 'allow',
            'label': 'Allow',
            'field_name': 'memberallowcmd',
            'tables': [
                { 'field_name': 'memberallowcmd_sudocmd' },
                { 'field_name': 'memberallowcmd_sudocmdgroup' }
            ]
        });
        that.add_section(section);

        section.add_field(ipa_sudorule_association_widget({
            'id': that.entity_name+'-memberallowcmd_sudocmd',
            'name': 'memberallowcmd_sudocmd', 'label': 'Command',
            'other_entity': 'sudocmd', 'add_method': 'add_allow_command', 'remove_method': 'remove_allow_command'
        }));
        section.add_field(ipa_sudorule_association_widget({
            'id': that.entity_name+'-memberallowcmd_sudocmdgroup',
            'name': 'memberallowcmd_sudocmdgroup', 'label': 'Groups',
            'other_entity': 'sudocmdgroup', 'add_method': 'add_allow_command', 'remove_method': 'remove_allow_command'
        }));

        section = ipa_rule_details_section({
            'name': 'deny',
            'label': 'Deny',
            'field_name': 'memberdenycmd',
            'tables': [
                { 'field_name': 'memberdenycmd_sudocmd' },
                { 'field_name': 'memberdenycmd_sudocmdgroup' }
            ]
        });
        that.add_section(section);

        section.add_field(ipa_sudorule_association_widget({
            'id': that.entity_name+'-memberdenycmd_sudocmd',
            'name': 'memberdenycmd_sudocmd', 'label': 'Command',
            'other_entity': 'sudocmd', 'add_method': 'add_deny_command', 'remove_method': 'remove_deny_command'
        }));
        section.add_field(ipa_sudorule_association_widget({
            'id': that.entity_name+'-memberdenycmd_sudocmdgroup',
            'name': 'memberdenycmd_sudocmdgroup', 'label': 'Groups',
            'other_entity': 'sudocmdgroup', 'add_method': 'add_deny_command', 'remove_method': 'remove_deny_command'
        }));

        that.details_facet_init();
    };

    return that;
}

function ipa_sudorule_association_widget(spec) {

    spec = spec || {};

    var that = ipa_rule_association_widget(spec);

    that.add = function(values, on_success, on_error) {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var command = ipa_command({
            'method': that.entity_name+'_'+that.add_method,
            'args': [pkey],
            'on_success': on_success,
            'on_error': on_error
        });
        command.set_option(that.other_entity, values.join(','));

        command.execute();
    };

    that.remove = function(values, on_success, on_error) {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var command = ipa_command({
            'method': that.entity_name+'_'+that.remove_method,
            'args': [pkey],
            'on_success': on_success,
            'on_error': on_error
        });

        command.set_option(that.other_entity, values.join(','));

        command.execute();
    };

    that.save = function() {
        return null;
    };

    return that;
}