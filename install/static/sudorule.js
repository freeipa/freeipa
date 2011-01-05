/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

        that.add_field(ipa_text_widget({name: 'cn', undo: false}));

        that.add_dialog_init();
    };

    return that;
}

function ipa_sudorule_search_facet(spec) {

    spec = spec || {};

    var that = ipa_search_facet(spec);

    that.init = function() {

        that.create_column({name:'cn'});
        that.create_column({name:'description'});
        that.create_column({name:'cmdcategory'});

        that.search_facet_init();
    };

    return that;
}

function ipa_sudorule_details_facet(spec) {

    spec = spec || {};

    var that = ipa_details_facet(spec);

    that.init = function() {

        var section;

        if (IPA.layout) {
            section = that.create_section({
                'name': 'general',
                'label': 'General',
                'template': 'sudorule-details-general.html #contents'
            });

        } else {
            section = ipa_sudorule_details_general_section({
                'name': 'general',
                'label': 'General'
            });
            that.add_section(section);
        }

        section.create_text({ 'name': 'cn', 'read_only': true });
        section.create_textarea({ 'name': 'description' });
        section.create_radio({ 'name': 'ipaenabledflag' });

        section = ipa_rule_details_section({
            'name': 'user',
            'label': 'Who',
            'field_name': 'usercategory',
            'options': [
                { 'value': 'all', 'label': 'Anyone' },
                { 'value': '', 'label': 'Specified Users and Groups' }
            ],
            'tables': [
                { 'field_name': 'memberuser_user' },
                { 'field_name': 'memberuser_group' }
            ]
        });
        that.add_section(section);

        var category = section.create_radio({ name: 'usercategory', label: 'User category' });
        section.add_field(ipa_sudorule_association_table_widget({
            'id': that.entity_name+'-memberuser_user',
            'name': 'memberuser_user', 'label': 'Users', 'category': category,
            'other_entity': 'user', 'add_method': 'add_user', 'remove_method': 'remove_user',
            'external': 'externaluser'
        }));
        section.add_field(ipa_sudorule_association_table_widget({
            'id': that.entity_name+'-memberuser_group',
            'name': 'memberuser_group', 'label': 'Groups', 'category': category,
            'other_entity': 'group', 'add_method': 'add_user', 'remove_method': 'remove_user'
        }));

        section = ipa_rule_details_section({
            'name': 'host',
            'label': 'Access this host',
            'field_name': 'hostcategory',
            'options': [
                { 'value': 'all', 'label': 'Any Host' },
                { 'value': '', 'label': 'Specified Hosts and Groups' }
            ],
            'tables': [
                { 'field_name': 'memberhost_host' },
                { 'field_name': 'memberhost_hostgroup' }
            ]
        });
        that.add_section(section);

        category = section.create_radio({ 'name': 'hostcategory', 'label': 'Host category' });
        section.add_field(ipa_sudorule_association_table_widget({
            'id': that.entity_name+'-memberhost_host',
            'name': 'memberhost_host', 'label': 'Host', 'category': category,
            'other_entity': 'host', 'add_method': 'add_host', 'remove_method': 'remove_host',
            'external': 'externalhost'
        }));
        section.add_field(ipa_sudorule_association_table_widget({
            'id': that.entity_name+'-memberhost_hostgroup',
            'name': 'memberhost_hostgroup', 'label': 'Groups', 'category': category,
            'other_entity': 'hostgroup', 'add_method': 'add_host', 'remove_method': 'remove_host'
        }));

        section = ipa_sudorule_details_command_section({
            'name': 'command',
            'label': 'Run Commands'
        });
        that.add_section(section);

        section = ipa_sudorule_details_runas_section({
            'name': 'runas',
            'label': 'As Whom'
        });
        that.add_section(section);

        that.details_facet_init();
    };

    that.load = function(record) {
        var category = record['cmdcategory'];
        if (category && category[0] == 'all') {
            record['cmdcategory'] = ['allow'];

        } else {
            var memberallowcmd_sudocmd = record['memberallowcmd_sudocmd'];
            var memberallowcmd_sudocmdgroup = record['memberallowcmd_sudocmdgroup'];
            var memberdenycmd_sudocmd = record['memberdenycmd_sudocmd'];
            var memberdenycmd_sudocmdgroup = record['memberdenycmd_sudocmdgroup'];

            if (!memberallowcmd_sudocmd && !memberallowcmd_sudocmdgroup
                && !memberdenycmd_sudocmd && !memberdenycmd_sudocmdgroup) {
                record['cmdcategory'] = ['deny'];

            } else {
                record['cmdcategory'] = [''];
            }
        }

        that.details_facet_load(record);
    };

    that.update = function() {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var modify_operation = {
            'execute': false,
            'command': ipa_command({
                'method': that.entity_name+'_mod',
                'args': [pkey],
                'options': {'all': true, 'rights': true}
            })
        };

        var categories = {
            'usercategory': {
                'remove_values': false
            },
            'hostcategory': {
                'remove_values': false
            },
            'cmdcategory': {
                'remove_values': false
            },
            'ipasudorunasusercategory': {
                'remove_values': false
            },
            'ipasudorunasgroupcategory': {
                'remove_values': false
            }
        };

        var member_operations = {
            'memberuser': {
                'category': 'usercategory',
                'has_values': false,
                'command': ipa_command({
                    'method': that.entity_name+'_remove_user',
                    'args': [pkey],
                    'options': {'all': true, 'rights': true}
                })
            },
            'memberhost': {
                'category': 'hostcategory',
                'has_values': false,
                'command': ipa_command({
                    'method': that.entity_name+'_remove_host',
                    'args': [pkey],
                    'options': {'all': true, 'rights': true}
                })
            },
            'memberallowcmd': {
                'category': 'cmdcategory',
                'has_values': false,
                'command': ipa_command({
                    'method': that.entity_name+'_remove_allow_command',
                    'args': [pkey],
                    'options': {'all': true, 'rights': true}
                })
            },
            'memberdenycmd': {
                'category': 'cmdcategory',
                'has_values': false,
                'command': ipa_command({
                    'method': that.entity_name+'_remove_deny_command',
                    'args': [pkey],
                    'options': {'all': true, 'rights': true}
                })
            },
            'ipasudorunas': {
                'category': 'ipasudorunasusercategory',
                'has_values': false,
                'command': ipa_command({
                    'method': that.entity_name+'_remove_runasuser',
                    'args': [pkey],
                    'options': {'all': true, 'rights': true}
                })
            },
            'ipasudorunasgroup': {
                'category': 'ipasudorunasgroupcategory',
                'has_values': false,
                'command': ipa_command({
                    'method': that.entity_name+'_remove_runasgroup',
                    'args': [pkey],
                    'options': {'all': true, 'rights': true}
                })
            }
        };

        var enable_operation = {
            'execute': false,
            'command': ipa_command({
                'method': that.entity_name+'_enable',
                'args': [pkey],
                'options': {'all': true, 'rights': true}
            })
        };

        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections[i];

            var div = $('#'+that.entity_name+'-'+that.name+'-'+section.name, that.container);

            for (var j=0; j<section.fields.length; j++) {
                var field = section.fields[j];

                var span = $('span[name='+field.name+']', div).first();
                var values = field.save();
                if (!values) continue;

                var param_info = ipa_get_param_info(that.entity_name, field.name);

                // skip primary key
                if (param_info && param_info['primary_key']) continue;

                var p = field.name.indexOf('_');
                if (p >= 0) {
                    // prepare command to remove members if needed
                    var attribute = field.name.substring(0, p);
                    var other_entity = field.name.substring(p+1);

                    if (values.length) {
                        member_operations[attribute].command.set_option(other_entity, values.join(','));
                        member_operations[attribute].has_values = true;
                    }
                    continue;
                }

                // skip unchanged field
                if (!field.is_dirty(span)) continue;

                // check enable/disable
                if (field.name == 'ipaenabledflag') {
                    if (values[0] == 'FALSE') enable_operation.command.method = that.entity_name+'_disable';
                    enable_operation.execute = true;
                    continue;
                }

                if (field.name == 'cmdcategory') {
                    var value = values[0];
                    if (value == 'allow') {
                        values = ['all'];
                        categories[field.name].remove_values = true;
                    } else if (value == 'deny') {
                        values = [];
                        categories[field.name].remove_values = true;
                    } else {
                        values = [];
                    }

                } else if (categories[field.name]) {
                    if (values[0] == 'all') {
                        categories[field.name].remove_values = true;
                    }
                }

                // use setattr/addattr if param_info not available
                if (!param_info) {
                    for (var k=0; k<values.length; k++) {
                        modify_operation.command.set_option(
                            k == 0 ? 'setattr' : 'addattr',
                            field.name+'='+values[k]
                        );
                        modify_operation.execute = true;
                    }
                    continue;
                }

                // set modify options
                if (values.length == 1) {
                    modify_operation.command.set_option(field.name, values[0]);
                } else {
                    modify_operation.command.set_option(field.name, values);
                }
                modify_operation.execute = true;
            }
        }

        var batch = ipa_batch_command({
            'name': 'sudorule_details_update',
            'on_success': function(data, text_status, xhr) {
                that.refresh();
            },
            'on_error': function(xhr, text_status, error_thrown) {
                that.refresh();
            }
        });

        for (var member_attribute in member_operations) {
            var member_operation = member_operations[member_attribute];
            if (member_operation.has_values &&
                categories[member_operation.category].remove_values) {
                batch.add_command(member_operation.command);
            }
        }

        if (modify_operation.execute) batch.add_command(modify_operation.command);
        if (enable_operation.execute) batch.add_command(enable_operation.command);

        if (!batch.commands.length) {
            that.refresh();
            return;
        }

        //alert(JSON.stringify(batch.to_json()));

        batch.execute();
    };

    return that;
}

function ipa_sudorule_details_general_section(spec){

    spec = spec || {};

    var that = ipa_details_section(spec);

    that.create = function(container) {

        var table = $('<table/>', {
            'style': 'width: 100%;'
        }).appendTo(container);

        var tr = $('<tr/>').appendTo(table);

        var td = $('<td/>', {
            'style': 'width: 100px; text-align: right;',
            'html': 'Name:'
        }).appendTo(tr);

        td = $('<td/>').appendTo(tr);

        var span = $('<span/>', { 'name': 'cn' }).appendTo(td);

        $('<input/>', {
            'type': 'text',
            'name': 'cn',
            'size': 30
        }).appendTo(span);

        span.append(' ');

        $('<span/>', {
            'name': 'undo',
            'class': 'ui-state-highlight ui-corner-all',
            'style': 'display: none;',
            'html': 'undo'
        }).appendTo(span);

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>', {
            'style': 'text-align: right; vertical-align: top;',
            'html': 'Description:'
        }).appendTo(tr);

        td = $('<td/>').appendTo(tr);

        span = $('<span/>', { 'name': 'description' }).appendTo(td);

        $('<textarea/>', {
            'name': 'description',
            'rows': 5,
            'style': 'width: 100%'
        }).appendTo(span);

        span.append(' ');

        $('<span/>', {
            'name': 'undo',
            'class': 'ui-state-highlight ui-corner-all',
            'style': 'display: none;',
            'html': 'undo'
        }).appendTo(span);

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>', {
            'style': 'text-align: right; vertical-align: top;',
            'html': 'Rule status:'
        }).appendTo(tr);

        td = $('<td/>').appendTo(tr);

        span = $('<span/>', { 'name': 'ipaenabledflag' }).appendTo(td);

        $('<input/>', {
            'type': 'radio',
            'name': 'ipaenabledflag',
            'value': 'TRUE'
        }).appendTo(span);

        span.append('Active');

        $('<input/>', {
            'type': 'radio',
            'name': 'ipaenabledflag',
            'value': 'FALSE'
        }).appendTo(span);

        span.append('Inactive');

        span.append(' ');

        $('<span/>', {
            'name': 'undo',
            'class': 'ui-state-highlight ui-corner-all',
            'style': 'display: none;',
            'html': 'undo'
        }).appendTo(span);
    };

    return that;
}

function ipa_sudorule_details_command_section(spec){

    spec = spec || {};

    var that = ipa_details_section(spec);

    that.init = function() {

        var category = that.create_radio({'name': 'cmdcategory'});

        that.add_field(ipa_sudorule_command_table_widget({
            'id': that.entity_name+'-memberallowcmd_sudocmd',
            'name': 'memberallowcmd_sudocmd', 'label': 'Command',
            'category': category, 'section': that,
            'other_entity': 'sudocmd', 'add_method': 'add_allow_command', 'remove_method': 'remove_allow_command'
        }));
        that.add_field(ipa_sudorule_command_table_widget({
            'id': that.entity_name+'-memberallowcmd_sudocmdgroup',
            'name': 'memberallowcmd_sudocmdgroup', 'label': 'Groups',
            'category': category, 'section': that,
            'other_entity': 'sudocmdgroup', 'add_method': 'add_allow_command', 'remove_method': 'remove_allow_command'
        }));

        that.add_field(ipa_sudorule_command_table_widget({
            'id': that.entity_name+'-memberdenycmd_sudocmd',
            'name': 'memberdenycmd_sudocmd', 'label': 'Command',
            'category': category, 'section': that,
            'other_entity': 'sudocmd', 'add_method': 'add_deny_command', 'remove_method': 'remove_deny_command'
        }));
        that.add_field(ipa_sudorule_command_table_widget({
            'id': that.entity_name+'-memberdenycmd_sudocmdgroup',
            'name': 'memberdenycmd_sudocmdgroup', 'label': 'Groups',
            'category': category, 'section': that,
            'other_entity': 'sudocmdgroup', 'add_method': 'add_deny_command', 'remove_method': 'remove_deny_command'
        }));

        that.section_init();
    };

    that.create = function(container) {

        if (that.template) return;

        var span = $('<span/>', { 'name': 'cmdcategory' }).appendTo(container);

        $('<input/>', {
            'type': 'radio',
            'name': 'cmdcategory',
            'value': 'allow'
        }).appendTo(span);

        span.append('Allow Any Command / Group');

        span.append(' ');

        $('<span/>', {
            'name': 'undo',
            'class': 'ui-state-highlight ui-corner-all',
            'style': 'display: none;',
            'html': 'undo'
        }).appendTo(span);

        span.append('<br/>');

        $('<input/>', {
            'type': 'radio',
            'name': 'cmdcategory',
            'value': 'deny'
        }).appendTo(span);

        span.append('Deny Any Command / Group');

        span.append('<br/>');

        $('<input/>', {
            'type': 'radio',
            'name': 'cmdcategory',
            'value': ''
        }).appendTo(span);

        span.append('Specific Command / Group');

        $('<h3/>', { text: 'Allow' }).appendTo(span);

        var table_span = $('<span/>', { 'name': 'memberallowcmd_sudocmd' }).appendTo(span);
        var field = that.get_field('memberallowcmd_sudocmd');
        field.create(table_span);

        table_span = $('<span/>', { 'name': 'memberallowcmd_sudocmdgroup' }).appendTo(span);
        field = that.get_field('memberallowcmd_sudocmdgroup');
        field.create(table_span);

        $('<h3/>', { text: 'Deny' }).appendTo(span);

        table_span = $('<span/>', { 'name': 'memberdenycmd_sudocmd' }).appendTo(span);
        field = that.get_field('memberdenycmd_sudocmd');
        field.create(table_span);

        table_span = $('<span/>', { 'name': 'memberdenycmd_sudocmdgroup' }).appendTo(span);
        field = that.get_field('memberdenycmd_sudocmdgroup');
        field.create(table_span);
    };

    return that;
}

function ipa_sudorule_details_runas_section(spec){

    spec = spec || {};

    var that = ipa_details_section(spec);

    that.init = function() {

        var category = that.create_radio({ name: 'ipasudorunasusercategory', label: 'Run as User category' });
        that.add_field(ipa_sudorule_association_table_widget({
            'id': that.entity_name+'-runasruser_user',
            'name': 'ipasudorunas_user', 'label': 'Users', 'category': category,
            'other_entity': 'user', 'add_method': 'add_runasuser', 'remove_method': 'remove_runasuser'
        }));
        that.add_field(ipa_sudorule_association_table_widget({
            'id': that.entity_name+'-runasuser_group',
            'name': 'ipasudorunas_group', 'label': 'Groups', 'category': category,
            'other_entity': 'group', 'add_method': 'add_runasuser', 'remove_method': 'remove_runasuser'
        }));

        category = that.create_radio({ name: 'ipasudorunasgroupcategory', label: 'Run as Group category' });
        that.add_field(ipa_sudorule_association_table_widget({
            'id': that.entity_name+'-runasgroup_group',
            'name': 'ipasudorunasgroup_group', 'label': 'Groups', 'category': category,
            'other_entity': 'group', 'add_method': 'add_runasgroup', 'remove_method': 'remove_runasgroup'
        }));

        that.section_init();
    };

    that.create = function(container) {

        if (that.template) return;

        var span = $('<span/>', { 'name': 'ipasudorunasusercategory' }).appendTo(container);

        $('<input/>', {
            'type': 'radio',
            'name': 'ipasudorunasusercategory',
            'value': 'all'
        }).appendTo(span);

        span.append('Anyone');

        $('<input/>', {
            'type': 'radio',
            'name': 'ipasudorunasusercategory',
            'value': ''
        }).appendTo(span);

        span.append('Specified Users and Groups');

        span.append(' ');

        $('<span/>', {
            'name': 'undo',
            'class': 'ui-state-highlight ui-corner-all',
            'style': 'display: none;',
            'html': 'undo'
        }).appendTo(span);

        span.append('<br/>');

        var table_span = $('<span/>', { 'name': 'ipasudorunas_user' }).appendTo(span);
        var field = that.get_field('ipasudorunas_user');
        field.create(table_span);

        table_span = $('<span/>', { 'name': 'ipasudorunas_group' }).appendTo(span);
        field = that.get_field('ipasudorunas_group');
        field.create(table_span);

        span = $('<span/>', { 'name': 'ipasudorunasgroupcategory' }).appendTo(container);

        $('<input/>', {
            'type': 'radio',
            'name': 'ipasudorunasgroupcategory',
            'value': 'all'
        }).appendTo(span);

        span.append('Any Group');

        $('<input/>', {
            'type': 'radio',
            'name': 'ipasudorunasgroupcategory',
            'value': ''
        }).appendTo(span);

        span.append('Specified Groups');

        span.append(' ');

        $('<span/>', {
            'name': 'undo',
            'class': 'ui-state-highlight ui-corner-all',
            'style': 'display: none;',
            'html': 'undo'
        }).appendTo(span);

        span.append('<br/>');

        table_span = $('<span/>', { 'name': 'ipasudorunasgroup_group' }).appendTo(span);
        field = that.get_field('ipasudorunasgroup_group');
        field.create(table_span);
    };

    return that;
}

function ipa_sudorule_association_table_widget(spec) {

    spec = spec || {};

    var that = ipa_rule_association_table_widget(spec);

    that.external = spec.external;

    that.create_add_dialog = function() {
        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var label = IPA.metadata[that.other_entity].label;
        var title = 'Add '+label+' to '+that.entity_name+' '+pkey;

        var template;
        if (IPA.layout) {
            template = 'sudorule-'+that.other_entity+'-dialog.html #contents';
        }

        return ipa_sudorule_association_adder_dialog({
            'title': title,
            'entity_name': that.entity_name,
            'pkey': pkey,
            'other_entity': that.other_entity,
            'external': that.external,
            'template': template
        });
    };

    that.load = function(result) {
        that.values = result[that.name] || [];
        if (that.external) {
            var external_values = result[that.external] || [];
            $.merge(that.values, external_values);
        }
        that.reset();
    };

    return that;
}

function ipa_sudorule_association_adder_dialog(spec) {

    spec = spec || {};

    var that = ipa_association_adder_dialog(spec);

    that.external = spec.external;

    that.init = function() {

        if (!that.columns.length) {
            var pkey_name = IPA.metadata[that.other_entity].primary_key;
            that.create_column({
                name: pkey_name,
                label: IPA.metadata[that.other_entity].label,
                primary_key: true,
                width: '200px'
            });
        }

        that.available_table = ipa_table_widget({
            name: 'available'
        });

        that.available_table.set_columns(that.columns);

        that.available_table.init();

        that.selected_table = ipa_table_widget({
            name: 'selected'
        });

        that.selected_table.set_columns(that.columns);

        that.selected_table.init();

        that.association_adder_dialog_init();
    };

    that.create = function() {

        // do not call that.dialog_create();

        var search_panel = $('<div/>', {
            'class': 'adder-dialog-filter'
        }).appendTo(that.container);

        $('<input/>', {
            type: 'text',
            name: 'filter',
            style: 'width: 244px'
        }).appendTo(search_panel);

        search_panel.append(' ');

        $('<input/>', {
            type: 'button',
            name: 'find',
            value: 'Find'
        }).appendTo(search_panel);

        var results_panel = $('<div/>', {
            'class': 'adder-dialog-results'
        }).appendTo(that.container);

        var class_name = that.external ? 'adder-dialog-internal' : 'adder-dialog-available';

        var available_panel = $('<div/>', {
            name: 'available',
            'class': class_name
        }).appendTo(results_panel);

        $('<div/>', {
            html: 'Available',
            'class': 'ui-widget-header'
        }).appendTo(available_panel);

        that.available_table.create(available_panel);

        var buttons_panel = $('<div/>', {
            name: 'buttons',
            'class': 'adder-dialog-buttons'
        }).appendTo(results_panel);

        var p = $('<p/>').appendTo(buttons_panel);
        $('<input />', {
            type: 'button',
            name: 'remove',
            value: '<<'
        }).appendTo(p);

        p = $('<p/>').appendTo(buttons_panel);
        $('<input />', {
            type: 'button',
            name: 'add',
            value: '>>'
        }).appendTo(p);

        var selected_panel = $('<div/>', {
            name: 'selected',
            'class': 'adder-dialog-selected'
        }).appendTo(results_panel);

        $('<div/>', {
            html: 'Prospective',
            'class': 'ui-widget-header'
        }).appendTo(selected_panel);

        that.selected_table.create(selected_panel);

        if (that.external) {
            var external_panel = $('<div/>', {
                name: 'external',
                'class': 'adder-dialog-external'
            }).appendTo(results_panel);

            $('<div/>', {
                html: 'External',
                'class': 'ui-widget-header'
            }).appendTo(external_panel);

            $('<input/>', {
                type: 'text',
                name: 'external',
                style: 'width: 244px'
            }).appendTo(external_panel);
        }
    };

    that.setup = function() {
        that.association_adder_dialog_setup();
        if (that.external) that.external_field = $('input[name=external]', that.container);
    };

    that.add = function() {
        var rows = that.available_table.remove_selected_rows();
        that.selected_table.add_rows(rows);

        if (that.external) {
            var pkey_name = IPA.metadata[that.other_entity].primary_key;
            var value = that.external_field.val();
            if (!value) return;

            var record = {};
            record[pkey_name] = value;
            that.selected_table.add_record(record);
            that.external_field.val('');
        }
    };

    return that;
}

function ipa_sudorule_command_table_widget(spec) {

    spec = spec || {};

    var that = ipa_association_table_widget(spec);

    that.category = spec.category;
    that.section = spec.section;

    that.add = function(values, on_success, on_error) {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var batch = ipa_batch_command({
            'on_success': on_success,
            'on_error': on_error
        });

        var command;

        if (that.category.save() == 'all') {
            command = ipa_command({
                'method': that.entity_name+'_mod',
                'args': [pkey],
                'options': {'all': true, 'rights': true}
            });
            command.set_option(that.category.name, '');
            batch.add_command(command);
        }

        command = ipa_command({
            'method': that.entity_name+'_'+that.add_method,
            'args': [pkey],
            'on_success': function() {
                var record = {};
                record[that.category.name] = [''];
                that.category.load(['']);
            }
        });
        command.set_option(that.other_entity, values.join(','));
        batch.add_command(command);

        batch.execute();
    };

    that.remove = function(values, on_success, on_error) {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var command = ipa_command({
            'method': that.entity_name+'_'+that.remove_method,
            'args': [pkey],
            'on_success': function(data, text_status, xhr) {

                // if all values in this field are removed
                // and other fields are already empty,
                // change category to 'deny'

                var update_category = values.length == that.values.length;

                if (update_category && that.name != 'memberallowcmd_sudocmd') {
                    var memberallowcmd_sudocmd = that.section.get_field('memberallowcmd_sudocmd').save();
                    if (memberallowcmd_sudocmd.length) update_category = false;
                }

                if (update_category && that.name != 'memberallowcmd_sudocmdgroup') {
                    var memberallowcmd_sudocmdgroup = that.section.get_field('memberallowcmd_sudocmdgroup').save();
                    if (memberallowcmd_sudocmdgroup.length) update_category = false;
                }

                if (update_category && that.name != 'memberdenycmd_sudocmd') {
                    var memberdenycmd_sudocmd = that.section.get_field('memberdenycmd_sudocmd').save();
                    if (memberdenycmd_sudocmd.length) update_category = false;
                }

                if (update_category && that.name != 'memberdenycmd_sudocmdgroup') {
                    var memberdenycmd_sudocmdgroup = that.section.get_field('memberdenycmd_sudocmdgroup').save();
                    if (memberdenycmd_sudocmdgroup.length) update_category = false;
                }

                if (update_category) {
                    var record = {};
                    record[that.category.name] = ['deny'];
                    that.category.load(record);
                }

                if (on_success) on_success(data, text_status, xhr);
            },
            'on_error': on_error
        });

        command.set_option(that.other_entity, values.join(','));

        command.execute();
    };

    return that;
}
