/*jsl:import ipa.js */

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

IPA.entity_factories.hbacrule = function () {

    var that = IPA.entity({
        'name': 'hbacrule'
    });

    that.init = function() {

        var facet = IPA.hbacrule_search_facet({
            'name': 'search',
            'label': 'Search'
        });

        var dialog = IPA.hbacrule_add_dialog({
            'name': 'add',
            'title': 'Add New Rule'
        });
        facet.dialog(dialog);

        that.add_facet(facet);

        facet = IPA.hbacrule_details_facet({
            'name': 'details'
        });
        that.add_facet(facet);

        that.entity_init();
    };

    return that;
};




IPA.hbacrule_add_dialog = function (spec) {

    spec = spec || {};

    var that = IPA.add_dialog(spec);

    that.init = function() {

        that.add_field(IPA.text_widget({
            'name': 'cn',
            'undo': false
        }));

        that.add_field(IPA.radio_widget({
            'name': 'accessruletype',
            'options': [
                { 'value': 'allow', 'label': 'Allow' },
                { 'value': 'deny', 'label': 'Deny' }
            ],
            'undo': false
        }));

        that.add_dialog_init();
    };

    return that;
};


IPA.hbacrule_search_facet = function (spec) {

    spec = spec || {};

    var that = IPA.search_facet(spec);

    that.init = function() {

        that.create_column({name:'cn'});
        that.create_column({name:'usercategory'});
        that.create_column({name:'hostcategory'});
        that.create_column({name:'ipaenabledflag'});
        that.create_column({name:'servicecategory'});
        that.create_column({name:'sourcehostcategory'});

        that.search_facet_init();
    };

    that.create = function(container) {

/*
        // Not yet implemented

        var left_buttons = $('<span/>', {
            'style': 'float: left;'
        }).appendTo(container);

        left_buttons.append(IPA.button({
            'label': 'Troubleshoot Rules'
        }));

        left_buttons.append(IPA.button({
            'label': 'Cull Disabled Rules'
        }));
*/

        that.search_facet_create(container);

    };

    return that;
};


IPA.hbacrule_details_facet = function (spec) {

    spec = spec || {};

    var that = IPA.details_facet(spec);

    that.init = function() {

        var section;

        if (IPA.layout) {
            section = that.create_section({
                'name': 'general',
                'label': 'General',
                'template': 'hbacrule-details-general.html #contents'
            });

        } else {
            section = IPA.hbacrule_details_general_section({
                'name': 'general',
                'label': 'General'
            });
            that.add_section(section);
        }

        section.text({name: 'cn', label: 'Name', read_only: true});
        section.radio({name: 'accessruletype', label: 'Rule Type'});
        section.textarea({name: 'description', label: 'Description'});
        section.radio({name: 'ipaenabledflag', label: 'Enabled'});

        if (IPA.layout) {
            section = that.create_section({
                'name': 'user',
                'label': 'Who',
                'template': 'hbacrule-details-user.html #contents'
            });

        } else {
            section = IPA.rule_details_section({
                'name': 'user',
                'label': 'Who',
                'text': 'Rule applies when access is requested by:',
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
        }

        var category = section.radio({ name: 'usercategory', label: 'User category' });
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberuser_user',
            'name': 'memberuser_user', 'label': 'Users', 'category': category,
            'other_entity': 'user', 'add_method': 'add_user', 'remove_method': 'remove_user'
        }));
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberuser_group',
            'name': 'memberuser_group', 'label': 'Groups', 'category': category,
            'other_entity': 'group', 'add_method': 'add_user', 'remove_method': 'remove_user'
        }));

        if (IPA.layout) {
            section = that.create_section({
                'name': 'host',
                'label': 'Accessing',
                'template': 'hbacrule-details-host.html #contents'
            });

        } else {
            section = IPA.rule_details_section({
                'name': 'host',
                'label': 'Accessing',
                'text': 'Rule applies when access is requested to:',
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
        }

        category = section.radio({ 'name': 'hostcategory', 'label': 'Host category' });
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberhost_host',
            'name': 'memberhost_host', 'label': 'Hosts', 'category': category,
            'other_entity': 'host', 'add_method': 'add_host', 'remove_method': 'remove_host'
        }));
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberhost_hostgroup',
            'name': 'memberhost_hostgroup', 'label': 'Host Groups', 'category': category,
            'other_entity': 'hostgroup', 'add_method': 'add_host', 'remove_method': 'remove_host'
        }));

        if (IPA.layout) {
            section = that.create_section({
                'name': 'service',
                'label': 'Via Service',
                'template': 'hbacrule-details-service.html #contents'
            });

        } else {
            section = IPA.rule_details_section({
                'name': 'service',
                'label': 'Via Service',
                'text': 'Rule applies when access is requested via:',
                'field_name': 'servicecategory',
                'options': [
                    { 'value': 'all', 'label': 'Any Service' },
                    { 'value': '', 'label': 'Specified Services and Groups' }
                ],
                'tables': [
                    { 'field_name': 'memberservice_hbacsvc' },
                    { 'field_name': 'memberservice_hbacsvcgroup' }
                ]
            });
            that.add_section(section);
        }

        category = section.radio({ 'name': 'servicecategory', 'label': 'Service category' });
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberservice_hbacsvc',
            'name': 'memberservice_hbacsvc', 'label': 'Services', 'category': category,
            'other_entity': 'hbacsvc', 'add_method': 'add_service', 'remove_method': 'remove_service'
        }));
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberservice_hbacsvcgroup',
            'name': 'memberservice_hbacsvcgroup', 'label': 'Service Groups', 'category': category,
            'other_entity': 'hbacsvcgroup', 'add_method': 'add_service', 'remove_method': 'remove_service'
        }));

        if (IPA.layout) {
            section = that.create_section({
                'name': 'sourcehost',
                'label': 'From',
                'template': 'hbacrule-details-sourcehost.html #contents'
            });

        } else {
            section = IPA.rule_details_section({
                'name': 'sourcehost',
                'label': 'From',
                'text': 'Rule applies when access is being initiated from:',
                'field_name': 'sourcehostcategory',
                'options': [
                    { 'value': 'all', 'label': 'Any Host' },
                    { 'value': '', 'label': 'Specified Hosts and Groups' }
                ],
                'tables': [
                    { 'field_name': 'sourcehost_host' },
                    { 'field_name': 'sourcehost_hostgroup' }
                ]
            });
            that.add_section(section);
        }

        category = section.radio({ 'name': 'sourcehostcategory', 'label': 'Source host category' });
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-sourcehost_host',
            'name': 'sourcehost_host', 'label': 'Host', 'category': category,
            'other_entity': 'host', 'add_method': 'add_sourcehost', 'remove_method': 'remove_sourcehost'
        }));
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-sourcehost_hostgroup',
            'name': 'sourcehost_hostgroup', 'label': 'Host Groups', 'category': category,
            'other_entity': 'hostgroup', 'add_method': 'add_sourcehost', 'remove_method': 'remove_sourcehost'
        }));
/*
        if (IPA.layout) {
            section = that.create_section({
                'name': 'accesstime',
                'label': 'When',
                'template': 'hbacrule-details-accesstime.html #contents'
            });

        } else {
            section = that.create_section({
                'name': 'accesstime',
                'label': 'When'
            });
        }

        section.add_field(ipa_hbacrule_accesstime_widget({
            'id': 'accesstime',
            'name': 'accesstime', 'label': 'Access Time',
            'text': 'Rule applies when access is being requested at:',
            'options': [
                { 'value': 'all', 'label': 'Any Time' },
                { 'value': '', 'label': 'Specified Times' }
            ]
        }));
*/
        that.details_facet_init();
    };

    that.update = function() {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var modify_operation = {
            'execute': false,
            'command': IPA.command({
                'method': that.entity_name+'_mod',
                'args': [pkey],
                'options': {'all': true, 'rights': true}
            })
        };

        var remove_accesstime = {
            'template': IPA.command({
                'method': that.entity_name+'_remove_accesstime',
                'args': [pkey],
                'options': {'all': true, 'rights': true}
            }),
            'commands': []
        };

        var categories = {
            'usercategory': {
                'remove_values': false
            },
            'hostcategory': {
                'remove_values': false
            },
            'servicecategory': {
                'remove_values': false
            },
            'sourcehostcategory': {
                'remove_values': false
            }
        };

        var member_operations = {
            'memberuser': {
                'category': 'usercategory',
                'has_values': false,
                'command': IPA.command({
                    'method': that.entity_name+'_remove_user',
                    'args': [pkey],
                    'options': {'all': true, 'rights': true}
                })
            },
            'memberhost': {
                'category': 'hostcategory',
                'has_values': false,
                'command': IPA.command({
                    'method': that.entity_name+'_remove_host',
                    'args': [pkey],
                    'options': {'all': true, 'rights': true}
                })
            },
            'memberservice': {
                'category': 'servicecategory',
                'has_values': false,
                'command': IPA.command({
                    'method': that.entity_name+'_remove_service',
                    'args': [pkey],
                    'options': {'all': true, 'rights': true}
                })
            },
            'sourcehost': {
                'category': 'sourcehostcategory',
                'has_values': false,
                'command': IPA.command({
                    'method': that.entity_name+'_remove_sourcehost',
                    'args': [pkey],
                    'options': {'all': true, 'rights': true}
                })
            }
        };

        var enable_operation = {
            'execute': false,
            'command': IPA.command({
                'method': that.entity_name+'_enable',
                'args': [pkey],
                'options': {'all': true, 'rights': true}
            })
        };

        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections[i];

            for (var j=0; j<section.fields.length; j++) {
                var field = section.fields[j];

                var span = $('span[name='+field.name+']', section.container).first();
                var values = field.save();
                if (!values) continue;

                var param_info = IPA.get_param_info(that.entity_name, field.name);

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

                if (field.name == 'accesstime') {
                    // if accesstime is dirty, it means 'Any Time' is selected,
                    // so existing values have to be removed
                    for (var k=0; k<field.values.length; k++) {
                        var command = IPA.command(remove_accesstime.template);
                        command.set_option(field.name, field.values[k]);
                        remove_accesstime.commands.push(command);
                    }
                    continue;
                }

                if (categories[field.name]) {
                    if (values[0] == 'all') {
                        categories[field.name].remove_values = true;
                    }
                }

                // use setattr/addattr if param_info not available
                if (!param_info) {
                    for (var l=0; l<values.length; l++) {
                        modify_operation.command.set_option(
                            l === 0 ? 'setattr' : 'addattr',
                            field.name+'='+values[l]);
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

        var batch = IPA.batch_command({
            'name': 'hbac_details_update',
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
                batch.add_command(member_operations[member_attribute].command);
            }
        }

        batch.add_commands(remove_accesstime.commands);

        if (modify_operation.execute) batch.add_command(modify_operation.command);
        if (enable_operation.execute) batch.add_command(enable_operation.command);

        if (!batch.commands.length) {
            that.refresh();
            return;
        }

        //alert(JSON.stringify(batch.to_json()));

        batch.execute();
    };

    that.reset = function() {
        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections[i];
            section.reset();
        }
    };

    return that;
};


IPA.hbacrule_details_general_section = function (spec){

    spec = spec || {};

    var that = IPA.details_section(spec);

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

        $('<label/>', {
            name: 'cn',
            style: 'display: none;'
        }).appendTo(span);

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

        td = $('<td/>', {
            'style': 'text-align: right;'
        }).appendTo(tr);

        td.append('Rule type:');

        span = $('<span/>', { 'name': 'accessruletype' }).appendTo(td);

        $('<input/>', {
            'type': 'radio',
            'name': 'accessruletype',
            'value': 'allow'
        }).appendTo(span);

        span.append(' ');

        // TODO: i18n
        span.append('Allow');

        span.append(' ');

        $('<input/>', {
            'type': 'radio',
            'name': 'accessruletype',
            'value': 'deny'
        }).appendTo(span);

        span.append(' ');

        // TODO: i18n
        span.append('Deny');

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

        td = $('<td/>', {
            'colspan': 2
        }).appendTo(tr);

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

        td = $('<td/>', {
            'colspan': 2
        }).appendTo(tr);

        span = $('<span/>', { 'name': 'ipaenabledflag' }).appendTo(td);

        $('<input/>', {
            'type': 'radio',
            'name': 'ipaenabledflag',
            'value': 'TRUE'
        }).appendTo(span);

        span.append(' ');

        // TODO: i18n
        span.append('Active');

        span.append(' ');

        $('<input/>', {
            'type': 'radio',
            'name': 'ipaenabledflag',
            'value': 'FALSE'
        }).appendTo(span);

        span.append(' ');

        // TODO: i18n
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
};

IPA.hbacrule_accesstime_widget = function (spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.text = spec.text;
    that.options = spec.options || [];

    that.init = function() {

        that.widget_init();

        that.table = IPA.table_widget({
            'id': 'accesstime-table',
            'name': 'table', 'label': that.label
        });

        that.table.create_column({
            'name': that.name,
            'label': that.label,
            'primary_key': true
        });

        that.table.init();
    };

    that.create = function(container) {

        that.widget_create(container);

        var span = $('<span/>', { 'name': 'text' }).appendTo(container);

        span.append(that.text);

        for (var i=0; i<that.options.length; i++) {
            var option = that.options[i];

            $('<input/>', {
                'type': 'radio',
                'name': that.name,
                'value': option.value
            }).appendTo(container);

            container.append(' ');

            container.append(option.label);

            container.append(' ');
        }

        $('<span/>', {
            'name': 'undo',
            'class': 'ui-state-highlight ui-corner-all',
            'style': 'display: none;',
            'html': 'undo'
        }).appendTo(container);

        container.append('<br/>');

        span = $('<span/>', { 'name': 'table' }).appendTo(container);

        that.table.create(span);

        var buttons = $('span[name=buttons]', span);

        $('<input/>', {
            'type': 'button',
            'name': 'remove',
            'value': 'Remove '+that.label
        }).appendTo(buttons);

        $('<input/>', {
            'type': 'button',
            'name': 'add',
            'value': 'Add '+that.label
        }).appendTo(buttons);
    };

    that.setup = function(container) {

        that.widget_setup(container);

        var span = $('span[name="table"]', that.container);
        that.table.setup(span);

        var button = $('input[name=remove]', span);
        button.replaceWith(IPA.button({
            'label': button.val(),
            'icon': 'ui-icon-trash',
            'click': function() { that.remove(that.container); }
        }));

        button = $('input[name=add]', span);
        button.replaceWith(IPA.button({
            'label': button.val(),
            'icon': 'ui-icon-plus',
            'click': function() { that.add(that.container); }
        }));

        var input = $('input[name="'+that.name+'"]', that.container);
        input.change(function() {
            that.show_undo();
        });

        var undo = that.get_undo();
        undo.click(function() {
            that.reset();
        });
    };

    that.save = function() {
        var value = $('input[name="'+that.name+'"]:checked', that.container).val();
        if (value === '') {
            return that.table.save();
        } else {
            return [];
        }
    };

    that.load = function(record) {

        that.values = record[that.name] || [];
        that.reset();
    };

    that.update = function() {

        that.set_category(that.container, that.values && that.values.length ? '' : 'all');

        that.table.tbody.empty();
        for (var i=0; that.values && i<that.values.length; i++) {
            var record = {};
            record[that.name] = that.values[i];
            that.table.add_record(record);
        }
    };

    that.set_category = function(container, value) {
        $('input[name="'+that.name+'"][value="'+value+'"]', that.container).get(0).checked = true;
    };

    that.add = function() {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var title = 'Add '+that.label+' to '+that.entity_name+' '+pkey;

        var dialog = IPA.dialog({
            'title': title
        });

        dialog.add_field(IPA.text_widget({
            'name': that.name,
            'label': that.label
        }));

        dialog.create = function() {
            var table = $('<table/>').appendTo(dialog.container);

            var tr = $('<tr/>').appendTo(table);

            var td = $('<td/>', {
                'style': 'vertical-align: top;'
            }).appendTo(tr);
            td.append(that.label+': ');

            td = $('<td/>').appendTo(tr);

            var span = $('<span/>', { 'name': that.name }).appendTo(td);

            $('<input/>', {
                'type': 'text',
                'name': that.name,
                'size': 40
            }).appendTo(span);

            tr = $('<tr/>').appendTo(table);

            td = $('<td/>', {
                'style': 'vertical-align: top;'
            }).appendTo(tr);
            td.append('Example:');

            td = $('<td/>').appendTo(tr);

            td.append('<b>Every day between 0800 and 1400:</b><br/>');
            td.append('periodic daily 0800-1400<br/><br/>');

            td.append('<b>December 16, 2010 from 10:32 until 10:33:</b><br/>');
            td.append('absolute 201012161032 ~ 201012161033<td/>');
        };

        function add(on_success, on_error) {

            var field = dialog.get_field(that.name);
            var value = field.save()[0];

            var command = IPA.command({
                'method': that.entity_name+'_add_'+that.name,
                'args': [pkey],
                'on_success': function() {
                    that.refresh();
                    if (on_success) on_success();
                },
                'on_error': function() {
                    that.refresh();
                    if (on_error) on_error();
                }
            });

            command.set_option(that.name, value);

            command.execute();
        }

        dialog.add_button('Add', function() {
            add(
                function() { dialog.reset(); }
            );
        });

        dialog.add_button('Add and Close', function() {
            add(
                function() { dialog.close(); },
                function() { dialog.close(); }
            );
        });

        dialog.add_button('Cancel', function() {
            dialog.close();
        });

        dialog.init();

        dialog.open(that.container);
    };

    that.remove = function() {

        var values = that.table.get_selected_values();

        if (!values.length) {
            alert('Select '+that.label+' to be removed.');
            return;
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        var title = 'Remove '+that.label+' from '+that.entity_name+' '+pkey;

        var dialog = IPA.deleter_dialog({
            'title': title,
            'values': values
        });

        dialog.execute = function() {

            var batch = IPA.batch_command({
                'on_success': function() {
                    that.refresh();
                    dialog.close();
                },
                'on_error': function() {
                    that.refresh();
                    dialog.close();
                }
            });

            for (var i=0; i<values.length; i++) {
                var command = IPA.command({
                    'method': that.entity_name+'_remove_'+that.name,
                    'args': [pkey]
                });

                command.set_option(that.name, values[i]);

                batch.add_command(command);
            }

            batch.execute();
        };

        dialog.init();

        dialog.open(that.container);
    };

    that.refresh = function() {

        function on_success(data, text_status, xhr) {
            that.load(data.result.result);
        }

        function on_error(xhr, text_status, error_thrown) {
            var summary = $('span[name=summary]', that.table.tfoot).empty();
            summary.append('<p>Error: '+error_thrown.name+'</p>');
            summary.append('<p>'+error_thrown.title+'</p>');
            summary.append('<p>'+error_thrown.message+'</p>');
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        IPA.cmd('show', [pkey], {'rights': true}, on_success, on_error, that.entity_name);
    };

    return that;
};
