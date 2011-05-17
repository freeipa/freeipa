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
    return IPA.entity_builder().
        entity('hbacrule').
        search_facet({
            columns:['cn','usercategory','hostcategory','ipaenabledflag',
                     'servicecategory','sourcehostcategory']
        }).
        details_facet({
            factory: IPA.hbacrule_details_facet
        }).
        adder_dialog({
            fields:[
                'cn',
                {
                    factory: IPA.radio_widget,
                    'name': 'accessruletype',
                    'options': [
                        { 'value': 'allow',
                          'label': IPA.messages.objects.hbacrule.allow
                        },
                        { 'value': 'deny',
                          'label': IPA.messages.objects.hbacrule.deny
                        }],
                    'undo': false
                }]
        }).
        build();
};

IPA.entity_factories.hbacsvc = function () {
    return IPA.entity_builder().
        entity('hbacsvc').
        search_facet({
            columns:['cn','description']}).
        details_facet({sections:[{
            name: 'general',
            label: IPA.messages.details.general,
            fields:[ 'cn', 'description']}]}).
        adder_dialog({
            fields:['cn','description']
        }).
        build();
};


IPA.entity_factories.hbacsvcgroup = function () {
    return IPA.entity_builder().
        entity('hbacsvcgroup').
        search_facet({
            columns:['cn', 'description']}).
        details_facet({sections:[
            {
                name: 'general',
                label: IPA.messages.details.general,
                fields:['cn','description']
            },
            {
                name: 'services',
                label: IPA.messages.objects.hbacsvcgroup.services,
                fields:[{
                    factory: IPA.hbacsvcgroup_member_hbacsvc_table_widget,
                    name: 'member_hbacsvc',
                    label: IPA.messages.objects.hbacsvcgroup.services,
                    other_entity: 'hbacsvc',
                    save_values: false
                }]
            }]}).
        adder_dialog({
            fields:['cn', 'description']
        }).
        build();
};

IPA.hbacsvcgroup_member_hbacsvc_table_widget = function (spec) {

    spec = spec || {};

    var that = IPA.association_table_widget(spec);

    that.init = function() {

        var column = that.create_column({
            name: 'cn',
            primary_key: true,
            width: '150px'
        });

        column.setup = function(container, record) {
            container.empty();

            var value = record[column.name];
            value = value ? value.toString() : '';

            $('<a/>', {
                'href': '#'+value,
                'html': value,
                'click': function (value) {
                    return function() {
                        IPA.nav.show_page(that.other_entity, 'details', value);
                        return false;
                    };
                }(value)
            }).appendTo(container);
        };

        that.create_column({
            name: 'description',
            width: '350px'
        });

        that.create_adder_column({
            name: 'cn',
            primary_key: true,
            width: '100px'
        });

        that.create_adder_column({
            name: 'description',
            width: '100px'
        });

        that.association_table_widget_init();
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
                'label': IPA.messages.details.general,
                'template': 'hbacrule-details-general.html #contents'
            });

        } else {
            section = IPA.hbacrule_details_general_section({
                'name': 'general',
                'label': IPA.messages.details.general
            });
            that.add_section(section);
        }

        section.text({name: 'cn', read_only: true});
        section.radio({name: 'accessruletype'});
        section.textarea({name: 'description'});
        section.radio({name: 'ipaenabledflag'});

        var param_info = IPA.get_entity_param('hbacrule', 'usercategory');

        if (IPA.layout) {
            section = that.create_section({
                'name': 'user',
                'label': IPA.messages.objects.hbacrule.user,
                'template': 'hbacrule-details-user.html #contents'
            });

        } else {
            section = IPA.rule_details_section({
                'name': 'user',
                'label': IPA.messages.objects.hbacrule.user,
                'text': param_info.doc+':',
                'field_name': 'usercategory',
                'options': [
                    { 'value': 'all', 'label': IPA.messages.objects.hbacrule.anyone },
                    { 'value': '', 'label': IPA.messages.objects.hbacrule.specified_users }
                ],
                'tables': [
                    { 'field_name': 'memberuser_user' },
                    { 'field_name': 'memberuser_group' }
                ]
            });
            that.add_section(section);
        }

        var category = section.radio({ name: 'usercategory' });
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberuser_user',
            'name': 'memberuser_user', 'category': category,
            'other_entity': 'user', 'add_method': 'add_user', 'remove_method': 'remove_user'
        }));
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberuser_group',
            'name': 'memberuser_group', 'category': category,
            'other_entity': 'group', 'add_method': 'add_user', 'remove_method': 'remove_user'
        }));

        param_info = IPA.get_entity_param('hbacrule', 'hostcategory');

        if (IPA.layout) {
            section = that.create_section({
                'name': 'host',
                'label': IPA.messages.objects.hbacrule.host,
                'template': 'hbacrule-details-host.html #contents'
            });

        } else {
            section = IPA.rule_details_section({
                'name': 'host',
                'label': IPA.messages.objects.hbacrule.host,
                'text': param_info.doc+':',
                'field_name': 'hostcategory',
                'options': [
                    { 'value': 'all', 'label': IPA.messages.objects.hbacrule.any_host },
                    { 'value': '', 'label': IPA.messages.objects.hbacrule.specified_hosts }
                ],
                'tables': [
                    { 'field_name': 'memberhost_host' },
                    { 'field_name': 'memberhost_hostgroup' }
                ]
            });
            that.add_section(section);
        }

        category = section.radio({ 'name': 'hostcategory' });
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberhost_host',
            'name': 'memberhost_host', 'category': category,
            'other_entity': 'host', 'add_method': 'add_host', 'remove_method': 'remove_host'
        }));
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberhost_hostgroup',
            'name': 'memberhost_hostgroup', 'category': category,
            'other_entity': 'hostgroup', 'add_method': 'add_host', 'remove_method': 'remove_host'
        }));

        param_info = IPA.get_entity_param('hbacrule', 'servicecategory');

        if (IPA.layout) {
            section = that.create_section({
                'name': 'service',
                'label': IPA.messages.objects.hbacrule.service,
                'template': 'hbacrule-details-service.html #contents'
            });

        } else {
            section = IPA.rule_details_section({
                'name': 'service',
                'label': IPA.messages.objects.hbacrule.service,
                'text': param_info.doc+':',
                'field_name': 'servicecategory',
                'options': [
                    { 'value': 'all', 'label': IPA.messages.objects.hbacrule.any_service },
                    { 'value': '', 'label': IPA.messages.objects.hbacrule.specified_services }
                ],
                'tables': [
                    { 'field_name': 'memberservice_hbacsvc' },
                    { 'field_name': 'memberservice_hbacsvcgroup' }
                ]
            });
            that.add_section(section);
        }

        category = section.radio({ 'name': 'servicecategory' });
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberservice_hbacsvc',
            'name': 'memberservice_hbacsvc', 'category': category,
            'other_entity': 'hbacsvc', 'add_method': 'add_service', 'remove_method': 'remove_service'
        }));
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-memberservice_hbacsvcgroup',
            'name': 'memberservice_hbacsvcgroup', 'category': category,
            'other_entity': 'hbacsvcgroup', 'add_method': 'add_service', 'remove_method': 'remove_service'
        }));

        param_info = IPA.get_entity_param('hbacrule', 'sourcehostcategory');

        if (IPA.layout) {
            section = that.create_section({
                'name': 'sourcehost',
                'label': IPA.messages.objects.hbacrule.sourcehost,
                'template': 'hbacrule-details-sourcehost.html #contents'
            });

        } else {
            section = IPA.rule_details_section({
                'name': 'sourcehost',
                'label': IPA.messages.objects.hbacrule.sourcehost,
                'text': param_info.doc+':',
                'field_name': 'sourcehostcategory',
                'options': [
                    { 'value': 'all', 'label': IPA.messages.objects.hbacrule.any_host },
                    { 'value': '', 'label': IPA.messages.objects.hbacrule.specified_hosts }
                ],
                'tables': [
                    { 'field_name': 'sourcehost_host' },
                    { 'field_name': 'sourcehost_hostgroup' }
                ]
            });
            that.add_section(section);
        }

        category = section.radio({ 'name': 'sourcehostcategory' });
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-sourcehost_host',
            'name': 'sourcehost_host', 'category': category,
            'other_entity': 'host', 'add_method': 'add_sourcehost', 'remove_method': 'remove_sourcehost'
        }));
        section.add_field(IPA.rule_association_table_widget({
            'id': that.entity_name+'-sourcehost_hostgroup',
            'name': 'sourcehost_hostgroup', 'category': category,
            'other_entity': 'hostgroup', 'add_method': 'add_sourcehost', 'remove_method': 'remove_sourcehost'
        }));
        that.details_facet_init();
    };

    that.update = function() {

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        var modify_operation = {
            'execute': false,
            'command': IPA.command({
                entity: that.entity_name,
                method: 'mod',
                args: [pkey],
                options: {all: true, rights: true}
            })
        };

        var remove_accesstime = {
            'template': IPA.command({
                entity: that.entity_name,
                method: 'remove_accesstime',
                args: [pkey],
                options: {all: true, rights: true}
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
                    entity: that.entity_name,
                    method: 'remove_user',
                    args: [pkey],
                    options: {all: true, rights: true}
                })
            },
            'memberhost': {
                'category': 'hostcategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity_name,
                    method: 'remove_host',
                    args: [pkey],
                    options: {all: true, rights: true}
                })
            },
            'memberservice': {
                'category': 'servicecategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity_name,
                    method: 'remove_service',
                    args: [pkey],
                    options: {all: true, rights: true}
                })
            },
            'sourcehost': {
                'category': 'sourcehostcategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity_name,
                    method: 'remove_sourcehost',
                    args: [pkey],
                    options: {all: true, rights: true}
                })
            }
        };

        var enable_operation = {
            'execute': false,
            'command': IPA.command({
                entity: that.entity_name,
                method: 'enable',
                args: [pkey],
                options: {all: true, rights: true}
            })
        };

        for (var i=0; i<that.sections.length; i++) {
            var section = that.sections[i];

            var section_fields = section.fields.values;
            for (var j=0; j<section_fields.length; j++) {
                var field = section_fields[j];

                var span = $('span[name='+field.name+']', section.container).first();
                var values = field.save();
                if (!values) continue;

                var param_info = IPA.get_entity_param(that.entity_name, field.name);

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
            'style': 'width: 100px; text-align: right;'
        }).appendTo(tr);

        var param_info = IPA.get_entity_param('hbacrule', 'cn');
        td.append(param_info.label+':');

        td = $('<td/>').appendTo(tr);

        var field = that.get_field('cn');
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

        field.create_undo(span);

        td = $('<td/>', {
            'style': 'text-align: right;'
        }).appendTo(tr);

        param_info = IPA.get_entity_param('hbacrule', 'accessruletype');
        td.append(param_info.label+':');

        field = that.get_field('accessruletype');
        span = $('<span/>', { 'name': 'accessruletype' }).appendTo(td);

        $('<input/>', {
            'type': 'radio',
            'name': 'accessruletype',
            'value': 'allow'
        }).appendTo(span);

        span.append(' ');

        span.append(IPA.messages.objects.hbacrule.allow);

        span.append(' ');

        $('<input/>', {
            'type': 'radio',
            'name': 'accessruletype',
            'value': 'deny'
        }).appendTo(span);

        span.append(' ');

        span.append(IPA.messages.objects.hbacrule.deny);

        span.append(' ');

        field.create_undo(span);

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>', {
            'style': 'text-align: right; vertical-align: top;'
        }).appendTo(tr);

        param_info = IPA.get_entity_param('hbacrule', 'description');
        td.append(param_info.label+':');

        td = $('<td/>', {
            'colspan': 2
        }).appendTo(tr);

        field = that.get_field('description');
        span = $('<span/>', { 'name': 'description' }).appendTo(td);

        $('<textarea/>', {
            'name': 'description',
            'rows': 5,
            'style': 'width: 100%'
        }).appendTo(span);

        span.append(' ');

        field.create_undo(span);

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>', {
            'style': 'text-align: right; vertical-align: top;'
        }).appendTo(tr);

        td.append(IPA.messages.objects.hbacrule.ipaenabledflag+':');

        td = $('<td/>', {
            'colspan': 2
        }).appendTo(tr);

        field = that.get_field('ipaenabledflag');
        span = $('<span/>', { 'name': 'ipaenabledflag' }).appendTo(td);

        $('<input/>', {
            'type': 'radio',
            'name': 'ipaenabledflag',
            'value': 'TRUE'
        }).appendTo(span);

        span.append(' ');

        span.append(IPA.messages.objects.hbacrule.active);

        span.append(' ');

        $('<input/>', {
            'type': 'radio',
            'name': 'ipaenabledflag',
            'value': 'FALSE'
        }).appendTo(span);

        span.append(' ');

        span.append(IPA.messages.objects.hbacrule.inactive);

        span.append(' ');

        field.create_undo(span);
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

        that.create_undo(container);

        container.append('<br/>');

        span = $('<span/>', { 'name': 'table' }).appendTo(container);

        that.table.create(span);

        var buttons = $('span[name=buttons]', span);

        $('<input/>', {
            'type': 'button',
            'name': 'remove',
            'value': IPA.messages.buttons.remove
        }).appendTo(buttons);

        $('<input/>', {
            'type': 'button',
            'name': 'add',
            'value': IPA.messages.buttons.add
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
        var title = IPA.messages.association.add;
        title = title.replace('${entity}', IPA.metadata.objects[that.entity_name].label);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', that.label);

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
                entity: that.entity_name,
                method: 'add_'+that.name,
                args: [pkey],
                on_success: function() {
                    that.refresh();
                    if (on_success) on_success();
                },
                on_error: function() {
                    that.refresh();
                    if (on_error) on_error();
                }
            });

            command.set_option(that.name, value);

            command.execute();
        }

        dialog.add_button(IPA.messages.buttons.add, function() {
            add(
                function() { dialog.reset(); }
            );
        });

        dialog.add_button(IPA.messages.buttons.add_and_close, function() {
            add(
                function() { dialog.close(); },
                function() { dialog.close(); }
            );
        });

        dialog.add_button(IPA.messages.buttons.cancel, function() {
            dialog.close();
        });

        dialog.init();

        dialog.open(that.container);
    };

    that.remove = function() {

        var values = that.table.get_selected_values();

        var title;
        if (!values.length) {
            title = IPA.messages.dialogs.remove_empty;
            title = title.replace('${entity}', that.label);
            alert(title);
            return;
        }

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';
        title = IPA.messages.association.remove;
        title = title.replace('${entity}', IPA.metadata.objects[that.entity_name].label);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', that.label);

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
                    entity: that.entity_name,
                    method: 'remove_'+that.name,
                    args: [pkey]
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
        IPA.command({
            entity: that.entity_name,
            method: 'show',
            args: [pkey],
            options: {'rights': true},
            on_success: on_success,
            on_error: on_error
        }).execute();
    };

    return that;
};
