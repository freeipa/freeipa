/*jsl:import ipa.js */

/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *    Adam Young <ayoung@redhat.com>
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

IPA.entity_factories.hbacrule = function() {
    return IPA.entity_builder().
        entity('hbacrule').
        search_facet({
            search_all: true,
            columns: [
                'cn',
                'ipaenabledflag',
                'description'
            ]
        }).
        details_facet({
            factory: IPA.hbacrule_details_facet
        }).
        adder_dialog({
            fields: [ 'cn' ]
        }).
        build();
};

IPA.entity_factories.hbacsvc = function() {
    return IPA.entity_builder().
        entity('hbacsvc').
        search_facet({
            columns: [
                'cn',
                'description'
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'general',
                    label: IPA.messages.details.general,
                    fields: [
                        'cn',
                        {
                            factory: IPA.textarea_widget,
                            name: 'description'
                        }
                    ]
                }
            ]
        }).
        association_facet({
            name: 'memberof_hbacsvcgroup',
            associator: IPA.serial_associator,
            columns:[
                {
                    name: 'cn',
                    primary_key: true,
                    link: true
                },
                { name: 'description' }
            ],
            adder_columns: [
                {
                    name: 'cn',
                    primary_key: true,
                    width: '100px'
                },
                {
                    name: 'description',
                    width: '100px'
                }
            ]
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
        }).
        build();
};


IPA.entity_factories.hbacsvcgroup = function() {
    return IPA.entity_builder().
        entity('hbacsvcgroup').
        search_facet({
            columns: [
                'cn',
                'description'
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'general',
                    label: IPA.messages.details.general,
                    fields: [
                        'cn',
                        {
                            factory: IPA.textarea_widget,
                            name: 'description'
                        }
                    ]
                }
            ]
        }).
        association_facet({
            name: 'member_hbacsvc',
            columns:[
                {
                    name: 'cn',
                    primary_key: true,
                    link: true
                },
                { name: 'description' }
            ],
            adder_columns: [
                {
                    name: 'cn',
                    primary_key: true,
                    width: '100px'
                },
                {
                    name: 'description',
                    width: '100px'
                }
            ]
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
        }).
        build();
};

IPA.hbacrule_details_facet = function(spec) {

    spec = spec || {};

    var that = IPA.details_facet(spec);

    function general_section(){
        var section = IPA.details_table_section({
            name: 'general',
            entity: that.entity,
            label: IPA.messages.details.general
        });

        section.text({
            name: 'cn'
        });
        section.textarea({
            name: 'description'
        });
        section.radio({
            name: 'ipaenabledflag',
            options: [
                { value: 'TRUE', label: IPA.get_message('true') },
                { value: 'FALSE', label: IPA.get_message('false') }
            ]
        });
        return section;
    }


    function user_category_section(){
        var section = IPA.rule_details_section({
            name: 'user',
            entity: that.entity,
            label: IPA.messages.objects.hbacrule.user,
            field_name: 'usercategory',
            options: [
                { value: 'all', label: IPA.messages.objects.hbacrule.anyone },
                { value: '',
                  label: IPA.messages.objects.hbacrule.specified_users }
            ],
            tables: [
                { field_name: 'memberuser_user' },
                { field_name: 'memberuser_group' }
            ]
        });

        section.add_field(IPA.radio_widget({
            name: 'usercategory'
        }));
        section.add_field(IPA.association_table_widget({
            id: that.entity.name+'-memberuser_user',
            name: 'memberuser_user',
            entity: that.entity,
            add_method: 'add_user',
            remove_method: 'remove_user',
            add_title: IPA.messages.association.add.member,
            remove_title: IPA.messages.association.remove.member
        }));
        section.add_field(IPA.association_table_widget({
            id: that.entity.name+'-memberuser_group',
            name: 'memberuser_group',
            entity: that.entity,
            add_method: 'add_user',
            remove_method: 'remove_user',
            add_title: IPA.messages.association.add.member,
            remove_title: IPA.messages.association.remove.member
        }));
        return section;
    }

    function hostcategory_section(){
        var section = IPA.rule_details_section({
            name: 'host',
            label: IPA.messages.objects.hbacrule.host,
            entity: that.entity,
            field_name: 'hostcategory',
            options: [
                { value: 'all', label: IPA.messages.objects.hbacrule.any_host },
                { value: '',
                  label: IPA.messages.objects.hbacrule.specified_hosts }
            ],
            tables: [
                { field_name: 'memberhost_host' },
                { field_name: 'memberhost_hostgroup' }
        ]
        });

        section.add_field(IPA.radio_widget({
            name: 'hostcategory'
        }));
        section.add_field(IPA.association_table_widget({
            id: that.entity.name+'-memberhost_host',
            name: 'memberhost_host',
            entity: that.entity,
            add_method: 'add_host',
            remove_method: 'remove_host',
            add_title: IPA.messages.association.add.member,
            remove_title: IPA.messages.association.remove.member
        }));
        section.add_field(IPA.association_table_widget({
            id: that.entity.name+'-memberhost_hostgroup',
            name: 'memberhost_hostgroup',
            entity: that.entity,
            add_method: 'add_host',
            remove_method: 'remove_host',
            add_title: IPA.messages.association.add.member,
            remove_title: IPA.messages.association.remove.member
        }));
        return section;
    }

    function servicecategory_section(){
        var section = IPA.rule_details_section({
            name: 'service',
            entity: that.entity,
            label: IPA.messages.objects.hbacrule.service,
            field_name: 'servicecategory',
            options: [
                { value: 'all',
                  label: IPA.messages.objects.hbacrule.any_service },
                { value: '',
                  label: IPA.messages.objects.hbacrule.specified_services }
            ],
            tables: [
                { field_name: 'memberservice_hbacsvc' },
                { field_name: 'memberservice_hbacsvcgroup' }
            ]
        });

        section.add_field(IPA.radio_widget({
            name: 'servicecategory'
        }));
        section.add_field(IPA.association_table_widget({
            id: that.entity.name+'-memberservice_hbacsvc',
            name: 'memberservice_hbacsvc',
            entity: that.entity,
            add_method: 'add_service',
            remove_method: 'remove_service',
            add_title: IPA.messages.association.add.member,
            remove_title: IPA.messages.association.remove.member
        }));
        section.add_field(IPA.association_table_widget({
            id: that.entity.name+'-memberservice_hbacsvcgroup',
            name: 'memberservice_hbacsvcgroup',
            entity: that.entity,
            add_method: 'add_service',
            remove_method: 'remove_service',
            add_title: IPA.messages.association.add.member,
            remove_title: IPA.messages.association.remove.member
        }));
        return section;
    }

    function sourcehostcategory_section(){
        var section = IPA.rule_details_section({
            name: 'sourcehost',
            entity: that.entity,
            label: IPA.messages.objects.hbacrule.sourcehost,
            field_name: 'sourcehostcategory',
            options: [
                { value: 'all', label: IPA.messages.objects.hbacrule.any_host },
                { value: '',
                  label: IPA.messages.objects.hbacrule.specified_hosts }
            ],
            tables: [
                { field_name: 'sourcehost_host' },
                { field_name: 'sourcehost_hostgroup' }
            ]
        });

        section.add_field(IPA.radio_widget({
            name: 'sourcehostcategory'
        }));
        section.add_field(IPA.association_table_widget({
            id: that.entity.name+'-sourcehost_host',
            name: 'sourcehost_host',
            entity: that.entity,
            add_method: 'add_sourcehost',
            remove_method: 'remove_sourcehost',
            add_title: IPA.messages.association.add.sourcehost,
            remove_title: IPA.messages.association.remove.sourcehost
        }));
        section.add_field(IPA.association_table_widget({
            id: that.entity.name+'-sourcehost_hostgroup',
            name: 'sourcehost_hostgroup',
            entity: that.entity,
            add_method: 'add_sourcehost',
            remove_method: 'remove_sourcehost',
            add_title: IPA.messages.association.add.sourcehost,
            remove_title: IPA.messages.association.remove.sourcehost
        }));
        return section;
    }

    that.update = function(on_success, on_error) {

        var args = that.get_primary_key();

        var modify_operation = {
            'execute': false,
            'command': IPA.command({
                entity: that.entity.name,
                method: 'mod',
                args: args,
                options: {all: true, rights: true}
            })
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
                    entity: that.entity.name,
                    method: 'remove_user',
                    args: args,
                    options: {all: true, rights: true}
                })
            },
            'memberhost': {
                'category': 'hostcategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity.name,
                    method: 'remove_host',
                    args: args,
                    options: {all: true, rights: true}
                })
            },
            'memberservice': {
                'category': 'servicecategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity.name,
                    method: 'remove_service',
                    args: args,
                    options: {all: true, rights: true}
                })
            },
            'sourcehost': {
                'category': 'sourcehostcategory',
                'has_values': false,
                'command': IPA.command({
                    entity: that.entity.name,
                    method: 'remove_sourcehost',
                    args: args,
                    options: {all: true, rights: true}
                })
            }
        };

        var enable_operation = {
            'execute': false,
            'command': IPA.command({
                entity: that.entity.name,
                method: 'enable',
                args: args,
                options: {all: true, rights: true}
            })
        };

        var sections = that.sections.values;
        for (var i=0; i<sections.length; i++) {
            var section = sections[i];

            var section_fields = section.fields.values;
            for (var j=0; j<section_fields.length; j++) {
                var field = section_fields[j];

                // association tables are never dirty, so call
                // is_dirty() after checking table values

                var values = field.save();
                if (!values) continue;

                var metadata = field.metadata;

                // skip primary key
                if (metadata && metadata.primary_key) continue;

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
                if (!field.is_dirty()) continue;

                // check enable/disable
                if (field.name == 'ipaenabledflag') {
                    if (values[0] == 'FALSE') enable_operation.command.method = 'disable';
                    enable_operation.execute = true;
                    continue;
                }

                if (categories[field.name]) {
                    if (values[0] == 'all') {
                        categories[field.name].remove_values = true;
                    }
                }

                if (metadata) {
                    if (values.length == 1) {
                        modify_operation.command.set_option(field.name, values[0]);
                    } else if (field.join) {
                        modify_operation.command.set_option(field.name, values.join(','));
                    } else {
                        modify_operation.command.set_option(field.name, values);
                    }

                } else {
                    if (values.length) {
                        modify_operation.command.set_option('setattr', field.name+'='+values[0]);
                    } else {
                        modify_operation.command.set_option('setattr', field.name+'=');
                    }
                    for (var l=1; l<values.length; l++) {
                        modify_operation.command.set_option('addattr', field.name+'='+values[l]);
                    }
                }

                modify_operation.execute = true;
            }
        }

        var batch = IPA.batch_command({
            'name': 'hbac_details_update',
            'on_success': function(data, text_status, xhr) {
                that.refresh();
                if (on_success) on_success.call(this, data, text_status, xhr);
            },
            'on_error': function(xhr, text_status, error_thrown) {
                that.refresh();
                if (on_error) on_error.call(this, xhr, text_status, error_thrown);
            }
        });

        for (var member_attribute in member_operations) {
            var member_operation = member_operations[member_attribute];
            if (member_operation.has_values &&
                categories[member_operation.category].remove_values) {
                batch.add_command(member_operations[member_attribute].command);
            }
        }


        if (modify_operation.execute) batch.add_command(modify_operation.command);
        if (enable_operation.execute) batch.add_command(enable_operation.command);

        if (!batch.commands.length) {
            that.refresh();
            return;
        }

        batch.execute();
    };

    /*initialization*/
    that.add_section(general_section());
    that.add_section(user_category_section());
    that.add_section(hostcategory_section());
    that.add_section(servicecategory_section());
    that.add_section(sourcehostcategory_section());


    return that;
};
