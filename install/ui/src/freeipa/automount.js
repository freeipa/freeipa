/*jsl:import ipa.js */
/*jsl:import search.js */

/*  Authors:
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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.automount = {};

IPA.automount.location_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.facet_groups([ 'automountmap', 'settings' ]).
        search_facet({
            title: IPA.metadata.objects.automountlocation.label,
            columns:['cn']
        }).
        nested_search_facet({
            facet_group: 'automountmap',
            nested_entity: 'automountmap',
            label: IPA.metadata.objects.automountmap.label,
            tab_label: IPA.metadata.objects.automountmap.label,
            name: 'maps',
            columns: [ 'automountmapname' ]
        }).
        details_facet({
            sections:[
                {
                    name: 'identity',
                    label: IPA.messages.details.identity,
                    fields: [ 'cn' ]
                }
            ]
        }).
        adder_dialog({
            fields: [ 'cn' ]
        });
    };

    return that;
};

IPA.automount.map_entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.containing_entity('automountlocation').
        facet_groups([ 'automountkey', 'settings' ]).
        nested_search_facet({
            factory: IPA.automount.key_search_facet,
            facet_group: 'automountkey',
            nested_entity: 'automountkey',
            search_all_entries: true,
            label: IPA.metadata.objects.automountkey.label,
            tab_label: IPA.metadata.objects.automountkey.label,
            name: 'keys',
            columns: [
                {
                    factory: IPA.automount_key_column,
                    name: 'automountkey',
                    label: IPA.get_entity_param('automountkey', 'automountkey').label
                },
                'automountinformation'
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'identity',
                    label: IPA.messages.details.identity,
                    fields: [
                        'automountmapname',
                        {
                            type: 'textarea',
                            name: 'description'
                        }
                    ]
                }
            ]
        }).
        adder_dialog({
            factory: IPA.automountmap_adder_dialog,
            sections: [
                {
                    name: 'general',
                    fields: [
                        {
                            type: 'radio',
                            name: 'method',
                            enabled: false, //don't use value in add command
                            label: IPA.messages.objects.automountmap.map_type,
                            options: [
                                {
                                    value: 'add',
                                    label: IPA.messages.objects.automountmap.direct
                                },
                                {
                                    value: 'add_indirect',
                                    label: IPA.messages.objects.automountmap.indirect
                                }
                            ]
                        },
                        'automountmapname',
                        {
                            type: 'textarea',
                            name: 'description'
                        }
                    ]
                },
                {
                    name: 'indirect',
                    fields: [
                        {
                            name: 'key',
                            label: IPA.get_command_option(
                                'automountmap_add_indirect', 'key').label
                        },
                        {
                            name: 'parentmap',
                            label: IPA.get_command_option(
                                'automountmap_add_indirect', 'parentmap').label
                        }
                    ]
                }
            ]
        });
    };

    return that;
};

IPA.automount.key_entity = function(spec) {

    spec = spec || {};

    spec.policies = spec.policies || [
        IPA.facet_update_policy({
            source_facet: 'details',
            dest_entity: 'automountmap',
            dest_facet: 'keys'
        })
    ];

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        that.builder.containing_entity('automountmap').
        details_facet({
            factory: IPA.automount.key_details_facet,
            sections: [
                {
                    name:'identity',
                    label: IPA.messages.details.identity,
                    fields: [
                        {
                            name: 'automountkey',
                            read_only: true
                        },
                        'automountinformation'
                    ]
                }
            ],
            disable_breadcrumb: false
        }).
        adder_dialog({
            show_edit_page : function(entity, result){
                var key = result.automountkey[0];
                var info = result.automountinformation[0];
                var state = IPA.nav.get_path_state(entity.name);
                state[entity.name + '-facet'] = 'default';
                state[entity.name + '-info'] = info;
                state[entity.name + '-pkey'] = key;
                IPA.nav.push_state(state);
                return false;
            },
            fields:['automountkey','automountinformation']
        });
    };

    return that;
};

IPA.automount.key_details_facet = function(spec) {

    var that = IPA.details_facet(spec);

    that.create_update_command = function() {

        var command = that.details_facet_create_update_command();

        command.args.pop();

        var key = IPA.nav.get_state(that.entity.name + '-pkey');
        var info = IPA.nav.get_state(that.entity.name + '-info');

        command.options.newautomountinformation = command.options.automountinformation;
        command.options.automountkey = key;
        command.options.automountinformation = info;

        return command;
    };

    that.create_refresh_command = function() {

        var command = that.details_facet_create_refresh_command();

        command.args.pop();

        var key = IPA.nav.get_state(that.entity.name + '-pkey');
        var info = IPA.nav.get_state(that.entity.name + '-info');

        command.options.automountkey = key;
        command.options.automountinformation = info;

        return command;
    };

    return that;
};

IPA.automount_key_column = function(spec) {

    var that = IPA.column(spec);

    that.setup = function(container, record) {

        container.empty();

        var key = record.automountkey;
        if (key instanceof Array) key = key[0];
        var info = record.automountinformation;
        if (info instanceof Array) info = info[0];

        $('<a/>', {
            href: '#'+key,
            text: key,
            click: function() {
                var state = IPA.nav.get_path_state(that.entity.name);
                state[that.entity.name + '-facet'] = 'default';
                state[that.entity.name + '-info'] = info;
                state[that.entity.name + '-pkey'] = key;
                IPA.nav.push_state(state);
                return false;
            }
        }).appendTo(container);

    };

    return that;
};

IPA.automountmap_adder_dialog = function(spec) {

    var that = IPA.entity_adder_dialog(spec);

    that.create = function() {
        that.entity_adder_dialog_create();

        var method_widget = that.widgets.get_widget('general.method');
        var indirect_section = that.widgets.get_widget('indirect');
        var key_field = that.fields.get_field('key');
        var parentmap_field = that.fields.get_field('parentmap');

        var direct_input = $('input[value="add"]', method_widget.container);
        direct_input.change(function() {
            that.method = 'add';

            key_field.set_enabled(false);
            parentmap_field.set_enabled(false);

            key_field.set_required(false);
            indirect_section.set_visible(false);
        });

        var indirect_input = $('input[value="add_indirect"]', method_widget.container);
        indirect_input.change(function() {
            that.method = 'add_indirect';

            key_field.set_enabled(true);
            parentmap_field.set_enabled(true);

            key_field.set_required(true);
            indirect_section.set_visible(true);
        });

        direct_input.click();
    };

    that.reset = function() {
        that.dialog_reset();

        var method_widget = that.widgets.get_widget('general.method');

        var direct_input = $('input[value="add"]', method_widget.container);
        direct_input.click();
    };

    return that;
};

IPA.automount.key_search_facet = function(spec) {

    var that = IPA.nested_search_facet(spec);

    that.get_selected_values = function() {

        var values = [];

        $('input[name="description"]:checked', that.table.tbody).each(function() {
            var value = {};
            $('div', $(this).parent().parent()).each(function() {
                var div = $(this);
                var name = div.attr('name');
                value[name] = div.text();
            });
            values.push(value);
        });

        return values;
    };

    return that;
};

IPA.register('automountlocation', IPA.automount.location_entity);
IPA.register('automountmap', IPA.automount.map_entity);
IPA.register('automountkey', IPA.automount.key_entity);
