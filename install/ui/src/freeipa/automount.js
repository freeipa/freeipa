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

define([
        './ipa',
        './jquery',
        './navigation',
        './phases',
        './reg',
        './details',
        './search',
        './association',
        './entity'],
            function(IPA, $, navigation, phases, reg) {

var exp = IPA.automount = {};

var make_location_spec = function() {
return {
    name: 'automountlocation',
    facet_groups: [ 'automountmap', 'settings' ],
    facets: [
        {
            $type: 'search',
            title: '@mo:automountlocation.label',
            columns:['cn']
        },
        {
            $type: 'nested_search',
            facet_group: 'automountmap',
            nested_entity: 'automountmap',
            label: '@mo:automountmap.label',
            tab_label: '@mo:automountmap.label',
            name: 'maps',
            columns: [ 'automountmapname' ]
        },
        {
            $type: 'details',
            sections:[
                {
                    name: 'identity',
                    label: '@i18n:details.identity',
                    fields: [ 'cn' ]
                }
            ]
        }
    ],
    adder_dialog: {
        fields: [ 'cn' ]
    },
    deleter_dialog: {
        title: '@i18n:objects.automountlocation.remove'
    }
};};

var make_map_spec = function() {
return {
    name: 'automountmap',
    containing_entity: 'automountlocation',
    facet_groups: [ 'automountkey', 'settings' ],
    facets: [
        {
            $type: 'nested_search',
            $factory: IPA.automount.key_search_facet,
            facet_group: 'automountkey',
            nested_entity: 'automountkey',
            search_all_entries: true,
            label: '@mo:automountkey.label',
            tab_label: '@mo:automountkey.label',
            name: 'keys',
            columns: [
                {
                    $factory: IPA.automount_key_column,
                    name: 'automountkey',
                    label: '@mo-param:automountkey:automountkey:label'
                },
                'automountinformation'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'identity',
                    label: '@i18n:details.identity',
                    fields: [
                        'automountmapname',
                        {
                            $type: 'textarea',
                            name: 'description'
                        }
                    ]
                }
            ]
        }
    ],
    adder_dialog: {
        $factory: IPA.automountmap_adder_dialog,
        sections: [
            {
                name: 'general',
                fields: [
                    {
                        $type: 'radio',
                        name: 'method',
                        flags: ['no_command'],
                        label: '@i18n:objects.automountmap.map_type',
                        options: [
                            {
                                value: 'add',
                                label: '@i18n:objects.automountmap.direct'
                            },
                            {
                                value: 'add_indirect',
                                label: '@i18n:objects.automountmap.indirect'
                            }
                        ]
                    },
                    'automountmapname',
                    {
                        $type: 'textarea',
                        name: 'description'
                    }
                ]
            },
            {
                name: 'indirect',
                fields: [
                    {
                        name: 'key',
                        label: '@mc-opt:automountmap_add_indirect:key:label'
                    },
                    {
                        name: 'parentmap',
                        label: '@mc-opt:automountmap_add_indirect:parentmap:label'
                    }
                ]
            }
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.automountmap.remove'
    }
};};

var make_key_spec = function() {
return {
    name: 'automountkey',
    policies:[
        {
            $factory: IPA.facet_update_policy,
            source_facet: 'details',
            dest_entity: 'automountmap',
            dest_facet: 'keys'
        }
    ],
    containing_entity: 'automountmap',
    facets: [
        {
            $type: 'details',
            $factory: IPA.automount.key_details_facet,
            sections: [
                {
                    name:'identity',
                    label: '@i18n:details.identity',
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
        }
    ],
    adder_dialog: {
        show_edit_page : function(entity, result){
            var key = result.automountkey[0];
            var info = result.automountinformation[0];
            var pkeys = this.pkey_prefix.slice(0);
            pkeys.push(key);

            var args = {
                info: info,
                key: key
            };

            navigation.show_entity(entity.name, 'details', pkeys, args);
            return false;
        },
        fields:['automountkey','automountinformation']
    },
    deleter_dialog: {
        title: '@i18n:objects.automountkey.remove'
    }
};};

IPA.automount.key_details_facet = function(spec) {

    var that = IPA.details_facet(spec);

    that.create_update_command = function() {

        var command = that.details_facet_create_update_command();

        command.args.pop();

        var key = that.state.key;
        var info = that.state.info;

        command.options.newautomountinformation = command.options.automountinformation;
        command.options.automountkey = key;
        command.options.automountinformation = info;

        return command;
    };

    that.create_refresh_command = function() {

        var command = that.details_facet_create_refresh_command();

        command.args.pop();

        var key = that.state.key;
        var info = that.state.info;

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

                var pkeys = that.facet.get_pkeys();
                pkeys.push(key);

                var args = {
                    info: info,
                    key: key
                };

                navigation.show_entity(that.entity.name, 'details', pkeys, args);
                return false;
            }
        }).appendTo(container);

    };

    return that;
};

IPA.automountmap_adder_dialog = function(spec) {

    var that = IPA.entity_adder_dialog(spec);

    that.create_content = function() {
        that.entity_adder_dialog_create_content();

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

        direct_input.prop('checked', true);
        direct_input.trigger('change');
    };

    that.reset = function() {
        that.dialog_reset();

        var method_widget = that.widgets.get_widget('general.method');

        var direct_input = $('input[value="add"]', method_widget.container);
        direct_input.prop('checked', true);
        direct_input.trigger('change');
    };

    return that;
};

IPA.automount.key_search_facet = function(spec) {

    var that = IPA.nested_search_facet(spec);

    that.get_selected_values = function() {

        var values = [];
        var keys = that.table.get_selected_values();
        var records = that.table.records;

        if (keys.length === 0 || !records) return values;

        for (var i=0,l=records.length; i<l; i++) {
            var record = records[i];
            if (keys.indexOf(record.description[0]) > -1) {
                values.push({
                    automountkey: record.automountkey[0],
                    automountinformation: record.automountinformation[0]
                });
            }
        }

        return values;
    };

    return that;
};

exp.location_spec = make_location_spec();
exp.map_spec = make_map_spec();
exp.key_spec = make_key_spec();

exp.register = function() {
    var e = reg.entity;

    e.register({type: 'automountlocation', spec: exp.location_spec});
    e.register({type: 'automountmap', spec: exp.map_spec});
    e.register({type: 'automountkey', spec: exp.key_spec});
};

phases.on('registration', exp.register);

return exp;
});
