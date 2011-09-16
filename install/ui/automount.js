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

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */


/**Automount*/

IPA.entity_factories.automountlocation = function() {
    return IPA.entity_builder().
        entity({ name: 'automountlocation' }).
        facet_groups([ 'automountmap', 'settings' ]).
        search_facet({
            title: IPA.metadata.objects.automountlocation.label,
            columns:['cn']
        }).
        nested_search_facet({
            facet_group: 'automountmap',
            nested_entity: 'automountmap',
            label: IPA.metadata.objects.automountmap.label,
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
        }).
        build();
};

IPA.entity_factories.automountmap = function() {
    return IPA.entity_builder().
        entity({ name: 'automountmap' }).
        containing_entity('automountlocation').
        facet_groups([ 'automountkey', 'settings' ]).
        nested_search_facet({
            facet_group: 'automountkey',
            nested_entity: 'automountkey',
            label: IPA.metadata.objects.automountkey.label,
            name: 'keys',
            get_values: IPA.get_option_values,
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
                            factory: IPA.textarea_widget,
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
                            factory: IPA.radio_widget,
                            name: 'method',
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
                            factory: IPA.textarea_widget,
                            name: 'description'
                        }
                    ]
                },
                {
                    name: 'indirect',
                    fields: [
                        {
                            name: 'key',
                            label: IPA.get_method_option(
                                'automountmap_add_indirect', 'key').label
                        },
                        {
                            name: 'parentmap',
                            label: IPA.get_method_option(
                                'automountmap_add_indirect', 'parentmap').label
                        }
                    ]
                }
            ]
        }).
        build();
};

IPA.entity_factories.automountkey = function() {
    return IPA.entity_builder().
        entity({ name: 'automountkey' }).
        containing_entity('automountmap').
        details_facet({
            sections:[
                {
                    name:'identity',
                    label: IPA.messages.details.identity,
                    fields:[
                        {
                            factory: IPA.text_widget,
                            read_only: true,
                            name:   'automountkey'
                        },
                        'automountinformation']
                }
            ],
            disable_breadcrumb: false,
            pre_execute_hook : function (command){
                var entity_name = this.entity_name;
                var info = IPA.nav.get_state(entity_name + '-info');
                var key = IPA.nav.get_state(entity_name + '-pkey');


                if (command.args.length ==3){
                    command.args.pop();
                }
                if (command.method === 'mod'){
                    command.options['newautomountinformation'] =
                        command.options['automountinformation'];

                }
                command.options['automountkey'] = key;
                command.options['automountinformation'] = info;
            }
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
        }).
        build();
};

IPA.automount_key_column = function(spec) {

    var that = IPA.column(spec);

    that.setup = function(container, record) {
        container.empty();
        var key = record.automountkey;
        var info = record.automountinformation;

        $('<a/>', {
            href: '#'+key,
            text: key,
            click: function() {
                var state = IPA.nav.get_path_state(that.entity_name);
                state[that.entity_name + '-facet'] = 'default';
                state[that.entity_name + '-info'] = info;
                state[that.entity_name + '-pkey'] = key;
                IPA.nav.push_state(state);
                return false;
            }
        }).appendTo(container);

    };

    return that;
};

IPA.automountmap_adder_dialog = function(spec) {

    var that = IPA.add_dialog(spec);

    that.create = function() {
        that.dialog_create();

        var method_field = that.get_field('method');

        var direct_input = $('input[value="add"]', method_field.container);
        direct_input.change(function() {
            that.method = 'add';
            that.get_section('indirect').set_visible(false);
        });

        var indirect_input = $('input[value="add_indirect"]', method_field.container);
        indirect_input.change(function() {
            that.method = 'add_indirect';
            that.get_section('indirect').set_visible(true);
        });

        direct_input.click();
    };

    that.reset = function() {
        that.dialog_reset();

        var method_field = that.get_field('method');

        var direct_input = $('input[value="add"]', method_field.container);
        direct_input.click();
    };

    return that;
};

IPA.get_option_values = function(){

    var values = [];
    $('input[name="select"]:checked', this.table.tbody).each(function() {
        var value = {};
        $('span',$(this).parent().parent()).each(function(){
            var name = this.attributes['name'].value;

            value[name] = $(this).text();
        });
        values.push (value);
    });
    return values;
};
