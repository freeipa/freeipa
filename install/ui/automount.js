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
        entity({name:'automountlocation',
                title:IPA.messages.tabs.automount}).
        search_facet({
            title: IPA.metadata.objects.automountlocation.label,
            columns:['cn']
        }).
        nested_search_facet({
            facet_group: 'member',
            nested_entity : 'automountmap',
            label : IPA.metadata.objects.automountmap.label,
            name: 'maps',
            columns:['automountmapname']
        }).
        details_facet({
            sections:[
                {
                    name:'identity',
                    label: IPA.messages.details.identity,
                    fields:['cn']
                }
            ]}).
        adder_dialog({
            fields:['cn']
        }).
        build();
};
IPA.entity_factories.automountmap = function() {
    return IPA.entity_builder().
        entity({name:'automountmap',
                title:IPA.messages.tabs.automount}).
        containing_entity('automountlocation').
        nested_search_facet({
            facet_group: 'member',
            nested_entity : 'automountkey',
            label : IPA.metadata.objects.automountkey.label,
            name: 'keys',
            get_values: IPA.get_option_values,
            columns:['automountkey','automountinformation']
        }).
        details_facet({
            sections:[
                {
                    name:'identity',
                    label: IPA.messages.details.identity,
                    fields:['automountmapname','description']
                }
            ]
        }).
        adder_dialog({
            factory: IPA.automountmap_adder_dialog,
            fields:[{factory:IPA.method_radio_widget,
                     name: 'method',
                     undo: false,
                     label:'Map Type',
                     options:[{value:'add',label:'Direct'},
                              {value:'add_indirect',label:'Indirect'}]
                    },
                    'automountmapname','description',
                    {
                        name:'key',
                        label:'Mount Point',
                        conditional:true,
                        undo: false
                    },
                    {
                        name:'parentmap',
                        label:'Parent Map',
                        conditional:true,
                        undo: false
                    }]
        }).
        build();
};

IPA.entity_factories.automountkey = function() {
    return IPA.entity_builder().
        entity({name:'automountkey',
                title:IPA.messages.tabs.automount}).
        containing_entity('automountmap').
        details_facet({
            sections:[
                {
                    name:'identity',
                    label: IPA.messages.details.identity,
                    fields:['automountkey','automountinformation','description']
                }
            ]
        }).
        adder_dialog({
            fields:['automountkey','automountinformation']
        }).
        build();
};


IPA.automountmap_adder_dialog = function(spec){
    var that = IPA.add_dialog(spec);

    that.super_setup = that.setup;
    that.setup = function(container) {
        that.super_setup(container);
        that.disable_conditional_fields();
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

IPA.method_radio_widget = function(spec){
    var direct = true;

    var that = IPA.radio_widget(spec);

    that.setup = function(container) {

        var input = $('input[name="'+that.name+'"]', that.container);
        input.
            filter("[value="+ that.dialog.method+"]").
            attr('checked', true);


        input.change(function() {
            that.dialog.method = this.value;

            if (this.value === 'add_indirect'){
                that.dialog.enable_conditional_fields();
            }else{
                that.dialog.disable_conditional_fields();
            }
        });
    };

    that.reset = function(){
        var input = $('input[name="'+that.name+'"]', that.container);
        input.filter("[value=add]").click();
    };

    return that;
};
