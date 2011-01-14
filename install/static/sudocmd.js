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

IPA.sudocmd = function () {

    var that = IPA.entity({
        'name': 'sudocmd'
    });

    that.init = function() {

        var dialog = IPA.sudocmd_add_dialog({
            'name': 'add',
            'title': 'Add New SUDO Command'
        });
        that.add_dialog(dialog);
        dialog.init();

        var facet = IPA.sudocmd_search_facet({
            'name': 'search',
            'label': 'Search'
        });
        that.add_facet(facet);

        facet = IPA.sudocmd_details_facet({
            'name': 'details',
        });
        that.add_facet(facet);

        that.entity_init();
    };

    return that;
};


IPA.add_entity(IPA.sudocmd());


IPA.sudocmd_add_dialog = function (spec) {

    spec = spec || {};

    var that = IPA.add_dialog(spec);

    that.init = function() {

        that.add_field(IPA.text_widget({name:'sudocmd', undo: false}));
        that.add_field(IPA.text_widget({name:'description', undo: false}));

        that.add_dialog_init();
    };

    return that;
};


IPA.sudocmd_search_facet = function (spec) {

    spec = spec || {};

    var that = IPA.search_facet(spec);

    that.init = function() {

        that.create_column({name:'sudocmd', primary_key: true});
        that.create_column({name:'description'});

        that.search_facet_init();
    };

    return that;
};


IPA.sudocmd_details_facet = function (spec) {

    spec = spec || {};

    var that = IPA.details_facet(spec);

    that.init = function() {

        var section = IPA.details_list_section({
            'name': 'general',
            'label': 'General'
        });
        that.add_section(section);

        section.create_field({'name': 'sudocmd'});
        section.create_field({'name': 'description'});

        section = IPA.details_section({
            'name': 'groups',
            'label': 'Groups'
        });
        that.add_section(section);

        var field = IPA.sudocmd_member_sudocmdgroup_table_widget({
            'name': 'memberof',
            'label': 'Groups',
            'other_entity': 'sudocmdgroup',
            'save_values': false
        });
        section.add_field(field);

        that.details_facet_init();
    };

    return that;
};


IPA.sudocmd_member_sudocmdgroup_table_widget = function (spec) {

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
                'click': function (value) {
                    return function() {
                        var state = IPA.tab_state(that.other_entity);
                        state[that.other_entity + '-facet'] = 'details';
                        state[that.other_entity + '-pkey'] = value;
                        $.bbq.pushState(state);
                        return false;
                    };
                }(value),
                'html': value
            }).appendTo(container);
        };

        that.create_column({
            name: 'description',
            label: 'Description',
            width: '150px'
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

    that.get_records = function(on_success, on_error) {

        if (!that.values.length) return;

        var batch = IPA.batch_command({
            'name': that.entity_name+'_'+that.name+'_show',
            'on_success': on_success,
            'on_error': on_error
        });

        for (var i=0; i<that.values.length; i++) {
            var dn = that.values[i];
            var j = dn.indexOf('=');
            var k = dn.indexOf(',');
            var value = dn.substring(j+1, k);

            var command = IPA.command({
                'method': that.other_entity+'_show',
                'args': [value],
                'options': {
                    'all': true,
                    'rights': true
                }
            });

            batch.add_command(command);
        }

        batch.execute();
    };

    that.add = function(values, on_success, on_error) {

        if (!values.length) return;

        var batch = IPA.batch_command({
            'name': that.entity_name+'_'+that.name+'_add',
            'on_success': on_success,
            'on_error': on_error
        });

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        for (var i=0; i<values.length; i++) {
            var value = values[i];

            var command = IPA.command({
                'method': that.other_entity+'_add_member',
                'args': [value]
            });

            command.set_option('sudocmd', pkey);

            batch.add_command(command);
        }

        batch.execute();
    };

    that.remove = function(values, on_success, on_error) {

        if (!values.length) return;

        var batch = IPA.batch_command({
            'name': that.entity_name+'_'+that.name+'_remove',
            'on_success': on_success,
            'on_error': on_error
        });

        var pkey = $.bbq.getState(that.entity_name + '-pkey', true) || '';

        for (var i=0; i<values.length; i++) {
            var value = values[i];

            var command = IPA.command({
                'method': that.other_entity+'_remove_member',
                'args': [value]
            });

            command.set_option('sudocmd', pkey);

            batch.add_command(command);
        }

        batch.execute();
    };

    return that;
};
