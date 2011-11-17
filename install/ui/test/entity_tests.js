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


var entities_container;

module('entity',{
    setup: function() {

        IPA.ajax_options.async = false;

        IPA.init({
            url: 'data',
            on_success: function(data, text_status, xhr) {

                IPA.register('user', function(spec) {

                    var that = IPA.entity(spec);

                    that.init = function() {
                        that.entity_init();

                        that.builder.search_facet({
                            columns: [ 'uid' ]
                        });
                    };

                    return that;
                });
            },
            on_error: function(xhr, text_status, error_thrown) {
                ok(false, "ipa_init() failed: "+error_thrown);
            }
        });

        entities_container = $('<div id="entities"/>').appendTo(document.body);

    },
    teardown: function() {
        entities_container.remove();

    }
});

test('Testing IPA.entity_set_search_definition().', function() {

    var uid_callback = function() {
        return true;
    };

    var entity = IPA.get_entity('user');

    var entity_container = $('<div/>', {
        name: 'user',
        title: 'User',
        'class': 'entity'
    }).appendTo(entities_container);

    entity.create(entity_container);

    var facet = entity.get_facet('search');

    var facet_container = $('<div/>', {
        name: facet.name,
        'class': 'facet'
    });

    facet.create(facet_container);

    var column = facet.get_columns()[0];
    ok(
        column,
        'column is not null');

    equals(
        column.name, 'uid',
        'column.name');

    equals(
        column.label, 'User login',
        'column.label');

});

