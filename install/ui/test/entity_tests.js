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


var entities_container;

module('entity',{
    setup: function() {

        IPA.ajax_options.async = false;

        IPA.init(
            "data",
            true,
            function(data, text_status, xhr) {

                IPA.entity_factories.user = function(){
                    return IPA.
                        entity_builder().
                        entity('user').
                        search_facet({
                            columns:['uid'],
                            add_fields:[]}).
                        build();
                };
                IPA.start_entities();
            },
            function(xhr, text_status, error_thrown) {
                ok(false, "ipa_init() failed: "+error_thrown);
            }
        );

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


    var entity =   IPA.
        entity_builder().
        entity('user').
        search_facet({
            columns:['uid'],
            add_fields:[]}).
        build();
    entity.init();

    var facet = entity.get_facet('search');
    facet.init();

    var content = $('<div/>', {
        'class': 'content'
    }).appendTo(entities_container);

    facet.create_content(content);

    facet.setup(entities_container);


    var column = facet.get_columns()[0];
    ok(
        column,
        'column is not null'
    );

    equals(
        column.name, 'uid',
        'column.name'
    );

    equals(
        column.label, 'User login',
        'column.label'
    );

    ok(
        column.setup,
        'column.setup not null'
    );

});

