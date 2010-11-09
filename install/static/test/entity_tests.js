/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

test('Testing ipa_entity_set_search_definition().', function() {

    var uid_callback = function() {
        return true;
    };

    ipa_entity_set_search_definition('user', [
        ['uid', 'Login', uid_callback]
    ]);

    var facet = ipa_entity_get_search_facet('user');
    ok(
        facet,
        'ipa_entity_get_search_facet(\'user\') is not null'
    );

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
        column.label, 'Login',
        'column.label'
    );

    ok(
        column.setup,
        'column.setup not null'
    );

    ok(
        column.setup(),
        'column.setup() works'
    );
});

test('Testing ipa_facet_setup_views().', function() {

    var orig_show_page = IPA.show_page;
    IPA.ajax_options.async = false;

    IPA.init(
        'data',
        true,
        function(data, text_status, xhr) {
            ok(true, 'ipa_init() succeeded.');
        },
        function(xhr, text_status, error_thrown) {
            ok(false, 'ipa_init() failed: '+error_thrown);
        }
    );

    var entity = ipa_entity({
        'name': 'user'
    });

    IPA.add_entity(entity);

    var facet = ipa_association_facet({
        'name': 'associate'
    });
    entity.add_facet(facet);

    var container = $('<div/>');

    var counter = 0;
    IPA.show_page = function(entity_name, facet_name, other_entity) {
        counter++;
    };

    facet.setup_views(container);

    var list = container.children();
    var views = list.children();

    equals(
        views.length, 4,
        'Checking number of views'
    );

    facet = views.first();
    var attribute_members = IPA.metadata['user'].attribute_members;
    for (attribute_member in attribute_members) {
        var objects = attribute_members[attribute_member];
        for (var i = 0; i < objects.length; i++) {
            var object = objects[i];

            equals(
                facet.attr('title'), object,
                'Checking the '+object+' facet'
            );

            facet.click();

            facet = facet.next();
        }
    }

    equals(
        counter, 4,
        'Checking callback invocations'
    );

    IPA.show_page = orig_show_page;
});

test('Testing ipa_entity_quick_links().', function() {

    var orig_push_state = nav_push_state;
    var orig_get_state = nav_get_state;
    var orig_remove_state = nav_remove_state;

    var state = {};

    nav_push_state = function(params) {
        $.extend(state, params);
    };
    nav_get_state = function(key) {
        return state[key];
    };
    nav_remove_state = function(key) {
        delete state[key];
    };

    IPA.ajax_options.async = false;

    IPA.init(
        'data',
        true,
        function(data, text_status, xhr) {
            ok(true, 'ipa_init() succeeded.');
        },
        function(xhr, text_status, error_thrown) {
            ok(false, 'ipa_init() failed: '+error_thrown);
        }
    );

    var obj_name = 'user';
    var pkey = IPA.metadata[obj_name].primary_key;
    var pkey_value = 'test';

    var entry_attrs = {};
    entry_attrs[pkey] =  [pkey_value];

    var container = $('<div/>', {
        title: obj_name,
        class: 'entity-container'
    });

    var search_table = $('<table/>', {
        class: 'search-table'
    }).appendTo(container);

    var tbody = $('<tbody/>').appendTo(search_table);
    var tr = $('<tr/>').appendTo(tbody);
    var td = $('<td/>').appendTo(tr);
    var span = $('<span/>', {name:'quick_links'}).appendTo(td);

    ipa_entity_quick_links(tr, 'quick_links', null, entry_attrs);

    var link = span.children().first();

    equals(
        link.attr('href'), '#details',
        'Checking details link'
    );

    link.click();

    equals(
        state[obj_name+'-facet'], 'details',
        'Checking state[\''+obj_name+'-facet\']'
    );

    equals(
        state[obj_name+'-pkey'], pkey_value,
        'Checking state[\''+obj_name+'-pkey\']'
    );

    var attribute_members = IPA.metadata[obj_name].attribute_members;
    for (attr_name in attribute_members) {
        var objs = attribute_members[attr_name];
        for (var i = 0; i < objs.length; ++i) {
            var m = objs[i];

            link = link.next();

            equals(
                link.attr('href'), '#'+m,
                'Checking '+m+' link'
            );

            link.click();

            equals(
                state[obj_name+'-facet'], 'associate',
                'Checking state[\''+obj_name+'-facet\']'
            );

            equals(
                state[obj_name+'-enroll'], m,
                'Checking state[\''+obj_name+'-enroll\']'
            );

            equals(
                state[obj_name+'-pkey'], pkey_value,
                'Checking state[\''+obj_name+'-pkey\']'
            );
        }
    }

    nav_push_state = orig_push_state;
    nav_get_state = orig_get_state;
    nav_remove_state = orig_remove_state;
});
