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

test("Testing ipa_entity_set_search_definition().", function() {

    var uid_callback = function() {
        return true;
    };

    ipa_entity_set_search_definition("user", [
        ["uid", "Login", uid_callback],
    ]);

    var list = ipa_entity_search_list["user"];
    ok(
        list,
        "ipa_entity_search_list[\"user\"] is not null"
    );

    var attr = list[0];
    ok(
        attr,
        "ipa_entity_search_list[\"user\"][0] is not null"
    );

    equals(
        attr[0], "uid",
        "ipa_entity_search_list[\"user\"][0][0]"
    );

    equals(
        attr[1], "Login",
        "ipa_entity_search_list[\"user\"][0][1]"
    );

    var callback = attr[2];
    ok(
        callback,
        "ipa_entity_search_list[\"user\"][0][2] not null"
    );

    ok(
        callback(),
        "ipa_entity_search_list[\"user\"][0][2]() works"
    );
});

test("Testing ipa_entity_generate_views().", function() {

    ipa_ajax_options["async"] = false;

    ipa_init(
        "data",
        true,
        function(data, status, xhr) {
            ok(true, "ipa_init() succeeded.");
        },
        function(xhr, options, thrownError) {
            ok(false, "ipa_init() failed: "+thrownError);
        }
    );

    var container = $("<div/>");
    ipa_entity_generate_views("user", container);

    var list = container.children();
    var facets = list.children();

    equals(
        facets.length, 6,
        "Checking number of facets"
    )

    var search = facets.first();

    equals(
        search.attr("title"), "search",
        "Checking the first facet"
    )

    var details = search.next();

    equals(
        details.attr("title"), "details",
        "Checking the second facet"
    )

    var facet = details.next();
    var attribute_members = ipa_objs["user"].attribute_members;
    for (attribute_member in attribute_members) {
        var objects = attribute_members[attribute_member];
        for (var i = 0; i < objects.length; i++) {
            var object = objects[i];

            equals(
                facet.attr("title"), object,
                "Checking the next facet"
            );

            facet = facet.next();
        }
    }
});
