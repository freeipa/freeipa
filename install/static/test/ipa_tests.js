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

test("Testing ipa_init().", function() {

    expect(1);

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
});

test("Testing ipa_get_param_info().", function() {

    var param_info = ipa_get_param_info("user", "uid");
    ok(
        param_info,
        "ipa_get_param_info(\"user\", \"uid\") not null"
    );

    equals(
        param_info["label"], "User login",
        "ipa_get_param_info(\"user\", \"uid\")[\"label\"]"
    );

    equals(
        ipa_get_param_info("user", "wrong_attribute"), null,
        "ipa_get_param_info(\"user\", \"wrong_attribute\")"
    );

    equals(
        ipa_get_param_info("user", null), null,
        "ipa_get_param_info(\"user\", null)"
    );

    equals(
        ipa_get_param_info("wrong_entity", "uid"), null,
        "ipa_get_param_info(\"wrong_entity\", \"uid\")"
    );

    equals(
        ipa_get_param_info(null, "uid"), null,
        "ipa_get_param_info(null, \"uid\")"
    );
});

test("Testing ipa_get_member_attribute().", function() {

    equals(
        ipa_get_member_attribute("user", "group"), "memberof",
        "ipa_get_member_attribute(\"user\", \"group\")"
    );

    equals(
        ipa_get_member_attribute("user", "host"), null,
        "ipa_get_member_attribute(\"user\", \"host\")"
    );

    equals(
        ipa_get_member_attribute("user", null), null,
        "ipa_get_member_attribute(\"user\", null)"
    );

    equals(
        ipa_get_member_attribute(null, "group"), null,
        "ipa_get_member_attribute(null, \"group\")"
    );
});
