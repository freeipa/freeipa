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

test("Testing ipa_init().", function() {

    expect(1);

    IPA.ajax_options.async = false;

    IPA.init(
        "data",
        true,
        function(data, text_status, xhr) {
            ok(true, "ipa_init() succeeded.");
        },
        function(xhr, text_status, error_thrown) {
            ok(false, "ipa_init() failed: "+error_thrown);
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

test("Testing successful ipa_cmd().", function() {

    var method = 'method';
    var args = ['arg1', 'arg2', 'arg3'];
    var options = {
        opt1: 'val1',
        opt2: 'val2',
        opt3: 'val3'
    };
    var object = 'object';

    var success_handler_counter = 0;
    var error_handler_counter = 0;

    function success_handler(data, status, xhr) {
        success_handler_counter++;
    }

    function error_handler(xhr, text_status, error_thrown) {
        error_handler_counter++;
    }

    var orig = $.ajax;

    var xhr = {};
    var text_status = null;
    var error_thrown = {name:'ERROR', message:'An error has occured'};

    var ajax_counter = 0;

    $.ajax = function(request) {
        ajax_counter++;

        equals(
            request.url, "data/"+object+"_"+method+".json",
            "Checking request.url"
        );

        var data = JSON.parse(request.data);

        equals(
            data.method, object+'_'+method,
            "Checking method"
        );

        same(
            data.params, [args, options],
            "Checking parameters"
        );

        request.success(xhr, text_status, error_thrown);
    };

    ipa_cmd(method, args, options, success_handler, error_handler, object);

    equals(
        ajax_counter, 1,
        "Checking ajax invocation counter"
    );

    var dialog = IPA.error_dialog.parent('.ui-dialog');

    ok(
        !dialog.length,
        "The dialog box is not created."
    );

    ok(
        success_handler_counter == 1 && error_handler_counter == 0,
        "Only the success handler is called."
    );

    $.ajax = orig;
});

test("Testing unsuccessful ipa_cmd().", function() {

    var method = 'method';
    var args = ['arg1', 'arg2', 'arg3'];
    var options = {
        opt1: 'val1',
        opt2: 'val2',
        opt3: 'val3'
    };
    var object = 'object';

    var success_handler_counter = 0;
    var error_handler_counter = 0;

    function success_handler(data, status, xhr) {
        success_handler_counter++;
    }

    function error_handler(xhr, text_status, error_thrown) {
        error_handler_counter++;
    }

    var orig = $.ajax;

    var xhr = {};
    var text_status = null;
    var error_thrown = {name:'ERROR', message:'An error has occured'};

    var ajax_counter = 0;

    $.ajax = function(request) {
        ajax_counter++;

        equals(
            request.url, "data/"+object+"_"+method+".json",
            "Checking request.url"
        );

        var data = JSON.parse(request.data);

        equals(
            data.method, object+'_'+method,
            "Checking method"
        );

        same(
            data.params, [args, options],
            "Checking parameters"
        );

        request.error(xhr, text_status, error_thrown);
    };

    ipa_cmd(method, args, options, success_handler, error_handler, object);

    var dialog = IPA.error_dialog.parent('.ui-dialog');

    equals(
        ajax_counter, 1,
        "Checking ajax invocation counter"
    );

    ok(
        dialog.length == 1 && IPA.error_dialog.dialog('isOpen'),
        "The dialog box is created and open."
    );

    ok(
        success_handler_counter == 0 && error_handler_counter == 0,
        "Initially none of the handlers are called."
    );

    // search the retry button from the beginning
    var retry = $('button', dialog).first();
    retry.trigger('click');

    equals(
        ajax_counter, 2,
        "Checking ajax invocation counter"
    );

    ok(
        success_handler_counter == 0 && error_handler_counter == 0,
        "After 1st retry, none of the handlers are called."
    );

    // search the retry button from the beginning again because the dialog
    // has been recreated
    dialog = IPA.error_dialog.parent('.ui-dialog');
    retry = $('button', dialog).first();
    retry.trigger('click');

    equals(
        ajax_counter, 3,
        "Checking ajax invocation counter"
    );

    ok(
        success_handler_counter == 0 && error_handler_counter == 0,
        "After 2nd retry, none of the handlers are called."
    );

    // search the cancel button from the beginning because the dialog has
    // been recreated
    dialog = IPA.error_dialog.parent('.ui-dialog');
    var cancel = $('button', dialog).first().next();
    cancel.trigger('click');

    equals(
        ajax_counter, 3,
        "Checking ajax invocation counter"
    );

    ok(
        !IPA.error_dialog.dialog('isOpen'),
        "After cancel, the dialog box is closed."
    );

    ok(
        success_handler_counter == 0 && error_handler_counter == 1,
        "Only the error handler is called."
    );

    $.ajax = orig;
});
