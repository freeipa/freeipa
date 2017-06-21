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

define([
    'freeipa/ipa',
    'freeipa/jquery',
    'freeipa/rpc',
    'freeipa/dialog',
    'freeipa/widget',
    'freeipa/details',
    'freeipa/entity'],
    function(IPA, $, rpc) {
    return function() {

module('ipa');

test("Testing ipa_init().", function() {

    expect(1);

    IPA.ajax_options.async = false;

    IPA.init({
        url: 'data',
        on_success: function(data, text_status, xhr) {
            ok(true, "ipa_init() succeeded.");
        },
        on_error: function(xhr, text_status, error_thrown) {
            ok(false, "ipa_init() failed: "+error_thrown);
        }
    });
});

test("Testing IPA.get_entity_param().", function() {

    var metadata = IPA.get_entity_param("user", "uid");
    ok(
        metadata,
        "IPA.get_entity_param(\"user\", \"uid\") not null");

    equals(
        metadata["label"], "User login",
        "IPA.get_entity_param(\"user\", \"uid\")[\"label\"]");

    equals(
        IPA.get_entity_param("user", "wrong_attribute"), null,
        "IPA.get_entity_param(\"user\", \"wrong_attribute\")");

    equals(
        IPA.get_entity_param("user", null), null,
        "IPA.get_entity_param(\"user\", null)");

    equals(
        IPA.get_entity_param("wrong_entity", "uid"), null,
        "IPA.get_entity_param(\"wrong_entity\", \"uid\")");

    equals(
        IPA.get_entity_param(null, "uid"), null,
        "IPA.get_entity_param(null, \"uid\")");
});

test("Testing IPA.get_member_attribute().", function() {

    equals(
        IPA.get_member_attribute("user", "group"), "memberofindirect",
        "IPA.get_member_attribute(\"user\", \"group\")");

    equals(
        IPA.get_member_attribute("user", "host"), null,
        "IPA.get_member_attribute(\"user\", \"host\")");

    equals(
        IPA.get_member_attribute("user", null), null,
        "IPA.get_member_attribute(\"user\", null)");

    equals(
        IPA.get_member_attribute(null, "group"), null,
        "IPA.get_member_attribute(null, \"group\")");
});

test("Testing successful rpc.command().", function() {

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

    // Result needs to be there as it is place where message from API call is
    // stored
    var xhr = {"result": {}};
    var text_status = null;
    var error_thrown = {name:'ERROR', message:'An error has occurred'};

    var ajax_counter = 0;

    $.ajax = function(request) {
        ajax_counter++;

        equals(
            request.url, "data/"+object+"_"+method+".json",
            "Checking request.url");

        var data = JSON.parse(request.data);

        equals(
            data.method, object+'_'+method,
            "Checking method");

        // By default all rpc calls contain version of API
        $.extend(options, {'version': window.ipa_loader.api_version});

        same(
            data.params, [args, options],
            "Checking parameters");

        request.success(xhr, text_status, error_thrown);
    };

    rpc.command({
        entity: object,
        method: method,
        args: args,
        options: options,
        on_success: success_handler,
        on_error: error_handler
    }).execute();

    equals(
        ajax_counter, 1,
        "Checking ajax invocation counter");

    var dialog = $('[data-name=error_dialog]');

    ok(
        dialog.length === 0,
        "The dialog box is not created.");

    ok(
        success_handler_counter === 1 && error_handler_counter === 0,
        "Only the success handler is called.");

    $.ajax = orig;
});

test("Testing unsuccessful rpc.command().", function() {

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
    var dialog_selector = '[data-name=error_dialog]';

    function success_handler(data, status, xhr) {
        success_handler_counter++;
    }

    function error_handler(xhr, text_status, error_thrown) {
        error_handler_counter++;
    }

    var orig = $.ajax;

    var xhr = {};
    var text_status = null;
    var error_thrown = {name:'ERROR', message:'An error has occurred'};

    var ajax_counter = 0;

    $.ajax = function(request) {
        ajax_counter++;

        equals(request.url, "data/"+object+"_"+method+".json",
               "Checking request.url");

        var data = JSON.parse(request.data);

        equals(data.method, object+'_'+method, "Checking method");

        // By default all rpc calls contain version of API
        $.extend(options, { 'version': window.ipa_loader.api_version});

        same(data.params, [args, options], "Checking parameters");

        // remove api version from options object
        delete options.version;

        request.error(xhr, text_status, error_thrown);
    };

    rpc.command({
        entity: object,
        method: method,
        args: args,
        options: options,
        on_success: success_handler,
        on_error: error_handler
    }).execute();

    function click_button(name) {
        var dialog = $(dialog_selector);
        var btn = $('button[name='+name+']', dialog).first();
        btn.trigger('click');
    }

    var dialog = $(dialog_selector);

    equals(
        ajax_counter, 1,
        "Checking ajax invocation counter");

    ok(
        dialog.length === 1,
        "The dialog box is created and open.");

    ok(
        success_handler_counter === 0 && error_handler_counter === 0,
        "Initially none of the handlers are called.");

    click_button('retry');

    equals(
        ajax_counter, 2,
        "Checking ajax invocation counter");

    ok(
        success_handler_counter === 0 && error_handler_counter === 0,
        "After 1st retry, none of the handlers are called.");

    click_button('retry');

    equals(ajax_counter, 3,
        "Checking ajax invocation counter");

    ok(success_handler_counter === 0 && error_handler_counter === 0,
        "After 2nd retry, none of the handlers are called.");

    click_button('cancel');

    equals(ajax_counter, 3,
        "Checking ajax invocation counter");

    ok(success_handler_counter === 0 && error_handler_counter === 1,
        "Only the error handler is called.");

    // cleanup - qunit doesn't really play well with asynchronous opening and
    // closing of dialogs
    // opening and closing may be rewritten as asynchronous test
    $('.modal').remove();
    $('.modal-backdrop').remove();

    $.ajax = orig;
});

test("Testing observer.", function() {
    expect(6);
    var obj = {};
    var param1_value = 'p1';
    var param2_value = 'p2';

    obj.event = IPA.observer();

    obj.event.attach(function(param1, param2) {
        ok(true, "Proper function 1 callback");
    });

    var first = true;

    var func = function(param1, param2) {
        if(first) {
            ok(true, "Proper function 2 callback");
            equals(param1, param1_value, "Testing Parameter 1");
            equals(param2, param2_value, "Testing Parameter 2");
            equals(this, obj, "Testing Context");
            first = false;
        } else {
            ok(false, "Fail function 2 callback");
        }
    };

    obj.event.attach(func);
    obj.event.notify([param1_value, param2_value], obj);
    obj.event.detach(func);
    obj.event.notify([param1_value, param2_value], obj);
});

};});
