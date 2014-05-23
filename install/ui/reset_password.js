/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
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

var RP = {}; //Reset Password Page

RP.reset_password = function(username, old_password, new_password, otp) {

    //possible results: 'ok', 'invalid-password', 'policy-error'

    var status, result, reason, invalid, failure, data, request;

    status = 'invalid';
    result = {
        status: status,
        message: "Password reset was not successful."
    };

    function success_handler(data, text_status, xhr) {

        result.status = xhr.getResponseHeader("X-IPA-Pwchange-Result") || status;

        if (result.status === 'policy-error') {
            result.message = xhr.getResponseHeader("X-IPA-Pwchange-Policy-Error");
        } else if (result.status === 'invalid-password') {
            result.message = "The password or username you entered is incorrect.";
        }

        return result;
    }

    function error_handler(xhr, text_status, error_thrown) {
        return result;
    }

    data = {
        user: username,
        old_password: old_password,
        new_password: new_password
    };

    if (otp) {
        data.otp = otp;
    }

    request = {
        url: '/ipa/session/change_password',
        data: data,
        contentType: 'application/x-www-form-urlencoded',
        processData: true,
        dataType: 'html',
        async: false,
        type: 'POST',
        success: success_handler,
        error: error_handler
    };

    $.ajax(request);

    return result;
};

RP.verify_required = function(field, value) {

    var valid = true;

    if (!value || value === '') {
        valid = false;
        RP.show_error(field +" is required");
    }

    return valid;
};


RP.on_submit = function() {

    var username = $('#user').val();
    var current_password = $('#old_password').val();
    var otp = $('#otp').val();
    var new_password = $('#new_password').val();
    var verify_password = $('#verify_password').val();

    if (!RP.verify_required('Username', username)) return;
    if (!RP.verify_required('Current Password', current_password)) return;
    if (!RP.verify_required('New Password', new_password)) return;
    if (!RP.verify_required('Verify Password', verify_password)) return;

    if (new_password !== verify_password) {
        RP.show_error("Passwords must match");
        return;
    }

    var result = RP.reset_password(username, current_password, new_password, otp);

    if (result.status !== 'ok') {
        RP.show_error(result.message);
    } else {
        RP.reset_form();
        RP.show_success("Password reset was successful.");
    }
};

RP.reset_form = function() {
    $('.alert-danger').css('display', 'none');
    $('.alert-success').css('display', 'none');
    $('#old_password').val('');
    $('#otp').val('');
    $('#new_password').val('');
    $('#verify_password').val('');
};

RP.show_error = function(message) {

    $('.alert-danger > p').text(message);
    $('.alert-danger').css('display', '');
    $('.alert-success').css('display', 'none');
};

RP.show_success = function(message) {

    $('.alert-success > p').text(message);
    $('.alert-danger').css('display', 'none');
    $('.alert-success').css('display', '');
};


RP.init = function() {

    $('#reset_password').submit(function() {
        RP.on_submit();
        return false;
    });
};

/* main (document onready event handler) */
$(function() {
    RP.init();
});
