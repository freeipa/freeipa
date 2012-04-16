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

var LP = {}; //Login Page

LP.login = function(username, password) {

    var result = 'invalid';

    function success_handler(data, text_status, xhr) {
        result = 'success';
    }

    function error_handler(xhr, text_status, error_thrown) {

        if (xhr.status === 401) {
            var reason = xhr.getResponseHeader("X-IPA-Rejection-Reason");

            //change result from invalid only if we have a header which we
            //understand
            if (reason === 'password-expired') {
                result = 'expired';
            }
        }
    }

    var data = {
        user: username,
        password: password
    };

    var request = {
        url: '/ipa/session/login_password',
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

LP.on_submit = function() {

    var username = $('input[name=username]', LP.form).val();
    var password = $('input[name=password]', LP.form).val();

    var result = LP.login(username, password);

    if (result === 'invalid') {
        $('#expired').css('display', 'none');
        $('#invalid').css('display', 'block');
    } else if (result === 'expired') {
        $('#invalid').css('display', 'none');
        $('#expired').css('display', 'block');
    } else {
        window.location = '/ipa/ui';
    }
};

LP.init = function() {

    LP.form = $('#login');

    $('input[name=submit]', LP.form).click(function() {
        LP.on_submit();
        return false;
    });
};

/* main (document onready event handler) */
$(function() {
    LP.init();
});
