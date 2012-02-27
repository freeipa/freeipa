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

    var success = false;

    function success_handler(data, text_status, xhr) {
        success = true;
    }

    var data = {
        user: username,
        password: password
    };

    var request = {
        url: '/ipa/session/login_password',
        data: data,
        async: false,
        type: "POST",
        success: success_handler
    };

    $.ajax(request);

    return success;
};

LP.on_submit = function() {

    var username = $('input[name=username]', LP.form).val();
    var password = $('input[name=password]', LP.form).val();

    var success = LP.login(username, password);

    if (!success) {
        $('#error-box').css('display', 'block');
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