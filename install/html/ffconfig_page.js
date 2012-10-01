/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2012 Red Hat
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

 $(document).ready(function() {

    var set_enabled = function(steps, enabled) {

        var method;

        if (enabled) method = function(el) { el.removeClass('ui-state-disabled'); };
        else method = function(el) { el.addClass('ui-state-disabled'); };

        for (var i=0; i<steps.length; i++) {
            method($(steps[i]));
        }
    };

    var show_installed = function(installed) {

        if (installed) {
            $('#ext-installed').show();
            $('#ext-missing').hide();
        } else {
            $('#ext-installed').hide();
            $('#ext-missing').show();
        }
        set_enabled(['#step3'], installed);
    };

    var install = function(event) {

        window.location = $(event.target).parent().attr('href');
        check_until_installed();
        return false;
    };

    var check_until_installed = function() {

        var installed = IPA.browser_config.extension_installed();
        show_installed(installed);

        if (!installed) {
            window.setTimeout(function() {
                check_until_installed();
            }, 300);
        }
    };

    var configure = function() {
        IPA.browser_config.configure_firefox();
        var result = IPA.browser_config.get_configure_result();
        var installed = IPA.browser_config.extension_installed();

        $('#config-success').hide();
        $('#config-aborted').hide();
        $('#config-noext').hide();
        $('#config-error').hide();

        if (result === 'configured') {
            $('#config-success').show();
        } else if (result == 'aborted') {
            $('#config-aborted').show();
        } else if (!installed) {
            $('#config-noext').show();
        } else {
            $('#config-error').show();
        }
        return false;
    };

    var check_version = function() {

        var firefox = $.browser.mozilla === true;
        var version = $.browser.version;

        if (!firefox) {
            $('#wrongbrowser').show();
            set_enabled(['#step1', '#step2', '#step3'], false);
        } else {
            // Disable for all version of FF older than 15. Theoretically
            // the extension is compatible with version 3.6, 10 and later
            // FF 4-9 are not compatible because there is an error in loading
            // resource from chrome.manifest
            if (compare_version(version, '15') === -1) {
                $('#step2a').show();
                set_enabled(['#step2', '#step3'], false);
            }// else if (compare_version(version, '15') === -1) {
//                 $('#step2a').show();
//                 $('#older-compatible').show();
//                 $('#older-required').hide();
//             }
        }
    };

    var compare_version = function(a, b) {

        var only_digits =/[^\d.]/g;

        var a_parts = a.replace(only_digits, '').split('.');
        var b_parts = b.replace(only_digits, '').split('.');

        for (var i=0; i<a_parts.length && i<b_parts.length; i++) {
            var a_num = Number(a_parts[i]);
            var b_num = Number(b_parts[i]);

            if (a_num > b_num) return 1;
            else if (a_num < b_num) return -1;
        }

        if (a_parts.length !== b_parts.length) {
            return a_parts.length > b_parts.length ? 1 : -1;
        }

        return 0;
    };

    $('#install-link').click(install);
    $('#reinstall-link').click(install);
    $('#configure-link').click(configure);

    $('#notfirefox-link').button();
    $('#ca-link').button();
    $('#oldfirefox-link').button();
    $('#reinstall-link').button();
    $('#install-link').button();
    $('#configure-link').button();
    $('#return-link').button();

    check_version();
    show_installed(IPA.browser_config.extension_installed());
});