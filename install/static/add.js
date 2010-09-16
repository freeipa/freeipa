/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
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

/* REQUIRES: ipa.js */

var IPA_ADD_POPULATE = 1;
var IPA_ADD_UPDATE = 2;

function add_dialog_create(obj_name, adl)
{
    var add_dialog = $('<div></div>');

    function add(evt, called_from_add_and_edit) {
        function add_win(data, text_status, xhr) {
            if (called_from_add_and_edit) {
                var state = {};
                state[obj_name + '-facet'] = 'details';
                var pkey_name = ipa_objs[obj_name].primary_key;
                var selector = 'input[name=' + pkey_name + ']';
                state[obj_name + '-pkey'] = add_dialog.find(selector).val();
                $.bbq.pushState(state);
            }
        };

        var pkey = [];
        var options = {};
        var pkey_name = ipa_objs[obj_name].primary_key;

        var fields = adl[2];
        for (var i = 0; i < fields.length; ++i) {
            var f = fields[i];
            var attr = f[0];
            if (typeof f[2] == 'function') {
                var value = f[2](add_dialog, IPA_ADD_UPDATE);
                if (value != null) {
                    if (attr == pkey_name)
                        pkey = [value];
                    else
                        options[attr] = value;
                }
            }
        }

        add_dialog.find('input').each(function () {
            var jobj = $(this);
            var attr = jobj.attr('name');
            var value = jobj.val();
            if (value) {
                if (pkey.length == 0 && attr == pkey_name)
                    pkey = [jobj.val()];
                else if (options[attr] == null)
                    options[attr] = jobj.val();
            }
        });

        ipa_cmd('add', pkey, options, add_win, null, obj_name);
        add_dialog.dialog('close');
    };

    function add_and_edit(evt) {
        add(evt, true);
        add_dialog.dialog('close');
    };

    function cancel() {
        add_dialog.dialog('close');
    };

    add_dialog.attr('id', adl[0]);
    add_dialog.attr('title', adl[1]);

    var fields = adl[2];
    for (var i = 0; i < fields.length; ++i) {
        var f = fields[i];
        if (typeof f[2] == 'function') {
            f[2](add_dialog, IPA_ADD_POPULATE);
        } else {
            add_dialog.append('<label>' + f[1] + '</label>');
            add_dialog.append('<input type="text" name="' + f[0] + '" />');
        }
    }

    add_dialog.dialog({
        modal: true,
        buttons: {
            'Add': add,
            'Add and edit': add_and_edit,
            'Cancel': cancel
        }
    });
}

