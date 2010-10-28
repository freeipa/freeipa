/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
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

/* REQUIRES: ipa.js */

var IPA_ADD_POPULATE = 1;
var IPA_ADD_UPDATE = 2;

function ipa_add_field(spec) {

    spec = spec || {};

    var that = {};
    that.name = spec.name;
    that.label = spec.label;

    that.init = spec.init;
    that.setup = spec.setup;

    return that;
}

function ipa_add_dialog(spec) {

    spec = spec || {};

    var that = {};
    that.name = spec.name;
    that.title = spec.title;
    that.entity_name = spec.entity_name;

    that.init = spec.init;

    that.fields = [];
    that.fields_by_name = {};

    var dialog = $('<div/>');

    that.get_fields = function() {
        return that.fields;
    };

    that.get_field = function(name) {
        return that.fields_by_name[name];
    };

    that.add_field = function(field) {
        that.fields.push(field);
        that.fields_by_name[field.name] = field;
    };

    that.create_field = function(spec) {
        var field = ipa_add_field(spec);
        that.add_field(field);
        return field;
    };

    that.open = function() {
        dialog.empty();
        dialog.attr('id', that.name);
        dialog.attr('title', that.title);

        for (var i = 0; i < that.fields.length; ++i) {
            var field = that.fields[i];
            if (field.setup) {
                field.setup(dialog, IPA_ADD_POPULATE);
            } else {
                dialog.append('<label>' + field.label + '</label>');
                dialog.append('<input type="text" name="' + field.name + '" />');
            }
        }

        dialog.dialog({
            modal: true,
            buttons: {
                'Add': that.add,
                'Add and edit': that.add_and_edit,
                'Cancel': that.cancel
            }
        });
    };

    that.add = function(evt, called_from_add_and_edit) {
        var pkey = [];
        var options = {};
        var pkey_name = IPA.metadata[that.entity_name].primary_key;

        function add_win(data, text_status, xhr) {
            if (called_from_add_and_edit) {
                var state = {};
                state[that.entity_name + '-facet'] = 'details';
                state[that.entity_name + '-pkey'] = pkey[0];
                $.bbq.pushState(state);
            }
        }

        for (var i = 0; i < that.fields.length; ++i) {
            var field = that.fields[i];
            if (field.setup) {
                var value = field.setup(dialog, IPA_ADD_UPDATE);
                if (value != null) {
                    if (field.name == pkey_name)
                        pkey = [value];
                    else
                        options[field.name] = value;
                }
            }
        }

        dialog.find('input').each(function () {
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

        ipa_cmd('add', pkey, options, add_win, null, that.entity_name);
    };

    that.add_and_edit = function(evt) {
        that.add(evt, true);
        dialog.dialog('close');
    };

    that.cancel = function() {
        dialog.dialog('close');
    };

    if (that.init) that.init();

    return that;
}

