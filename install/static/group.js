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

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */

ipa_entity_set_search_definition('group', [
    ['cn', 'Name', null],
    ['gidnumber', 'GID', null],
    ['description', 'Description', null],
    ['quick_links', 'Quick Links', ipa_entity_quick_links]
]);

ipa_entity_set_add_definition('group', [
    'dialog-add-group', 'Add New Group', [
        ['cn', 'Name', null],
        ['description', 'Description', null],
        ['posix', 'Is this a POSIX group?', f_posix],
        ['gidnumber', 'GID', null]
    ]
]);

ipa_entity_set_details_definition('group', [
    ['identity', 'Group Details', [
        ['cn', 'Group Name'],
        ['description', 'Description'],
        ['gidnumber', 'Group ID']
    ]]
]);

function f_posix(dlg, mode)
{
    function checkbox_on_click() {
        var jobj = $(this);
        if (jobj.attr('checked'))
            jobj.attr('checked', false);
        else
            jobj.attr('checked', true);
    };

    if (mode == IPA_ADD_POPULATE) {
        dlg.append('<label>Is this a POSIX group?</label>');
        dlg.append('<input type="checkbox" name="posix" />');
        dlg.children().last().click(checkbox_on_click);
    } else {
        if (dlg.find('input:checkbox[name=posix]').attr('checked'))
            return (true);
        return (false);
    }
}
