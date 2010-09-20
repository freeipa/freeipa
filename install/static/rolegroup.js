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

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */

ipa_entity_set_search_definition('rolegroup', [
    ['cn', 'Role-group name', null],
    ['description', 'Description', null],
    ['quick_links', 'Quick Links', rolegroup_render_quick_links]
]);

ipa_entity_set_add_definition('rolegroup', [
    'dialog-add-rolegroup', 'Add New Rolegroup', [
        ['cn', 'Name', null],
        ['description', 'Description', null],
    ]
]);

ipa_entity_set_details_definition('rolegroup', [
    ['identity', 'Rolegroup Details', [
        ['cn', 'Name', null],
        ['description', 'Description', null],
    ]]
]);

function rolegroup_render_quick_links(tr, attr, value, entry_attrs) {

    var td = $("<td/>");
    tr.append(td);

    $("<a/>", {
        href: "jslink",
        html: $("<img src='rolegroup_details.png' />"),
        click: function() {
            var state = {};
            state['rolegroup-facet'] = 'details';
            state['rolegroup-pkey'] = entry_attrs['cn'][0];
            $.bbq.pushState(state);
            return false;
        }
    }).appendTo(td);

    $("<a/>", {
        href: "jslink",
        html: $("<img src='user_member.png' />"),
        click: function() {
            var state = {};
            state['rolegroup-facet'] = 'associate';
            state['rolegroup-enroll'] = 'user';
            state['rolegroup-pkey'] = entry_attrs['cn'][0];
            $.bbq.pushState(state);
            return false;
        }
    }).appendTo(td);

    $("<a/>", {
        href: "jslink",
        html: $("<img src='group_member.png' />"),
        click: function() {
            var state = {};
            state['rolegroup-facet'] = 'associate';
            state['rolegroup-enroll'] = 'group';
            state['rolegroup-pkey'] = entry_attrs['cn'][0];
            $.bbq.pushState(state);
            return false;
        }
    }).appendTo(td);

    $("<a/>", {
        href: "jslink",
        html: $("<img src='host_member.png' />"),
        click: function() {
            var state = {};
            state['rolegroup-facet'] = 'associate';
            state['rolegroup-enroll'] = 'host';
            state['rolegroup-pkey'] = entry_attrs['cn'][0];
            $.bbq.pushState(state);
            return false;
        }
    }).appendTo(td);

    $("<a/>", {
        href: "jslink",
        html: $("<img src='hostgroup_member.png' />"),
        click: function() {
            var state = {};
            state['rolegroup-facet'] = 'associate';
            state['rolegroup-enroll'] = 'hostgroup';
            state['rolegroup-pkey'] = entry_attrs['cn'][0];
            $.bbq.pushState(state);
            return false;
        }
    }).appendTo(td);
}
