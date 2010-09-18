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

ipa_entity_set_search_definition('service', [
    ['krbprincipalname', 'Principal', null],
    ['quick_links', 'Quick Links', service_render_quick_links]
]);

ipa_entity_set_add_definition('service', [
    'dialog-add-service', 'Add New Service', [
        ['krbprincipalname', 'Principal', service_add_krbprincipalname],
        ['service', 'Service', null],
        ['host', 'Host Name', null],
    ]
]);

ipa_entity_set_details_definition('service', [
    ['identity', 'Service Details', [
        ['krbprincipalname', 'Principal', null],
    ]]
]);

function service_render_quick_links(tr, attr, value, entry_attrs) {

    var td = $("<td/>");
    tr.append(td);

    $("<a/>", {
        href: "jslink",
        html: $("<img src='service_details.png' />"),
        click: function() {
            var state = {};
            state['service-facet'] = 'details';
            state['service-pkey'] = entry_attrs['krbprincipalname'][0];
            $.bbq.pushState(state);
            return false;
        }
    }).appendTo(td);

    $("<a/>", {
        href: "jslink",
        html: $("<img src='host_enroll.png' />"),
        click: function() {
            var state = {};
            state['service-facet'] = 'associate';
            state['service-enroll'] = 'host';
            state['service-pkey'] = entry_attrs['krbprincipalname'][0];
            $.bbq.pushState(state);
            return false;
        }
    }).appendTo(td);
}

function service_add_krbprincipalname(add_dialog, flag) {
    if (flag == IPA_ADD_UPDATE) {
        var service = add_dialog.find('input[name=service]').val();
        var host = add_dialog.find('input[name=host]').val();
        return service+'/'+host;
    }
    return null;
}
