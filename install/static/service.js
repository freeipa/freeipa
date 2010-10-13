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
    ['quick_links', 'Quick Links', ipa_entity_quick_links]
]);

ipa_entity_set_add_definition('service', [
    'dialog-add-service', 'Add New Service', [
        ['krbprincipalname', 'Principal', service_add_krbprincipalname],
        ['service', 'Service', null],
        ['host', 'Host Name', null]
    ]
]);

ipa_entity_set_details_definition('service', [
    ipa_stanza({name:'identity', label:'Service Details'}).
        input({name:'krbprincipalname',
               label:'Principal',
               setup:service_krbprincipalname_setup,
               load:service_krbprincipalname_load}).
        input({name:'service', label:'Service', load:service_service_load}).
        input({name:'host', label:'Host Name', load:service_host_load}).
        input({name:'usercertificate', label:'Certificate',
               load:service_usercertificate_load,
               save:service_usercertificate_save})
]);

function service_add_krbprincipalname(add_dialog, mode) {
    if (mode == IPA_ADD_UPDATE) {
        var service = add_dialog.find('input[name=service]').val();
        var host = add_dialog.find('input[name=host]').val();
        return service+'/'+host;
    }
    return null;
}

ipa_entity_set_association_definition('service', {
    'host': { method: 'add_host' }
});

function service_krbprincipalname_setup(container, dl, section) {
    // skip krbprincipalname
}

function service_krbprincipalname_load(container, dt, result) {
    // skip krbprincipalname
}

function service_service_load(container, dt, result) {
    var krbprincipalname = result['krbprincipalname'][0];
    var service = krbprincipalname.replace(/\/.*$/, '');
    var dd = ipa_create_first_dd(this.name, service);
    dt.after(dd);
}

function service_host_load(container, dt, result) {
    var krbprincipalname = result['krbprincipalname'][0];
    var host = krbprincipalname.replace(/^.*\//, '');
    var dd = ipa_create_first_dd(this.name, host);
    dt.after(dd);
}

function service_usercertificate_load(container, dt, result) {
    var textarea = $("<textarea/>", {
        title: 'usercertificate',
        style: 'width: 300px; height: 200px;'
    });

    var dd = ipa_create_first_dd(this.name, textarea);
    dt.after(dd);

    var usercertificate = result['usercertificate'];
    if (!usercertificate) return;

    var value = usercertificate[0].__base64__;
    textarea.val(value);
}

function service_usercertificate_save(container) {
    var field = this;
    var values = [];

    var dd = $('dd[title='+field.name+']', container);
    dd.each(function () {
        var textarea = $('textarea', dd);
        if (!textarea.length) return;

        var value = $.trim(textarea.val());
        if (value) {
            value = {'__base64__': value};
        } else {
            value = '';
        }

        values.push(value);
    });

    return values;
}
