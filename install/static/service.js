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
    ipa_stanza({name:'details', label:'Service Details'}).
        input({name:'krbprincipalname',
               label:'Principal',
               setup:service_krbprincipalname_setup,
               load:service_krbprincipalname_load}).
        input({name:'service', label:'Service', load:service_service_load}).
        input({name:'host', label:'Host Name', load:service_host_load}),
    ipa_stanza({name:'provisioning', label:'Provisioning'}).
        input({name:'provisioning_status', label:'Status',
               load:service_provisioning_status_load}),
    ipa_stanza({name:'certificate', label:'Service Certificate'}).
        input({name:'certificate_status', label:'Status',
               load:service_usercertificate_load})
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
    var host = krbprincipalname.replace(/^.*\//, '').replace(/@.*$/, '');
    var dd = ipa_create_first_dd(this.name, host);
    dt.after(dd);
}

function service_provisioning_status_load(container, dt, result) {
    // skip provisioning_status
}

function service_usercertificate_get(result) {

    var usercertificate = result['usercertificate'];
    if (!usercertificate) {
        alert('Service has no usercertificate.');
        return;
    }

    var krbprincipalname = result['krbprincipalname'][0];
    var service_name = krbprincipalname.replace(/@.*$/, '');

    var dialog = certificate_get_dialog({
        'title': 'Certificate for Service '+service_name,
        'usercertificate': usercertificate[0].__base64__
    });

    dialog.open();
}

function service_usercertificate_view(result) {

    var usercertificate = result['usercertificate'];
    if (!usercertificate) {
        alert('Service has no usercertificate.');
        return;
    }

    var krbprincipalname = result['krbprincipalname'][0];
    var service_name = krbprincipalname.replace(/@.*$/, '');

    var dialog = certificate_view_dialog({
        'title': 'Certificate for Service '+service_name,
        'subject': result['subject'],
        'serial_number': result['serial_number'],
        'issuer': result['issuer'],
        'issued_on': result['valid_not_before'],
        'expires_on': result['valid_not_after'],
        'md5_fingerprint': result['md5_fingerprint'],
        'sha1_fingerprint': result['sha1_fingerprint']
    });

    dialog.open();
}

function service_usercertificate_revoke(result) {

    var usercertificate = result['usercertificate'];
    if (!usercertificate) {
        alert('Service has no usercertificate.');
        return;
    }

    var krbprincipalname = result['krbprincipalname'][0];
    var service_name = krbprincipalname.replace(/@.*$/, '');

    var serial_number = result['serial_number'];

    var dialog = certificate_revoke_dialog({
        'title': 'Revoke Certificate for Service '+service_name,
        'revoke': function(values) {
            var reason = values['reason'];

            ipa_cmd(
                'cert_revoke',
                [serial_number],
                {
                    'revocation_reason': reason
                },
                function(data, text_status, xhr) {
                    var dialog = certificate_confirmation_dialog({
                        title: 'Success',
                        message: 'Certificate has been revoked successfully.'
                    });
                    dialog.open();
                }
            );
        }
    });

    dialog.open();
}

function service_usercertificate_restore(result) {

    var usercertificate = result['usercertificate'];
    if (!usercertificate) {
        alert('Service has no usercertificate.');
        return;
    }

    var krbprincipalname = result['krbprincipalname'][0];
    var service_name = krbprincipalname.replace(/@.*$/, '');

    var serial_number = result['serial_number'];

    var dialog = certificate_restore_dialog({
        'title': 'Restore Certificate for Service '+service_name,
        'restore': function(values) {
            ipa_cmd(
                'cert_remove_hold',
                [serial_number],
                { },
                function(data, text_status, xhr) {
                    var dialog = certificate_confirmation_dialog({
                        title: 'Success',
                        message: 'Certificate has been restored successfully.'
                    });
                    dialog.open();
                }
            );
        }
    });

    dialog.open();
}

function service_usercertificate_request(result) {

    var krbprincipalname = result['krbprincipalname'][0];
    var service_name = krbprincipalname.replace(/@.*$/, '');

    var dialog = certificate_request_dialog({
        'title': 'Issue New Certificate for Service '+service_name,
        'request': function(values) {
            var request = values['request'];

            ipa_cmd(
                'cert_request',
                [request],
                {
                    'principal': krbprincipalname
                }
            );
        }
    });

    dialog.open();
}

function service_usercertificate_load(container, dt, result) {

    var krbprincipalname = result['krbprincipalname'][0];

    var table = $('<table/>');

    var tr = $('<tr/>').appendTo(table);

    var td = $('<td/>').appendTo(tr);
    td.append('Valid Certificate Present:');

    td = $('<td/>').appendTo(tr);
    $('<input/>', {
        type: 'button',
        value: 'Get',
        click: function() {
            ipa_cmd('service_show', [krbprincipalname], {},
                function(data, text_status, xhr) {
                    service_usercertificate_get(data.result.result);
                }
            );
        }
    }).appendTo(td);

    $('<input/>', {
        type: 'button',
        value: 'Revoke',
        click: function() {
            ipa_cmd('service_show', [krbprincipalname], {},
                function(data, text_status, xhr) {
                    service_usercertificate_revoke(data.result.result);
                }
            );
        }
    }).appendTo(td);

    $('<input/>', {
        type: 'button',
        value: 'View',
        click: function() {
            ipa_cmd('service_show', [krbprincipalname], {},
                function(data, text_status, xhr) {
                    service_usercertificate_view(data.result.result);
                }
            );
        }
    }).appendTo(td);

    tr = $('<tr/>').appendTo(table);

    td = $('<td/>').appendTo(tr);
    td.append('Certificate Revoked:');

    td = $('<td/>').appendTo(tr);
    $('<input/>', {
        type: 'button',
        value: 'Restore',
        click: function() {
            ipa_cmd('service_show', [krbprincipalname], {},
                function(data, text_status, xhr) {
                    service_usercertificate_restore(data.result.result);
                }
            );
        }
    }).appendTo(td);

    tr = $('<tr/>').appendTo(table);

    td = $('<td/>').appendTo(tr);
    td.append('No Valid Certificate:');

    td = $('<td/>').appendTo(tr);
    $('<input/>', {
        type: 'button',
        value: 'New Certificate',
        click: function() {
            service_usercertificate_request(result);
        }
    }).appendTo(td);

    var dd = ipa_create_first_dd(this.name, table);
    dt.after(dd);
}
