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

var BEGIN_CERTIFICATE = '-----BEGIN CERTIFICATE-----';
var END_CERTIFICATE   = '-----END CERTIFICATE-----';

var BEGIN_CERTIFICATE_REQUEST = '-----BEGIN CERTIFICATE REQUEST-----';
var END_CERTIFICATE_REQUEST   = '-----END CERTIFICATE REQUEST-----';

var CRL_REASON = [
    'Unspecified',
    'Key Compromise',
    'CA Compromise',
    'Affiliation Changed',
    'Superseded',
    'Cessation of Operation',
    'Certificate Hold',
    null,
    'Remove from CRL',
    'Privilege Withdrawn',
    'AA Compromise'
];

var CERTIFICATE_STATUS_MISSING = 0;
var CERTIFICATE_STATUS_VALID   = 1;
var CERTIFICATE_STATUS_REVOKED = 2;

function certificate_parse_dn(dn) {

    var result = {};
    if (!dn) return result;

    // TODO: Use proper LDAP DN parser
    var rdns = dn.split(',');
    for (var i=0; i<rdns.length; i++) {
        var rdn = rdns[i];
        if (!rdn) continue;

        var parts = rdn.split('=');
        var name = $.trim(parts[0].toLowerCase());
        var value = $.trim(parts[1]);

        var old_value = result[name];
        if (!old_value) {
            result[name] = value;
        } else if (typeof old_value == "string") {
            result[name] = [old_value, value];
        } else {
            result[name].push(value);
        }
    }

    return result;
}

function certificate_get_dialog(spec) {
    var that = {};
    spec = spec || {};

    that.title = spec.title || '';
    that.usercertificate = spec.usercertificate || '';

    var dialog = $('<div/>', {
        'title': that.title
    });

    var textarea = $('<textarea/>', {
        readonly: 'yes',
        style: 'width: 100%; height: 275px;'
    }).appendTo(dialog);

    textarea.val(
        BEGIN_CERTIFICATE+'\n'+
        that.usercertificate+'\n'+
        END_CERTIFICATE
    );

    that.open = function() {
        dialog.dialog({
            modal: true,
            width: 500,
            height: 400,
            buttons: {
                'Close': function() {
                    dialog.dialog('destroy');
                }
            }
        });
    };

    return that;
}

function certificate_revoke_dialog(spec) {
    var that = {};
    spec = spec || {};

    that.title = spec.title || '';
    that.revoke = spec.revoke;

    var dialog = $('<div/>', {
        'title': that.title
    });

    var table = $('<table/>').appendTo(dialog);

    var tr = $('<tr/>').appendTo(table);

    var td = $('<td/>').appendTo(tr);
    td.append('Note:');

    td = $('<td/>').appendTo(tr);
    td.append(
        'To confirm your intention to revoke this certificate, '+
        'select a reason from the pull-down list, and click '+
        'the "Revoke" button.');

    tr = $('<tr/>').appendTo(table);

    td = $('<td/>').appendTo(tr);
    td.append('Reason for Revocation:');

    td = $('<td/>').appendTo(tr);

    var select = $('<select/>').appendTo(td);
    for (var i=0; i<CRL_REASON.length; i++) {
        if (!CRL_REASON[i]) continue;
        $('<option/>', {
            'value': i,
            'html': CRL_REASON[i]
        }).appendTo(select);
    }

    that.open = function() {
        dialog.dialog({
            modal: true,
            width: 500,
            height: 300,
            buttons: {
                'Revoke': function() {
                    var values = {};
                    values['reason'] = select.val();
                    if (that.revoke) {
                        that.revoke(values);
                    }
                    dialog.dialog('destroy');
                },
                'Cancel': function() {
                    dialog.dialog('destroy');
                }
            }
        });
    };

    return that;
}

function certificate_restore_dialog(spec) {
    var that = {};
    spec = spec || {};

    that.title = spec.title || '';
    that.restore = spec.restore;

    var dialog = $('<div/>', {
        'title': that.title
    });

    dialog.append(
        'To confirm your intention to restore this certificate, '+
        'click the "Restore" button.');

    that.open = function() {
        dialog.dialog({
            modal: true,
            width: 400,
            height: 200,
            buttons: {
                'Restore': function() {
                    var values = {};
                    if (that.restore) {
                        that.restore(values);
                    }
                    dialog.dialog('destroy');
                },
                'Cancel': function() {
                    dialog.dialog('destroy');
                }
            }
        });
    };

    return that;
}

function certificate_view_dialog(spec) {
    var that = {};
    spec = spec || {};

    that.title = spec.title || '';
    that.subject = certificate_parse_dn(spec.subject);
    that.serial_number = spec.serial_number || '';
    that.issuer = certificate_parse_dn(spec.issuer);
    that.issued_on = spec.issued_on || '';
    that.expires_on = spec.expires_on || '';
    that.md5_fingerprint = spec.md5_fingerprint || '';
    that.sha1_fingerprint = spec.sha1_fingerprint || '';

    var dialog = $('<div/>', {
        'title': that.title
    });

    var table = $('<table/>').appendTo(dialog);

    var tr = $('<tr/>').appendTo(table);
    $('<td/>', {
        'colspan': 2,
        'html': '<h3>Issued To</h3>'
    }).appendTo(tr);

    tr = $('<tr/>').appendTo(table);
    $('<td>Common Name:</td>').appendTo(tr);
    $('<td/>', {
        'html': that.subject.cn
    }).appendTo(tr);

    tr = $('<tr/>').appendTo(table);
    $('<td>Organization:</td>').appendTo(tr);
    $('<td/>', {
        'html': that.subject.o
    }).appendTo(tr);

    tr = $('<tr/>').appendTo(table);
    $('<td>Organizational Unit:</td>').appendTo(tr);
    $('<td/>', {
        'html': that.subject.ou
    }).appendTo(tr);

    tr = $('<tr/>').appendTo(table);
    $('<td>Serial Number:</td>').appendTo(tr);
    $('<td/>', {
        'html': that.serial_number
    }).appendTo(tr);

    tr = $('<tr/>').appendTo(table);
    $('<td/>', {
        'colspan': 2,
        'html': '<h3>Issued By</h3>'
    }).appendTo(tr);

    tr = $('<tr/>').appendTo(table);
    $('<td>Common Name:</td>').appendTo(tr);
    $('<td/>', {
        'html': that.issuer.cn
    }).appendTo(tr);

    tr = $('<tr/>').appendTo(table);
    $('<td>Organization:</td>').appendTo(tr);
    $('<td/>', {
        'html': that.issuer.o
    }).appendTo(tr);

    tr = $('<tr/>').appendTo(table);
    $('<td>Organizational Unit:</td>').appendTo(tr);
    $('<td/>', {
        'html': that.issuer.ou
    }).appendTo(tr);

    tr = $('<tr/>').appendTo(table);
    $('<td/>', {
        'colspan': 2,
        'html': '<h3>Validity</h3>'
    }).appendTo(tr);

    tr = $('<tr/>').appendTo(table);
    $('<td>Issued On:</td>').appendTo(tr);
    $('<td/>', {
        'html': that.issued_on
    }).appendTo(tr);

    tr = $('<tr/>').appendTo(table);
    $('<td>Expires On:</td>').appendTo(tr);
    $('<td/>', {
        'html': that.expires_on
    }).appendTo(tr);

    tr = $('<tr/>').appendTo(table);
    $('<td/>', {
        'colspan': 2,
        'html': '<h3>Fingerprints</h3>'
    }).appendTo(tr);

    tr = $('<tr/>').appendTo(table);
    $('<td>SHA1 Fingerprint:</td>').appendTo(tr);
    $('<td/>', {
        'html': that.sha1_fingerprint
    }).appendTo(tr);

    tr = $('<tr/>').appendTo(table);
    $('<td>MD5 Fingerprint:</td>').appendTo(tr);
    $('<td/>', {
        'html': that.md5_fingerprint
    }).appendTo(tr);

    that.open = function() {
        dialog.dialog({
            modal: true,
            width: 600,
            height: 500,
            buttons: {
                'Close': function() {
                    dialog.dialog('destroy');
                }
            }
        });
    };

    return that;
}

function certificate_request_dialog(spec) {
    var that = {};
    spec = spec || {};

    that.title = spec.title || '';
    that.request = spec.request;

    var dialog = $('<div/>', {
        'title': that.title
    });

    dialog.append('Copy and paste the Base64-encoded CSR below:');
    dialog.append('<br/>');
    dialog.append('<br/>');

    dialog.append(BEGIN_CERTIFICATE_REQUEST);
    dialog.append('<br/>');

    var textarea = $('<textarea/>', {
        style: 'width: 100%; height: 225px;'
    }).appendTo(dialog);

    dialog.append('<br/>');
    dialog.append(END_CERTIFICATE_REQUEST);

    that.open = function() {
        dialog.dialog({
            modal: true,
            width: 500,
            height: 400,
            buttons: {
                'Issue': function() {
                    var values = {};
                    var request = textarea.val();
                    request =
                        BEGIN_CERTIFICATE_REQUEST+'\n'+
                        $.trim(request)+'\n'+
                        END_CERTIFICATE_REQUEST+'\n';
                    values['request'] = request;
                    if (that.request) {
                        that.request(values);
                    }
                    dialog.dialog('destroy');
                },
                'Cancel': function() {
                    dialog.dialog('destroy');
                }
            }
        });
    };

    return that;
}

function certificate_status_panel(spec) {
    var that = $('<div/>');
    spec = spec || {};

    that.entity_type = spec.entity_type;
    that.entity_label = spec.entity_label || that.entity_type;

    that.result = spec.result;

    that.get_entity_pkey = spec.get_entity_pkey;
    that.get_entity_name = spec.get_entity_name;
    that.get_entity_principal = spec.get_entity_principal;
    that.get_entity_certificate = spec.get_entity_certificate;

    var li1, li2, li3;

    function init() {
        var pkey = that.get_entity_pkey(that.result);

        var table = $('<table/>').appendTo(that);

        var tr = $('<tr/>').appendTo(table);

        var td = $('<td/>').appendTo(tr);
        li1 = $('<li/>', {
            'class': 'certificate-status-valid'
        }).appendTo(td);

        td = $('<td/>').appendTo(tr);
        td.append('Valid Certificate Present:');

        td = $('<td/>').appendTo(tr);
        ipa_button({
            'id': 'get_button',
            'label': 'Get',
            'click': function() {
                ipa_cmd(that.entity_type+'_show', [pkey], {},
                    function(data, text_status, xhr) {
                        get_certificate(data.result.result);
                    }
                );
            }
        }).appendTo(td);

        ipa_button({
            'id': 'revoke_button',
            'label': 'Revoke',
            'click': function() {
                ipa_cmd(that.entity_type+'_show', [pkey], {},
                    function(data, text_status, xhr) {
                        revoke_certificate(data.result.result);
                    }
                );
            }
        }).appendTo(td);

        ipa_button({
            'id': 'view_button',
            'label': 'View',
            'click': function() {
                ipa_cmd(that.entity_type+'_show', [pkey], {},
                    function(data, text_status, xhr) {
                        view_certificate(data.result.result);
                    }
                );
            }
        }).appendTo(td);

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>').appendTo(tr);
        li2 = $('<li/>', {
            'class': 'certificate-status-revoked'
        }).appendTo(td);

        td = $('<td/>').appendTo(tr);
        td.append('Certificate Revoked:');

        td = $('<td/>').appendTo(tr);
        td.append($('<span/>', {
            'id': 'revocation_reason'
        }));
        td.append(' ');

        ipa_button({
            'id': 'restore_button',
            'label': 'Restore',
            'click': function() {
                ipa_cmd(that.entity_type+'_show', [pkey], {},
                    function(data, text_status, xhr) {
                        restore_certificate(data.result.result);
                    }
                );
            }
        }).appendTo(td);

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>').appendTo(tr);
        li3 = $('<li/>', {
            'class': 'certificate-status-missing'
        }).appendTo(td);

        td = $('<td/>').appendTo(tr);
        td.append('No Valid Certificate:');

        td = $('<td/>').appendTo(tr);
        ipa_button({
            'id': 'create_button',
            'label': 'New Certificate',
            'click': function() {
                request_certificate(that.result);
            }
        }).appendTo(td);

        var entity_certificate = that.get_entity_certificate(that.result);
        if (entity_certificate) {
            check_status(that.result.serial_number);
        } else {
            set_status(CERTIFICATE_STATUS_MISSING);
        }
    }

    function set_status(status, revocation_reason) {
        li1.toggleClass('certificate-status-active', status == CERTIFICATE_STATUS_VALID);
        li2.toggleClass('certificate-status-active', status == CERTIFICATE_STATUS_REVOKED);
        li3.toggleClass('certificate-status-active', status == CERTIFICATE_STATUS_MISSING);

        $('#get_button', that).css('visibility', status == CERTIFICATE_STATUS_VALID ? 'visible' : 'hidden');
        $('#revoke_button', that).css('visibility', status == CERTIFICATE_STATUS_VALID ? 'visible' : 'hidden');
        $('#view_button', that).css('visibility', status == CERTIFICATE_STATUS_VALID ? 'visible' : 'hidden');
        $('#revocation_reason', that).html(revocation_reason == undefined ? '' : CRL_REASON[revocation_reason]);
        $('#restore_button', that).css('visibility', revocation_reason == 6 ? 'visible' : 'hidden');
    }

    function check_status(serial_number) {
        ipa_cmd(
            'cert_show',
            [serial_number],
            { },
            function(data, text_status, xhr) {
                var revocation_reason = data.result.result.revocation_reason;
                if (revocation_reason == undefined) {
                    set_status(CERTIFICATE_STATUS_VALID);
                } else {
                    set_status(CERTIFICATE_STATUS_REVOKED, revocation_reason);
                }
            }
        );
    }

    function view_certificate(result) {

        var entity_certificate = that.get_entity_certificate(result);
        if (!entity_certificate) {
            set_status(CERTIFICATE_STATUS_MISSING);
            return;
        }

        var entity_name = that.get_entity_name(result);

        var dialog = certificate_view_dialog({
            'title': 'Certificate for '+that.entity_label+' '+entity_name,
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

    function get_certificate(result) {

        var entity_certificate = that.get_entity_certificate(result);
        if (!entity_certificate) {
            set_status(CERTIFICATE_STATUS_MISSING);
            return;
        }

        var entity_name = that.get_entity_name(result);

        var dialog = certificate_get_dialog({
            'title': 'Certificate for '+that.entity_label+' '+entity_name,
            'usercertificate': entity_certificate
        });

        dialog.open();
    }

    function request_certificate(result) {

        var entity_name = that.get_entity_name(result);
        var entity_principal = that.get_entity_principal(result);

        var dialog = certificate_request_dialog({
            'title': 'Issue New Certificate for '+that.entity_label+' '+entity_name,
            'request': function(values) {
                var request = values['request'];

                ipa_cmd(
                    'cert_request',
                    [request],
                    {
                        'principal': entity_principal
                    },
                    function(data, text_status, xhr) {
                        check_status(data.result.result.serial_number);
                    }
                );
            }
        });

        dialog.open();
    }

    function revoke_certificate(result) {

        var entity_certificate = that.get_entity_certificate(result);
        if (!entity_certificate) {
            set_status(CERTIFICATE_STATUS_MISSING);
            return;
        }

        var entity_name = that.get_entity_name(result);
        var serial_number = result['serial_number'];

        var dialog = certificate_revoke_dialog({
            'title': 'Revoke Certificate for '+that.entity_label+' '+entity_name,
            'revoke': function(values) {
                var reason = values['reason'];

                ipa_cmd(
                    'cert_revoke',
                    [serial_number],
                    {
                        'revocation_reason': reason
                    },
                    function(data, text_status, xhr) {
                        check_status(serial_number);
                    }
                );
            }
        });

        dialog.open();
    }

    function restore_certificate(result) {

        var entity_certificate = that.get_entity_certificate(result);
        if (!entity_certificate) {
            set_status(CERTIFICATE_STATUS_MISSING);
            return;
        }

        var entity_name = that.get_entity_name(result);
        var serial_number = result['serial_number'];

        var dialog = certificate_restore_dialog({
            'title': 'Restore Certificate for '+that.entity_label+' '+entity_name,
            'restore': function(values) {
                ipa_cmd(
                    'cert_remove_hold',
                    [serial_number],
                    { },
                    function(data, text_status, xhr) {
                        check_status(serial_number);
                    }
                );
            }
        });

        dialog.open();
    }

    init();

    return that;
}
