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

function certificate_parse_dn(dn) {

    var result = {};

    // TODO: Use proper LDAP DN parser
    var rdns = dn.split(',');
    for (var i=0; i<rdns.length; i++) {
        var rdn = rdns[i];
        var parts = rdn.split('=');
        var name = parts[0].toLowerCase();
        var value = parts[1];

        result[name] = value;
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
        BEGIN_CERTIFICATE_REQUEST+'\n'+
        that.usercertificate+'\n'+
        END_CERTIFICATE_REQUEST
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
