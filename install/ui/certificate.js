/*jsl:import ipa.js */

/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *
 * Copyright (C) 2010 Red Hat
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


IPA.cert = {
    BEGIN_CERTIFICATE : '-----BEGIN CERTIFICATE-----',
    END_CERTIFICATE   : '-----END CERTIFICATE-----',
    BEGIN_CERTIFICATE_REQUEST : '-----BEGIN CERTIFICATE REQUEST-----',
    END_CERTIFICATE_REQUEST   : '-----END CERTIFICATE REQUEST-----',
    CRL_REASON : [
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
    ],
    CERTIFICATE_STATUS_MISSING : 0,
    CERTIFICATE_STATUS_VALID   : 1,
    CERTIFICATE_STATUS_REVOKED : 2,

    parse_dn : function (dn) {

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
    },


    get_dialog:    function (spec) {
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
            IPA.cert.BEGIN_CERTIFICATE+'\n'+
                that.usercertificate+'\n'+
                IPA.cert.END_CERTIFICATE  );

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
    },


    revoke_dialog: function (spec) {
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
        for (var i=0; i<IPA.cert.CRL_REASON.length; i++) {
            if (!IPA.cert.CRL_REASON[i]) continue;
            $('<option/>', {
                'value': i,
                'html': IPA.cert.CRL_REASON[i]
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
    },

    restore_dialog: function (spec) {
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
    },

    view_dialog: function (spec) {
        var that = {};
        spec = spec || {};

        that.title = spec.title || '';
        that.subject = IPA.cert.parse_dn(spec.subject);
        that.serial_number = spec.serial_number || '';
        that.issuer = IPA.cert.parse_dn(spec.issuer);
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
    },

    request_dialog: function (spec) {
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

        dialog.append(IPA.cert.BEGIN_CERTIFICATE_REQUEST);
        dialog.append('<br/>');

        var textarea = $('<textarea/>', {
            style: 'width: 100%; height: 225px;'
        }).appendTo(dialog);

        dialog.append('<br/>');
        dialog.append(IPA.cert.END_CERTIFICATE_REQUEST);

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
                            IPA.cert.BEGIN_CERTIFICATE_REQUEST+'\n'+
                            $.trim(request)+'\n'+
                            IPA.cert.END_CERTIFICATE_REQUEST+'\n';
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
};

IPA.certificate_status_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.entity_label = spec.entity_label || that.entity_name;

    that.result = spec.result;

    that.get_entity_pkey = spec.get_entity_pkey;
    that.get_entity_name = spec.get_entity_name;
    that.get_entity_principal = spec.get_entity_principal;
    that.get_entity_certificate = spec.get_entity_certificate;

    that.is_selfsign = function() {
        return IPA.env.ra_plugin == 'selfsign';
    };

    that.create = function(container) {

        that.widget_create(container);

        var div = $('<div/>', {
            name: 'certificate-valid',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'check.png',
            style: 'float: left;',
            'class': 'status-icon'
        }).appendTo(div);

        var content_div = $('<div/>', {
            style: 'float: left;'
        }).appendTo(div);

        content_div.append('<b>Valid Certificate Present:</b>');

        content_div.append(' ');

        $('<input/>', {
            'type': 'button',
            'name': 'get',
            'value': 'Get'
        }).appendTo(content_div);

        content_div.append(' ');

        if (!that.is_selfsign()) {
            $('<input/>', {
                'type': 'button',
                'name': 'revoke',
                'value': 'Revoke'
            }).appendTo(content_div);

            content_div.append(' ');
        }

        $('<input/>', {
            'type': 'button',
            'name': 'view',
            'value': 'View'
        }).appendTo(content_div);

        content_div.append(' ');

        $('<input/>', {
            'type': 'button',
            'name': 'create',
            'value': 'New Certificate'
        }).appendTo(content_div);

        if (!that.is_selfsign()) {
            div = $('<div/>', {
                name: 'certificate-revoked',
                style: 'display: none;'
            }).appendTo(container);

            $('<img/>', {
                src: 'caution.png',
                style: 'float: left;',
                'class': 'status-icon'
            }).appendTo(div);

            content_div = $('<div/>', {
                style: 'float: left;'
            }).appendTo(div);

            content_div.append('<b>Certificate Revoked:</b>');

            content_div.append(' ');

            content_div.append($('<span/>', {
                'name': 'revocation_reason'
            }));

            content_div.append(' ');

            $('<input/>', {
                'type': 'button',
                'name': 'restore',
                'value': 'Restore'
            }).appendTo(content_div);

            content_div.append(' ');

            $('<input/>', {
                'type': 'button',
                'name': 'create',
                'value': 'New Certificate'
            }).appendTo(content_div);
        }

        div = $('<div/>', {
            name: 'certificate-missing',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'caution.png',
            style: 'float: left;',
            'class': 'status-icon'
        }).appendTo(div);

        content_div = $('<div/>', {
            style: 'float: left;'
        }).appendTo(div);

        content_div.append('<b>No Valid Certificate:</b>');

        content_div.append(' ');

        $('<input/>', {
            'type': 'button',
            'name': 'create',
            'value': 'New Certificate'
        }).appendTo(content_div);
    };

    that.setup = function(container) {

        that.widget_setup(container);

        that.status_valid = $('div[name=certificate-valid]', that.container);
        that.status_revoked = $('div[name=certificate-revoked]', that.container);
        that.status_missing = $('div[name=certificate-missing]', that.container);

        var button = $('input[name=get]', that.container);
        that.get_button = IPA.button({
            'label': 'Get',
            'click': function() {
                IPA.cmd(that.entity_name+'_show', [that.pkey], {},
                    function(data, text_status, xhr) {
                        get_certificate(data.result.result);
                    }
                );
            }
        });
        button.replaceWith(that.get_button);

        button = $('input[name=revoke]', that.container);
        that.revoke_button = IPA.button({
            'label': 'Revoke',
            'click': function() {
                IPA.cmd(that.entity_name+'_show', [that.pkey], {},
                    function(data, text_status, xhr) {
                        revoke_certificate(data.result.result);
                    }
                );
            }
        });
        button.replaceWith(that.revoke_button);

        button = $('input[name=view]', that.container);
        that.view_button = IPA.button({
            'label': 'View',
            'click': function() {
                IPA.cmd(that.entity_name+'_show', [that.pkey], {},
                    function(data, text_status, xhr) {
                        view_certificate(data.result.result);
                    }
                );
            }
        });
        button.replaceWith(that.view_button);

        that.revocation_reason = $('span[name=revocation_reason]', that.container);

        button = $('input[name=restore]', that.container);
        that.restore_button = IPA.button({
            'label': 'Restore',
            'click': function() {
                IPA.cmd(that.entity_name+'_show', [that.pkey], {},
                    function(data, text_status, xhr) {
                        restore_certificate(data.result.result);
                    }
                );
            }
        });
        button.replaceWith(that.restore_button);

        $('input[name=create]', that.container).each(function(index) {
            button = $(this);
            that.create_button = IPA.button({
                'label': 'New Certificate',
                'click': function() {
                    request_certificate(that.result);
                }
            });
            button.replaceWith(that.create_button);
        });
    };

    that.load = function(result) {

        that.result = result;
        that.pkey = that.get_entity_pkey(that.result);

        var entity_certificate = that.get_entity_certificate(that.result);
        if (entity_certificate) {
            check_status(that.result.serial_number);
        } else {
            set_status(IPA.cert.CERTIFICATE_STATUS_MISSING);
        }
    };

    function set_status(status, revocation_reason) {
        that.status_valid.css('display', status == IPA.cert.CERTIFICATE_STATUS_VALID ? 'inline' : 'none');
        that.status_missing.css('display', status == IPA.cert.CERTIFICATE_STATUS_MISSING ? 'inline' : 'none');

        if (!that.is_selfsign()) {
            that.status_revoked.css('display', status == IPA.cert.CERTIFICATE_STATUS_REVOKED ? 'inline' : 'none');
            that.revoke_button.css('visibility', status == IPA.cert.CERTIFICATE_STATUS_VALID ? 'visible' : 'hidden');
            that.revocation_reason.html(revocation_reason == undefined ? '' : IPA.cert.CRL_REASON[revocation_reason]);
            that.restore_button.css('visibility', revocation_reason == 6 ? 'visible' : 'hidden');
        }
    }

    function check_status(serial_number) {

        if (that.is_selfsign()) {
            set_status(IPA.cert.CERTIFICATE_STATUS_VALID);
            return;
        }

        IPA.cmd(
            'cert_show',
            [serial_number],
            { },
            function(data, text_status, xhr) {
                var revocation_reason = data.result.result.revocation_reason;
                if (revocation_reason == undefined) {
                    set_status(IPA.cert.CERTIFICATE_STATUS_VALID);
                } else {
                    set_status(IPA.cert.CERTIFICATE_STATUS_REVOKED, revocation_reason);
                }
            }
        );
    }

    function view_certificate(result) {

        var entity_certificate = that.get_entity_certificate(result);
        if (!entity_certificate) {
            set_status(IPA.cert.CERTIFICATE_STATUS_MISSING);
            return;
        }

        var entity_name = that.get_entity_name(result);

        var dialog = IPA.cert.view_dialog({
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
            set_status(IPA.cert.CERTIFICATE_STATUS_MISSING);
            return;
        }

        var entity_name = that.get_entity_name(result);

        var dialog = IPA.cert.get_dialog({
            'title': 'Certificate for '+that.entity_label+' '+entity_name,
            'usercertificate': entity_certificate
        });

        dialog.open();
    }

    function request_certificate(result) {

        var entity_name = that.get_entity_name(result);
        var entity_principal = that.get_entity_principal(result);

        var dialog = IPA.cert.request_dialog({
            'title': 'Issue New Certificate for '+that.entity_label+' '+entity_name,
            'request': function(values) {
                var request = values['request'];

                IPA.cmd(
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
            set_status(IPA.cert.CERTIFICATE_STATUS_MISSING);
            return;
        }

        var entity_name = that.get_entity_name(result);
        var serial_number = result['serial_number'];

        var dialog = IPA.cert.revoke_dialog({
            'title': 'Revoke Certificate for '+that.entity_label+' '+entity_name,
            'revoke': function(values) {
                var reason = values['reason'];

                IPA.cmd(
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
            set_status(IPA.cert.CERTIFICATE_STATUS_MISSING);
            return;
        }

        var entity_name = that.get_entity_name(result);
        var serial_number = result['serial_number'];

        var dialog = IPA.cert.restore_dialog({
            'title': 'Restore Certificate for '+that.entity_label+' '+entity_name,
            'restore': function(values) {
                IPA.cmd(
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

    return that;
};
