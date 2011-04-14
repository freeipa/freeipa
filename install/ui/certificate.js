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

IPA.cert = {};

IPA.cert.BEGIN_CERTIFICATE = '-----BEGIN CERTIFICATE-----';
IPA.cert.END_CERTIFICATE   = '-----END CERTIFICATE-----';

IPA.cert.BEGIN_CERTIFICATE_REQUEST = '-----BEGIN CERTIFICATE REQUEST-----';
IPA.cert.END_CERTIFICATE_REQUEST   = '-----END CERTIFICATE REQUEST-----';

IPA.cert.CERTIFICATE_STATUS_MISSING = 0;
IPA.cert.CERTIFICATE_STATUS_VALID   = 1;
IPA.cert.CERTIFICATE_STATUS_REVOKED = 2;

IPA.cert.CRL_REASON = [
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

IPA.cert.parse_dn = function(dn) {

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
};

IPA.cert.download_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.width = spec.width || 500;
    that.height = spec.height || 400;
    that.add_pem_delimiters = typeof spec.add_pem_delimiters == 'undefined' ? true : spec.add_pem_delimiters;

    that.certificate = spec.certificate || '';

    that.add_button(IPA.messages.buttons.close, function() {
        that.close();
    });

    that.create = function() {
        var textarea = $('<textarea/>', {
            readonly: 'yes',
            style: 'width: 100%; height: 275px;'
        }).appendTo(that.container);

        var certificate = that.certificate;

        if (that.add_pem_delimiters) {
            certificate = IPA.cert.BEGIN_CERTIFICATE+'\n'+
                that.certificate+'\n'+
                IPA.cert.END_CERTIFICATE;
        }

        textarea.val(certificate);
    };

    return that;
};

IPA.cert.revoke_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.width = spec.width || 500;
    that.height = spec.height || 300;

    that.revoke = spec.revoke;

    that.add_button(IPA.messages.buttons.revoke, function() {
        var values = {};
        values['reason'] = that.select.val();
        if (that.revoke) {
            that.revoke(values);
        }
        that.close();
    });

    that.add_button(IPA.messages.buttons.cancel, function() {
        that.close();
    });

    that.create = function() {

        var table = $('<table/>').appendTo(that.container);

        var tr = $('<tr/>').appendTo(table);

        var td = $('<td/>').appendTo(tr);
        td.append(IPA.messages.objects.cert.note+':');

        td = $('<td/>').appendTo(tr);
        td.append(IPA.messages.objects.cert.revoke_confirmation);

        tr = $('<tr/>').appendTo(table);

        td = $('<td/>').appendTo(tr);
        td.append(IPA.messages.objects.cert.reason+':');

        td = $('<td/>').appendTo(tr);

        that.select = $('<select/>').appendTo(td);
        for (var i=0; i<IPA.cert.CRL_REASON.length; i++) {
            if (!IPA.cert.CRL_REASON[i]) continue;
            $('<option/>', {
                'value': i,
                'html': IPA.cert.CRL_REASON[i]
            }).appendTo(that.select);
        }
    };

    return that;
};

IPA.cert.restore_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.width = spec.width || 400;
    that.height = spec.height || 200;

    that.restore = spec.restore;

    that.add_button(IPA.messages.buttons.restore, function() {
        var values = {};
        if (that.restore) {
            that.restore(values);
        }
        that.close();
    });

    that.add_button(IPA.messages.buttons.cancel, function() {
        that.close();
    });

    that.create = function() {
        that.container.append(
            IPA.messages.objects.cert.restore_confirmation);
    };

    return that;
};

IPA.cert.view_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.width = spec.width || 600;
    that.height = spec.height || 500;

    that.subject = IPA.cert.parse_dn(spec.subject);
    that.serial_number = spec.serial_number || '';
    that.issuer = IPA.cert.parse_dn(spec.issuer);
    that.issued_on = spec.issued_on || '';
    that.expires_on = spec.expires_on || '';
    that.md5_fingerprint = spec.md5_fingerprint || '';
    that.sha1_fingerprint = spec.sha1_fingerprint || '';

    that.add_button(IPA.messages.buttons.close, function() {
        that.close();
    });

    that.create = function() {

        var table = $('<table/>').appendTo(that.container);

        var tr = $('<tr/>').appendTo(table);
        $('<td/>', {
            'colspan': 2,
            'html': '<h3>'+IPA.messages.objects.cert.issued_to+'</h3>'
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.common_name+':</td>').appendTo(tr);
        $('<td/>', {
            'html': that.subject.cn
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.organization+':</td>').appendTo(tr);
        $('<td/>', {
            'html': that.subject.o
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.organizational_unit+':</td>').appendTo(tr);
        $('<td/>', {
            'html': that.subject.ou
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.serial_number+':</td>').appendTo(tr);
        $('<td/>', {
            'html': that.serial_number
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td/>', {
            'colspan': 2,
            'html': '<h3>'+IPA.messages.objects.cert.issued_by+'</h3>'
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.common_name+':</td>').appendTo(tr);
        $('<td/>', {
            'html': that.issuer.cn
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.organization+':</td>').appendTo(tr);
        $('<td/>', {
            'html': that.issuer.o
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.organizational_unit+':</td>').appendTo(tr);
        $('<td/>', {
            'html': that.issuer.ou
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td/>', {
            'colspan': 2,
            'html': '<h3>'+IPA.messages.objects.cert.validity+'</h3>'
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.issued_on+':</td>').appendTo(tr);
        $('<td/>', {
            'html': that.issued_on
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.expires_on+':</td>').appendTo(tr);
        $('<td/>', {
            'html': that.expires_on
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td/>', {
            'colspan': 2,
            'html': '<h3>'+IPA.messages.objects.cert.fingerprints+'</h3>'
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.sha1_fingerprint+':</td>').appendTo(tr);
        $('<td/>', {
            'html': that.sha1_fingerprint
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.md5_fingerprint+':</td>').appendTo(tr);
        $('<td/>', {
            'html': that.md5_fingerprint
        }).appendTo(tr);
    };

    return that;
};

IPA.cert.request_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.width = spec.width || 500;
    that.height = spec.height || 400;

    that.request = spec.request;

    that.add_button(IPA.messages.buttons.issue, function() {
        var values = {};
        var request = that.textarea.val();
        request =
            IPA.cert.BEGIN_CERTIFICATE_REQUEST+'\n'+
            $.trim(request)+'\n'+
            IPA.cert.END_CERTIFICATE_REQUEST+'\n';
        values['request'] = request;
        if (that.request) {
            that.request(values);
        }
        that.close();
    });

    that.add_button(IPA.messages.buttons.cancel, function() {
        that.close();
    });

    that.create = function() {
        that.container.append(IPA.messages.objects.cert.enter_csr+':');
        that.container.append('<br/>');
        that.container.append('<br/>');

        that.container.append(IPA.cert.BEGIN_CERTIFICATE_REQUEST);
        that.container.append('<br/>');

        that.textarea = $('<textarea/>', {
            style: 'width: 100%; height: 225px;'
        }).appendTo(that.container);

        that.container.append('<br/>');
        that.container.append(IPA.cert.END_CERTIFICATE_REQUEST);
    };

    return that;
};

IPA.cert.status_widget = function(spec) {

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

        content_div.append('<b>'+IPA.messages.objects.cert.valid+':</b>');

        content_div.append(' ');

        $('<input/>', {
            'type': 'button',
            'name': 'get',
            'value': IPA.messages.buttons.get
        }).appendTo(content_div);

        content_div.append(' ');

        if (!that.is_selfsign()) {
            $('<input/>', {
                'type': 'button',
                'name': 'revoke',
                'value': IPA.messages.buttons.revoke
            }).appendTo(content_div);

            content_div.append(' ');
        }

        $('<input/>', {
            'type': 'button',
            'name': 'view',
            'value': IPA.messages.buttons.view
        }).appendTo(content_div);

        content_div.append(' ');

        $('<input/>', {
            'type': 'button',
            'name': 'create',
            'value': IPA.messages.objects.cert.new_certificate
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

            content_div.append('<b>'+IPA.messages.objects.cert.revoked+':</b>');

            content_div.append(' ');

            content_div.append($('<span/>', {
                'name': 'revocation_reason'
            }));

            content_div.append(' ');

            $('<input/>', {
                'type': 'button',
                'name': 'restore',
                'value': IPA.messages.buttons.restore
            }).appendTo(content_div);

            content_div.append(' ');

            $('<input/>', {
                'type': 'button',
                'name': 'create',
                'value': IPA.messages.objects.cert.new_certificate
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

        content_div.append('<b>'+IPA.messages.objects.cert.missing+':</b>');

        content_div.append(' ');

        $('<input/>', {
            'type': 'button',
            'name': 'create',
            'value': IPA.messages.objects.cert.new_certificate
        }).appendTo(content_div);
    };

    that.setup = function(container) {

        that.widget_setup(container);

        that.status_valid = $('div[name=certificate-valid]', that.container);
        that.status_revoked = $('div[name=certificate-revoked]', that.container);
        that.status_missing = $('div[name=certificate-missing]', that.container);

        var button = $('input[name=get]', that.container);
        that.get_button = IPA.button({
            label: IPA.messages.buttons.get,
            'click': function() {
                IPA.command({
                    entity: that.entity_name,
                    method: 'show',
                    args: [that.pkey],
                    on_success: function(data, text_status, xhr) {
                        get_certificate(data.result.result);
                    }
                }).execute();
            }
        });
        button.replaceWith(that.get_button);

        button = $('input[name=revoke]', that.container);
        that.revoke_button = IPA.button({
            label: IPA.messages.buttons.revoke,
            'click': function() {
                IPA.command({
                    entity: that.entity_name,
                    method: 'show',
                    args: [that.pkey],
                    on_success: function(data, text_status, xhr) {
                        revoke_certificate(data.result.result);
                    }
                }).execute();
            }
        });
        button.replaceWith(that.revoke_button);

        button = $('input[name=view]', that.container);
        that.view_button = IPA.button({
            label: IPA.messages.buttons.view,
            'click': function() {
                IPA.command({
                    entity: that.entity_name,
                    method: 'show',
                    args: [that.pkey],
                    on_success: function(data, text_status, xhr) {
                        view_certificate(data.result.result);
                    }
                }).execute();
            }
        });
        button.replaceWith(that.view_button);

        that.revocation_reason = $('span[name=revocation_reason]', that.container);

        button = $('input[name=restore]', that.container);
        that.restore_button = IPA.button({
            label: IPA.messages.buttons.restore,
            'click': function() {
                IPA.command({
                    entity: that.entity_name,
                    method: 'show',
                    args: [that.pkey],
                    on_success: function(data, text_status, xhr) {
                        restore_certificate(data.result.result);
                    }
                }).execute();
            }
        });
        button.replaceWith(that.restore_button);

        $('input[name=create]', that.container).each(function(index) {
            button = $(this);
            that.create_button = IPA.button({
                label: IPA.messages.objects.cert.new_certificate,
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
            that.revoke_button.css('display', status == IPA.cert.CERTIFICATE_STATUS_VALID ? 'inline' : 'none');
            that.revocation_reason.html(revocation_reason == undefined ? '' : IPA.cert.CRL_REASON[revocation_reason]);
            that.restore_button.css('display', revocation_reason == 6 ? 'inline' : 'none');
        }
    }

    function check_status(serial_number) {

        if (that.is_selfsign()) {
            set_status(IPA.cert.CERTIFICATE_STATUS_VALID);
            return;
        }

        IPA.command({
            entity: 'cert',
            method: 'show',
            args: [serial_number],
            on_success: function(data, text_status, xhr) {
                var revocation_reason = data.result.result.revocation_reason;
                if (revocation_reason == undefined) {
                    set_status(IPA.cert.CERTIFICATE_STATUS_VALID);
                } else {
                    set_status(IPA.cert.CERTIFICATE_STATUS_REVOKED, revocation_reason);
                }
            }
        }).execute();
    }

    function view_certificate(result) {

        var entity_certificate = that.get_entity_certificate(result);
        if (!entity_certificate) {
            set_status(IPA.cert.CERTIFICATE_STATUS_MISSING);
            return;
        }

        var entity_name = that.get_entity_name(result);

        var title = IPA.messages.objects.cert.view_certificate;
        title = title.replace('${entity}', that.entity_label);
        title = title.replace('${primary_key}', entity_name);

        var dialog = IPA.cert.view_dialog({
            'title': title,
            'subject': result['subject'],
            'serial_number': result['serial_number'],
            'issuer': result['issuer'],
            'issued_on': result['valid_not_before'],
            'expires_on': result['valid_not_after'],
            'md5_fingerprint': result['md5_fingerprint'],
            'sha1_fingerprint': result['sha1_fingerprint']
        });

        dialog.init();
        dialog.open();
    }

    function get_certificate(result) {

        var entity_certificate = that.get_entity_certificate(result);
        if (!entity_certificate) {
            set_status(IPA.cert.CERTIFICATE_STATUS_MISSING);
            return;
        }

        var entity_name = that.get_entity_name(result);

        var title = IPA.messages.objects.cert.view_certificate;
        title = title.replace('${entity}', that.entity_label);
        title = title.replace('${primary_key}', entity_name);

        var dialog = IPA.cert.download_dialog({
            title: title,
            certificate: entity_certificate
        });

        dialog.init();
        dialog.open();
    }

    function request_certificate(result) {

        var entity_name = that.get_entity_name(result);
        var entity_principal = that.get_entity_principal(result);

        var title = IPA.messages.objects.cert.issue_certificate;
        title = title.replace('${entity}', that.entity_label);
        title = title.replace('${primary_key}', entity_name);

        var dialog = IPA.cert.request_dialog({
            'title': title,
            'request': function(values) {
                var request = values['request'];

                IPA.command({
                    entity: 'cert',
                    method: 'request',
                    args: [request],
                    options: {
                        'principal': entity_principal
                    },
                    on_success: function(data, text_status, xhr) {
                        check_status(data.result.result.serial_number);
                    }
                }).execute();
            }
        });

        dialog.init();
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

        var title = IPA.messages.objects.cert.revoke_certificate;
        title = title.replace('${entity}', that.entity_label);
        title = title.replace('${primary_key}', entity_name);

        var dialog = IPA.cert.revoke_dialog({
            'title': title,
            'revoke': function(values) {
                var reason = values['reason'];

                IPA.command({
                    entity: 'cert',
                    method: 'revoke',
                    args: [serial_number],
                    options: {
                        'revocation_reason': reason
                    },
                    on_success: function(data, text_status, xhr) {
                        check_status(serial_number);
                    }
                }).execute();
            }
        });

        dialog.init();
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

        var title = IPA.messages.objects.cert.restore_certificate;
        title = title.replace('${entity}', that.entity_label);
        title = title.replace('${primary_key}', entity_name);

        var dialog = IPA.cert.restore_dialog({
            'title': title,
            'restore': function(values) {
                IPA.command({
                    entity: 'cert',
                    method: 'remove_hold',
                    args: [serial_number],
                    on_success: function(data, text_status, xhr) {
                        check_status(serial_number);
                    }
                }).execute();
            }
        });

        dialog.init();
        dialog.open();
    }

    return that;
};
