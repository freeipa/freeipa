/*jsl:import ipa.js */

/*  Authors:
 *    Endi Sukma Dewata <edewata@redhat.com>
 *    Petr Vobornik <pvoborni@redhat.com>
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

/*
 * Pre-compiled regular expression to match a PEM cert.
 *
 * regexp group 1: entire canonical cert (delimiters plus base64)
 * regexp group 2: base64 data inside PEM delimiters
 */
IPA.cert.PEM_CERT_REGEXP = RegExp('(-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----)');

/*
 * Pre-compiled regular expression to match a CSR (Certificate Signing Request).
 * The delimiter "CERTIFICATE REQUEST" is the cononical standard, however some legacy
 * software will produce a delimiter with "NEW" in it, i.e. "NEW CERTIFICATE REQUEST"
 * This regexp will work with either form.
 *
 * regexp group 1: entire canonical CSR (delimiters plus base64)
 * regexp group 2: base64 data inside canonical CSR delimiters
 * regexp group 3: entire legacy CSR (delimiters plus base64)
 * regexp group 4: base64 data inside legacy CSR delimiters
 */
IPA.cert.PEM_CSR_REGEXP = RegExp('(-----BEGIN CERTIFICATE REQUEST-----([^-]*)-----END CERTIFICATE REQUEST-----)|(-----BEGIN NEW CERTIFICATE REQUEST-----([^-]*)-----END NEW CERTIFICATE REQUEST-----)');

IPA.cert.CERTIFICATE_STATUS_MISSING = 0;
IPA.cert.CERTIFICATE_STATUS_VALID   = 1;
IPA.cert.CERTIFICATE_STATUS_REVOKED = 2;

IPA.cert.CRL_REASON = [
    'unspecified',
    'key_compromise',
    'ca_compromise',
    'affiliation_changed',
    'superseded',
    'cessation_of_operation',
    'certificate_hold',
    null,
    'remove_from_crl',
    'privilege_withdrawn',
    'aa_compromise'
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

IPA.cert.pem_format_base64 = function(text) {
    /*
     * Input is assumed to be base64 possibly with embedded whitespace.
     * Format the base64 text such that it conforms to PEM, which is a
     * sequence of 64 character lines, except for the last line which
     * may be less than 64 characters. The last line does NOT have a
     * new line appended to it.
     */
    var formatted = "";

    /* Strip out any whitespace including line endings */
    text = text.replace(/\s*/g,"");

    /*
     * Break up into lines with 64 chars each.
     * Do not add a newline to final line.
     */
    for (var i = 0; i < text.length; i+=64) {
        formatted += text.substring(i, i+64);
        if (i+64 < text.length) {
            formatted += "\n";
        }
    }
    return (formatted);
};

IPA.cert.pem_cert_format = function(text) {
    /*
     * Input is assumed to be either PEM formated data or the
     * base64 encoding of DER binary certificate data. Return data
     * in PEM format. The function checks if the input text is PEM
     * formatted, if so it just returns the input text. Otherwise
     * the input is treated as base64 which is formatted to be PEM>
     */

    /*
     * Does the text already have the PEM delimiters?
     * If so just return the text unmodified.
     */
    if (text.match(IPA.cert.PEM_CERT_REGEXP)) {
        return text;
    }
    /* No PEM delimiters so format the base64 & add the delimiters. */
    return IPA.cert.BEGIN_CERTIFICATE + "\n" +
           IPA.cert.pem_format_base64(text) + "\n" +
           IPA.cert.END_CERTIFICATE;
};

IPA.cert.pem_csr_format = function(text) {
    /*
     * Input is assumed to be either PEM formated data or the base64
     * encoding of DER binary certificate request (csr) data. Return
     * data in PEM format. The function checks if the input text is
     * PEM formatted, if so it just returns the input text. Otherwise
     * the input is treated as base64 which is formatted to be PEM>
     */

    /*
     * Does the text already have the PEM delimiters?
     * If so just return the text unmodified.
     */
    if (text.match(IPA.cert.PEM_CSR_REGEXP)) {
        return text;
    }

    /* No PEM delimiters so format the base64 & add the delimiters. */
    return IPA.cert.BEGIN_CERTIFICATE_REQUEST + "\n" +
           IPA.cert.pem_format_base64(text) + "\n" +
           IPA.cert.END_CERTIFICATE_REQUEST;
};

IPA.cert.download_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.width = spec.width || 500;
    that.height = spec.height || 380;
    that.add_pem_delimiters = typeof spec.add_pem_delimiters == 'undefined' ? true : spec.add_pem_delimiters;

    that.certificate = spec.certificate || '';

    that.create_button({
        name: 'close',
        label: IPA.messages.buttons.close,
        click: function() {
            that.close();
        }
    });

    that.create = function() {
        var textarea = $('<textarea/>', {
            'class': 'certificate',
            readonly: 'yes'
        }).appendTo(that.container);

        var certificate = that.certificate;

        if (that.add_pem_delimiters) {
            certificate = IPA.cert.pem_cert_format(that.certificate);
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

    that.create_button({
        name: 'revoke',
        label: IPA.messages.buttons.revoke,
        click: function() {
            var values = {};
            values.reason = that.select.val();
            if (that.revoke) {
                that.revoke(values);
            }
            that.close();
        }
    });

    that.create_button({
        name: 'cancel',
        label: IPA.messages.buttons.cancel,
        click: function() {
            that.close();
        }
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
            var reason = IPA.cert.CRL_REASON[i];
            if (!reason) continue;
            $('<option/>', {
                'value': i,
                'html': IPA.messages.objects.cert[reason]
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

    that.create_button({
        name: 'restore',
        label: IPA.messages.buttons.restore,
        click: function() {
            if (that.restore) {
                that.restore();
            }
            that.close();
        }
    });

    that.create_button({
        name: 'cancel',
        label: IPA.messages.buttons.cancel,
        click: function() {
            that.close();
        }
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

    that.subject = IPA.cert.parse_dn(spec.certificate.subject);
    that.serial_number = spec.certificate.serial_number || '';
    that.serial_number_hex = spec.certificate.serial_number_hex || '';
    that.issuer = IPA.cert.parse_dn(spec.certificate.issuer);
    that.issued_on = spec.certificate.valid_not_before || '';
    that.expires_on = spec.certificate.valid_not_after || '';
    that.md5_fingerprint = spec.certificate.md5_fingerprint || '';
    that.sha1_fingerprint = spec.certificate.sha1_fingerprint || '';

    that.create_button({
        name: 'close',
        label: IPA.messages.buttons.close,
        click: function() {
            that.close();
        }
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
            text: that.subject.cn
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.organization+':</td>').appendTo(tr);
        $('<td/>', {
            text: that.subject.o
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.organizational_unit+':</td>').appendTo(tr);
        $('<td/>', {
            text: that.subject.ou
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.serial_number+':</td>').appendTo(tr);
        $('<td/>', {
            text: that.serial_number
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.serial_number_hex+':</td>').appendTo(tr);
        $('<td/>', {
            text: that.serial_number_hex
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td/>', {
            'colspan': 2,
            'html': '<h3>'+IPA.messages.objects.cert.issued_by+'</h3>'
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.common_name+':</td>').appendTo(tr);
        $('<td/>', {
            text: that.issuer.cn
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.organization+':</td>').appendTo(tr);
        $('<td/>', {
            text: that.issuer.o
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.organizational_unit+':</td>').appendTo(tr);
        $('<td/>', {
            text: that.issuer.ou
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td/>', {
            'colspan': 2,
            'html': '<h3>'+IPA.messages.objects.cert.validity+'</h3>'
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.issued_on+':</td>').appendTo(tr);
        $('<td/>', {
            text: that.issued_on
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.expires_on+':</td>').appendTo(tr);
        $('<td/>', {
            text: that.expires_on
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td/>', {
            'colspan': 2,
            'html': '<h3>'+IPA.messages.objects.cert.fingerprints+'</h3>'
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.sha1_fingerprint+':</td>').appendTo(tr);
        $('<td/>', {
            text: that.sha1_fingerprint
        }).appendTo(tr);

        tr = $('<tr/>').appendTo(table);
        $('<td>'+IPA.messages.objects.cert.md5_fingerprint+':</td>').appendTo(tr);
        $('<td/>', {
            text: that.md5_fingerprint
        }).appendTo(tr);
    };

    return that;
};

IPA.cert.request_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.width = spec.width || 600;
    that.height = spec.height || 480;
    that.message = spec.message;

    that.request = spec.request;

    that.create_button({
        name: 'issue',
        label: IPA.messages.buttons.issue,
        click: function() {
            var values = {};
            var request = $.trim(that.textarea.val());
            values.request = IPA.cert.pem_csr_format(request);
            if (that.request) {
                that.request(values);
            }
            that.close();
        }
    });

    that.create_button({
        name: 'cancel',
        label: IPA.messages.buttons.cancel,
        click: function() {
            that.close();
        }
    });

    that.create = function() {
        that.container.append(that.message);

        that.textarea = $('<textarea/>', {
            'class': 'certificate'
        }).appendTo(that.container);
    };

    return that;
};

IPA.cert.loader = function(spec) {

    spec = spec || {};

    var that = {};
    that.get_pkey = spec.get_pkey;
    that.get_name = spec.get_name;
    that.get_principal = spec.get_principal;
    that.get_hostname = spec.get_hostname;

    that.load = function (result) {

        var certificate = {
            issuer: result.issuer,
            certificate: result.certificate,
            md5_fingerprint: result.md5_fingerprint,
            revocation_reason: result.revocation_reason,
            serial_number: result.serial_number,
            serial_number_hex: result.serial_number_hex,
            sha1_fingerprint: result.sha1_fingerprint,
            subject: result.subject,
            valid_not_after: result.valid_not_after,
            valid_not_before: result.valid_not_before
        };

        if (that.get_entity_certificate) {
            certificate.certificate = that.get_entity_certificate(result);
        } else if (!certificate.certificate && result.usercertificate) {
            // default method of storing certificate for object commands
            // which include certificate
            certificate.certificate = result.usercertificate[0].__base64__;
        }

        var info = {};

        if (that.get_pkey) info.pkey = that.get_pkey(result);
        if (that.get_name) info.name = that.get_name(result);
        if (that.get_principal) info.principal = that.get_principal(result);
        if (that.get_hostname) info.hostname = that.get_hostname(result);

        certificate.entity_info = info;

        return certificate;
    };

    return that;
};

IPA.cert.load_policy = function(spec) {

    spec = spec || {};
    spec.loader = spec.loader || {
        factory: IPA.cert.loader,
        get_pkey: spec.get_pkey,
        get_name: spec.get_name,
        get_principal: spec.get_principal,
        get_hostname: spec.get_hostname
    };

    var that = IPA.facet_policy();
    that.loader = IPA.build(spec.loader);

    that.post_load = function(data) {

        // update cert info in facet (show at least something)
        var certificate = that.loader.load(data.result.result);

        //store cert directly to facet. FIXME: introduce concept of models
        that.container.certificate = certificate;
        that.notify_loaded();

        // initialize another load of certificate because current entity
        // show commands don't contain revocation_reason so previous data
        // might be slightly incorrect
        if (certificate && certificate.certificate && !IPA.cert.is_selfsign()) {
            that.load_revocation_reason(certificate.serial_number);
        }
    };

    that.load_revocation_reason = function(serial_number) {
        IPA.command({
            entity: 'cert',
            method: 'show',
            args: [serial_number],
            on_success: function(data, text_status, xhr) {
                var cert = that.container.certificate;
                cert.revocation_reason = data.result.result.revocation_reason;
                that.notify_loaded();
            }
        }).execute();
    };

    that.notify_loaded = function() {
        if (that.container.certificate_loaded) {
            that.container.certificate_loaded.notify(
                [that.container.certificate], that.container);
        }
    };

    return that;
};

IPA.cert.is_selfsign = function() {
    return IPA.env.ra_plugin == 'selfsign';
};

IPA.cert.view_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'view_cert';
    spec.label = spec.label || IPA.messages.buttons.view;
    spec.enable_cond = spec.enable_cond || ['has_certificate'];

    var that = IPA.action(spec);
    that.entity_label = spec.entity_label;

    that.execute_action = function(facet) {

        var certificate = facet.certificate;
        if (!certificate) that.facet.refresh();

        var entity_label = that.entity_label || facet.entity.metadata.label_singular;
        var entity_name = certificate.entity_info.name;

        var title = IPA.messages.objects.cert.view_certificate;
        title = title.replace('${entity}', entity_label);
        title = title.replace('${primary_key}', entity_name);

        var dialog = IPA.cert.view_dialog({
            title: title,
            certificate: certificate
        });

        dialog.open();
    };

    return that;
};

IPA.cert.get_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'get_cert';
    spec.label = spec.label || IPA.messages.buttons.get;
    spec.enable_cond = spec.enable_cond || ['has_certificate'];

    var that = IPA.action(spec);
    that.entity_label = spec.entity_label;

    that.execute_action = function(facet) {

        var certificate = facet.certificate;
        if (!certificate) that.facet.refresh();

        var entity_label = that.entity_label || facet.entity.metadata.label_singular;
        var entity_name = certificate.entity_info.name;

        var title = IPA.messages.objects.cert.view_certificate;
        title = title.replace('${entity}', entity_label);
        title = title.replace('${primary_key}', entity_name);

        var dialog = IPA.cert.download_dialog({
            title: title,
            certificate: certificate.certificate
        });

        dialog.open();
    };

    return that;
};

IPA.cert.request_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'request_cert';
    spec.label = spec.label || IPA.messages.objects.cert.new_certificate;

    var that = IPA.action(spec);
    that.entity_label = spec.entity_label;

    that.execute_action = function(facet) {

        var certificate = facet.certificate;
        if (!certificate) facet.refresh();

        var entity_principal = certificate.entity_info.principal;
        var entity_label = that.entity_label || facet.entity.metadata.label_singular;
        var entity_name = certificate.entity_info.name;
        var hostname = certificate.entity_info.hostname;

        var title = IPA.messages.objects.cert.issue_certificate;
        title = title.replace('${entity}', entity_label);
        title = title.replace('${primary_key}', entity_name);

        var request_message = IPA.messages.objects.cert.request_message;
        request_message = request_message.replace(/\$\{hostname\}/g, hostname);
        request_message = request_message.replace(/\$\{realm\}/g, IPA.env.realm);

        var dialog = IPA.cert.request_dialog({
            title: title,
            message: request_message,
            request: function(values) {

                IPA.command({
                    entity: 'cert',
                    method: 'request',
                    args: [values.request],
                    options: {
                        'principal': entity_principal
                    },
                    on_success: function(data, text_status, xhr) {
                        facet.refresh();
                        IPA.notify_success(IPA.messages.objects.cert.requested);
                    }
                }).execute();
            }
        });

        dialog.open();
    };

    return that;
};

IPA.cert.revoke_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'revoke_cert';
    spec.label = spec.label || IPA.messages.buttons.revoke;
    spec.enable_cond = spec.enable_cond || ['has_certificate'];
    spec.disable_cond = spec.disable_cond || ['certificate_revoked'];
    spec.hide_cond = spec.hide_cond || ['selfsign'];

    var that = IPA.action(spec);
    that.entity_label = spec.entity_label;
    that.request_message = spec.request_message;

    that.execute_action = function(facet) {

        var certificate = facet.certificate;
        if (!certificate) facet.refresh();

        var entity_label = that.entity_label || facet.entity.metadata.label_singular;
        var entity_name = certificate.entity_info.name;

        var title = IPA.messages.objects.cert.revoke_certificate;
        title = title.replace('${entity}', entity_label);
        title = title.replace('${primary_key}', entity_name);

        var dialog = IPA.cert.revoke_dialog({
            title: title,
            message: that.request_message,
            revoke: function(values) {

                IPA.command({
                    entity: 'cert',
                    method: 'revoke',
                    args: [certificate.serial_number],
                    options: {
                        'revocation_reason': values.reason
                    },
                    on_success: function(data, text_status, xhr) {
                        facet.refresh();
                        IPA.notify_success(IPA.messages.objects.cert.revoked);
                    }
                }).execute();
            }
        });

        dialog.open();
    };

    return that;
};

IPA.cert.restore_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'restore_cert';
    spec.label = spec.label || IPA.messages.buttons.restore;
    spec.enable_cond = spec.enable_cond || ['has_certificate', 'certificate_hold'];
    spec.hide_cond = spec.hide_cond || ['selfsign'];

    var that = IPA.action(spec);
    that.entity_label = spec.entity_label;
    that.request_message = spec.request_message;

    that.execute_action = function(facet) {

        var certificate = facet.certificate;
        if (!certificate) facet.refresh();

        var entity_label = that.entity_label || facet.entity.metadata.label_singular;
        var entity_name = certificate.entity_info.name;

        var title = IPA.messages.objects.cert.restore_certificate;
        title = title.replace('${entity}', entity_label);
        title = title.replace('${primary_key}', entity_name);

        var dialog = IPA.cert.restore_dialog({
            title: title,
            message: that.request_message,
            restore: function() {

                IPA.command({
                    entity: 'cert',
                    method: 'remove_hold',
                    args: [certificate.serial_number],
                    on_success: function(data, text_status, xhr) {
                        facet.refresh();
                        IPA.notify_success(IPA.messages.objects.cert.restored);
                    }
                }).execute();
            }
        });

        dialog.open();
    };

    return that;
};

IPA.cert.certificate_evaluator = function(spec) {

    spec.name = spec.name || 'has_certificate_evaluator';
    spec.event = spec.event || 'certificate_loaded';

    var that = IPA.state_evaluator(spec);

    that.on_event = function(certificate) {

        var old_state, record, state, value, loaded_value;

        old_state = that.state;
        that.state = [];

        if (certificate && certificate.certificate) {
            that.state.push('has_certificate');

            if (certificate.revocation_reason !== undefined) {
                that.state.push('certificate_revoked');

                if (certificate.revocation_reason === 6) {
                    that.state.push('certificate_hold');
                }
            }
        }

        if (IPA.cert.is_selfsign()) {
            that.state.push('selfsign');
        }

        that.notify_on_change(old_state);
    };

    return that;
};


IPA.cert.status_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.create = function(container) {

        that.widget_create(container);

        that.status_valid = $('<div/>', {
            name: 'certificate-valid',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'images/check-icon.png',
            style: 'float: left;',
            'class': 'status-icon'
        }).appendTo(that.status_valid);

        var content_div = $('<div/>', {
            style: 'float: left;'
        }).appendTo(that.status_valid);

        content_div.append('<b>'+IPA.messages.objects.cert.valid+'</b>');

        that.status_revoked = $('<div/>', {
            name: 'certificate-revoked',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'images/caution-icon.png',
            style: 'float: left;',
            'class': 'status-icon'
        }).appendTo(that.status_revoked);

        content_div = $('<div/>', {
            style: 'float: left;'
        }).appendTo(that.status_revoked);

        content_div.append('<b>'+IPA.messages.objects.cert.revoked+'</b>');
        content_div.append(' ');
        that.revocation_reason = $('<span/>', {
            'name': 'revocation_reason'
        }).appendTo(content_div);

        that.status_missing = $('<div/>', {
            name: 'certificate-missing',
            style: 'display: none;'
        }).appendTo(container);

        $('<img/>', {
            src: 'images/caution-icon.png',
            style: 'float: left;',
            'class': 'status-icon'
        }).appendTo(that.status_missing);

        content_div = $('<div/>', {
            style: 'float: left;'
        }).appendTo(that.status_missing);

        content_div.append('<b>'+IPA.messages.objects.cert.missing+'</b>');
    };

    that.update = function(certificate) {

        certificate = certificate || {};

        var selfsign = IPA.cert.is_selfsign();
        var has_certificate = certificate.certificate;
        var revoked = certificate.revocation_reason !== undefined;
        var status = IPA.cert.CERTIFICATE_STATUS_MISSING;

        if (has_certificate && (selfsign || !revoked)) {
            status = IPA.cert.CERTIFICATE_STATUS_VALID;
        } else if (has_certificate) {
            status = IPA.cert.CERTIFICATE_STATUS_REVOKED;
        }
        that.set_status(status, certificate.revocation_reason);
    };

    that.clear = function() {
        that.status_valid.css('display', 'none');
        that.status_missing.css('display', 'none');
        that.status_revoked.css('display', 'none');
        that.revocation_reason.text('');
    };

    that.set_status = function(status, revocation_reason) {
        that.status_valid.css('display', status === IPA.cert.CERTIFICATE_STATUS_VALID ? '' : 'none');
        that.status_missing.css('display', status === IPA.cert.CERTIFICATE_STATUS_MISSING ? '' : 'none');

        if (!IPA.cert.is_selfsign()) {
            that.status_revoked.css('display', status === IPA.cert.CERTIFICATE_STATUS_REVOKED ? '' : 'none');

            var reason = IPA.cert.CRL_REASON[revocation_reason];
            that.revocation_reason.html(revocation_reason === undefined || reason === null ? '' : IPA.messages.objects.cert[reason]);
        }
    };

    return that;
};

IPA.cert.status_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);
    that.registered = false;

    that.load = function(result) {
        that.register_listener();
        that.reset();
    };

    that.set_certificate = function(certificate) {
        that.values = certificate;
        that.reset();
    };

    that.register_listener = function() {
        if (!that.registered) {
            that.registered = true;
            that.container.certificate_loaded.attach(that.set_certificate);
        }
    };

    return that;
};

IPA.widget_factories['certificate_status'] = IPA.cert.status_widget;
IPA.field_factories['certificate_status'] = IPA.cert.status_field;