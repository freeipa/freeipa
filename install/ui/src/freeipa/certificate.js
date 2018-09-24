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

define([
    'dojo/_base/lang',
    'dojo/on',
    './builder',
    './datetime',
    './metadata',
    './ipa',
    './jquery',
    './menu',
    './phases',
    './reg',
    './rpc',
    './text',
    './widget',
    './widgets/DropdownWidget',
    './dialog'],
    function(
        lang, on, builder, datetime, metadata_provider, IPA, $, menu,
        phases, reg, rpc, text, widget_mod, DropdownWidget) {

var exp = IPA.cert = {};

IPA.cert.TOPLEVEL_CA = 'ipa';

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

IPA.cert.get_base64 = function(text) {
    /*
     * Input is assumed to be base64 or PEM formatted certificate.
     * The function just cuts the '-----BEGIN CERTIFICATE----' and
     * '-----END CERTIFICATE-----' strings if they are present.
     * Returns only base64 blob.
     */

    var match = IPA.cert.PEM_CERT_REGEXP.exec(text);

    if (match) {
        match = match[2].replace(/\s*/g, '');
        return $.trim(match);
    }

    text = text.replace(/\s*/g, '');
    return $.trim(text);
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
        label: '@i18n:buttons.close',
        click: function() {
            that.close();
        }
    });

    that.create_content = function() {
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

IPA.cert.revocation_reason_select_widget = function(spec) {
    spec = spec || {};

    var that = IPA.select_widget(spec);

    that.create_options = function() {
        for (var i=0; i<IPA.cert.CRL_REASON.length; i++) {
            var reason = IPA.cert.CRL_REASON[i];
            if (!reason) continue;
            var label = text.get('@i18n:objects.cert.'+reason);
            that.options.push({ label: label, value: i});
        }

        that.select_create_options();
    };

    return that;
};

IPA.cert.revoke_dialog = function(spec, no_init) {

    spec = spec || {};

    spec.width = spec.width || 500;
    spec.ok_label = spec.ok_label || '@i18n:buttons.revoke';
    spec.sections = [
        {
            name: 'note',
            show_header: false,
            fields: [
                {
                    field: false,
                    $type: 'html',
                    name: 'note',
                    html: ''
                }
            ],
            layout:
            {
                $factory: widget_mod.fluid_layout,
                widget_cls: "col-sm-12 controls",
                label_cls: "hide"
            }
        },
        {
            name: 'revocation',
            show_header: false,
            fields: [
                {
                    $type: 'revocation_reason_select',
                    name: 'revocation_reason',
                    label: '@i18n:objects.cert.find_revocation_reason'
                },
                {
                    $type: 'entity_select',
                    label: '@i18n:objects.cert.ca',
                    name: 'cacn',
                    empty_option: false,
                    other_entity: 'ca',
                    other_field: 'cn'
                }
            ]
        }
    ];

    var that = IPA.confirm_dialog(spec);

    that.open = function() {

        that.confirmed = false;
        that.dialog_open();
        that.set_cacn(that.facet.state.cacn);
    };

    that.get_reason = function() {
        return that.get_field('revocation_reason').value[0];
    };

    that.set_cacn = function(cacn) {
        that.get_field('cacn').set_value([cacn]);
    };

    that.get_cacn = function() {
        return that.get_field('cacn').value[0];
    };

    that.create_content = function() {
        that.dialog_create_content();

    };

    that.init = function() {
        var note = text.get('@i18n:objects.cert.revoke_confirmation');
        that.widgets.get_widget('note.note').html = note;
    };

    if (!no_init) that.init();

    return that;
};

IPA.cert.view_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);
    IPA.table_mixin().apply(that);

    that.width = spec.width || 600;
    that.height = spec.height || 500;

    that.subject = IPA.cert.parse_dn(spec.certificate.subject);
    that.serial_number = spec.certificate.serial_number || '';
    that.serial_number_hex = spec.certificate.serial_number_hex || '';
    that.issuer = IPA.cert.parse_dn(spec.certificate.issuer);
    that.issued_on = spec.certificate.valid_not_before || '';
    that.expires_on = spec.certificate.valid_not_after || '';
    that.sha1_fingerprint = spec.certificate.sha1_fingerprint || '';
    that.sha256_fingerprint = spec.certificate.sha256_fingerprint || '';

    that.create_button({
        name: 'close',
        label: '@i18n:buttons.close',
        click: function() {
            that.close();
        }
    });

    that.create_content = function() {

        var new_row = function(title, value) {
            var row = that.create_row();
            row.append(that
                .create_header_cell(title, ':'));
            row.append(that.create_cell(value, '', 'break-words'));

            return row;
        };

        that.create_title('@i18n:objects.cert.issued_to')
            .appendTo(that.container);

        var table_layout = that.create_layout().appendTo(that.container);

        new_row('@i18n:objects.cert.common_name', that.subject.cn)
            .appendTo(table_layout);
        new_row('@i18n:objects.cert.organization', that.subject.o)
            .appendTo(table_layout);
        new_row('@i18n:objects.cert.organizational_unit', that.subject.ou)
            .appendTo(table_layout);
        new_row('@i18n:objects.cert.serial_number',
            that.serial_number.toString()).appendTo(table_layout);
        new_row('@i18n:objects.cert.serial_number_hex', that.serial_number_hex)
            .appendTo(table_layout);

        that.create_title('@i18n:objects.cert.issued_by')
            .appendTo(that.container);

        table_layout = that.create_layout().appendTo(that.container);

        new_row('@i18n:objects.cert.common_name', that.issuer.cn)
            .appendTo(table_layout);
        new_row('@i18n:objects.cert.organization', that.issuer.o)
            .appendTo(table_layout);
        new_row('@i18n:objects.cert.organizational_unit', that.issuer.ou)
            .appendTo(table_layout);

        that.create_title('@i18n:objects.cert.validity')
            .appendTo(that.container);

        table_layout = that.create_layout().appendTo(that.container);

        new_row('@i18n:objects.cert.issued_on', that.issued_on)
            .appendTo(table_layout);
        new_row('@i18n:objects.cert.expires_on', that.expires_on)
            .appendTo(table_layout);

        that.create_title('@i18n:objects.cert.fingerprints')
            .appendTo(that.container);

        table_layout = that.create_layout().appendTo(that.container);

        new_row('@i18n:objects.cert.sha1_fingerprint', that.sha1_fingerprint)
            .appendTo(table_layout);
        new_row('@i18n:objects.cert.sha256_fingerprint', that.sha256_fingerprint)
            .appendTo(table_layout);
    };

    return that;
};

IPA.cert.request_dialog = function(spec) {

    spec = spec || {};

    spec.sections = spec.sections || [];
    var section0 = { fields: [] };
    var section_csr = {
        show_header: false,
        fields: [
            {
                field: false,
                $type: 'html',
                name: 'message',
                html: spec.message
            },
            {
                $type: 'textarea',
                name: 'csr',
                required: true
            }
        ],
        layout:
        {
            $factory: widget_mod.fluid_layout,
            widget_cls: "col-sm-12 controls",
            label_cls: "hide"
        }
    };

    spec.sections.push(section0);
    spec.sections.push(section_csr);

    if (spec.show_principal) {
        section0.fields.push(
            {
                $type: 'text',
                name: 'principal',
                label: '@mc-opt:cert_request:principal:label',
                required: true
            },
            {
                $type: 'checkbox',
                name: 'add',
                label: '@i18n:objects.cert.add_principal',
                tooltip: '@mc-opt:cert_request:add:doc'
            }
        );
    }
    section0.fields.push(
        {
            $type: 'entity_select',
            name: 'cacn',
            label: '@i18n:objects.cert.ca',
            other_entity: 'ca',
            other_field: 'cn',
            required: true
        },
        {
            $type: 'entity_select',
            name: 'profile_id',
            other_entity: 'certprofile',
            other_field: 'cn',
            label: '@mc-opt:cert_request:profile_id:label'
        }
    );

    var that = IPA.dialog(spec);

    that.width = spec.width || 600;
    that.height = spec.height || 480;
    that.message = text.get(spec.message);
    that.show_principal = spec.show_principal;

    that.request = spec.request;

    that.create_button({
        name: 'issue',
        label: '@i18n:buttons.issue',
        click: function() {
            var values = {};
            that.save(values);

            // check requested fields
            if (!that.validate()) {
                widget_mod.focus_invalid(that);
                return;
            }

            // get csr from the textarea
            var request = $.trim(that.get_field('csr').get_value());
            values.request = IPA.cert.pem_csr_format(request);

            if (that.request) {
                that.request(values);
            }
        }
    });

    that.create_button({
        name: 'cancel',
        label: '@i18n:buttons.cancel',
        click: function() {
            that.close();
        }
    });

    that.open = function() {
        that.dialog_open();
        that.get_field('cacn').set_value([IPA.cert.TOPLEVEL_CA]);
    };

    return that;
};

IPA.cert.loader = function(spec) {

    spec = spec || {};

    var that = IPA.object();
    that.get_pkey = spec.get_pkey;
    that.get_name = spec.get_name;
    that.get_principal = spec.get_principal;
    that.get_cn = spec.get_cn;
    that.get_cn_name = spec.get_cn_name;
    that.adapter = builder.build('adapter', spec.adapter || 'adapter', {});

    that.load = function (data) {

        var result = that.adapter.get_record(data);
        var certificate = {
            issuer: result.issuer,
            certificate: result.certificate,
            revocation_reason: result.revocation_reason,
            serial_number: result.serial_number,
            serial_number_hex: result.serial_number_hex,
            sha1_fingerprint: result.sha1_fingerprint,
            sha256_fingerprint: result.sha256_fingerprint,
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
        if (that.get_cn_name) info.cn_name = that.get_cn_name(result);
        if (that.get_cn) info.cn = that.get_cn(result);

        certificate.entity_info = info;

        return certificate;
    };

    return that;
};

IPA.cert.load_policy = function(spec) {

    spec = spec || {};
    spec.loader = spec.loader || {
        $factory: IPA.cert.loader,
        get_pkey: spec.get_pkey,
        get_name: spec.get_name,
        get_principal: spec.get_principal,
        get_cn: spec.get_cn,
        get_cn_name: spec.get_cn_name,
        adapter: spec.adapter
    };

    var that = IPA.facet_policy();
    that.loader = IPA.build(spec.loader);
    that.has_reason = spec.has_reason;

    that.post_load = function(data) {

        // update cert info in facet (show at least something)
        var certificate = that.loader.load(data);

        //store cert directly to facet. FIXME: introduce concept of models
        that.container.certificate = certificate;
        that.notify_loaded();
    };

    that.notify_loaded = function() {
        if (that.container.certificate_loaded) {
            that.container.certificate_loaded.notify(
                [that.container.certificate], that.container);
        }
    };

    return that;
};

IPA.cert.is_enabled = function() {
    return !!IPA.ca_enabled;
};

IPA.cert.create_data_uri = function(certificate) {
    if (typeof certificate !== 'string') return '';

    var format = 'data:,';
    var uri_new_line = '%0A';

    var data_uri = IPA.cert.pem_format_base64(certificate);
    data_uri = IPA.cert.pem_cert_format(data_uri);
    data_uri = format + data_uri.replace(/\n/g, uri_new_line);

    return data_uri;
};

IPA.cert.perform_download = function(data_uri) {
    var a = document.createElement("a");
    // Adding own click function as workaround for Firefox
    a.click = function() {
        var evt = this.ownerDocument.createEvent('MouseEvents');
        evt.initMouseEvent('click', true, true, this.ownerDocument.defaultView,
            1, 0, 0, 0, 0, false, false, false, false, 0, null);
        this.dispatchEvent(evt);
    };
    a.download = 'cert.pem';
    a.href = data_uri;

    a.click();
};

IPA.cert.download_action = function(spec) {
    spec = spec || {};
    spec.name = spec.name || 'download_cert';
    spec.label = spec.label || '@i18n:objects.cert.download';

    var that = IPA.action(spec);

    that.execute_action = function(facet) {
        if (!facet.certificate) return;

        var data_uri = IPA.cert.create_data_uri(facet.certificate.certificate);
        IPA.cert.perform_download(data_uri);
    };

    return that;
};

IPA.cert.request_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'request_cert';
    spec.label = spec.label || '@i18n:objects.cert.new_certificate';
    spec.enable_cond = spec.enable_cond || ['ra_enabled'];
    spec.hide_cond = spec.hide_cond || ['ra_disabled'];

    var that = IPA.action(spec);
    that.generic = spec.generic !== undefined ? spec.generic : false;

    that.execute_action = function(facet) {

        var entity_principal = null;
        var cn_name = 'common name';
        var cn = '&ltcommon name&gt';
        var title = text.get('@i18n:objects.cert.issue_certificate_generic');
        if (!that.generic) {
            var certificate = facet.certificate;
            if (!certificate) facet.refresh();

            entity_principal = certificate.entity_info.principal;
            var entity_name = certificate.entity_info.name;
            cn = certificate.entity_info.cn || cn;
            cn_name = certificate.entity_info.cn_name || cn_name;

            title = text.get(spec.title) || title;
            title = title.replace('${primary_key}', entity_name);
        }

        var request_message = text.get('@i18n:objects.cert.request_message');
        var ext;
        if (facet.entity.name === 'service' || facet.entity.name === 'host') {
            ext = text.get('@i18n:objects.cert.request_message_san');
        }
        else {
            ext = '';
        }
        request_message = request_message.replace(/\$\{san\}/g, ext);
        request_message = request_message.replace(/\$\{cn_name\}/g, cn_name);
        request_message = request_message.replace(/\$\{cn\}/g, cn);
        request_message = request_message.replace(/\$\{realm\}/g, IPA.env.realm);


        var dialog = IPA.cert.request_dialog({
            title: title,
            message: request_message,
            show_principal: !entity_principal,
            request: function(values) {

                var options = {
                    'principal': entity_principal,
                    'cacn': values.cacn[0]
                };
                if (values.profile_id) options.profile_id = values.profile_id[0];
                if (values.principal) options.principal = values.principal[0];
                if (values.add) options.add = values.add[0];

                rpc.command({
                    entity: 'cert',
                    method: 'request',
                    args: [values.request],
                    options: options,
                    on_success: function(data, text_status, xhr) {
                        facet.refresh();
                        dialog.close();
                        IPA.notify_success('@i18n:objects.cert.requested');
                        if (facet.certificate_updated) {
                            facet.certificate_updated.notify([], that.facet);
                        }
                    },
                    on_error: function() {
                        widget_mod.focus_invalid(dialog);
                    }
                }).execute();
            }
        });

        dialog.open();
    };

    return that;
};

IPA.cert.perform_revoke = function(spec, sn, revocation_reason, cacn) {

    /**
     * Sets whether activity notification box will be shown
     * during executing command or not.
     */
    spec.notify_globally = spec.notify_globally === undefined ? true :
            spec.notify_globally;


    /**
     * Specifies function which will be called before command execution starts.
     */
    spec.start_handler = spec.start_handler || null;

    /**
     * Specifies function which will be called after command execution ends.
     */
    spec.end_handler = spec.end_handler || null;

    rpc.command({
        entity: 'cert',
        method: 'revoke',
        args: [ sn ],
        options: {
            revocation_reason: revocation_reason,
            cacn: cacn
        },
        notify_globally: spec.notify_globally,
        start_handler: spec.start_handler,
        end_handler: spec.end_handler,
        on_success: spec.on_success,
        on_error: spec.on_error
    }).execute();
};

IPA.cert.revoke_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'revoke_cert';
    spec.label = spec.label || '@i18n:objects.cert.revoke_certificate_simple';
    spec.enable_cond = spec.enable_cond || ['has_certificate'];
    spec.disable_cond = spec.disable_cond || ['certificate_revoked'];
    spec.hide_cond = spec.hide_cond || ['ra_disabled'];
    spec.confirm_dialog = spec.confirm_dialog || IPA.cert.revoke_dialog;
    spec.needs_confirm = spec.needs_confirm !== undefined ? spec.needs_confirm : true;

    var that = IPA.action(spec);
    that.confirm_msg = spec.request_message;

    that.update_confirm_dialog = function(facet) {

        var certificate = facet.certificate;
        var entity_name = certificate.entity_info.name;

        var title = text.get('@i18n:objects.cert.revoke_certificate_simple');
        if (entity_name) {
            title = text.get(spec.title) || title;
            title = title.replace('${primary_key}', entity_name);
        }

        that.dialog.title = title;
        that.dialog.message = that.get_confirm_message(facet);
    };

    that.execute_action = function(facet) {

        var spec = {
            on_success: function(data, text_status, xhr) {
                facet.refresh();
                IPA.notify_success('@i18n:objects.cert.revoked');
                facet.certificate_updated.notify([], that.facet);
            }
        };

        var sn = facet.certificate.serial_number;
        var revocation_reason = that.dialog.get_reason();
        var cacn = that.dialog.get_cacn();
        IPA.cert.perform_revoke(spec, sn, revocation_reason, cacn);
    };

    return that;
};

IPA.cert.remove_hold_action = function(spec) {

    spec = spec || {};
    spec.name = spec.name || 'remove_hold_cert';
    spec.label = spec.label || '@i18n:objects.cert.remove_hold';
    spec.enable_cond = spec.enable_cond || ['has_certificate', 'certificate_hold'];
    spec.hide_cond = spec.hide_cond || ['ra_disabled'];
    spec.confirm_msg = spec.confirm_msg ||
        '@i18n:objects.cert.remove_certificate_hold_confirmation';
    spec.confirm_dialog = spec.confirm_dialog || {
        $factory: IPA.confirm_dialog,
        ok_label: '@i18n:buttons.remove_hold'
    };
    spec.needs_confirm = spec.needs_confirm !== undefined ? spec.needs_confirm : true;

    var that = IPA.action(spec);

    that.update_confirm_dialog = function(facet) {

        var certificate = facet.certificate;

        var entity_name = certificate.entity_info.name;
        var title = text.get('@i18n:objects.cert.remove_certificate_hold_simple');

        if (entity_name) {
            title = text.get(spec.title) || title;
            title = title.replace('${primary_key}', entity_name);
        }

        that.dialog.title = title;
        that.dialog.message = that.get_confirm_message(facet);
    };

    that.execute_action = function(facet) {

        var spec = {
            on_success: function(data, text_status, xhr) {
                facet.refresh();
                IPA.notify_success('@i18n:objects.cert.hold_removed');
                facet.certificate_updated.notify([], that.facet);
            }
        };

        IPA.cert.perform_remove_hold(spec, facet.certificate.serial_number,
                            facet.state.cacn);
    };

    return that;
};

IPA.cert.perform_remove_hold = function(spec, sn, cacn) {

    /**
     * Sets whether activity notification box will be shown
     * during executing command or not.
     */
    spec.notify_globally = spec.notify_globally === undefined ? true :
            spec.notify_globally;


    /**
     * Specifies function which will be called before command execution starts.
     */
    spec.start_handler = spec.start_handler || null;

    /**
     * Specifies function which will be called after command execution ends.
     */
    spec.end_handler = spec.end_handler || null;


    rpc.command({
        entity: 'cert',
        method: 'remove_hold',
        args: [sn],
        options: {
            cacn: cacn
        },
        on_success: spec.on_success,
        notify_globally: spec.notify_globally,
        start_handler: spec.start_handler,
        end_handler: spec.end_handler
    }).execute();
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

        if (IPA.cert.is_enabled()) {
            that.state.push('ra_enabled');
        } else {
            that.state.push('ra_disabled');
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

        that.status_valid = that.create_status('certificate-valid',
                                               text.get('@i18n:objects.cert.valid'),
                                               'fa fa-check');
        that.status_valid.appendTo(container);

        that.status_revoked = that.create_status('certificate-revoked',
                                               text.get('@i18n:objects.cert.revoked'),
                                               'fa fa-warning');
        that.status_revoked.appendTo(container);

        that.revocation_reason = $('<span/>', {
            'name': 'revocation_reason'
        }).appendTo(that.status_revoked);

        that.status_missing = that.create_status('certificate-missing',
                                               text.get('@i18n:objects.cert.missing'),
                                               'fa fa-warning');
        that.status_missing.appendTo(container);
    };

    that.create_status = function(name, text, icon) {

        var container = $('<div>', {
            name: name,
            style: 'display: none;'
        });

        var status = $('<label/>', {
            'class': 'certificate-status'
        }).appendTo(container);

        $('<i/>', {
            'class': icon
        }).appendTo(status);

        status.append(" " +text);

        return container;
    };

    that.update = function(certificate) {

        certificate = certificate || {};

        var has_certificate = certificate.certificate;
        var revoked = certificate.revocation_reason !== undefined;
        var status = IPA.cert.CERTIFICATE_STATUS_MISSING;

        if (has_certificate && !revoked) {
            status = IPA.cert.CERTIFICATE_STATUS_VALID;
        } else if (has_certificate) {
            status = IPA.cert.CERTIFICATE_STATUS_REVOKED;
        }
        that.set_status(status, certificate.revocation_reason);
        that.on_value_changed(certificate);
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

        if (IPA.cert.is_enabled()) {
            that.status_revoked.css('display', status === IPA.cert.CERTIFICATE_STATUS_REVOKED ? '' : 'none');

            var reason = IPA.cert.CRL_REASON[revocation_reason];
            var reason_text = revocation_reason === undefined || reason === null ? '' : text.get('@i18n:objects.cert.'+reason);
            reason_text = ' ('+reason_text+')';
            that.revocation_reason.html(reason_text);
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
        that.field_load(result);
    };

    that.set_certificate = function(certificate) {
        that.set_value(certificate);
    };

    that.register_listener = function() {
        if (!that.registered) {
            that.registered = true;
            that.container.certificate_loaded.attach(that.set_certificate);
        }
    };

    return that;
};


/**
 * Certificates widget
 *
 * Multivalued widget with certificate widget instead of text widget.
 *
 * @class
 * @extends IPA.multivalued_widget
 */
IPA.cert.certs_widget = function(spec) {

    spec = spec || {};
    spec.child_spec = spec.child_spec || {
        $factory: IPA.cert.cert_widget,
        css_class: 'certificate-widget',
        facet: spec.facet
    };

    spec.item_name = 'cert';

    spec.custom_actions = spec.custom_actions === undefined ? true :
        spec.custom_actions;

    spec.adder_dialog_spec = {
        name: 'cert-add-dialog',
        title: '@i18n:objects.cert.new_certificate',
        sections: [
            {
                show_header: false,
                fields: [
                    {
                        $type: 'textarea',
                        name: 'new_cert',
                        label: '@i18n:objects.cert.new_cert_format',
                        required: true,
                        rows: 15
                    }
                ],
                layout:
                {
                    $factory: widget_mod.fluid_layout,
                    widget_cls: 'col-sm-12',
                    label_cls: 'col-sm-6 control-label'
                }
            }
        ]
    };

    var that = IPA.custom_command_multivalued_widget(spec);

    that.create_remove_options = function(row) {
        var blob = row.widget.save();
        var options = {
            usercertificate: blob
        };

        return options;
    };

    /**
     * Called on success of remove command. Override point.
     */
    that.on_success_remove = function(data, text_status, xhr) {
        that.facet.refresh();
        that.facet.certificate_updated.notify();
        IPA.notify_success(data.result.summary);
    };

    that.create_add_options = function() {
        var blob = that.adder_dialog.get_field('new_cert').get_value()[0];
        blob = IPA.cert.get_base64(blob);
        var options = {
            usercertificate: blob
        };

        return options;
    };

    that.on_success_add = function(data, text_status, xhr) {
        that.facet.refresh();
        that.facet.certificate_updated.notify();
        IPA.notify_success(data.result.summary);
        that.adder_dialog.close();
    };

    that.create_remove_dialog_title = function(row) {
        var title = row.widget.compose_dialog_title();

        return title;
    };

    that.create_remove_dialog_message = function(row) {
        var sn = row.widget.certificate.serial_number;
        var message = text.get('@i18n:actions.delete_confirm');
        message = message.replace('${object}',
            text.get('@i18n:objects.cert.delete_cert_end') + ' ' + sn);

        return message;
    };

    return that;
};

/**
 * certificate widget
 *
 * @class
 * @extends IPA.input_widget
 */
IPA.cert.cert_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);
    IPA.table_mixin().apply(that);

    that.certificate = null;

    that.create = function(container) {

        that.widget_create(container);

        that.container = container;
        that.container.addClass('cert-container col-sm-12');

        var spinner_spec = {
            name: 'working-notification'
        };

        that.spinner = IPA.working_widget(spinner_spec);
        that.spinner.create(that.container);

        that.cert_subject = $('<div />', {
            style: 'font-weight: bold;',
            text: ''
        }).appendTo(that.container);

        that.table_layout = that.create_layout().appendTo(that.container);

        var tr = that.create_row().appendTo(that.table_layout);
        that.create_header_cell('@i18n:objects.cert.serial_number', ':')
            .appendTo(tr);
        that.cert_sn = that.create_cell('', '', 'cert-value').appendTo(tr);

        tr = that.create_row().appendTo(that.table_layout);
        that.create_header_cell('@i18n:objects.cert.issued_by', ':')
            .appendTo(tr);
        that.cert_issuer = that.create_cell('', '', 'cert-value').appendTo(tr);

        tr = that.create_row().appendTo(that.table_layout);
        that.create_header_cell('@i18n:objects.cert.valid_from', ':')
            .appendTo(tr);
        that.cert_valid_from = that.create_cell('', '', 'cert-value')
            .appendTo(tr);

        tr = that.create_row().appendTo(that.table_layout);
        that.create_header_cell('@i18n:objects.cert.valid_to', ':')
            .appendTo(tr);
        that.cert_valid_to = that.create_cell('', '', 'cert-value')
            .appendTo(tr);

        that.dropdown = builder.build(null, {
            $ctor: DropdownWidget,
            toggle_text: text.get('@i18n:actions.title'),
            toggle_class: 'btn btn-default dropdown-toggle',
            toggle_icon: 'caret',
            right_aligned: true,
            name: 'cert-actions',
            'class': 'dropdown cert-actions',
            items: [
                {
                    name: 'view',
                    label: text.get('@i18n:buttons.view'),
                    handler: that.open_view_dialog
                },
                {
                    name: 'get',
                    label: text.get('@i18n:buttons.get'),
                    handler: that.open_get_dialog
                },
                {
                    name: 'download',
                    label: text.get('@i18n:buttons.download'),
                    handler: that.perform_download
                },
                {
                    name: 'revoke',
                    label: text.get('@i18n:buttons.revoke'),
                    disabled: true,
                    handler: that.open_revoke_dialog
                },
                {
                    name: 'remove_hold',
                    label: text.get('@i18n:buttons.remove_hold'),
                    disabled: true,
                    handler: that.perform_remove_hold
                }
            ]
        });

        on(that.dropdown, 'item-click', function(item) {
            if (!item.disabled && item.handler) {
                item.handler();
            }
        });

        that.container.append(that.dropdown.render());
        that.table_layout.appendTo(that.container);

        that.create_error_link(that.container);
    };

    that.get_custom_actions = function() {
        return that.dropdown;
    };

    that.update_displayed_data = function() {

        that.revoke_note = $('<div />', {
            text: text.get('@i18n:objects.cert.revoked_status'),
            style: 'display: none',
            'class': 'watermark'
        }).appendTo(that.container);

        var cert = that.certificate;

        if (cert) {
            that.cert_subject.text(IPA.cert.parse_dn(cert.subject).cn);
            that.cert_sn.text(cert.serial_number);
            that.cert_issuer.text(IPA.cert.parse_dn(cert.issuer).cn);
            that.cert_valid_from.text(cert.valid_not_before);
            that.cert_valid_to.text(cert.valid_not_after);
        }

        that.handle_revocation_reason(cert.revocation_reason);
    };

    that.toggle_revoked_note = function(show) {
        if (show) {
            that.revoke_note.css('display', 'block');
        }
        else {
            that.revoke_note.css('display', 'none');
        }
    };

    that.handle_revocation_reason = function(reason) {
        // Skip certificates which are not issued by ipa's CA
        if (that.certificate.revoked === undefined) return;

        var dd_menu = that.get_custom_actions();

        if (reason && reason === 6) {
            dd_menu.enable_item('remove_hold');
            dd_menu.disable_item('revoke');
            that.toggle_revoked_note(true);
        }
        else if (reason === null || reason === undefined) {
            dd_menu.enable_item('revoke');
            dd_menu.disable_item('remove_hold');
        }
        else if (typeof reason === 'number' && reason >= 0 &&
            reason < IPA.cert.CRL_REASON.length) {
                dd_menu.disable_item('revoke');
                that.toggle_revoked_note(true);
        }
    };

    that.update = function(values) {

        var certificate = values[0];

        if (!certificate ) certificate = {};

        that.certificate = certificate;

        that.update_displayed_data();
    };

    that.save = function() {
        return that.certificate.certificate;
    };

    that.compose_dialog_title = function() {
        var cert = that.certificate;
        var cn, o;

        if (cert.subject) {
            cn = IPA.cert.parse_dn(cert.subject).cn;
            o = IPA.cert.parse_dn(cert.subject).o;
        }
        else {
            cn = o = text.get('@i18n:objects.cert.unspecified');
        }

        var r = text.get('@i18n:objects.cert.view_certificate');
        r = r.replace('${entity}', cn);
        r = r.replace('${primary_key}', o);

        return r;
    };

    that.open_view_dialog = function() {

        var spec = {
            title: that.compose_dialog_title(),
            certificate: that.certificate
        };

        var dialog = IPA.cert.view_dialog(spec);
        dialog.open();
    };

    that.open_get_dialog = function() {
        var spec = {
            title: that.compose_dialog_title(),
            certificate: that.certificate.certificate
        };

        var dialog = IPA.cert.download_dialog(spec);
        dialog.open();
    };

    that.perform_download = function() {
        var data_uri = IPA.cert.create_data_uri(that.certificate.certificate);
        IPA.cert.perform_download(data_uri);
    };

    that.open_revoke_dialog = function() {
        var spec = {
            title: that.compose_dialog_title(),
            message: '@i18n:objects.cert.revoke_confirmation',
            ok_label: '@i18n:buttons.revoke',
            on_ok: function() {

                var command_spec = {
                    notify_globally: false,
                    end_handler: function() {
                        that.spinner.emit('hide-spinner');
                    },
                    start_handler: function() {
                        that.spinner.emit('display-spinner');
                    },
                    on_success: function() {
                        var reason = parseInt(dialog.get_reason(), 10);
                        that.handle_revocation_reason(reason);
                        that.facet.certificate_updated.notify();
                        IPA.notify_success('@i18n:objects.cert.revoked');
                    }
                };

                var sn = that.certificate.serial_number;
                var cacn = dialog.get_cacn();
                var revocation_reason = dialog.get_reason();
                IPA.cert.perform_revoke(command_spec, sn, revocation_reason, cacn);
            }
        };

        var dialog = IPA.cert.revoke_dialog(spec);
        dialog.open();
        dialog.set_cacn(that.certificate.cacn);
    };

    that.perform_remove_hold = function() {
        var spec = {
            title: that.compose_dialog_title(),
            message: '@i18n:objects.cert.remove_certificate_hold_confirmation',
            ok_label: '@i18n:buttons.remove_hold',
            on_ok: function () {
                var command_spec = {
                    notify_globally: false,
                    end_handler: function() {
                        that.spinner.emit('hide-spinner');
                    },
                    start_handler: function() {
                        that.spinner.emit('display-spinner');
                    },
                    on_success: function() {
                        that.toggle_revoked_note();
                        that.handle_revocation_reason();
                        that.facet.certificate_updated.notify();
                        IPA.notify_success('@i18n:objects.cert.hold_removed');
                    }
                };

                var sn =  that.certificate.serial_number;
                var cacn = that.certificate.cacn;
                IPA.cert.perform_remove_hold(command_spec, sn, cacn);
            }
        };

        var dialog = IPA.confirm_dialog(spec);
        dialog.open();
    };

    return that;
};

exp.create_cert_metadata = function() {

    if (!IPA.cert.is_enabled()) return null;

    var add_param = function(name, label, doc,  primary_key) {
        entity.takes_params.push({
            name: name,
            label: label,
            doc: doc,
            primary_key: !!primary_key,
            flags: ['no_update']
        });
    };

    var get_param = function(params, name) {

        for (var i=0;i<params.length;i++) {
            if (params[i].name === name) return params[i];
        }
        return null;
    };

    var metadata = metadata_provider.source;
    var cmd = metadata.commands.cert_find;
    var entity = lang.clone(cmd);
    entity.attribute_members = {};
    entity.label = text.get('@i18n:objects.cert.certificates');
    entity.label_singular = text.get('@i18n:objects.cert.certificate');
    entity.methods = [
        'find',
        'remove-hold',
        'request',
        'revoke',
        'show',
        'status'
    ];
    entity.name = "cert";
    entity.object_name = "certificate";
    entity.object_name_plural = "certificates";
    entity.parent_object = "";
    entity.primary_key = "serial_number";
    entity.rdn_attribute = "";
    entity.relationships = {};
    entity.takes_params = lang.clone(entity.takes_options);
    entity.only_webui = true;

    get_param(entity.takes_params, 'subject').flags = ['no_update'];
    var reason = get_param(entity.takes_params, 'revocation_reason');
    reason.flags = ['no_update'];
    reason.label = text.get('@i18n:objects.cert.revocation_reason');

    add_param('serial_number',
                text.get('@i18n:objects.cert.serial_number'),
                text.get('@i18n:objects.cert.serial_number'),
                true);
    add_param('serial_number_hex',
                text.get('@i18n:objects.cert.serial_number_hex'),
                text.get('@i18n:objects.cert.serial_number_hex'));
    add_param('issuer',
                text.get('@i18n:objects.cert.issued_by'),
                text.get('@i18n:objects.cert.issued_by'));
    add_param('status',
                text.get('@i18n:objects.cert.status'),
                text.get('@i18n:objects.cert.status'));
    add_param('valid_not_before',
                text.get('@i18n:objects.cert.issued_on'),
                text.get('@i18n:objects.cert.issued_on'));
    add_param('valid_not_after',
                text.get('@i18n:objects.cert.expires_on'),
                text.get('@i18n:objects.cert.expires_on'));
    add_param('sha1_fingerprint',
                text.get('@i18n:objects.cert.sha1_fingerprint'),
                text.get('@i18n:objects.cert.sha1_fingerprint'));
    add_param('sha256_fingerprint',
                text.get('@i18n:objects.cert.sha256_fingerprint'),
                text.get('@i18n:objects.cert.sha256_fingerprint'));
    add_param('certificate',
                text.get('@i18n:objects.cert.certificate'),
                text.get('@i18n:objects.cert.certificate'));


    metadata.objects.cert = entity;
    return entity;
};

exp.facet_group = {
    name: 'certificates',
    label: '@i18n:tabs.cert',
    facets: {
        certificates: 'cert_search',
        profiles: 'certprofile_search',
        acls: 'caacl_search',
        ca_search: 'ca_search'
    }
};

var make_spec = function() {
return {
    name: 'cert',

    policies: [
        IPA.search_facet_update_policy,
        IPA.details_facet_update_policy,
        {
            $factory: IPA.cert.cert_update_policy,
            source_facet: 'details',
            dest_facet: 'search'
        },
        {
            $factory: IPA.cert.cert_update_policy,
            source_facet: 'details',
            dest_entity: 'host',
            dest_facet: 'details'
        },
        {
            $factory: IPA.cert.cert_update_policy,
            source_facet: 'details',
            dest_entity: 'service',
            dest_facet: 'details'
        },
        {
            $factory: IPA.cert.cert_update_policy,
            source_facet: 'details',
            dest_entity: 'user',
            dest_facet: 'details'
        }
    ],
    enable_test: function() {
        return IPA.cert.is_enabled();
    },
    facets: [
        {
            $type: 'search',
            $factory: IPA.cert.search_facet,
            disable_facet_tabs: false,
            tabs_in_sidebar: true,
            tab_label: '@i18n:tabs.cert',
            row_enabled_attribute: 'status',
            facet_groups: [exp.facet_group],
            facet_group: 'certificates',
            additional_navigation_arguments: [ 'cacn' ],
            pagination: false,
            no_update: true,
            columns: [
                {
                    name: 'serial_number',
                    primary_key: true,
                    width: '90px'
                },
                'subject',
                'cacn',
                {
                    name: 'status',
                    width: '120px'
                }
            ],
            control_buttons: [
                 {
                    name: 'request_cert',
                    label: '@i18n:buttons.issue',
                    icon: 'fa-plus'
                }
            ],
            actions: [
                {
                    $type: 'cert_request',
                    enable_cond: [],
                    generic: true
                }
            ],
            search_options:  [
                {
                    value: 'subject',
                    label: '@i18n:objects.cert.find_subject'
                },
                {
                    value: 'revocation_reason',
                    label: '@i18n:objects.cert.find_revocation_reason'
                },
                {
                    value: 'min_serial_number',
                    label: '@i18n:objects.cert.find_min_serial_number'
                },
                {
                    value: 'max_serial_number',
                    label: '@i18n:objects.cert.find_max_serial_number'
                },
                {
                    value: 'validnotafter_from',
                    label: '@i18n:objects.cert.find_validnotafter_from'
                },
                {
                    value: 'validnotafter_to',
                    label: '@i18n:objects.cert.find_validnotafter_to'
                },
                {
                    value: 'validnotbefore_from',
                    label: '@i18n:objects.cert.find_validnotbefore_from'
                },
                {
                    value: 'validnotbefore_to',
                    label: '@i18n:objects.cert.find_validnotbefore_to'
                },
                {
                    value: 'issuedon_from',
                    label: '@i18n:objects.cert.find_issuedon_from'
                },
                {
                    value: 'issuedon_to',
                    label: '@i18n:objects.cert.find_issuedon_to'
                },
                {
                    value: 'revokedon_from',
                    label: '@i18n:objects.cert.find_revokedon_from'
                },
                {
                    value: 'revokedon_to',
                    label: '@i18n:objects.cert.find_revokedon_to'
                }
            ]
        },
        {
            $type: 'details',
            $factory: IPA.cert.details_facet,
            no_update: true,
            disable_facet_tabs: true,
            actions: [
                'cert_revoke',
                'cert_remove_hold',
                'download_cert'
            ],
            state: {
                evaluators: [
                    IPA.cert.certificate_evaluator
                ]
            },
            header_actions: ['revoke_cert', 'remove_hold_cert', 'download_cert'],
            sections: [
                {
                    name: 'details',
                    label: '@i18n:objects.cert.certificate',
                    fields: [
                        'serial_number',
                        'serial_number_hex',
                        'cacn',
                        'subject',
                        {
                            name: 'issuer',
                            read_only: true
                        },
                        'valid_not_before',
                        'valid_not_after',
                        'sha1_fingerprint',
                        'sha256_fingerprint',
                        {
                            $type: 'revocation_reason',
                            name: 'revocation_reason'
                        },
                        {
                            $type: 'textarea',
                            name: 'certificate',
                            style: {
                                width: '550px',
                                height: '350px'
                            }
                        }
                    ]
                }
            ],
            policies: [
                {
                    $factory: IPA.cert.load_policy,
                    has_reason: true
                },
                {
                    $factory: IPA.hide_empty_row_policy,
                    widget: 'revocation_reason',
                    section: 'details'
                }
            ]
        }
    ]
};};

IPA.cert.search_facet = function(spec) {

    spec = spec || {};

    var that = IPA.search_facet(spec);

    that.search_options = spec.search_options || [];

    that.create_header = function(container) {
        that.search_facet_create_header(container);

        that.search_option = $('<select/>', {
            name: 'search_option',
            'class': 'search-option form-control'
        });

        that.filter_container.before(that.search_option);

        for (var i=0; i<that.search_options.length; i++) {
            var option = that.search_options[i];

            var metadata = IPA.get_command_option('cert_find', option.value);
            var doc = metadata.doc || '';

            $('<option/>', {
                text: text.get(option.label),
                value: option.value,
                title: doc
            }).appendTo(that.search_option);
        }
    };

    that.create_refresh_command = function() {

        var command = that.search_facet_create_refresh_command();

        var value = command.args.pop();
        var opt_name = that.state.search_option;

        if (value) {
            command.set_option(opt_name, value);
        }

        return command;
    };

    that.table.setup_column = function(column, div, record) {
        var supress_link = record.status === undefined;
        column.setup(div, record, supress_link);
    };

    // parent method only sets expired flag when filter change, it doesn't
    // expect that option can change -> set expire flag for every search
    that.find = function() {

        var filter = that.filter.val();
        var search_opt = that.search_option.val();

        that.state.set({
            'search_option': search_opt,
            'filter': filter
        });
    };

    that.show = function() {
        that.search_facet_show();

        if (that.search_option && that.state.search_option) {
            that.search_option.val(that.state.search_option);
        }
    };

    return that;
};

IPA.cert.details_facet = function(spec, no_init) {

    spec = spec || {};

    var that = IPA.details_facet(spec, true);
    that.certificate_loaded = IPA.observer();
    that.certificate_updated = IPA.observer();

    that.create_refresh_command = function() {

        var command = that.details_facet_create_refresh_command();
        delete command.options.rights;

        command.options = command.options || {};
        $.extend(command.options, { cacn: that.state.cacn });

        return command;
    };

    if (!no_init) that.init_details_facet();

    return that;
};


IPA.revocation_reason_field = function(spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    that.load = function(record) {

        that.field_load(record);

        var reason = record.revocation_reason;
        var text = IPA.cert.CRL_REASON[reason] || '';
        that.values = [text];

        that.reset();
    };

    return that;
};

IPA.cert.cert_update_policy = function(spec) {

    spec = spec || {};
    spec.event = spec.event || 'certificate_updated';
    return IPA.facet_update_policy(spec);
};

exp.remove_menu_item = function() {
    if (!IPA.cert.is_enabled()) {
        menu.remove_item('authentication/cert');
    }
};

exp.entity_spec = make_spec();

exp.register = function() {
    var e = reg.entity;
    var w = reg.widget;
    var f = reg.field;
    var a = reg.action;

    w.register('certs', IPA.cert.certs_widget);
    w.register('certificate_status', IPA.cert.status_widget);
    f.register('certificate_status', IPA.cert.status_field);
    f.register('revocation_reason', IPA.revocation_reason_field);
    w.register('revocation_reason', IPA.text_widget);
    w.register('revocation_reason_select', IPA.cert.revocation_reason_select_widget);

    a.register('cert_request', IPA.cert.request_action);
    a.register('download_cert', IPA.cert.download_action);
    a.register('cert_revoke', IPA.cert.revoke_action);
    a.register('cert_remove_hold', IPA.cert.remove_hold_action);

    e.register({type: 'cert', spec: exp.entity_spec});
};

phases.on('registration', exp.register);
phases.on('post-metadata', exp.create_cert_metadata);
phases.on('profile', exp.remove_menu_item, 20);

return exp;
});
