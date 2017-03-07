//
// Copyright (C) 2017  FreeIPA Contributors see COPYING for license
//

define([
        'dojo/_base/lang',
        'dojo/_base/declare',
        'dojo/Evented',
        'dojo/on',
        '../metadata',
        '../ipa',
        '../phases',
        '../reg',
        '../rpc',
        '../widget',
        '../util',
        // plain imports
        '../search',
        '../entity'],
            function(lang, declare, Evented, on, metadata_provider, IPA, phases,
                    reg, rpc, widget_mod, util ) {

var certmapmatch = IPA.certmapmatch = {};

var make_certmap_spec = function() {
return {
    name: 'certmap_match',
    facets: [
        {

            $factory: certmapmatch.details_certmapmatch_facet,
            disable_breadcrumb: true,
            no_update: true,
            name: 'cert',
            label: "@i18n:objects.certmap_match.facet_label",
            actions: [
                'match', 'clear'
            ],
            control_buttons: [
                {
                    name: 'match',
                    title: '@i18n:buttons.match_title',
                    label: '@i18n:buttons.match',
                    icon: 'fa-gear'
                },
                {
                    name: 'clear',
                    title: '@i18n:buttons.clear_title',
                    label: '@i18n:buttons.clear',
                    icon: 'fa-refresh'
                }
            ],
            sections: [
                {
                    name: 'cert_input',
                    label: '@i18n:objects.certmap_match.cert_for_match',
                    fields: [
                        {
                            $type: 'cert_textarea',
                            name: 'cert_textarea',
                            label: '@i18n:objects.cert.certificate',
                            autoload_value: false,
                            undo: false,
                            rows: 20,
                            cols: 70
                        }
                    ]
                },
                {
                    name: 'parsed_cert',
                    label: '@i18n:objects.certmap_match.cert_data',
                    fields: [
                        {
                            name: 'issuer',
                            label: '@i18n:objects.cert.issued_by',
                            adapter: {
                                object_index: 0,
                                result_index: 1
                            },
                            read_only: true
                        },
                        {
                            name: 'subject',
                            label: '@i18n:objects.cert.issued_to',
                            adapter: {
                                object_index: 0,
                                result_index: 1
                            },
                            read_only: true
                        },
                        {
                            name: 'serial_number',
                            label: '@i18n:objects.cert.serial_number',
                            adapter: {
                                object_index: 0,
                                result_index: 1
                            },
                            read_only: true
                        },
                        {
                            name: 'serial_number_hex',
                            label: '@i18n:objects.cert.serial_number_hex',
                            adapter: {
                                object_index: 0,
                                result_index: 1
                            },
                            read_only: true
                        },
                        {
                            name: 'valid_not_before',
                            label: '@i18n:objects.cert.valid_from',
                            adapter: {
                                object_index: 0,
                                result_index: 1
                            },
                            read_only: true
                        },
                        {
                            name: 'valid_not_after',
                            label: '@i18n:objects.cert.valid_to',
                            adapter: {
                                object_index: 0,
                                result_index: 1
                            },
                            read_only: true
                        },
                        {
                            name: 'sha1_fingerprint',
                            label: '@i18n:objects.cert.sha1_fingerprint',
                            adapter: {
                                object_index: 0,
                                result_index: 1
                            },
                            read_only: true
                        },
                        {
                            name: 'sha256_fingerprint',
                            label: '@i18n:objects.cert.sha256_fingerprint',
                            adapter: {
                                object_index: 0,
                                result_index: 1
                            },
                            read_only: true
                        }
                    ]
                },
                {
                    $factory: IPA.section,
                    name: 'divider',
                    layout_css_class: 'col-sm-12 col-sm-12',
                    fields: []
                },
                {
                    name: 'user_result_table',
                    label: '@i18n:objects.certmap_match.matched_users',
                    layout: {
                        $factory: widget_mod.fluid_layout,
                        widget_cls: "col-sm-12 col-sm-12",
                        label_cls: "hide"
                    },
                    layout_css_class: 'col-md-12 col-sm-12',
                    fields: [
                        {
                            $type: 'association_table',
                            name: 'result_table',
                            read_only: true,
                            selectable: false,
                            other_entity: 'user',
                            adapter: {
                                $type: 'certmatch_transform'
                            },
                            columns: [
                                {
                                    name: 'uid',
                                    label: '@i18n:objects.certmap_match.userlogin'
                                },
                                {
                                    name: 'domain',
                                    label: '@i18n:objects.certmap_match.domain'
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    ]
};};


/**
 * Artificial entity created from command which does not have its own entity
 *
 * @class certmapmatch.certmapmatch_entity
 * @extends IPA.entity
 */
certmapmatch.certmapmatch_entity = function(spec) {
    var that = IPA.entity(spec);

    that.get_default_metadata = function() {
        return metadata_provider.get('@mc:'+that.name);
    };

    return that;
};

/**
 * Custom facet which is used for showing certmap match information
 *
 * @class certmapmatch.details_certmapmatch_facet
 * @extends IPA.details_facet
 */
certmapmatch.details_certmapmatch_facet = function(spec) {

    spec = spec || {};

    var that = IPA.details_facet(spec);

    that.refresh = function() {};

    // always not dirty
    that.is_dirty = function() {
        return false;
    };

    that.get_result_table_widget = function() {
        return that.widgets.get_widget("user_result_table.result_table");
    };

    that.update_result_table_summary = function(summary) {
        var result_w = that.get_result_table_widget();
        result_w.summary.text(summary);
    };

    that.clean_result = function() {
        var result_w = that.get_result_table_widget();
        result_w.empty();
        that.update_result_table_summary('');
    };

    that.clean_cert_info = function() {
        var widgets = that.widgets.get_widget('parsed_cert').widgets.get_widgets();

        for (var i=0, l=widgets.length; i<l; i++) {
            var widget = widgets[i];

            widget.update();
        }
    };

    that.obtain_cert = function() {
        var cert_w = that.widgets.get_widget('cert_input.cert_textarea');

        return cert_w.save();
    };

    that.on_cert_match = function(data) {
        that.clean_result();
        that.clean_cert_info();
        var cert = that.obtain_cert();

        if (util.is_empty(cert)) return;

        var batch_command = rpc.batch_command({
            name: 'certmap-match-batch',
            show_error: false
        });

        var command = rpc.command({
            method: 'certmap_match',
            args: cert
        });

        batch_command.add_command(command);

        command = rpc.command({
            entity: 'cert',
            method: 'find',
            options: {
                certificate: cert[0],
                all: true
            }
        });

        batch_command.add_command(command);

        batch_command.on_success = function(data, text_status, xhr) {
            // Error handling needs to be here because cert-find never fails,
            // therefore batch_command always calls on_success method.
            var certmatch_r = data.result.results[0];
            if (certmatch_r.error === null) {
                //no error
                that.load(data);
                that.update_result_table_summary(certmatch_r.summary);
                IPA.notify_success(certmatch_r.summary);
            } else {
                that.update_result_table_summary(certmatch_r.error);
                IPA.notify(certmatch_r.error, 'error');
            }
        };

        batch_command.execute();
    };

    that.on_clear_facet = function() {
        that.reset();
        that.clean_result();
        that.clean_cert_info();
    };

    that.init = function() {
        on(that, 'cert-match', that.on_cert_match);
        on(that, 'clear-facet', that.on_clear_facet);
    };

    return that;
};

/**
 * Action which run certmap match.
 *
 * @class certmapmatch.match_action
 * @extends IPA.object_action
 */
certmapmatch.match_action = function(spec) {
    spec = spec || {};
    spec.name = spec.name || 'match';

    var that = IPA.object_action(spec);

    that.execute_action = function(facet) {
        facet.emit('cert-match');
    };

    return that;
};


/**
 * Action which allows to clean whole facet.
 *
 * @class certmapmatch.clean_action
 * @extends IPA.object_action
 */
certmapmatch.clear_action = function(spec) {
    spec = spec || {};
    spec.name = spec.name || 'clear';

    var that = IPA.object_action(spec);

    that.execute_action = function(facet) {
        facet.emit('clear-facet');
    };

    return that;
};

/**
 * Certificate Mapping Configuration entity specification object
 * @member certmap
 */
certmapmatch.certmap_spec = make_certmap_spec();


/**
 * Register entity
 * @member cermap
 */
certmapmatch.register = function() {
    var e = reg.entity;
    var f = reg.field;
    var a = reg.action;

    a.register('match', certmapmatch.match_action);
    a.register('clear', certmapmatch.clear_action);
    f.register('cert_textarea', certmapmatch.cert_textarea_field);
    e.register({
        type: 'certmap_match',
        spec: certmapmatch.certmap_spec,
        factory: certmapmatch.certmapmatch_entity
    });
};

phases.on('registration', certmapmatch.register);

return certmapmatch;
});
