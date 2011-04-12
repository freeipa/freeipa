/*jsl:import ipa.js */

/*  Authors:
 *    Endi S. Dewata <edewata@redhat.com>
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

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */


IPA.entitle = {};

IPA.entitle.unregistered = 'unregistered';
IPA.entitle.online = 'online';
IPA.entitle.offline = 'offline';

IPA.entity_factories.entitle = function() {

    var builder = IPA.entity_builder();

    builder.
        entity({
            factory: IPA.entitle.entity,
            name: 'entitle'
        }).
        facet({
            factory: IPA.entitle.search_facet,
            columns: [
                {
                    name: 'product',
                    label: 'Product'
                },
                {
                    name: 'quantity',
                    label: 'Quantity'
                },
                {
                    name: 'start',
                    label: 'Start'
                },
                {
                    name: 'end',
                    label: 'End'
                }
            ]
        }).
        details_facet({
            sections: [
                {
                    name: 'identity',
                    label: IPA.messages.details.identity,
                    fields: ['ipaentitlementid']
                }
            ]
        }).
        standard_association_facets().
        dialog({
            factory: IPA.entitle.register_online_dialog,
            name: 'online_registration',
            title: 'Registration',
            fields: [
                {
                    name: 'username',
                    label: 'Username',
                    undo: false
                },
                {
                    name: 'password',
                    label: IPA.get_method_param('entitle_register', 'password').label,
                    type: 'password',
                    undo: false
                }
            ]
        }).
        dialog({
            factory: IPA.entitle.register_offline_dialog,
            name: 'offline_registration',
            title: 'Import Certificate',
            message: 'Enter the Base64-encoded entitlement certificate below:',
            label: 'Import',
            fields: [
                {
                    name: 'certificate',
                    label: 'Certificate',
                    undo: false
                }
            ]
        }).
        dialog({
            factory: IPA.entitle.consume_dialog,
            name: 'consume',
            title: 'Consume Entitlement',
            fields: [
                {
                    name: 'quantity',
                    label: 'Quantity',
                    undo: false
                }
            ]
        }).
        dialog({
            factory: IPA.entitle.import_dialog,
            name: 'import',
            title: 'Import Certificate',
            message: 'Enter the Base64-encoded entitlement certificate below:',
            label: 'Import',
            fields: [
                {
                    name: 'certificate',
                    label: 'Certificate',
                    undo: false
                }
            ]
        });

    return builder.build();
};

IPA.entitle.entity = function(spec) {

    spec = spec || {};

    var that = IPA.entity(spec);

    that.status = IPA.entitle.unregistered;

    that.get_status = function(on_success, on_error) {

        var command = IPA.command({
            name: 'entitle_status_'+that.status,
            entity: 'entitle',
            method: 'status',
            on_success: function(data, text_status, xhr) {
                if (data.result.result.uuid == 'IMPORTED') {
                    that.status = IPA.entitle.offline;
                } else {
                    that.status = IPA.entitle.online;
                }

                if (on_success) {
                    on_success.call(this, data, text_status, xhr);
                }
            },
            on_error: function(xhr, text_status, error_thrown) {
                that.status = IPA.entitle.unregistered;

                if (on_error) {
                    on_error.call(this, xhr, text_status, error_thrown);
                }
            },
            retry: false
        });

        command.execute();
    };

    that.get_certificates = function(on_success, on_error) {

        var command = IPA.command({
            entity: 'entitle',
            method: 'get',
            on_success: on_success,
            on_error: on_error,
            retry: false
        });

        command.execute();
    };

    that.register_online = function(username, password, on_success, on_error) {

        var command = IPA.command({
            entity: 'entitle',
            method: 'register',
            args: [ username ],
            options: { password: password },
            on_success: function(data, text_status, xhr) {
                that.status = IPA.entitle.online;
                if (on_success) {
                    on_success.call(this, data, text_status, xhr);
                }
            },
            on_error: on_error
        });

        command.execute();
    };

    that.register_offline = function(certificate, on_success, on_error) {

        var command = IPA.command({
            entity: 'entitle',
            method: 'import',
            args: [ certificate ],
            on_success: function(data, text_status, xhr) {
                that.status = IPA.entitle.offline;
                if (on_success) {
                    on_success.call(this, data, text_status, xhr);
                }
            },
            on_error: on_error
        });

        command.execute();
    };

    that.consume = function(quantity, on_success, on_error) {

        var command = IPA.command({
            entity: 'entitle',
            method: 'consume',
            args: [ quantity ],
            on_success: on_success,
            on_error: on_error
        });

        command.execute();
    };

    that.import_certificate = function(certificate, on_success, on_error) {

        var command = IPA.command({
            entity: 'entitle',
            method: 'import',
            args: [ certificate ],
            on_success: on_success,
            on_error: on_error
        });

        command.execute();
    };

    return that;
};

IPA.entitle.search_facet = function(spec) {

    spec = spec || {};

    var that = IPA.search_facet(spec);

    that.create_action_panel = function(container) {

        that.facet_create_action_panel(container);

        var li = $('.action-controls', container);

        var buttons = $('<span/>', {
            'class': 'search-buttons'
        }).appendTo(li);

        that.register_buttons = $('<span/>', {
            style: 'display: none;'
        }).appendTo(buttons);

        $('<input/>', {
            type: 'button',
            name: 'register_online',
            value: 'Register'
        }).appendTo(that.register_buttons);

        $('<input/>', {
            type: 'button',
            name: 'register_offline',
            value: 'Import'
        }).appendTo(that.register_buttons);

        that.consume_buttons = $('<span/>', {
            style: 'display: none;'
        }).appendTo(buttons);

        $('<input/>', {
            type: 'button',
            name: 'consume',
            value: 'Consume'
        }).appendTo(that.consume_buttons);

        $('<input/>', {
            type: 'button',
            name: 'import',
            value: 'Import'
        }).appendTo(that.consume_buttons);
    };

    that.setup = function(container) {

        that.search_facet_setup(container);

        var action_panel = that.get_action_panel();

        var button = $('input[name=register_online]', action_panel);
        that.register_online_button = IPA.action_button({
            label: 'Register',
            icon: 'ui-icon-plus',
            click: function() {
                var dialog = that.entity.get_dialog('online_registration');
                dialog.open(that.container);
            }
        });
        button.replaceWith(that.register_online_button);

        button = $('input[name=register_offline]', action_panel);
        that.register_offline_button = IPA.action_button({
            label: 'Import',
            icon: 'ui-icon-plus',
            click: function() {
                var dialog = that.entity.get_dialog('offline_registration');
                dialog.open(that.container);
            }
        });
        button.replaceWith(that.register_offline_button);

        button = $('input[name=consume]', action_panel);
        that.consume_button = IPA.action_button({
            label: 'Consume',
            icon: 'ui-icon-plus',
            style: 'display: none;',
            click: function() {
                var dialog = that.entity.get_dialog('consume');
                dialog.open(that.container);
            }
        });
        button.replaceWith(that.consume_button);

        button = $('input[name=import]', action_panel);
        that.import_button = IPA.action_button({
            label: 'Import',
            icon: 'ui-icon-plus',
            style: 'display: none;',
            click: function() {
                var dialog = that.entity.get_dialog('import');
                dialog.open(that.container);
            }
        });
        button.replaceWith(that.import_button);
    };

    that.refresh = function() {

        function on_success(data, text_status, xhr) {

            that.register_buttons.css('display', 'none');
            that.consume_buttons.css('display', 'inline');

            if (that.entity.status == IPA.entitle.online) {
                that.consume_button.css('display', 'inline');
                that.import_button.css('display', 'none');
            } else {
                that.consume_button.css('display', 'none');
                that.import_button.css('display', 'inlnie');
            }

            that.table.empty();

            var result = data.result.result;
            for (var i = 0; i<result.length; i++) {
                var record = that.table.get_record(result[i], 0);
                that.table.add_record(record);
            }

            var summary = $('span[name=summary]', that.table.tfoot).empty();
            if (data.result.truncated) {
                var message = IPA.messages.search.truncated;
                message = message.replace('${counter}', data.result.count);
                summary.text(message);
            } else {
                summary.text(data.result.summary);
            }
        }

        function on_error(xhr, text_status, error_thrown) {

            that.register_buttons.css('display', 'inline');
            that.consume_buttons.css('display', 'none');

            var summary = $('span[name=summary]', that.table.tfoot).empty();
            summary.append(error_thrown.message);
        }

        that.entity.get_status(
            function(data, text_status, xhr) {
                that.entity.get_certificates(
                    on_success,
                    on_error);
            },
            on_error);
    };

    return that;
};

IPA.entitle.certificate_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.width = spec.width || 500;
    that.height = spec.height || 400;
    that.message = spec.message;
    that.label = spec.label;

    that.get_certificate = function() {
        var certificate = that.textarea.val();
        return IPA.cert.BEGIN_CERTIFICATE+'\n'+
            $.trim(certificate)+'\n'+
            IPA.cert.END_CERTIFICATE+'\n';
    };

    that.create = function() {
        that.container.append(that.message);
        that.container.append('<br/>');
        that.container.append('<br/>');

        that.container.append(IPA.cert.BEGIN_CERTIFICATE);
        that.container.append('<br/>');

        that.textarea = $('<textarea/>', {
            style: 'width: 100%; height: 225px;'
        }).appendTo(that.container);

        that.container.append('<br/>');
        that.container.append(IPA.cert.END_CERTIFICATE);
    };

    return that;
};

IPA.entitle.register_online_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.add_button('Register', function() {
        var record = {};
        that.save(record);

        that.entity.register_online(
            record.username,
            record.password,
            function() {
                var facet = that.entity.get_facet('search');
                facet.refresh();
                that.close();
            }
        );
    });

    that.add_button('Cancel', function() {
        that.close();
    });

    return that;
};

IPA.entitle.register_offline_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.entitle.certificate_dialog(spec);

    that.add_button(that.label, function() {
        that.entity.register_offline(
            that.get_certificate(),
            function() {
                var facet = that.entity.get_facet('search');
                facet.refresh();
                that.close();
            }
        );
    });

    that.add_button(IPA.messages.buttons.cancel, function() {
        that.close();
    });

    return that;
};

IPA.entitle.consume_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.add_button('Consume', function() {
        var record = {};
        that.save(record);

        that.entity.consume(
            record.quantity,
            function() {
                var facet = that.entity.get_facet('search');
                facet.refresh();
                that.close();
            }
        );
    });

    that.add_button('Cancel', function() {
        that.close();
    });

    return that;
};

IPA.entitle.import_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.entitle.certificate_dialog(spec);

    that.add_button(that.label, function() {
        that.entity.import_certificate(
            that.get_certificate(),
            function() {
                var facet = that.entity.get_facet('search');
                facet.refresh();
                that.close();
            }
        );
    });

    that.add_button(IPA.messages.buttons.cancel, function() {
        that.close();
    });

    return that;
};