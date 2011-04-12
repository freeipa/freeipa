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
IPA.entitle.registered = 'registered';

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
            factory: IPA.entitle.register_dialog,
            name: 'register',
            title: 'Register Entitlements',
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
            factory: IPA.entitle.consume_dialog,
            name: 'consume',
            title: 'Consume Entitlements',
            fields: [
                {
                    name: 'quantity',
                    label: 'Quantity',
                    undo: false
                }
            ]
        });

    return builder.build();
};

IPA.entitle.entity = function(spec) {

    spec = spec || {};

    var that = IPA.entity(spec);

    that.get_certificates = function(on_success, on_error) {

        var command = IPA.command({
            name: 'entitle_get' + (that.status == IPA.entitle.registered ? '' : '_unregistered'),
            entity: 'entitle',
            method: 'get',
            on_success: function(data, text_status, xhr) {
                that.status = IPA.entitle.registered;
                if (on_success) {
                    on_success.call(this, data, text_status, xhr);
                }
            },
            on_error: on_error,
            retry: false
        });

        command.execute();
    };

    that.register = function(username, password, on_success, on_error) {

        var command = IPA.command({
            entity: 'entitle',
            method: 'register',
            args: [ username ],
            options: { password: password },
            on_success: function(data, text_status, xhr) {
                that.status = IPA.entitle.registered;
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

        $('<input/>', {
            type: 'button',
            name: 'register',
            value: 'Register'
        }).appendTo(buttons);

        $('<input/>', {
            type: 'button',
            name: 'consume',
            value: 'Consume'
        }).appendTo(buttons);
    };

    that.setup = function(container) {

        that.search_facet_setup(container);

        var action_panel = that.get_action_panel();

        var button = $('input[name=register]', action_panel);
        that.register_button = IPA.action_button({
            label: 'Register',
            icon: 'ui-icon-plus',
            click: function() {
                var dialog = that.entity.get_dialog('register');
                dialog.open(that.container);
            }
        });
        that.register_button.css('display', 'none');
        button.replaceWith(that.register_button);

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
        that.consume_button.css('display', 'none');
        button.replaceWith(that.consume_button);
    };

    that.refresh = function() {

        function on_success(data, text_status, xhr) {

            that.register_button.css('display', 'none');
            that.consume_button.css('display', 'inline');

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

            that.register_button.css('display', 'inline');
            that.consume_button.css('display', 'none');

            var summary = $('span[name=summary]', that.table.tfoot).empty();
            summary.append(error_thrown.message);
        }

        that.entity.get_certificates(
            on_success,
            on_error);
    };

    return that;
};

IPA.entitle.register_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.add_button('Register', function() {
        var record = {};
        that.save(record);

        that.entity.register(
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
