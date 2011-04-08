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

IPA.entity_factories.entitle = function() {

    var builder = IPA.entity_builder();

    builder.
        entity('entitle').
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
            ],
            search_all: true
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
        standard_association_facets();

    return builder.build();
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
            name: 'consume',
            value: 'Consume'
        }).appendTo(buttons);
    };

    that.setup = function(container) {

        that.search_facet_setup(container);

        var action_panel = that.get_action_panel();

        var button = $('input[name=consume]', action_panel);
        that.consume_button = IPA.action_button({
            label: 'Consume',
            icon: 'ui-icon-plus',
            click: function() {
                var dialog = that.get_dialog('consume');
                dialog.open(that.container);
            }
        });
        button.replaceWith(that.consume_button);
    };

    that.refresh = function() {

        function on_success(data, text_status, xhr) {

            that.table.empty();

            var result = data.result.result;
            for (var i = 0; i<result.length; i++) {
                var record = that.table.get_record(result[i], 0);
                that.table.add_record(record);
            }

            var summary = $('span[name=summary]', that.table.tfoot);
            if (data.result.truncated) {
                var message = IPA.messages.search.truncated;
                message = message.replace('${counter}', data.result.count);
                summary.text(message);
            } else {
                summary.text(data.result.summary);
            }
        }

        function on_error(xhr, text_status, error_thrown) {
            var summary = $('span[name=summary]', that.table.tfoot).empty();
            summary.append('<p>Error: '+error_thrown.name+'</p>');
            summary.append('<p>'+error_thrown.title+'</p>');
            summary.append('<p>'+error_thrown.message+'</p>');
        }

        var command = IPA.command({
            method: 'entitle_get',
            options: {
                all: that.search_all
            },
            on_success: on_success,
            on_error: on_error
        });

        command.execute();
    };

    return that;
};

IPA.entitle.consume_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.dialog(spec);

    that.add_button('Consume', function() {
        var record = {};
        that.save(record);

        var command = IPA.command({
            method: 'entitle_consume',
            args: [ record.quantity ],
            on_success: function() {
                var entity = IPA.get_entity(that.entity_name);
                var facet = entity.get_facet('search');
                facet.table.refresh();
                that.close();
            }
        });

        command.execute();
    });

    that.add_button('Cancel', function() {
        that.close();
    });

    return that;
};
