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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js,hbac.js */

IPA.hbac.test_entity = function(spec) {

    var that = IPA.entity(spec);

    that.get_default_metadata = function() {
        return IPA.metadata.commands[that.name];
    };

    that.init = function() {
        that.entity_init();

        that.label = IPA.messages.objects.hbactest.label;

        that.builder.facet_groups([ 'default' ]).
        facet({
            factory: IPA.hbac.test_select_facet,
            name: 'user',
            label: IPA.messages.objects.hbacrule.user,
            managed_entity: 'user',
            disable_breadcrumb: true,
            facet_group: 'default',
            row_disabled_attribute: 'nsaccountlock',
            columns: [
                'uid',
                'givenname',
                'sn',
                {
                    name: 'nsaccountlock',
                    label: IPA.messages.status.label,
                    formatter: IPA.boolean_status_formatter({
                        invert_value: true
                    })
                }
            ]
        }).
        facet({
            factory: IPA.hbac.test_select_facet,
            name: 'targethost',
            label: IPA.messages.objects.hbacrule.host,
            managed_entity: 'host',
            disable_breadcrumb: true,
            facet_group: 'default',
            columns: [
                'fqdn',
                'description',
                {
                    name: 'has_keytab',
                    label: IPA.messages.objects.host.enrolled,
                    formatter: IPA.boolean_formatter()
                }
            ]
        }).
        facet({
            factory: IPA.hbac.test_select_facet,
            name: 'service',
            label: IPA.messages.objects.hbacrule.service,
            managed_entity: 'hbacsvc',
            disable_breadcrumb: true,
            facet_group: 'default',
            columns: [
                'cn',
                'description'
            ]
        }).
        facet({
            factory: IPA.hbac.test_select_facet,
            name: 'sourcehost',
            label: IPA.messages.objects.hbacrule.sourcehost,
            managed_entity: 'host',
            disable_breadcrumb: true,
            facet_group: 'default',
            columns: [
                'fqdn',
                'description',
                {
                    name: 'has_keytab',
                    label: IPA.messages.objects.host.enrolled,
                    formatter: IPA.boolean_formatter()
                }
            ]
        }).
        facet({
            factory: IPA.hbac.test_rules_facet,
            name: 'rules',
            label: IPA.messages.objects.hbactest.rules,
            managed_entity: 'hbacrule',
            disable_breadcrumb: true,
            facet_group: 'default',
            row_enabled_attribute: 'ipaenabledflag',
            columns: [
                'cn',
                {
                    name: 'ipaenabledflag',
                    label: IPA.messages.status.label,
                    formatter: IPA.boolean_status_formatter()
                },
                'description'
            ]
        }).
        facet({
            factory: IPA.hbac.test_run_facet,
            name: 'run_test',
            label: IPA.messages.objects.hbactest.run_test,
            managed_entity: 'hbacrule',
            disable_breadcrumb: true,
            facet_group: 'default',
            row_enabled_attribute: 'ipaenabledflag',
            columns: [
                'cn',
                {
                    name: 'matched',
                    label: IPA.messages.objects.hbactest.matched,
                    formatter: IPA.boolean_formatter()
                },
                {
                    name: 'ipaenabledflag',
                    label: IPA.messages.status.label,
                    formatter: IPA.boolean_status_formatter()
                },
                'description'
            ]
        });
    };

    return that;
};

IPA.hbac.test_facet = function(spec) {

    spec = spec || {};

    var that = IPA.table_facet(spec);

    var init = function() {

        that.managed_entity = IPA.get_entity(that.managed_entity);

        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++) {
            var column = columns[i];

            var metadata = IPA.get_entity_param(that.managed_entity.name, column.name);
            column.primary_key = metadata && metadata.primary_key;
            column.link = column.primary_key;
        }

        that.init_table(that.managed_entity);
    };

    that.create_buttons = function(container) {

        var buttons = $('<div/>', {
            'class': 'hbac-test-navigation-buttons'
        }).appendTo(container);

        var facet_group = that.entity.get_facet_group('default');
        var index = facet_group.get_facet_index(that.name);

        if (index > 0) {
            that.prev_button = IPA.button({
                name: 'prev',
                label: IPA.messages.widget.prev,
                icon: 'ui-icon ui-icon-triangle-1-w',
                click: function() {
                    if (!that.prev_button.hasClass('action-button-disabled')) {
                        that.prev();
                    }
                    return false;
                }
            }).appendTo(buttons);

            buttons.append(' ');
        }

        that.next_button = IPA.button({
            name: 'next',
            label: IPA.messages.widget.next,
            icon: 'ui-icon ui-icon-triangle-1-e',
            click: function() {
                if (!that.next_button.hasClass('action-button-disabled')) {
                    that.next();
                }
                return false;
            }
        }).appendTo(buttons);
    };

    that.prev = function() {
        var facet_group = that.entity.get_facet_group('default');
        var index = facet_group.get_facet_index(that.name);
        if (index <= 0) return;

        var facet = facet_group.get_facet_by_index(index - 1);

        var state = {};
        state[that.entity.name+'-facet'] = facet.name;
        IPA.nav.push_state(state);
    };

    that.next = function() {
        var facet_group = that.entity.get_facet_group('default');
        var index = facet_group.get_facet_index(that.name);
        if (index >= facet_group.get_facet_count() - 1) return;

        var facet = facet_group.get_facet_by_index(index + 1);

        var state = {};
        state[that.entity.name+'-facet'] = facet.name;
        IPA.nav.push_state(state);
    };

    that.get_search_command_name = function() {
        return that.managed_entity.name + '_find' + (that.pagination ? '_pkeys' : '');
    };

    that.refresh = function() {

        var filter = IPA.nav.get_state(that.entity.name+'-'+that.name+'-filter');

        var command = IPA.command({
            name: that.get_search_command_name(),
            entity: that.managed_entity.name,
            method: 'find',
            args: [filter]
        });

        if (that.pagination) {
            command.set_option('pkey_only', true);
            command.set_option('sizelimit', 0);
        }

        command.on_success = function(data, text_status, xhr) {
            that.load(data);
            that.show_content();
        };

        command.on_error = function(xhr, text_status, error_thrown) {
            that.report_error(error_thrown);
        };

        command.execute();
    };

    init();

    return that;
};

IPA.hbac.test_select_facet = function(spec) {

    var that = IPA.hbac.test_facet(spec);

    var init = function() {
        that.table.multivalued = false;

        that.table.set_values = function(values) {
            if (values && values.length && values[0] === '__external__') {
                if (that.external_radio) that.external_radio.prop('checked', true);
            } else {
                that.table.table_set_values(values);
            }
        };
    };

    that.create_content = function(container) {

        var header = $('<div/>', {
            'class': 'hbac-test-header'
        }).appendTo(container);

        var title = $('<span/>', {
            text: that.label,
            'class': 'hbac-test-title'
        }).appendTo(header);

        var filter_container = $('<div/>', {
            'class': 'search-filter'
        }).appendTo(header);

        that.filter = $('<input/>', {
            type: 'text',
            name: 'filter'
        }).appendTo(filter_container);

        that.filter.keypress(function(e) {
            /* if the key pressed is the enter key */
            if (e.which == 13) {
                that.find();
            }
        });

        that.find_button = IPA.action_button({
            name: 'find',
            icon: 'search-icon',
            click: function() {
                that.find();
                return false;
            }
        }).appendTo(filter_container);

        header.append(IPA.create_network_spinner());

        var content = $('<div/>', {
            'class': 'hbac-test-content'
        }).appendTo(container);

        that.table.create(content);

        var id = that.entity.name+'-'+that.name+'-external';
        var pkey_name = that.managed_entity.metadata.primary_key;

        var tr = $('<tr/>').appendTo(that.table.tfoot);

        var td = $('<td/>', {
            name: 'external'
        }).appendTo(tr);

        that.external_radio = $('<input/>', {
            id: id,
            type: 'radio',
            name: pkey_name,
            value: '__external__',
            click: function() {
                that.selected_values = [ that.external_radio.val() ];
            }
        }).appendTo(td);

        var message = IPA.messages.objects.hbactest.specify_external;
        message = message.replace('${entity}', that.managed_entity.metadata.label_singular);

        $('<label/>', {
            text: message+':',
            'for': id
        }).appendTo(td);

        td.append(' ');

        that.external_text = $('<input/>', {
            name: id,
            focus: function() {
                that.external_radio.click();
            }
        }).appendTo(td);

        var footer = $('<div/>', {
            'class': 'hbac-test-footer'
        }).appendTo(container);

        that.create_buttons(footer);
    };

    that.find = function() {

        var old_filter = IPA.nav.get_state(that.entity.name+'-'+that.name+'-filter');
        var filter = that.filter.val();

        that.set_expired_flag();

        if (old_filter === filter) {
            that.refresh();
        } else {
            var state = {};
            state[that.entity.name+'-'+that.name+'-filter'] = filter;
            IPA.nav.push_state(state);
        }
    };

    that.get_selected_values = function() {
        var values = that.table.get_selected_values();
        if (values && values.length) return values;

        if (that.external_radio && that.external_radio.is(':checked')) {
            return [ that.external_radio.val() ];
        }

        return [];
    };

    that.reset = function() {
        delete that.selected_values;
        if (that.external_radio) that.external_radio.prop('checked', false);
        if (that.external_text) that.external_text.val('');
    };

    that.save = function(record) {
        if (that.selected_values && that.selected_values.length) {
            var value = that.selected_values[0];
            if (that.external_radio && value === that.external_radio.val()) {
                record[that.name] = that.external_text.val();
            } else {
                record[that.name] = value;
            }
        }
    };

    that.validate = function(record) {
        if (record[that.name]) return true;

        return false;
    };

    init();

    return that;
};

IPA.hbac.test_rules_facet = function(spec) {

    spec = spec || {};

    var that = IPA.hbac.test_facet(spec);

    var init = function() {
    };

    that.create_content = function(container) {

        var header = $('<div/>', {
            'class': 'hbac-test-header'
        }).appendTo(container);

        var title = $('<span/>', {
            text: that.label,
            'class': 'hbac-test-title'
        }).appendTo(header);

        header.append(' ');

        that.enabled = $('<input/>', {
            id: 'hbactest-rules-include-enabled',
            type: 'checkbox',
            name: 'enabled'
        }).appendTo(header);

        $('<label/>', {
            'for': 'hbactest-rules-include-enabled',
            text: IPA.messages.objects.hbactest.include_enabled
        }).appendTo(header);

        that.disabled = $('<input/>', {
            id: 'hbactest-rules-include-disabled',
            type: 'checkbox',
            name: 'disabled'
        }).appendTo(header);

        $('<label/>', {
            'for': 'hbactest-rules-include-disabled',
            text: IPA.messages.objects.hbactest.include_disabled
        }).appendTo(header);

        var content = $('<div/>', {
            'class': 'hbac-test-content'
        }).appendTo(container);

        that.table.create(content);

        var footer = $('<div/>', {
            'class': 'hbac-test-footer'
        }).appendTo(container);

        that.create_buttons(footer);
    };

    that.get_selected_values = function() {
        return that.table.get_selected_values();
    };

    that.reset = function() {
        delete that.selected_values;
        if (that.enabled) that.enabled.prop('checked', false);
        if (that.disabled) that.disabled.prop('checked', false);
    };

    that.save = function(record) {
        if (that.selected_values && that.selected_values.length) {
            record[that.name] = that.selected_values;
        }
        if (that.enabled && that.enabled.is(':checked')) {
            record['enabled'] = true;
        }
        if (that.disabled && that.disabled.is(':checked')) {
            record['disabled'] = true;
        }
    };

    init();

    return that;
};

IPA.hbac.test_run_facet = function(spec) {

    spec = spec || {};

    var that = IPA.hbac.test_facet(spec);

    var init = function() {
        that.table.selectable = false;
        that.show_matched = true;
        that.show_unmatched = true;
    };

    that.create_content = function(container) {

        var header = $('<div/>', {
            'class': 'hbac-test-header'
        }).appendTo(container);

        var top_panel = $('<div/>', {
            'class': 'hbac-test-top-panel'
        }).appendTo(header);

        var button_panel = $('<div/>', {
            'class': 'hbac-test-button-panel'
        }).appendTo(top_panel);

        that.run_button = IPA.button({
            name: 'run_test',
            label: IPA.messages.objects.hbactest.run_test,
            click: function() {
                if (!that.run_button.hasClass('action-button-disabled')) {
                    that.run();
                }
                return false;
            }
        }).appendTo(button_panel);

        var result_panel = $('<div/>', {
            'class': 'hbac-test-result-panel'
        }).appendTo(top_panel);

        that.test_result = $('<p/>', {
            'class': 'hbac-test-title'
        }).appendTo(result_panel);

        var title = $('<span/>', {
            text: IPA.messages.objects.hbactest.rules,
            'class': 'hbac-test-title'
        }).appendTo(header);

        header.append(' ');

        that.matched_checkbox = $('<input/>', {
            id: 'hbactest-rules-matched',
            type: 'checkbox',
            name: 'matched',
            checked: true,
            change: function() {
                that.show_matched = that.matched_checkbox.is(':checked');
                that.refresh();
            }
        }).appendTo(header);

        $('<label/>', {
            'for': 'hbactest-rules-matched',
            text: IPA.messages.objects.hbactest.matched
        }).appendTo(header);

        that.unmatched_checkbox = $('<input/>', {
            id: 'hbactest-rules-unmatched',
            type: 'checkbox',
            name: 'unmatched',
            checked: true,
            change: function() {
                that.show_unmatched = that.unmatched_checkbox.is(':checked');
                that.refresh();
            }
        }).appendTo(header);

        $('<label/>', {
            'for': 'hbactest-rules-unmatched',
            text: IPA.messages.objects.hbactest.unmatched
        }).appendTo(header);

        var content = $('<div/>', {
            'class': 'hbac-test-content'
        }).appendTo(container);

        that.table.create(content);

        var footer = $('<div/>', {
            'class': 'hbac-test-footer'
        }).appendTo(container);

        var buttons = $('<div/>', {
            'class': 'hbac-test-navigation-buttons'
        }).appendTo(footer);

        that.prev_button = IPA.button({
            name: 'prev',
            label: IPA.messages.widget.prev,
            icon: 'ui-icon ui-icon-triangle-1-w',
            click: function() {
                if (!that.prev_button.hasClass('action-button-disabled')) {
                    that.prev();
                }
                return false;
            }
        }).appendTo(buttons);

        buttons.append(' ');

        that.new_test_button = IPA.button({
            name: 'new_test',
            label: IPA.messages.objects.hbactest.new_test,
            click: function() {
                if (!that.new_test_button.hasClass('action-button-disabled')) {
                    that.new_test();
                }
                return false;
            }
        }).appendTo(buttons);
    };

    that.new_test = function() {
        var facet = that.entity.get_facet('user');
        facet.reset();

        facet = that.entity.get_facet('targethost');
        facet.reset();

        facet = that.entity.get_facet('service');
        facet.reset();

        facet = that.entity.get_facet('sourcehost');
        facet.reset();

        facet = that.entity.get_facet('rules');
        facet.reset();

        facet = that.entity.get_facet('run_test');
        facet.reset();

        var state = {};
        state[that.entity.name+'-facet'] = 'user';
        IPA.nav.push_state(state);
    };

    that.reset = function() {
        delete that.data;
        that.show_matched = true;
        that.show_unmatched = true;
        if (that.matched_checkbox) that.matched_checkbox.prop('checked', true);
        if (that.unmatched_checkbox) that.unmatched_checkbox.prop('checked', true);
        that.refresh();
    };

    that.refresh = function() {
        if (that.data) {
            var message = that.data.result.value ?
                IPA.messages.objects.hbactest.access_granted :
                IPA.messages.objects.hbactest.access_denied;
            that.test_result.text(message);

        } else {
            that.test_result.text('');
        }

        that.load(that.data);
    };

    that.run = function() {

        var command = IPA.command({ method: 'hbactest' });

        var options = {};
        var validation_results = {
            valid: true,
            invalid_facets: []
        };

        var facet = that.entity.get_facet('user');
        facet.save(options);
        that.validate_facet(facet, options, validation_results);

        facet = that.entity.get_facet('targethost');
        facet.save(options);
        that.validate_facet(facet, options, validation_results);

        facet = that.entity.get_facet('service');
        facet.save(options);
        that.validate_facet(facet, options, validation_results);

        facet = that.entity.get_facet('sourcehost');
        facet.save(options);
        that.validate_facet(facet, options, validation_results);

        if (!validation_results.valid) {
            var dialog = IPA.hbac.validation_dialog({
                validation_results: validation_results
            });
            dialog.open();
            return;
        }

        facet = that.entity.get_facet('rules');
        facet.save(options);

        command.set_options(options);

        command.on_success = function(data, text_status, xhr) {
            that.data = data;
            that.refresh();
        };

        command.execute();
    };

    that.validate_facet = function(facet, options, validation_results) {

        var facet_valid = facet.validate(options);

        validation_results.valid = facet_valid && validation_results.valid;

        if (!facet_valid) {
            validation_results.invalid_facets.push(facet);
        }
    };

    that.get_records_map = function(data) {

        var records_map = $.ordered_map();

        var matched = data.result.matched;
        if (that.show_matched && matched) {
            for (var i=0; i<matched.length; i++) {
                var pkey = matched[i];
                records_map.put(pkey, { matched: true });
            }
        }

        var notmatched = data.result.notmatched;
        if (that.show_unmatched && notmatched) {
            for (i=0; i<notmatched.length; i++) {
                pkey = notmatched[i];
                records_map.put(pkey, { matched: false });
            }
        }

        return records_map;
    };

    that.get_records_command_name = function() {
        if (that.show_matched && !that.show_unmatched) {
            return 'hbactest_matched';
        }
        if (!that.show_matched && that.show_unmatched) {
            return 'hbactest_unmatched';
        }
        return that.managed_entity.name+'_get_records';
    };

    init();

    return that;
};

IPA.hbac.validation_dialog = function(spec)  {

    spec = spec || {};
    spec.title = spec.title || IPA.messages.dialogs.validation_title;
    spec.message = spec.message || IPA.messages.dialogs.validation_message;

    var that = IPA.message_dialog(spec);

    that.validation_results = spec.validation_results;

    that.create = function() {

        if (that.message) {
            that.message_dialog_create();
        }

        if (that.validation_results && that.validation_results.invalid_facets) {
            var invalid_facets = that.validation_results.invalid_facets;

            var ul;

            if (invalid_facets.length > 0) {
                var div = $('<div/>',{
                     text: IPA.messages.objects.hbactest.missing_values
                }).appendTo(that.container);
                ul = $('<ul/>').appendTo(that.container);
            }

            for (var i=0; i<invalid_facets.length; i++) {

                var facet = invalid_facets[i];

                var li = $('<li />').appendTo(ul);

                var metadata = IPA.get_command_option('hbactest', facet.name);

                $('<a />', {
                    href: '#'+facet.name,
                    text: metadata.label,
                    click: function(facet) {
                        return function() {
                            that.redirect_to_facet(facet);
                            return false;
                        };
                    }(facet)
                }).appendTo(li);
            }
        }
    };

    that.redirect_to_facet = function(facet) {
        that.close();
        var state = {};
        state[facet.entity.name+'-facet'] = facet.name;
        IPA.nav.push_state(state);
    };

    return that;
};

IPA.register('hbactest', IPA.hbac.test_entity);
