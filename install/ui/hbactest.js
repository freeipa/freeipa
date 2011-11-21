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
            factory: IPA.hbac.test_facet,
            name: 'user',
            label: 'Who',
            managed_entity_name: 'user',
            disable_breadcrumb: true,
            facet_group: 'default',
            columns: [
                'uid',
                'givenname',
                'sn'
            ]
        }).
        facet({
            factory: IPA.hbac.test_facet,
            name: 'targethost',
            label: 'Accessing',
            managed_entity_name: 'host',
            disable_breadcrumb: true,
            facet_group: 'default',
            columns: [
                'fqdn',
                'description',
                {
                    name: 'has_keytab',
                    label: IPA.messages.objects.host.enrolled
                }
            ]
        }).
        facet({
            factory: IPA.hbac.test_facet,
            name: 'service',
            label: 'Via Service',
            managed_entity_name: 'hbacsvc',
            disable_breadcrumb: true,
            facet_group: 'default',
            columns: [
                'cn',
                'description'
            ]
        }).
        facet({
            factory: IPA.hbac.test_facet,
            name: 'sourcehost',
            label: 'From Host',
            managed_entity_name: 'host',
            disable_breadcrumb: true,
            facet_group: 'default',
            columns: [
                'fqdn',
                'description',
                {
                    name: 'has_keytab',
                    label: IPA.messages.objects.host.enrolled
                }
            ]
        }).
        facet({
            factory: IPA.hbac.test_rules_facet,
            name: 'rules',
            label: 'On Rules',
            managed_entity_name: 'hbacrule',
            disable_breadcrumb: true,
            facet_group: 'default',
            multivalued: true,
            columns: [
                'cn',
                'ipaenabledflag',
                'description'
            ]
        }).
        facet({
            factory: IPA.hbac.test_run_facet,
            name: 'run',
            label: 'Run Test',
            managed_entity_name: 'hbacrule',
            disable_breadcrumb: true,
            pagination: true,
            facet_group: 'default',
            columns: [
                'cn',
                {
                    name: 'matched',
                    label: 'Matched'
                },
                'ipaenabledflag',
                'description'
            ]
        });
    };

    return that;
};

IPA.hbac.test_facet = function(spec) {

    spec = spec || {};

    var that = IPA.table_facet(spec);
    that.multivalued = spec.multivalued;

    var init = function() {

        that.managed_entity = IPA.get_entity(that.managed_entity_name);

        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++) {
            var column = columns[i];

            var metadata = IPA.get_entity_param(that.managed_entity_name, column.name);
            column.primary_key = metadata && metadata.primary_key;
            column.link = column.primary_key;
        }

        that.init_table(that.managed_entity);
        that.table.multivalued = that.multivalued ? true : false;
    };

    that.create_content = function(container) {

        var header = $('<h3/>', {
            text: that.label
        }).appendTo(container);

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

        var div = $('<div/>', {
            style: 'position: relative; height: 200px'
        }).appendTo(container);

        that.table.create(div);

        container.append('<br/>');

        that.create_buttons(container);
    };

    that.create_buttons = function(container) {

        var buttons = $('<div/>', {
            style: 'float: right'
        }).appendTo(container);

        var facet_group = that.entity.get_facet_group('default');
        var index = facet_group.get_facet_index(that.name);

        if (index > 0) {
            that.back_button = IPA.button({
                name: 'back',
                label: 'Back',
                icon: 'ui-icon ui-icon-triangle-1-w',
                click: function() {
                    if (!that.back_button.hasClass('action-button-disabled')) {
                        that.back();
                    }
                    return false;
                }
            }).appendTo(buttons);

            buttons.append(' ');
        }

        that.next_button = IPA.button({
            name: 'next',
            label: 'Next',
            icon: 'ui-icon ui-icon-triangle-1-e',
            click: function() {
                if (!that.next_button.hasClass('action-button-disabled')) {
                    that.next();
                }
                return false;
            }
        }).appendTo(buttons);
    };

    that.back = function() {
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

    that.get_pkeys = function(data) {
        var result = data.result.result;
        var pkey_name = that.managed_entity.metadata.primary_key;
        var pkeys = [];
        for (var i=0; i<result.length; i++) {
            var record = result[i];
            var values = record[pkey_name];
            pkeys.push(values[0]);
        }
        return pkeys;
    };

    that.get_search_command_name = function() {
        return that.managed_entity.name + '_find' + (that.pagination ? "_pkeys" : "");
    };

    that.refresh = function() {

        var filter = IPA.nav.get_state(that.managed_entity.name+'-filter');

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
            if (that.filter) that.filter.focus();
            that.load(data);
        };

        command.on_error = function(xhr, text_status, error_thrown) {
            that.report_error(error_thrown);
        };

        command.execute();
    };

    that.reset = function() {
        that.table.set_values([]);
    };

    that.save = function(record) {
        if (that.selected_values && that.selected_values.length) {
            record[that.name] = that.selected_values[0];
        }
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

        var header = $('<p/>', {
        }).appendTo(container);

        $('<h3/>', {
            text: that.label,
            style: 'display: inline-block'
        }).appendTo(header);

        header.append(' ');

        that.enabled = $('<input/>', {
            id: 'hbactest-rules-include-enabled',
            type: 'checkbox',
            name: 'enabled'
        }).appendTo(header);

        $('<label/>', {
            'for': 'hbactest-rules-include-enabled',
            text: 'Include enabled'
        }).appendTo(header);

        that.disabled = $('<input/>', {
            id: 'hbactest-rules-include-disabled',
            type: 'checkbox',
            name: 'disabled'
        }).appendTo(header);

        $('<label/>', {
            'for': 'hbactest-rules-include-disabled',
            text: 'Include disabled'
        }).appendTo(header);

        var div = $('<div/>', {
            style: 'position: relative; height: 200px'
        }).appendTo(container);

        that.table.create(div);

        container.append('<br/>');

        that.create_buttons(container);
    };

    that.reset = function() {
        that.table.set_values([]);
        if (that.enabled) that.enabled.attr('checked', false);
        if (that.disabled) that.enabled.attr('checked', false);
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
    };

    that.create_content = function(container) {

        var action_panel = $('<div/>', {
            style: 'border: 1px solid #C9C3BA; padding: 10px'
        }).appendTo(container);

        var action_button = $('<div/>', {
            style: 'width: 100px; display: inline-block'
        }).appendTo(action_panel);

        that.run_button = IPA.button({
            name: 'run',
            label: 'Run Test',
            click: function() {
                if (!that.run_button.hasClass('action-button-disabled')) {
                    that.run();
                }
                return false;
            }
        }).appendTo(action_button);

        var action_result = $('<div/>', {
            style: 'display: inline-block'
        }).appendTo(action_panel);

        that.test_result = $('<p/>').appendTo(action_result);

        var header = $('<h3/>', {
            text: 'Rules'
        }).appendTo(container);

        var div = $('<div/>', {
            style: 'position: relative; height: 200px'
        }).appendTo(container);

        that.table.create(div);

        container.append('<br/>');

        var buttons = $('<div/>', {
            style: 'float: right'
        }).appendTo(container);

        that.back_button = IPA.button({
            name: 'back',
            label: 'Back',
            icon: 'ui-icon ui-icon-triangle-1-w',
            click: function() {
                if (!that.back_button.hasClass('action-button-disabled')) {
                    that.back();
                }
                return false;
            }
        }).appendTo(buttons);

        buttons.append(' ');

        that.new_test_button = IPA.button({
            name: 'new_test',
            label: 'New Test',
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

        facet = that.entity.get_facet('run');
        facet.reset();

        var state = {};
        state[that.entity.name+'-facet'] = 'user';
        IPA.nav.push_state(state);
    };

    that.reset = function() {
        that.test_result.text('');
        that.table.empty();
        that.table.set_values([]);
    };

    that.refresh = function() {
    };

    that.run = function() {

        var command = IPA.command({ method: 'hbactest' });

        var options = {};

        var facet = that.entity.get_facet('user');
        facet.save(options);

        facet = that.entity.get_facet('targethost');
        facet.save(options);

        facet = that.entity.get_facet('service');
        facet.save(options);

        facet = that.entity.get_facet('sourcehost');
        facet.save(options);

        facet = that.entity.get_facet('rules');
        facet.save(options);

        command.set_options(options);

        command.on_success = function(data, text_status, xhr) {
            var message = data.result.value ? 'Access granted' : 'Access Denied';
            that.test_result.text(message);

            that.load(data);
        };

        command.execute();
    };

    that.get_pkeys = function(data) {
        var pkeys = [];
        that.matched = {};

        var matched = data.result.matched;
        if (matched) {
            for (var i=0; i<matched.length; i++) {
                var pkey = matched[i];
                pkeys.push(pkey);
                that.matched[pkey] = 'TRUE';
            }
        }

        var notmatched = data.result.notmatched;
        if (notmatched) {
            for (i=0; i<notmatched.length; i++) {
                pkey = notmatched[i];
                pkeys.push(pkey);
                that.matched[pkey] = 'FALSE';
            }
        }

        return pkeys;
    };

    that.load_records = function(records) {
        var pkey_name = that.table.entity.metadata.primary_key;
        that.table.empty();
        for (var i=0; i<records.length; i++) {
            var record = records[i];
            var pkey = record[pkey_name];
            record.matched = that.matched[pkey];
            that.table.add_record(record);
        }
        that.table.set_values(that.selected_values);
    };

    init();

    return that;
};

IPA.register('hbactest', IPA.hbac.test_entity);
