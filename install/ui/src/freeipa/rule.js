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

define([
    './ipa',
    './jquery',
    './phases',
    './reg',
    './rpc',
    './text',
    './details',
    './search',
    './association',
    './entity'],
        function(IPA, $, phases, reg, rpc, text) {

IPA.rule_details_widget = function(spec) {

    spec = spec || {};

    var that = IPA.composite_widget(spec);

    that.radio_name = spec.radio_name;
    that.options = spec.options || [];
    that.tables = spec.tables || [];
    that.columns = spec.columns;
    that.note = spec.note;

    that.init = function() {

        that.enable_radio = IPA.rule_radio_widget({
            name: that.radio_name,
            options: that.options,
            entity: that.entity,
            css_class: 'rule-enable-radio',
            note: that.note
        });

        that.widgets.add_widget(that.enable_radio);
        that.enable_radio.value_changed.attach(that.on_enable_radio_changed);
    };

    that.on_enable_radio_changed = function() {
        var value = that.enable_radio.save();
        if(value.length > 0) {
            var enabled = ('' === value[0]);
            for (var i=0; i<that.tables.length; i++) {
                var table = that.tables[i];

                var table_widget = that.widgets.get_widget(table.name);
                table_widget.set_enabled(enabled);
            }
        }
    };

    that.init();

    return that;
};

/**
 * Rule radio widget
 *
 * Intended to be used especially by rule widget.
 *
 * @class IPA.rule_radio_widget
 * @extends IPA.radio_widget
 */
IPA.rule_radio_widget = function(spec) {

    spec = spec || {};
    var that = IPA.radio_widget(spec);

    /**
     * The text from note will be displayed after radio buttons.
     */
    that.note = spec.note || '';

    /** @inheritDoc */
    that.create = function(container) {

        var param_info = IPA.get_entity_param(that.entity.name, that.name);
        var title = param_info ? param_info.doc : that.name;

        container.append(document.createTextNode(title + ': '));
        that.widget_create(container);
        that.owb_create(container);
        if (that.undo) {
            that.create_undo(container);
        }

        if (that.note) {
            $('<div />', {
                text: text.get(that.note),
                'class': 'rule-radio-note'
            }).appendTo(container);
        }
    };

    return that;
};


IPA.rule_association_table_widget = function(spec) {

    spec = spec || {};
    spec.footer = spec.footer === undefined ? false : spec.footer;

    var that = IPA.association_table_widget(spec);

    that.external = spec.external;

    that.setup_column = function(column, div, record) {
        var suppress_link = false;
        if (that.external) {
            suppress_link = record[that.external] === 'true';
        }
        column.setup(div, record, suppress_link);
    };

    that.create_columns = function() {

        if (!that.columns.length) {
            that.association_table_widget_create_columns();
            if (that.external) {
                that.create_column({
                    name: that.external,
                    label: '@i18n:objects.sudorule.external',
                    entity: that.other_entity,
                    formatter: 'boolean',
                    width: '200px'
                });
            }
        }
    };

    that.create_add_dialog = function() {

        var pkey = that.facet.get_pkey();

        var title = that.add_title;
        title = title.replace('${primary_key}', pkey);

        var exclude = that.values;
        if (that.external) {
            exclude = [];
            for (var i=0; i<that.values.length; i++) {
                exclude.push(that.values[i][that.name]);
            }
        }

        return IPA.rule_association_adder_dialog({
            title: title,
            pkey: pkey,
            other_entity: that.other_entity,
            attribute_member: that.attribute_member,
            entity: that.entity,
            external: that.external,
            exclude: exclude
        });
    };

    return that;
};

IPA.rule_association_table_field = function(spec) {

    spec = spec || {};

    var that = IPA.association_table_field(spec);

    that.external = spec.external;

    that.set_values_external = function(values, external) {

        for (var i=0; i<values.length; i++) {

            var record = values[i];

            if (typeof record !== 'object') {
                record = {};
                record[that.param] = values[i];
            }

            record[that.external] = external;

            values[i] = record;
        }
    };

    that.load = function(data) {
        that.values = that.adapter.load(data);

        if (that.external) {
            that.set_values_external(that.values, '');
            var external_values = that.adapter.load(data, that.external, []);
            that.set_values_external(external_values, 'true');
            $.merge(that.values, external_values);
        }

        that.widget.update(that.values);
        that.widget.unselect_all();
    };

    that.get_update_info = function() {

        var update_info = IPA.update_info_builder.new_update_info();

        //association_table_widget performs basic add and remove operation
        //immediately. Rule association field test if its enabled and if not it
        //performs delete operation.

        if (!that.widget.enabled) {
            var values = that.widget.save();

            if (values.length > 0) { //no need to delete if has no values

                var command = rpc.command({
                    entity: that.entity.name,
                    method: that.widget.remove_method,
                    args: that.facet.get_pkeys()
                });

                command.set_option(that.widget.other_entity.name, values);
                update_info.append_command(command, that.priority);
            }
        }

        return update_info;
    };

    return that;
};

IPA.rule_association_adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.association_adder_dialog(spec);

    that.external = spec.external;

    that.add = function() {
        var rows = that.available_table.remove_selected_rows();
        that.selected_table.add_rows(rows);

        if (that.external) {
            var pkey_name = that.other_entity.metadata.primary_key;
            var value = that.external_field.val();
            if (!value) return;

            var record = {};
            record[pkey_name] = value;
            that.selected_table.add_record(record);
            that.external_field.val('');
        }
    };

    return that;
};

phases.on('registration', function() {
    var w = reg.widget;
    var f = reg.field;

    w.register('rule_association_table', IPA.rule_association_table_widget);
    f.register('rule_association_table', IPA.rule_association_table_field);
});

return {};
});
