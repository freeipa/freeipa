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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.rule_details_widget = function(spec) {

    spec = spec || {};

    var that = IPA.composite_widget(spec);

    that.radio_name = spec.radio_name;
    that.options = spec.options || [];
    that.tables = spec.tables || [];
    that.columns = spec.columns;

    that.init = function() {

        that.enable_radio = IPA.radio_widget({
            name: that.radio_name,
            options: that.options
        });

        that.widgets.add_widget(that.enable_radio);
        that.enable_radio.value_changed.attach(that.on_enable_radio_changed);
    };

    that.on_enable_radio_changed = function(value) {
        if(value.length > 0) {
            var enabled = ('' === value[0]);
            for (var i=0; i<that.tables.length; i++) {
                var table = that.tables[i];

                var table_widget = that.widgets.get_widget(table.name);
                table_widget.set_enabled(enabled);
            }
        }
    };

    that.create = function(container) {

        that.container = container;

        //enable radios
        var param_info = IPA.get_entity_param(that.entity.name, that.radio_name);
        var title = param_info ? param_info.doc : that.radio_name;
        var enable_radio_container = $('<div/>', {
            name: that.radio_name,
            title: title,
            'class': 'field'
        }).appendTo(container);

        enable_radio_container.append(title+': ');
        that.enable_radio.create(enable_radio_container);

        //tables
        for (var j=0; j<that.tables.length; j++) {
            var table = that.tables[j];

            var metadata = IPA.get_entity_param(that.entity.name, table.name);

            var table_container = $('<div/>', {
                name: table.name,
                title: metadata ? metadata.doc : table.name,
                'class': 'field'
            }).appendTo(container);

            var widget = that.widgets.get_widget(table.name);
            widget.create(table_container);
        }
    };

    that.init();

    return that;
};


IPA.rule_association_table_widget = function(spec) {

    spec = spec || {};

    var that = IPA.association_table_widget(spec);

    that.external = spec.external;

    that.enabled = spec.enabled !== undefined ? spec.enabled : true;

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
                    label: IPA.messages.objects.sudorule.external,
                    entity: that.other_entity,
                    formatter: IPA.boolean_formatter(),
                    width: '200px'
                });
            }
        }
    };

    that.create_add_dialog = function() {

        var entity_label = that.entity.metadata.label_singular;
        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        var other_entity_label = that.other_entity.metadata.label;

        var title = that.add_title;
        title = title.replace('${entity}', entity_label);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', other_entity_label);

        return IPA.rule_association_adder_dialog({
            title: title,
            pkey: pkey,
            other_entity: that.other_entity,
            attribute_member: that.attribute_member,
            entity: that.entity,
            external: that.external,
            exclude: that.values
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

    that.load = function(result) {
        that.values = result[that.param] || [];

        if (that.external) {
            that.set_values_external(that.values, '');
            var external_values = result[that.external] || [];
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
            var values = that.save();

            if (values.length > 0) { //no need to delete if has no values

                var command = IPA.command({
                    entity: that.entity.name,
                    method: that.widget.remove_method,
                    args: that.entity.get_primary_key()
                });

                command.set_option(that.widget.other_entity.name, values);
                update_info.append_command(command, that.priority);
            }
        }

        return update_info;
    };

    return that;
};

IPA.widget_factories['rule_association_table'] = IPA.rule_association_table_widget;
IPA.field_factories['rule_association_table'] = IPA.rule_association_table_field;

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
