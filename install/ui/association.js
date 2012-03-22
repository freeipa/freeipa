/*jsl:import ipa.js */

/*  Authors:
 *    Adam Young <ayoung@redhat.com>
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

/* REQUIRES: ipa.js */
/* CURRENTLY ALSO REQUIRES search.js, because it reuses it's code to create
 * the AssociationList elements; IT NEEDS IT'S OWN CODE! */

IPA.associator = function (spec) {

    spec = spec || {};

    var that = {};

    that.entity = IPA.get_entity(spec.entity);
    that.pkey = spec.pkey;

    that.other_entity = IPA.get_entity(spec.other_entity);
    that.values = spec.values;

    that.method = spec.method;

    that.on_success = spec.on_success;
    that.on_error = spec.on_error;

    that.execute = function() {
    };

    return that;
};


/**
*This associator is built for the case where each association requires a separate rpc
*/
IPA.serial_associator = function(spec) {

    spec = spec || {};

    var that = IPA.associator(spec);

    that.execute = function() {

        if (!that.values || !that.values.length) {
            that.on_success();
            return;
        }

        var batch = IPA.batch_command({
            on_success: that.on_success,
            on_error: that.on_error
        });

        var args, options, command;

        for(var i=0; i < that.values.length; i++) {
            args = [that.values[i]];
            options = {};
            options[that.entity.name] = that.pkey;

            command = IPA.command({
                entity: that.other_entity.name,
                method: that.method,
                args: args,
                options: options
            });

            batch.add_command(command);
        }
        //alert(JSON.stringify(command.to_json()));

        batch.execute();
    };

    return that;
};

/**
*This associator is for the common case where all the asociations can be sent
in a single rpc
*/
IPA.bulk_associator = function(spec) {

    spec = spec || {};

    var that = IPA.associator(spec);

    that.execute = function() {

        if (!that.values || !that.values.length) {
            that.on_success();
            return;
        }

        var command = IPA.command({
            entity: that.entity.name,
            method: that.method,
            args: [that.pkey],
            options: { 'all': true },
            on_success: that.on_success,
            on_error: that.on_error
        });

        command.set_option(that.other_entity.name, that.values);

        //alert(JSON.stringify(command.to_json()));

        command.execute();
    };

    return that;
};

/**
 * This dialog is used for adding associations between two entities.
 */
IPA.association_adder_dialog = function(spec) {

    spec = spec || {};

    var that = IPA.adder_dialog(spec);

    that.entity = IPA.get_entity(spec.entity);
    that.pkey = spec.pkey;

    that.other_entity = IPA.get_entity(spec.other_entity);
    that.attribute_member = spec.attribute_member;

    that.exclude = spec.exclude || [];

    var init = function() {
        if (!that.get_columns().length) {
            var pkey_name = that.other_entity.metadata.primary_key;
            that.create_column({
                entity: that.entity,
                name: pkey_name,
                label: that.other_entity.metadata.label,
                primary_key: true,
                width: '600px'
            });
        }
    };

    that.search = function() {
        function on_success(data, text_status, xhr) {

            that.clear_available_values();

            var pkey_attr = that.other_entity.metadata.primary_key;

            var selected = that.get_selected_values();

            var results = data.result;
            var same_entity = that.entity === that.other_entity;
            for (var i=0; i<results.count; i++) {
                var result = results.result[i];
                var pkey = result[pkey_attr][0];

                if (same_entity && pkey === that.pkey) continue;
                if (that.exclude.indexOf(pkey) >= 0) continue;
                if (selected.indexOf(pkey) >= 0) continue;

                that.add_available_value(result);
            }
        }

        var options = { all: true };
        var relationships = that.other_entity.metadata.relationships;

        /* TODO: better generic handling of different relationships! */
        var other_attribute_member = '';
        if (that.attribute_member == 'member')
            other_attribute_member = 'memberof';
        else if (that.attribute_member == 'memberuser')
            other_attribute_member = 'memberof';
        else if (that.attribute_member == 'memberhost')
            other_attribute_member = 'memberof';
        else if (that.attribute_member == 'memberof')
            other_attribute_member = 'member';
        else if (that.attribute_member == 'managedby')
            other_attribute_member = 'managing';

        var relationship = relationships[other_attribute_member];
        if (relationship) {
            var param_name = relationship[2] + that.entity.name;
            options[param_name] = that.pkey;
        }

        IPA.command({
            entity: that.other_entity.name,
            method: 'find',
            args: [that.get_filter()],
            options: options,
            on_success: on_success
        }).execute();
    };

    init();

    return that;
};


/**
 * This dialog is used for removing associations between two entities.
 */
IPA.association_deleter_dialog = function (spec) {

    spec = spec || {};

    var that = IPA.deleter_dialog(spec);

    that.entity = IPA.get_entity(spec.entity);
    that.pkey = spec.pkey;

    that.other_entity = IPA.get_entity(spec.other_entity);
    that.values = spec.values;

    that.associator = spec.associator;
    that.method = spec.method || 'remove_member';

    that.on_success = spec.on_success;
    that.on_error = spec.on_error;

    that.execute = function() {

        var associator = that.associator({
            entity: that.entity,
            pkey: that.pkey,
            other_entity: that.other_entity,
            values: that.values,
            method: that.method,
            on_success: that.on_success,
            on_error: that.on_error
        });

        associator.execute();
    };

    return that;
};


IPA.association_config = function (spec) {

    spec = spec || {};

    var that = {};

    that.name = spec.name;
    that.associator = spec.associator;
    that.add_method = spec.add_method;
    that.remove_method = spec.remove_method;

    return that;
};

IPA.association_table_widget = function (spec) {

    spec = spec || {};

    var index = spec.name.indexOf('_');
    spec.attribute_member = spec.attribute_member || spec.name.substring(0, index);
    spec.other_entity = spec.other_entity || spec.name.substring(index+1);

    spec.managed_entity = IPA.get_entity(spec.other_entity);

    var that = IPA.table_widget(spec);

    that.other_entity = IPA.get_entity(spec.other_entity);
    that.attribute_member = spec.attribute_member;

    that.associator = spec.associator || IPA.bulk_associator;
    that.add_method = spec.add_method || 'add_member';
    that.remove_method = spec.remove_method || 'remove_member';

    that.add_title = spec.add_title || IPA.messages.association.add.member;
    that.remove_title = spec.remove_title || IPA.messages.association.remove.member;

    that.adder_columns = $.ordered_map();

    that.needs_refresh = IPA.observer();

    that.get_adder_column = function(name) {
        return that.adder_columns.get(name);
    };

    that.add_adder_column = function(column) {
        that.adder_columns.put(column.name, column);
    };

    that.create_adder_column = function(spec) {
        spec.entity = that.other_entity;
        var column = IPA.column(spec);
        that.add_adder_column(column);
        return column;
    };

    that.create_columns = function() {
        // create a column if none defined
        if (!that.columns.length) {
            that.create_column({
                name: that.name,
                label: that.label,
                entity: that.other_entity,
                primary_key: true,
                link: true
            });
        }
    };

    that.init_columns = function() {
        var column;
        var columns = that.columns.values;
        for (var i=0; i<columns.length; i++) {
            column = columns[i];
            column.entity = that.other_entity;

            if (column.link) {
                column.link_handler = function(value) {
                    IPA.nav.show_page(that.other_entity.name, 'default', value);
                    return false;
                };
            }
        }
    };

    that.init_adder_columns = function() {
        var column;
        var adder_columns = that.adder_columns.values;
        for (var j=0; j<adder_columns.length; j++) {
            column = adder_columns[j];
            column.entity = that.other_entity;
        }
    };

    that.init = function() {

        that.create_columns();
        that.init_columns();
        that.init_adder_columns();
    };

    that.create = function(container) {

        that.init();

        that.table_create(container);

        that.remove_button = IPA.action_button({
            name: 'remove',
            label: IPA.messages.buttons.remove,
            icon: 'remove-icon',
            'class': 'action-button-disabled',
            click: function() {
                if (!that.remove_button.hasClass('action-button-disabled')) {
                    that.remove_handler();
                }
                return false;
            }
        }).appendTo(that.buttons);

        that.add_button = IPA.action_button({
            name: 'add',
            label: IPA.messages.buttons.add,
            icon: 'add-icon',
            click: function() {
                if (!that.add_button.hasClass('action-button-disabled')) {
                    that.add_handler();
                }
                return false;
            }
        }).appendTo(that.buttons);
    };

    that.add_handler = function() {
        var facet = that.entity.get_facet();

        if (facet.is_dirty()) {
            var dialog = IPA.dirty_dialog({
                entity:that.entity,
                facet: facet
            });

            dialog.callback = function() {
                that.show_add_dialog();
            };

            dialog.open(that.container);

        } else {
            that.show_add_dialog();
        }
    };

    that.remove_handler = function() {
        var facet = that.entity.get_facet();

        if (facet.is_dirty()) {
            var dialog = IPA.dirty_dialog({
                entity:that.entity,
                facet: facet
            });

            dialog.callback = function() {
                that.show_remove_dialog();
            };

            dialog.open(that.container);

        } else {
            that.show_remove_dialog();
        }
    };

    that.set_enabled = function(enabled) {
        that.table_set_enabled(enabled);
        if (enabled) {
            if(that.add_button) {
                that.add_button.removeClass('action-button-disabled');
            }
        } else {
            $('.action-button', that.table).addClass('action-button-disabled');
            that.unselect_all();
        }
        that.enabled = enabled;
    };

    that.select_changed = function() {

        var values = that.get_selected_values();

        if (that.remove_button) {
            if (values.length === 0) {
                that.remove_button.addClass('action-button-disabled');
            } else {
                that.remove_button.removeClass('action-button-disabled');
            }
        }
    };

    that.load = function(result) {
        that.values = result[that.name] || [];
        that.update();
        that.unselect_all();
    };

    that.update = function(values) {

        if (values) that.values = values;

        that.empty();

        var i;
        var columns = that.columns.values;
        if (columns.length == 1) { // show pkey only
            var name = columns[0].name;
            for (i=0; i<that.values.length; i++) {
                var record = {};
                record[name] = that.values[i];
                that.add_record(record);
            }
        } else {
            for (i=0; i<that.values.length; i++) {
                that.add_record(that.values[i]);
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

        return IPA.association_adder_dialog({
            title: title,
            entity: that.entity,
            pkey: pkey,
            other_entity: that.other_entity,
            attribute_member: that.attribute_member,
            method: that.add_method,
            exclude: that.values
        });
    };

    that.show_add_dialog = function() {

        var dialog = that.create_add_dialog({entity:that.entity});

        var columns = that.adder_columns.values;
        if (columns.length) {
            dialog.set_columns(columns);
        }

        dialog.execute = function() {
            that.add(
                dialog.get_selected_values(),
                function() {
                    that.refresh();
                    dialog.close();
                },
                function() {
                    that.refresh();
                    dialog.close();
                }
            );
        };

        dialog.open(that.container);
    };

    that.add = function(values, on_success, on_error) {

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');

        var command = IPA.command({
            entity: that.entity.name,
            method: that.add_method,
            args: [pkey],
            on_success: on_success,
            on_error: on_error
        });
        command.set_option(that.other_entity.name, values);

        command.execute();
    };

    that.show_remove_dialog = function() {

        var selected_values = that.get_selected_values();

        if (!selected_values.length) {
            var message = IPA.messages.dialogs.remove_empty;
            alert(message);
            return;
        }

        var entity_label = that.entity.metadata.label_singular;
        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        var other_entity_label = that.other_entity.metadata.label;

        var title = that.remove_title;
        title = title.replace('${entity}', entity_label);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', other_entity_label);

        var dialog = IPA.association_deleter_dialog({
            title: title,
            entity: that.entity,
            pkey: pkey,
            other_entity: that.other_entity,
            values: selected_values,
            method: that.remove_method
        });

        dialog.execute = function() {
            that.remove(
                selected_values,
                function() {
                    that.refresh();
                    dialog.close();
                },
                function() {
                    that.refresh();
                    dialog.close();
                }
            );
        };


        dialog.open(that.container);
    };

    that.remove = function(values, on_success, on_error) {

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');

        var command = IPA.command({
            entity: that.entity.name,
            method: that.remove_method,
            args: [pkey],
            on_success: on_success,
            on_error: on_error
        });

        command.set_option(that.other_entity.name, values);

        command.execute();
    };

    that.refresh = function() {

        that.needs_refresh.notify([], that);
    };

    /*initialization code*/
    /*this is duplicated in the facet... should be unified*/
    var i;
    if (spec.columns){
        for (i = 0; i < spec.columns.length; i+= 1){
            spec.columns[i].entity = spec.columns[i].entity || that.other_entity;
            that.create_column(spec.columns[i]);
        }
    }
    if (spec.adder_columns){
        for (i = 0; i < spec.adder_columns.length; i+= 1){
            that.create_adder_column(spec.adder_columns[i]);
        }
    }

    // methods that should be invoked by subclasses
    that.association_table_widget_create_columns = that.create_columns;
    that.association_table_widget_show_add_dialog = that.show_add_dialog;
    that.association_table_widget_show_remove_dialog = that.show_remove_dialog;

    return that;
};

IPA.association_table_field = function (spec) {

    spec = spec || {};

    var that = IPA.field(spec);

    that.refresh = function() {

        function on_success(data, text_status, xhr) {
            that.load(data.result.result);
        }

        function on_error(xhr, text_status, error_thrown) {
            that.widget.summary.text(error_thrown.name+': '+error_thrown.message);
        }

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        IPA.command({
            entity: that.entity.name,
            method: 'show',
            args: [pkey],
            options: { all: true, rights: true },
            on_success: on_success,
            on_error: on_error
        }).execute();
    };

    that.widgets_created = function() {

        that.field_widgets_created();
        that.widget.needs_refresh.attach(that.refresh);
    };

    return that;
};

IPA.widget_factories['association_table'] = IPA.association_table_widget;
IPA.field_factories['association_table'] = IPA.association_table_field;


IPA.association_facet = function (spec) {

    spec = spec || {};

    /*
       Link parameter is used to turn off the links in selfservice mode.
       Default it to true if not set so that facets that would not otherwise
       link by default get links set.

       link must be set before the call to the base class, to affect the  table.
     */
    spec.link = spec.link === undefined ? true : spec.link;
    spec.managed_entity = IPA.get_entity(spec.other_entity);

    var that = IPA.table_facet(spec);

    that.attribute_member = spec.attribute_member;
    that.indirect_attribute_member = spec.indirect_attribute_member;

    that.other_entity = IPA.get_entity(spec.other_entity);

    that.association_type = 'direct';
    that.facet_group = spec.facet_group;

    that.read_only = spec.read_only;

    that.associator = spec.associator || IPA.bulk_associator;
    that.add_method = spec.add_method || 'add_member';
    that.remove_method = spec.remove_method || 'remove_member';

    that.add_title = spec.add_title || IPA.messages.association.add.member;
    that.remove_title = spec.remove_title || IPA.messages.association.remove.member;

    that.adder_columns = $.ordered_map();

    that.get_adder_column = function(name) {
        return that.adder_columns.get(name);
    };

    that.add_adder_column = function(column) {
        column.entity = that.other_entity;
        that.adder_columns.put(column.name, column);
    };

    /*TODO try to reuse the association_table_widget in association_facet*/
    that.create_adder_column = function(spec) {
        var column;
        var factory;
        if (spec instanceof Object) {
            factory = spec.factory || IPA.column;
        } else {
            factory  = IPA.column;
            spec = { name: spec };
        }
        spec.entity = that.other_entity;
        column = factory(spec);
        that.add_adder_column(column);
        return column;
    };

    var init = function() {

        var column;
        var i;

        var pkey_name;
        if (that.other_entity) {
            pkey_name = that.other_entity.metadata.primary_key;
        }

        if (!that.columns.length){
            that.create_column({
                name: pkey_name
            });
        }

        var columns = that.columns.values;
        for (i=0; i<columns.length; i++) {
            column = columns[i];
            column.link = spec.link;
        }

        that.init_table(that.other_entity);

        var adder_columns = spec.adder_columns || [];
        for (i=0; i<adder_columns.length; i++) {
            that.create_adder_column(adder_columns[i]);
        }

        if (!that.adder_columns.length) {
            that.create_adder_column({
                name: pkey_name,
                primary_key: true
            });
        }

        adder_columns = that.adder_columns.values;
        for (i=0; i<adder_columns.length; i++) {
            column = adder_columns[i];
            column.entity = that.other_entity;
        }
    };

    that.get_records_command_name = function() {
        return that.entity.name+'_'+that.get_attribute_name();
    };

    that.create_header = function(container) {

        that.facet_create_header(container);

        that.refresh_button = IPA.action_button({
            name: 'refresh',
            href: 'refresh',
            label: IPA.messages.buttons.refresh,
            icon: 'reset-icon',
            click: function() {
                that.refresh();
                return false;
            }
        }).appendTo(that.controls);

        if (!that.read_only) {
            that.remove_button = IPA.action_button({
                name: 'remove',
                label: IPA.messages.buttons.remove,
                icon: 'remove-icon',
                'class': 'action-button-disabled',
                click: function() {
                    if (!that.remove_button.hasClass('action-button-disabled')) {
                        that.show_remove_dialog();
                    }
                    return false;
                }
            }).appendTo(that.controls);

            that.add_button = IPA.action_button({
                name: 'add',
                label: IPA.messages.buttons.add,
                icon: 'add-icon',
                click: function() {
                    if (!that.add_button.hasClass('action-button-disabled')) {
                        that.show_add_dialog();
                    }
                    return false;
                }
            }).appendTo(that.controls);
        }

        if (that.indirect_attribute_member) {

            var div = $('<div/>', {
                'class': 'right-aligned-facet-controls'
            }).appendTo(that.controls);

            div.append(IPA.messages.association.show_results);
            div.append(' ');

            var name = that.entity.name+'-'+that.attribute_member+'-'+that.other_entity.name+'-type-radio';
            var direct_id = name + '-direct';

            that.direct_radio = $('<input/>', {
                id: direct_id,
                type: 'radio',
                name: name,
                value: 'direct',
                click: function() {
                    that.association_type = $(this).val();
                    that.refresh();
                    return true;
                }
            }).appendTo(div);

            $('<label/>', {
                text: IPA.messages.association.direct_membership,
                'for': direct_id
            }).appendTo(div);

            div.append(' ');

            var indirect_id = name + '-indirect';

            that.indirect_radio = $('<input/>', {
                id: indirect_id,
                type: 'radio',
                name: name,
                value: 'indirect',
                click: function() {
                    that.association_type = $(this).val();
                    that.refresh();
                    return true;
                }
            }).appendTo(div);

            $('<label/>', {
                text: IPA.messages.association.indirect_membership,
                'for': indirect_id
            }).appendTo(div);
        }
    };

    that.get_attribute_name = function() {
        if (that.association_type == 'direct') {
            return that.attribute_member+'_'+that.other_entity.name;
        } else {
            return that.indirect_attribute_member+'_'+that.other_entity.name;
        }
    };

    that.show = function() {
        that.facet_show();

        that.pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        that.header.set_pkey(that.pkey);
    };

    that.show_add_dialog = function() {

        var entity_label = that.entity.metadata.label_singular;
        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        var other_entity_label = that.other_entity.metadata.label;

        var title = that.add_title;
        title = title.replace('${entity}', entity_label);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', other_entity_label);

        var pkeys = that.data.result.result[that.get_attribute_name()];

        var dialog = IPA.association_adder_dialog({
            title: title,
            entity: that.entity,
            pkey: pkey,
            other_entity: that.other_entity,
            attribute_member: that.attribute_member,
            exclude: pkeys
        });

        var adder_columns = that.adder_columns.values;
        if (adder_columns.length) {
            dialog.set_columns(adder_columns);
        }

        dialog.execute = function() {

            var pkey = IPA.nav.get_state(that.entity.name+'-pkey');

            var associator = that.associator({
                entity: that.entity,
                pkey: pkey,
                other_entity: that.other_entity,
                values: dialog.get_selected_values(),
                method: that.add_method,
                on_success: function() {
                    that.refresh();
                    dialog.close();
                },
                on_error: function() {
                    that.refresh();
                    dialog.close();
                }
            });

            associator.execute();
        };

        dialog.open(that.container);
    };

    that.show_remove_dialog = function() {

        var values = that.table.get_selected_values();

        if (!values.length) {
            var message = IPA.messages.dialogs.remove_empty;
            alert(message);
            return;
        }

        var entity_label = that.entity.metadata.label_singular;
        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        var other_entity_label = that.other_entity.metadata.label;

        var title = that.remove_title;
        title = title.replace('${entity}', entity_label);
        title = title.replace('${primary_key}', pkey);
        title = title.replace('${other_entity}', other_entity_label);

        var dialog = IPA.association_deleter_dialog({
            title: title,
            entity: that.entity,
            pkey: pkey,
            other_entity: that.other_entity,
            values: values
        });

        dialog.execute = function() {

            var associator = that.associator({
                entity: that.entity,
                pkey: pkey,
                other_entity: that.other_entity,
                values: values,
                method: that.remove_method,
                on_success: function() {
                    that.refresh();
                    dialog.close();
                },
                on_error: function() {
                    that.refresh();
                    dialog.close();
                }
            });

            associator.execute();
        };

        dialog.open(that.container);
    };

    that.get_records_map = function(data) {

        var records_map = $.ordered_map();
        var association_name = that.get_attribute_name();
        var pkey_name = that.managed_entity.metadata.primary_key;

        var pkeys = data.result.result[association_name];
        for (var i=0; pkeys && i<pkeys.length; i++) {
            var pkey = pkeys[i];
            var record = {};
            record[pkey_name] = pkey;
            records_map.put(pkey, record);
        }

        return records_map;
    };

    that.refresh = function() {

        if (that.association_type == 'direct') {
            if (that.direct_radio) that.direct_radio.attr('checked', true);
            if (that.add_button) that.add_button.css('display', 'inline-block');
            if (that.remove_button) that.remove_button.css('display', 'inline-block');
        } else {
            if (that.indirect_radio) that.indirect_radio.attr('checked', true);
            if (that.add_button) that.add_button.css('display', 'none');
            if (that.remove_button) that.remove_button.css('display', 'none');
        }

        var pkey = that.entity.get_primary_key();

        var command = IPA.command({
            entity: that.entity.name,
            method: 'show',
            args: pkey
        });

        command.on_success = function(data, text_status, xhr) {
            that.load(data);
            that.show_content();
        };

        command.on_error = function(xhr, text_status, error_thrown) {
            that.redirect_error(error_thrown);
            that.report_error(error_thrown);
        };

        command.execute();
    };

    that.clear = function() {
        that.header.clear();
        that.table.clear();
    };

    that.needs_update = function() {
        if (that._needs_update !== undefined) return that._needs_update;

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');
        if (that.pkey !== pkey) return true;

        var page = parseInt(IPA.nav.get_state(that.entity.name+'-page'), 10) || 1;
        if (that.table.current_page !== page) return true;

        return that.facet_needs_update();
    };

    init();

    return that;
};
