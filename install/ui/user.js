/*jsl:import ipa.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
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

/* REQUIRES: ipa.js, details.js, search.js, add.js, facet.js, entity.js */

IPA.user = {};

IPA.user.entity = function(spec) {

    var that = IPA.entity(spec);

    that.init = function() {
        that.entity_init();

        var self_service = IPA.nav.name === 'self-service';
        var link = self_service ? false : undefined;

        that.builder.search_facet({
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
                },
                'uidnumber',
                'mail',
                'telephonenumber',
                'title'
            ]
        }).
        details_facet({
            factory: IPA.user.details_facet,
            sections: [
                {
                    name: 'identity',
                    label: IPA.messages.details.identity,
                    fields: [
                        'title',
                        'givenname',
                        'sn',
                        'cn',
                        'displayname',
                        'initials'
                    ]
                },
                {
                    name: 'account',
                    fields: [
                        {
                            factory: IPA.user_status_widget,
                            name: 'nsaccountlock',
                            label: IPA.messages.status.label
                        },
                        'uid',
                        {
                            factory: IPA.user_password_widget,
                            name: 'userpassword'
                        },
                        {
                            name: 'krbpasswordexpiration',
                            label: IPA.messages.objects.user.krbpasswordexpiration,
                            read_only: true,
                            formatter: IPA.utc_date_formatter()
                        },
                        'uidnumber',
                        'gidnumber',
                        'loginshell',
                        'homedirectory',
                        {
                            type: 'sshkeys',
                            name: 'ipasshpubkey',
                            label: IPA.messages.objects.sshkeystore.keys
                        }
                    ]
                },
                {
                    name: 'pwpolicy',
                    label: IPA.messages.objects.pwpolicy.identity,
                    fields: [
                        {
                            name: 'krbmaxpwdlife',
                            label: IPA.get_entity_param('pwpolicy', 'krbmaxpwdlife').label,
                            read_only: true
                        },
                        {
                            name: 'krbminpwdlife',
                            label: IPA.get_entity_param('pwpolicy', 'krbminpwdlife').label,
                            read_only: true
                        },
                        {
                            name: 'krbpwdhistorylength',
                            label: IPA.get_entity_param('pwpolicy', 'krbpwdhistorylength').label,
                            read_only: true
                        },
                        {
                            name: 'krbpwdmindiffchars',
                            label: IPA.get_entity_param('pwpolicy', 'krbpwdmindiffchars').label,
                            read_only: true
                        },
                        {
                            name: 'krbpwdminlength',
                            label: IPA.get_entity_param('pwpolicy', 'krbpwdminlength').label,
                            read_only: true
                        },
                        {
                            name: 'krbpwdmaxfailure',
                            label: IPA.get_entity_param('pwpolicy', 'krbpwdmaxfailure').label,
                            read_only: true
                        },
                        {
                            name: 'krbpwdfailurecountinterval',
                            label: IPA.get_entity_param('pwpolicy', 'krbpwdfailurecountinterval').label,
                            read_only: true
                        },
                        {
                            name: 'krbpwdlockoutduration',
                            label: IPA.get_entity_param('pwpolicy', 'krbpwdlockoutduration').label,
                            read_only: true
                        }
                    ]
                },
                {
                    name: 'krbtpolicy',
                    label: IPA.messages.objects.krbtpolicy.identity,
                    fields: [
                        {
                            name: 'krbmaxrenewableage',
                            label: IPA.get_entity_param('krbtpolicy', 'krbmaxrenewableage').label,
                            read_only: true
                        },
                        {
                            name: 'krbmaxticketlife',
                            label: IPA.get_entity_param('krbtpolicy', 'krbmaxticketlife').label,
                            read_only: true
                        }
                    ]
                },
                {
                    name: 'contact',
                    fields: [
                        { type: 'multivalued', name: 'mail' },
                        { type: 'multivalued', name: 'telephonenumber' },
                        { type: 'multivalued', name: 'pager' },
                        { type: 'multivalued', name: 'mobile' },
                        { type: 'multivalued', name: 'facsimiletelephonenumber' }
                    ]
                },
                {
                    name: 'mailing',
                    fields: ['street', 'l', 'st', 'postalcode']
                },
                {
                    name: 'employee',
                    fields: [
                        'ou',
                        {
                            type: 'entity_select',
                            name: 'manager',
                            other_entity: 'user',
                            other_field: 'uid'
                        }
                    ]
                },
                {
                    name: 'misc',
                    fields: [ 'carlicense' ]
                }
            ]
        }).
        association_facet({
            name: 'memberof_group',
            associator: IPA.serial_associator,
            link: link,
            read_only: self_service
        }).
        association_facet({
            name: 'memberof_netgroup',
            associator: IPA.serial_associator,
            link: link,
            read_only: self_service
        }).
        association_facet({
            name: 'memberof_role',
            associator: IPA.serial_associator,
            link: link,
            read_only: self_service
        }).
        association_facet({
            name: 'memberof_hbacrule',
            associator: IPA.serial_associator,
            add_method: 'add_user',
            remove_method: 'remove_user',
            link: link,
            read_only: self_service
        }).
        association_facet({
            name: 'memberof_sudorule',
            associator: IPA.serial_associator,
            add_method: 'add_user',
            remove_method: 'remove_user',
            link: link,
            read_only: self_service
        }).
        standard_association_facets({
            link: link
        }).
        adder_dialog({
            factory: IPA.user_adder_dialog,
            sections: [
                {
                    fields: [
                        {
                            name: 'uid',
                            required: false
                        },
                        'givenname',
                        'sn'
                    ]
                },
                {
                    fields: [
                        {
                            name: 'userpassword',
                            label: IPA.messages.password.new_password,
                            type: 'password'
                        },
                        {
                            name: 'userpassword2',
                            label: IPA.messages.password.verify_password,
                            type: 'password'
                        }
                    ]
                }
            ]
        });
    };

    return that;
};

IPA.user.details_facet = function(spec) {

    spec = spec || {};

    var that = IPA.details_facet(spec);

    that.refresh_on_success = function(data, text_status, xhr) {
        // do not load data from batch

        that.show_content();
    };

    that.create_refresh_command = function() {

        var pkey = IPA.nav.get_state(that.entity.name+'-pkey');

        var batch = IPA.batch_command({
            name: 'user_details_refresh'
        });

        var user_command = that.details_facet_create_refresh_command();

        user_command.on_success = function(data, text_status, xhr) {
            // create data that mimics user-show output
            var user_data = {};
            user_data.result = data;
            that.load(user_data);
        };

        batch.add_command(user_command);

        var pwpolicy_command = IPA.command({
            entity: 'pwpolicy',
            method: 'show',
            options: {
                user: pkey,
                all: true,
                rights: true
            }
        });

        pwpolicy_command.on_success = function(data, text_status, xhr) {
            // TODO: Use nested fields: that.fields.get_field('pwpolicy').get_fields();
            var fields = that.fields.get_fields();
            for (var i=0; i<fields.length; i++) {
                var field = fields[i];

                // load result into pwpolicy fields
                if (field.widget_name.match(/^pwpolicy\./)) {
                    field.load(data.result);
                }
            }
        };

        batch.add_command(pwpolicy_command);

        var krbtpolicy_command = IPA.command({
            entity: 'krbtpolicy',
            method: 'show',
            args: [ pkey ],
            options: {
                all: true,
                rights: true
            }
        });

        krbtpolicy_command.on_success = function(data, text_status, xhr) {
            // TODO: Use nested fields: that.fields.get_field('krbtpolicy').get_fields();
            var fields = that.fields.get_fields();
            for (var i=0; i<fields.length; i++) {
                var field = fields[i];

                // load result into krbtpolicy fields
                if (field.widget_name.match(/^krbtpolicy\./)) {
                    field.load(data.result);
                }
            }
        };

        batch.add_command(krbtpolicy_command);

        return batch;
    };

    return that;
};

IPA.user_adder_dialog = function(spec) {

    var that = IPA.entity_adder_dialog(spec);

    that.validate = function() {
        var valid = that.dialog_validate();

        var field1 = that.fields.get_field('userpassword');
        var field2 = that.fields.get_field('userpassword2');

        var password1 = field1.save()[0];
        var password2 = field2.save()[0];

        if (password1 !== password2) {
            field2.show_error(IPA.messages.password.password_must_match);
            valid = false;
        }

        return valid;
    };

    that.save = function(record) {
        that.dialog_save(record);
        delete record.userpassword2;
    };

    return that;
};

IPA.user_status_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);


    that.create = function(container) {

        that.widget_create(container);

        that.status_span = $('<span/>', {
            name: 'status'
        }).appendTo(container);

        that.link_span = $('<span/>', {
            name: 'link'
        }).appendTo(container);

        that.link_span.append(': ');

        that.status_link = $('<a/>', {
            name: 'link',
            click: function() {

                var facet = that.entity.get_facet();

                if (facet.is_dirty()) {
                    var dialog = IPA.dirty_dialog({
                        facet: facet
                    });

                    dialog.callback = function() {
                        that.show_activation_dialog();
                    };

                    dialog.open(container);

                } else {
                    that.show_activation_dialog();
                }

                return false;
            }
        }).appendTo(that.link_span);
    };

    that.update = function(values) {

        //if (!that.record) return;

        //var lock_field = 'nsaccountlock';
        //var locked_field = that.record[lock_field];
        var locked_field = values;
        var locked = false;

        if (locked_field instanceof Array) {
            locked_field = locked_field[0];
        }
        if (typeof locked_field === 'boolean') {
            locked = locked_field;
        } else {
            locked = locked_field && locked_field.toLowerCase() === 'true';
        }

        var status;
        var action;

        if (locked) {
            status = IPA.messages.status.disabled;
            action = 'enable';

        } else {
            status = IPA.messages.status.enabled;
            action = 'disable';
        }

        that.status_span.html(status);
        that.status_link.attr('href', action);

        var message = IPA.messages.objects.user.status_link;
        var action_label = IPA.messages.status[action];
        message = message.replace('${action}', action_label);

        that.status_link.html(message);

        if (that.writable) {
            that.link_span.css('display', '');

        } else {
            that.link_span.css('display', 'none');
        }
    };

    that.clear = function() {
        that.link_span.css('display', 'none');
        that.status_span.text('');
    };

    that.show_activation_dialog = function() {

        var action = that.status_link.attr('href');

        var message = IPA.messages.objects.user.status_confirmation;
        var action_label = IPA.messages.status[action];
        message = message.replace('${action}', action_label.toLocaleLowerCase());

        var dialog = IPA.dialog({
            title: IPA.messages.dialogs.confirmation
        });

        dialog.create = function() {
            dialog.container.append(message);
        };

        dialog.create_button({
            name: 'set_status',
            label: action_label,
            click: function() {
                that.set_status(
                    action,
                    function(data, textStatus, xhr) {
                        var facet = that.entity.get_facet();
                        facet.refresh();
                        dialog.close();
                    }
                );
            }
        });

        dialog.create_button({
            name: 'cancel',
            label: IPA.messages.buttons.cancel,
            click: function() {
                dialog.close();
            }
        });

        dialog.open(that.container);
    };

    that.set_status = function(method, on_success, on_error) {

        var pkey = IPA.nav.get_state('user-pkey');

        IPA.command({
            entity: 'user',
            method: method,
            args: [pkey],
            on_success: on_success,
            on_error: on_error
        }).execute();
    };

    that.widgets_created = function() {
        that.widget = that;
    };

    return that;
};

IPA.user_password_widget = function(spec) {

    spec = spec || {};

    var that = IPA.input_widget(spec);

    that.create = function(container) {

        that.widget_create(container);

        $('<a/>', {
            href: 'jslink',
            title: 'userpassword',
            text: IPA.messages.password.reset_password,
            click: function() {
                that.show_dialog();
                return false;
            }
        }).appendTo(container);
    };

    that.show_dialog = function() {

        var pkey = IPA.nav.get_state('user-pkey');
        var self_service = pkey === IPA.whoami.uid[0];

        var sections = [];
        if (self_service) {
            sections.push({
                fields: [
                    {
                        name: 'current_password',
                        label: IPA.messages.password.current_password,
                        type: 'password'
                    }
                ]
            });
        }

        sections.push({
            fields: [
                {
                    name: 'password1',
                    label: IPA.messages.password.new_password,
                    type: 'password'
                },
                {
                    name: 'password2',
                    label: IPA.messages.password.verify_password,
                    type: 'password'
                }
            ]
        });

        var dialog = IPA.dialog({
            entity: that.entity,
            title: IPA.messages.password.reset_password,
            width: 400,
            sections: sections
        });


        dialog.create_button({
            name: 'reset_password',
            label: IPA.messages.password.reset_password,
            click: function() {

                var record = {};
                dialog.save(record);

                var current_password;

                if (self_service) {
                    current_password = record.current_password[0];
                    if (!current_password) {
                        alert(IPA.messages.password.current_password_required);
                        return;
                    }
                }

                var new_password = record.password1[0];
                var repeat_password = record.password2[0];

                if (new_password != repeat_password) {
                    alert(IPA.messages.password.password_must_match);
                    return;
                }

                that.set_password(
                    pkey,
                    current_password,
                    new_password,
                    function(data, text_status, xhr) {
                        alert(IPA.messages.password.password_change_complete);
                        dialog.close();
                        // refresh password expiration field
                        var facet = IPA.current_entity.get_facet();
                        facet.refresh();
                    },
                    function(xhr, text_status, error_thrown) {
                        dialog.close();
                    }
                );
            }
        });

        dialog.create_button({
            name: 'cancel',
            label: IPA.messages.buttons.cancel,
            click: function() {
                dialog.close();
            }
        });

        dialog.open(that.container);
    };

    that.set_password = function(pkey, current_password, password, on_success, on_error) {

        var command = IPA.command({
            method: 'passwd',
            args: [ pkey ],
            options: {
                current_password: current_password,
                password: password
            },
            on_success: on_success,
            on_error: on_error
        });

        command.execute();
    };

    return that;
};

IPA.register('user', IPA.user.entity);