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

/* REQUIRES: ipa.js, details.js, search.js, add.js, entity.js */


IPA.entity_factories.user = function() {

    var link = true;
    if (IPA.nav && IPA.nav.name == 'self-service') {
        link = false;
    }

    var builder = IPA.entity_builder();

    builder.
        entity('user').
        search_facet({
            columns: [
                'uid',
                'givenname',
                'sn',
                'uidnumber',
                'mail',
                'telephonenumber',
                'title'
            ]
        }).
        details_facet({ sections: [
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
                        label: IPA.messages.objects.user.account_status
                    },
                    'uid',
                    { factory: IPA.user_password_widget, name: 'userpassword' },
                    'uidnumber',
                    'gidnumber',
                    'loginshell',
                    'homedirectory'
                ]
            },
            {
                name: 'contact',
                fields: [
                    { factory: IPA.multivalued_text_widget, name: 'mail' },
                    { factory: IPA.multivalued_text_widget, name: 'telephonenumber' },
                    { factory: IPA.multivalued_text_widget, name: 'pager' },
                    { factory: IPA.multivalued_text_widget, name: 'mobile' },
                    { factory: IPA.multivalued_text_widget,
                      name: 'facsimiletelephonenumber' }
                ]
            },
            {
                name: 'mailing',
                fields: ['street', 'l', 'st', 'postalcode']
            },
            {
                name: 'employee',
                fields:
                ['ou',
                 {
                     factory:IPA.entity_select_widget,
                     name: 'manager',
                     other_entity: 'user',
                     other_field: 'uid'
                 }
                ]
            },
            {
                name: 'misc',
                fields: ['carlicense']
            }]}).
        association_facet({
            name: 'memberof_group',
            associator: IPA.serial_associator,
            link: link
        }).
        association_facet({
            name: 'memberof_netgroup',
            associator: IPA.serial_associator,
            link: link
        }).
        association_facet({
            name: 'memberof_role',
            associator: IPA.serial_associator,
            link: link
        }).
        association_facet({
            name: 'memberof_hbacrule',
            associator: IPA.serial_associator,
            add_method: 'add_user',
            remove_method: 'remove_user',
            link: link
        }).
        association_facet({
            name: 'memberof_sudorule',
            associator: IPA.serial_associator,
            add_method: 'add_user',
            remove_method: 'remove_user',
            link: link
        }).
        standard_association_facets({
            link: link
        }).
        adder_dialog({
            fields: [
                {
                    factory : IPA.text_widget,
                    optional: true,
                    name:'uid'
                },
                'givenname',
                'sn'
            ]
        });

    return builder.build();
};

IPA.user_status_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

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

    that.update = function() {

        if (!that.record) return;

        var lock_field = 'nsaccountlock';
        var locked_field = that.record[lock_field];
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
            status = IPA.messages.objects.user.inactive;
            action = 'activate';

        } else {
            status = IPA.messages.objects.user.active;
            action = 'deactivate';
        }

        that.status_span.html(status);
        that.status_link.attr('href', action);

        var message = IPA.messages.objects.user.activation_link;
        var action_label = IPA.messages.objects.user[action];
        message = message.replace('${action}', action_label);

        that.status_link.html(message);

        if (that.writable) {
            that.link_span.css('display', '');

        } else {
            that.link_span.css('display', 'none');
        }
    };

    that.show_activation_dialog = function() {

        var action = that.status_link.attr('href');

        var message = IPA.messages.objects.user.activation_confirmation;
        var action_label = IPA.messages.objects.user[action];
        message = message.replace('${action}', action_label.toLocaleLowerCase());

        var dialog = IPA.dialog({
            'title': IPA.messages.dialogs.confirmation
        });

        dialog.create = function() {
            dialog.container.append(message);
        };

        dialog.create_button({
            name: 'set_status',
            label: action_label,
            click: function() {
                that.set_status(
                    action == 'activate',
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

    that.set_status = function(enabled, on_success, on_error) {

        var pkey = IPA.nav.get_state('user-pkey');
        var method = enabled ? 'enable' : 'disable';

        IPA.command({
            entity: 'user',
            method: method,
            args: [pkey],
            on_success: on_success,
            on_error: on_error
        }).execute();
    };

    return that;
};

IPA.user_password_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.create = function(container) {

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

        var dialog = IPA.dialog({
            title: IPA.messages.password.reset_password,
            width: 400
        });

        var password1 = dialog.add_field(IPA.text_widget({
            name: 'password1',
            label: IPA.messages.password.new_password,
            type: 'password'
        }));

        var password2 = dialog.add_field(IPA.text_widget({
            name: 'password2',
            label: IPA.messages.password.verify_password,
            type: 'password'
        }));

        dialog.create_button({
            name: 'reset_password',
            label: IPA.messages.password.reset_password,
            click: function() {

                var record = {};
                dialog.save(record);

                var new_password = record.password1[0];
                var repeat_password = record.password2[0];

                if (new_password != repeat_password) {
                    alert(IPA.messages.password.password_must_match);
                    return;
                }

                that.set_password(
                    new_password,
                    function(data, text_status, xhr) {
                        alert(IPA.messages.password.password_change_complete);
                        dialog.close();
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

    that.set_password = function(password, on_success, on_error) {
        var user_pkey = IPA.nav.get_state('user-pkey');

        var args;
        if (user_pkey === IPA.whoami.uid[0]) {
            args = [];
        } else {
            args = [user_pkey];
        }

        var command = IPA.command({
            method: 'passwd',
            args: args,
            options: {
                password: password
            },
            on_success: on_success,
            on_error: on_error
        });

        command.execute();
    };

    return that;
};
