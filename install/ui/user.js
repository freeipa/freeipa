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
                     name: 'manager', entity: 'user', field_name: 'uid'
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
                    undo: false,
                    optional: true,
                    name:'uid'
                },
                'givenname', 'sn']
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

        container.append(': ');

        that.status_link = $('<a/>', {
            name: 'link',
            click: function() {

                var entity = IPA.get_entity(that.entity_name);
                var facet_name = IPA.current_facet(entity);
                var facet = entity.get_facet(facet_name);

                if (facet.is_dirty()) {
                    var dialog = IPA.dirty_dialog({
                        facet: facet
                    });

                    dialog.callback = function() {
                        that.show_activation_dialog();
                    };

                    dialog.init();
                    dialog.open(container);

                } else {
                    that.show_activation_dialog();
                }

                return false;
            }
        }).appendTo(container);
    };

    that.update = function() {

        if (!that.record) return;

        var lock_field = 'nsaccountlock';

        var locked = that.record[lock_field] &&
            that.record[lock_field][0].toLowerCase() === 'true';

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

        dialog.add_button(action_label, function() {
            that.set_status(
                action == 'activate',
                function(data, textStatus, xhr) {
                    var entity = IPA.get_entity(that.entity_name);
                    var facet_name = IPA.current_facet(entity);
                    var facet = entity.get_facet(facet_name);
                    facet.refresh();
                    dialog.close();
                }
            );
        });

        dialog.add_button(IPA.messages.buttons.cancel, function() {
            dialog.close();
        });

        dialog.init();

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
            text: IPA.messages.objects.user.reset_password,
            click: function() {
                that.show_dialog();
                return false;
            }
        }).appendTo(container);
    };

    that.show_dialog = function() {

        var dialog = IPA.dialog({
            title: IPA.messages.objects.user.reset_password,
            width: 400
        });

        dialog.create = function() {

            var dl = $('<dl/>', {
                'class': 'modal'
            }).appendTo(dialog.container);

            $('<dt/>', {
                html: IPA.messages.objects.user.new_password
            }).appendTo(dl);

            var dd = $('<dd/>', {
                'class': 'first'
            }).appendTo(dl);

            dialog.password1 = $('<input/>', {
                type: 'password'
            }).appendTo(dd);

            $('<dt/>', {
                html: IPA.messages.objects.user.repeat_password
            }).appendTo(dl);

            dd = $('<dd/>', {
                'class': 'first'
            }).appendTo(dl);

            dialog.password2 = $('<input/>', {
                type: 'password'
            }).appendTo(dd);
        };

        dialog.add_button(IPA.messages.objects.user.reset_password, function() {

            var new_password = dialog.password1.val();
            var repeat_password = dialog.password2.val();

            if (new_password != repeat_password) {
                alert(IPA.messages.objects.user.password_must_match);
                return;
            }

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
                    password: new_password
                },
                on_success: function(data, text_status, xhr) {
                    alert(IPA.messages.objects.user.password_change_complete);
                    dialog.close();
                },
                on_error: function(xhr, text_status, error_thrown) {
                    dialog.close();
                }
            });

            command.execute();
        });

        dialog.add_button(IPA.messages.buttons.cancel, function() {
            dialog.close();
        });

        dialog.init();

        dialog.open(that.container);
    };

    return that;
};
