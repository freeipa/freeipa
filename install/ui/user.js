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

    return IPA.entity({
        name: 'user'
    }).
        facet(
            IPA.search_facet().
                column({name:'uid'}).
                column({name:'cn'}).
                column({name:'uidnumber'}).
                column({name:'mail'}).
                column({name:'telephonenumber'}).
                column({name:'title'}).
                dialog(
                    IPA.add_dialog({
                        'name': 'add',
                        'title': IPA.messages.objects.user.add
                    }).
                        field(IPA.text_widget({ name: 'uid', undo: false })).
                        field(IPA.text_widget({ name: 'givenname', undo: false })).
                        field(IPA.text_widget({ name: 'sn', undo: false })))).
        facet(IPA.details_facet().
            section(
                IPA.stanza({name: 'identity', label: IPA.messages.details.identity}).
                    input({name:'title'}).
                    input({name:'givenname'}).
                    input({name:'sn'}).
                    input({name:'cn'}).
                    input({name:'displayname'}).
                    input({name:'initials'})).
            section(
                IPA.stanza({name: 'account', label: IPA.messages.objects.user.account}).
                    custom_input(IPA.user_status_widget({name:'nsaccountlock'})).
                    input({name:'uid'}).
                    custom_input(IPA.user_password_widget({name:'userpassword'})).
                    input({name:'uidnumber'}).
                    input({name:'gidnumber'}).
                    input({name:'loginshell'}).
                    input({name:'homedirectory'})).
            section(
                IPA.stanza({name: 'contact', label: IPA.messages.objects.user.contact}).
                    multivalued_text({name:'mail'}).
                    multivalued_text({name:'telephonenumber'}).
                    multivalued_text({name:'pager'}).
                    multivalued_text({name:'mobile'}).
                    multivalued_text({name:'facsimiletelephonenumber'})).
            section(
                IPA.stanza({name: 'mailing', label: IPA.messages.objects.user.mailing}).
                    input({name:'street'}).
                    input({name:'l'}).
                    input({name:'st'}).
                    input({name:'postalcode'})).
            section(
                IPA.stanza({name: 'employee', label: IPA.messages.objects.user.employee}).
                    input({name:'ou'}).
                    input({name:'manager'})).
            section(
                IPA.stanza({name: 'misc', label: IPA.messages.objects.user.misc}).
                    input({name:'carlicense'}))).
        facet(
            IPA.association_facet({
                name: 'memberof_group',
                associator: IPA.serial_associator
            })).
        facet(
            IPA.association_facet({
                name: 'memberof_netgroup',
                associator: IPA.serial_associator
            })).
        facet(
            IPA.association_facet({
                name: 'memberof_role',
                associator: IPA.serial_associator
            })).
        standard_associations();
};

/* ATTRIBUTE CALLBACKS */


IPA.user_status_widget = function(spec) {

    spec = spec || {};

    var that = IPA.widget(spec);

    that.update = function() {

        if (!that.record) return;

        that.container.empty();

        var lock_field = 'nsaccountlock';

        var locked  = that.record[lock_field] &&
            that.record[lock_field][0].toLowerCase() === 'true';
        var title = IPA.messages.objects.user.active;
        var text = title+":  "+IPA.messages.objects.user.deactivate;
        if (locked) {
            title = IPA.messages.objects.user.inactive;
            text = title+":  "+IPA.messages.objects.user.activate;
        }

        function on_lock_win(data, textStatus, xhr){
            var entity = IPA.get_entity(that.entity_name);
            var facet = entity.get_facet('details');
            facet.refresh();
            return false;
        }

        function on_lock_fail(data, textStatus, xhr){
            $("#userstatuslink").text = IPA.messages.objects.user.error_changing_status;
            return false;
        }

        var status_field =
            $('<a/>',
              {
                  id: 'userstatuslink',
                  title: title,
                  href: "jslink",
                  text: text,
                  click: function() {
                      var jobj = $(this);
                      var val = jobj.attr('title');
                      var pkey =  $.bbq.getState('user-pkey');
                      var command = 'user_enable';
                      if (val == IPA.messages.objects.user.active) {
                          command = 'user_disable';
                      }
                      IPA.cmd(command, [pkey], {}, on_lock_win,on_lock_fail);

                      return (false);
                  }
              });
        status_field.appendTo(that.container);
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

            var user_pkey = $.bbq.getState('user-pkey');

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
