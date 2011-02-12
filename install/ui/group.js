/*jsl:import ipa.js */

/*  Authors:
 *    Pavel Zuna <pzuna@redhat.com>
 *    Endi Dewata <edewata@redhat.com>
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

IPA.entity_factories.group =  function () {

    return IPA.entity({
        'name': 'group'
    }).
        facet(
            IPA.search_facet().
                column({name: 'cn'}).
                column({name: 'gidnumber'}).
                column({name: 'description'}).
                dialog(
                    IPA.add_dialog({
                        'name': 'add',
                        'title': 'Add New Group'
                    }).
                        field(IPA.text_widget({name: 'cn', undo: false})).
                        field(IPA.text_widget({name: 'description', undo: false})).
                        // TODO: Replace with i18n label
                        field(IPA.checkbox_widget({
                            name: 'posix',
                            label: 'Is this a POSIX group?',
                            undo: false,
                            checked: 'checked'})).
                        field(IPA.text_widget({name: 'gidnumber', undo: false})))).
        facet(
            IPA.details_facet().
                section(
                    IPA.stanza({label: 'Group Settings' }).
                        input({name: 'cn' }).
                        input({name: 'description'}).
                        input({name: 'gidnumber' }))).
        facet(
            IPA.group_member_user_facet({
                'name': 'member_user'
            })).
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


IPA.group_member_user_facet = function (spec) {

    spec = spec || {};

    var that = IPA.association_facet(spec);

    that.init = function() {

        that.create_column({name: 'cn'});

        var column = that.create_column({
            name: 'uid',
            primary_key: true
        });

        column.setup = function(container, record) {
            container.empty();

            var value = record[column.name];
            value = value ? value.toString() : '';

            $('<a/>', {
                'href': '#'+value,
                'html': value,
                'click': function (value) {
                    return function() {
                        var state = IPA.tab_state(that.other_entity);
                        state[that.other_entity + '-facet'] = 'details';
                        state[that.other_entity + '-pkey'] = value;
                        $.bbq.pushState(state);
                        return false;
                    };
                }(value)
            }).appendTo(container);
        };

        that.create_column({name: 'uidnumber'});
        that.create_column({name: 'mail'});
        that.create_column({name: 'telephonenumber'});
        that.create_column({name: 'title'});

        that.create_adder_column({
            name: 'cn',
            width: '100px'
        });

        that.create_adder_column({
            name: 'uid',
            primary_key: true,
            width: '100px'
        });

        that.association_facet_init();
    };

    return that;

};